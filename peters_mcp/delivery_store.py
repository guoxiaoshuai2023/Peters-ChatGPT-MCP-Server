"""Persistent, actor-bound original-byte deliveries with create-only publication.

Preparation tokens bind reviewed bytes; they are NOT proof of user consent. The
calling client must confirm the exact commit arguments as a write action.
"""

import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timezone
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import stat
import threading
import time
import unicodedata
from urllib.parse import urlsplit

from .candidates import publish_exclusive
from .audit import audit_request_id
from .catalog import AccessError, INTERNAL_DELIVERY_PREFIX
from .delivery_types import DeliveryTarget


_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
_ACTIVE = set()
_ACTIVE_LOCK = threading.Lock()


def _error(code, message):
    return AccessError(message, code="delivery_" + code)


def _json(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _manifest_bytes(manifest):
    # Native clients can serialize Unicode as JSON escape sequences. Budget that
    # larger representation, independently of the compact UTF-8 persistent form.
    return len(json.dumps(manifest, ensure_ascii=True, separators=(",", ":")).encode("ascii"))


def _identity(info):
    return [info.st_dev, info.st_ino]


def _allocation(info):
    return max(info.st_size, getattr(info, "st_blocks", 0) * 512)


def _tree_allocation(fd):
    total = _allocation(os.fstat(fd))
    for name in os.listdir(fd):
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            child = os.open(name, _DIR, dir_fd=fd)
            try:
                if _identity(os.fstat(child)) != _identity(info):
                    raise _error("state_changed", "Directory changed during allocation accounting.")
                total += _tree_allocation(child)
            finally:
                os.close(child)
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            total += _allocation(info)
        else:
            raise _error("state_unsafe", "Linked or unexpected entry prevents allocation accounting.")
    return total


def _version(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_nlink)


def _snapshot(target):
    value = asdict(target)
    value["root"] = str(target.root)
    return json.loads(_json(value))


def _target(value):
    value = dict(value)
    value["root"] = Path(value["root"])
    for key in ("parent_parts", "root_identity", "parent_identity"):
        value[key] = tuple(value[key])
    return DeliveryTarget(**value)


def _actor(actor):
    if not isinstance(actor, str) or not actor.isascii() or not actor.strip() or len(actor) > 256 or any(ord(c) < 33 for c in actor):
        raise _error("actor_required", "A verified nonempty actor is required.")


def _name(name):
    if (not isinstance(name, str) or not name or len(name.encode("utf-8")) > 160
            or name != unicodedata.normalize("NFC", name) or name.startswith(".")
            or not all(c.isalnum() or c in "-_." for c in name) or ".." in name
            or name.endswith(".") or name.casefold() in {"agents.md", "claude.md", "skill.md"}):
        raise _error("version_invalid", "Choose one version directory using letters, digits, -, _, and single dots.")


class DeliveryStore:
    def __init__(self, state_dir: Path, policy, *, downloader=None, audit=None):
        self.path = Path(state_dir).absolute()
        self.policy = policy
        self.downloader = downloader
        self.audit = audit
        self.path.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.path.resolve() != self.path or self.path.is_symlink():
            raise _error("state_unsafe", "State directory must be canonical and unlinked.")
        info = self.path.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise _error("state_unsafe", "State directory must be owner-only (0700).")
        self._state_identity = _identity(info)
        self._mutex = threading.RLock()
        self._closed = False
        with self._locked():
            key_path = self.path / "preview.key"
            try:
                fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            except FileExistsError:
                pass
            else:
                with os.fdopen(fd, "wb") as output:
                    output.write(secrets.token_bytes(32))
                    output.flush()
                    os.fsync(output.fileno())
            fd = os.open(key_path, _READ)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600):
                    raise _error("state_unsafe", "Preparation key is not private.")
                self._key = os.read(fd, 33)
                if len(self._key) != 32:
                    raise _error("state_unsafe", "Preparation key has invalid length.")
            finally:
                os.close(fd)
            db_path = self.path / "deliveries.sqlite3"
            fd = os.open(db_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
                    raise _error("state_unsafe", "Delivery database is not private.")
            finally:
                os.close(fd)
            self.db = sqlite3.connect(db_path, check_same_thread=False)
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("CREATE TABLE IF NOT EXISTS deliveries (id TEXT PRIMARY KEY, intent TEXT UNIQUE NOT NULL, body TEXT NOT NULL)")
            self.db.commit()
        self._worker = ThreadPoolExecutor(max_workers=1, thread_name_prefix="package-receive")

    @contextmanager
    def _locked(self):
        with self._mutex:
            info = os.lstat(self.path)
            if not stat.S_ISDIR(info.st_mode) or _identity(info) != self._state_identity:
                raise _error("state_changed", "State directory identity changed.")
            fd = os.open(self.path / "store.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
                    raise _error("state_unsafe", "Delivery lock is not private.")
                fcntl.flock(fd, fcntl.LOCK_EX)
                yield
            finally:
                os.close(fd)

    def _put(self, row):
        row["updated_at"] = time.time()
        with self.db:
            self.db.execute("INSERT INTO deliveries VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET body=excluded.body",
                            (row["delivery_id"], row["intent"], _json(row)))
        self._event(row, "state")

    def _event(self, row, phase, **details):
        if self.audit is not None:
            event = {'time': datetime.now(timezone.utc).isoformat(), 'event': 'package_delivery',
                     'version': '0.5.0', 'delivery_id': row['delivery_id'], 'phase': phase,
                     'status': row['status'], 'error_code': row.get('error_code'), **details}
            request_id = audit_request_id.get() or row.get('request_id')
            if request_id is not None:
                event['request_id'] = request_id
            self.audit.info(json.dumps(event))

    def _get(self, actor, delivery_id):
        _actor(actor)
        if not isinstance(delivery_id, str) or not re.fullmatch(r"[0-9a-f]{32}", delivery_id):
            raise _error("not_found", "Delivery is unavailable for this actor.")
        result = self.db.execute("SELECT body FROM deliveries WHERE id=?", (delivery_id,)).fetchone()
        if result is None:
            raise _error("not_found", "Delivery is unavailable for this actor.")
        row = json.loads(result[0])
        if not hmac.compare_digest(row["actor"], actor):
            raise _error("not_found", "Delivery is unavailable for this actor.")
        return row

    def _check_policy(self, row):
        target = _target(row["target"])
        self.policy.revalidate(target)
        if _snapshot(self.policy.resolve(target.target_id)) != row["target"]:
            raise _error("scope_changed", "Delivery permission or target changed; review a new delivery.")
        return target

    def _clean_expired(self, *, clean_private=False, clean_target=False, selected_id=None):
        now = time.time()
        for (body,) in self.db.execute("SELECT body FROM deliveries").fetchall():
            row = json.loads(body)
            if selected_id is not None and row["delivery_id"] != selected_id:
                continue
            if row["status"] in {"ready", "interrupted", "failed", "receiving", "committing", "expired", "expired_cleanup_pending"} and row["expires_at"] <= now:
                with _ACTIVE_LOCK:
                    active = (str(self.path), row["delivery_id"]) in _ACTIVE
                if active or (row["status"] == "receiving" and self._receiving_live(row["delivery_id"])):
                    continue
                try:
                    if row.get("temporary_name"):
                        target = self._check_policy(row)
                        with self.policy.open_parent(target) as parent_fd:
                            if self._published(row, parent_fd):
                                if clean_private:
                                    self._release_completed(row)
                                continue
                            if not clean_target:
                                row.update(status="expired_cleanup_pending", error_code="delivery_cleanup_confirmation_required")
                                self._put(row)
                                continue
                            self._remove_partial(row, parent_fd)
                    if clean_private:
                        self._remove_staging(row)
                except (AccessError, OSError):
                    # Changed/revoked/unknown data stays untouched and charged to quota.
                    row.update(status="expired_cleanup_pending", error_code="delivery_cleanup_review_required")
                else:
                    row.update(status="expired", error_code="delivery_staging_expired")
                    if clean_private:
                        row["reserved_bytes"] = 0
                self._put(row)

    def _remove_partial(self, row, parent_fd):
        name = row.get("temporary_name")
        if not name:
            return
        try:
            fd = os.open(name, _DIR, dir_fd=parent_fd)
        except FileNotFoundError:
            return
        try:
            if _identity(os.fstat(fd)) != row.get("temporary_identity"):
                raise _error("target_conflict", "Publication staging identity changed; cleanup requires review.")
            owned = row.get("temporary_entries", {})
            entries = {item["path"]: item for item in row["manifest"]}
            observed = {}

            def check(directory, source, prefix=""):
                for child in os.listdir(directory):
                    path = prefix + child
                    info = os.stat(child, dir_fd=directory, follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        key = path + "/"
                        if _identity(info) != owned.get(key):
                            raise _error("target_conflict", "Unknown temporary directory must not be removed.")
                        nested = os.open(child, _DIR, dir_fd=directory)
                        try:
                            if _identity(os.fstat(nested)) != owned[key]:
                                raise _error("target_conflict", "Temporary directory changed.")
                            check(nested, source, key)
                        finally:
                            os.close(nested)
                    elif (stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and path in entries
                          and _identity(info) == owned.get(path) and info.st_size <= entries[path]["size_bytes"]):
                        key = path
                        reader = os.open(child, _READ, dir_fd=directory)
                        try:
                            if _version(os.fstat(reader)) != _version(info):
                                raise _error("content_changed", "Temporary file changed before cleanup.")
                            with self._open_file(source, path) as original:
                                while chunk := os.read(reader, 65536):
                                    if chunk != os.read(original, len(chunk)):
                                        raise _error("content_changed", "Modified temporary bytes require review.")
                            if _version(os.fstat(reader)) != _version(info):
                                raise _error("content_changed", "Temporary file changed during cleanup check.")
                        finally:
                            os.close(reader)
                    else:
                        raise _error("target_conflict", "Unknown or linked temporary entry must not be removed.")
                    observed[key] = _version(info)

            def remove(directory, prefix=""):
                for child in os.listdir(directory):
                    path = prefix + child
                    info = os.stat(child, dir_fd=directory, follow_symlinks=False)
                    key = path + "/" if stat.S_ISDIR(info.st_mode) else path
                    if _version(info) != observed.get(key):
                        raise _error("content_changed", "Temporary entry changed; cleanup stopped.")
                    if key.endswith("/"):
                        nested = os.open(child, _DIR, dir_fd=directory)
                        try:
                            if _identity(os.fstat(nested)) != owned[key]:
                                raise _error("content_changed", "Temporary directory changed; cleanup stopped.")
                            remove(nested, key)
                        finally:
                            os.close(nested)
                        os.rmdir(child, dir_fd=directory)
                    else:
                        os.unlink(child, dir_fd=directory)

            with self._payload(row) as source:
                check(fd, source)
            if set(observed) != set(owned):
                raise _error("target_conflict", "Recorded temporary entries are missing; cleanup requires review.")
            remove(fd)
            if _identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)) != row["temporary_identity"]:
                raise _error("target_conflict", "Temporary directory changed before removal.")
            os.rmdir(name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        finally:
            os.close(fd)

    def _remove_staging(self, row):
        directory = self.path / row["delivery_id"]
        try:
            info = directory.lstat()
        except FileNotFoundError:
            return
        if (not stat.S_ISDIR(info.st_mode)
                or _identity(info) != row.get("staging_directory_identity")):
            raise _error("state_changed", "Staging directory was replaced; it will not be deleted.")
        shutil.rmtree(directory)

    def _clean_completed_private(self):
        """Write-operation maintenance: release only this store's private spool.

        Completion metadata remains a permanent no-recreation tombstone even if
        the published directory has subsequently changed or permissions changed.
        """
        for (body,) in self.db.execute("SELECT body FROM deliveries").fetchall():
            row = json.loads(body)
            if row["status"] != "completed" or not row.get("reserved_bytes"):
                continue
            try:
                self._release_completed(row)
            except (AccessError, OSError):
                row["error_code"] = "delivery_cleanup_review_required"
                self._put(row)

    def _receive_lease(self, delivery_id):
        fd = os.open(self.path / (delivery_id + ".receive.lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
                raise _error("state_unsafe", "Receive lock is not private.")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _receiving_live(self, delivery_id):
        try:
            fd = self._receive_lease(delivery_id)
        except BlockingIOError:
            return True
        os.close(fd)
        return False

    def _metadata_bytes(self, rows=None):
        if rows is None:
            rows = [json.loads(r[0]) for r in self.db.execute("SELECT body FROM deliveries")]
        reserved_spools = {row["delivery_id"]: row.get("staging_directory_identity")
                           for row in rows if row.get("reserved_bytes", 0) > 0}

        def visit(fd, root=False):
            total = _allocation(os.fstat(fd))
            for name in os.listdir(fd):
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    if root and _identity(info) == reserved_spools.get(name):
                        # The full directory allocation is charged by its
                        # reservation, including file and directory blocks.
                        continue
                    child = os.open(name, _DIR, dir_fd=fd)
                    try:
                        if _identity(os.fstat(child)) != _identity(info):
                            raise _error("state_changed", "State changed during quota accounting.")
                        total += visit(child)
                    finally:
                        os.close(child)
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    total += _allocation(info)
                else:
                    raise _error("state_unsafe", "Linked or unexpected state entry prevents safe quota accounting.")
            return total

        fd = os.open(self.path, _DIR)
        try:
            return visit(fd, root=True)
        finally:
            os.close(fd)

    def _spool_bytes(self, row):
        try:
            info = (self.path / row["delivery_id"]).lstat()
        except FileNotFoundError:
            return 0
        if _identity(info) != row.get("staging_directory_identity"):
            # An unrecognized replacement is counted by _metadata_bytes instead.
            return 0
        fd = os.open(self.path / row["delivery_id"], _DIR)
        try:
            if _identity(os.fstat(fd)) != row["staging_directory_identity"]:
                raise _error("state_changed", "Staging changed during allocation accounting.")
            return _tree_allocation(fd)
        finally:
            os.close(fd)

    @staticmethod
    def _block_bytes(fd):
        info = os.fstatvfs(fd)
        # f_bsize can be an optimal I/O size (1 MiB on APFS), not an allocation
        # unit. POSIX f_frsize is the filesystem fragment/allocation unit.
        return max(4096, info.f_frsize or info.f_bsize)

    @staticmethod
    def _package_budget(size, files, directories, block):
        # One padding block per file, one per directory, and one per directory
        # entry. A supported component is <=240 bytes, well below this entry budget.
        return size + 2 * (files + directories) * block

    def _reservation(self, target, limits, *, manifest=None, spool_bytes=None):
        state_fd = os.open(self.path, _DIR)
        try:
            state_block = self._block_bytes(state_fd)
        finally:
            os.close(state_fd)
        with self.policy.open_parent(target) as parent_fd:
            target_block = self._block_bytes(parent_fd)
        if manifest is None:
            files, size = limits.max_files, limits.max_package_bytes
            directories = 1 + files * max(0, limits.max_depth - 1)
            archive = ((limits.max_archive_bytes + state_block - 1) // state_block) * state_block
            # Two extra blocks cover the private delivery directory and entries
            # for archive.zip and payload. The package estimate includes its root.
            private = archive + self._package_budget(size, files, directories, state_block) + 2 * state_block
        else:
            files, size = len(manifest), sum(item["size_bytes"] for item in manifest)
            directories = 1 + len({"/".join(item["path"].split("/")[:index])
                                   for item in manifest for index in range(1, len(item["path"].split("/")))})
            private = spool_bytes
        target_bytes = self._package_budget(size, files, directories, target_block)
        # State rows grow to hold the manifest and created inode map. Include
        # bounded row growth plus SQLite page/journal churn before accepting work.
        metadata_headroom = 4 * limits.max_manifest_bytes + 16 * state_block
        return {"reserved_bytes": private + target_bytes + metadata_headroom,
                "target_reserved_bytes": target_bytes, "metadata_reserved_bytes": metadata_headroom}

    def _accounted_bytes(self):
        rows = [json.loads(r[0]) for r in self.db.execute("SELECT body FROM deliveries")]
        return self._metadata_bytes(rows) + sum(max(row.get("reserved_bytes", 0), self._spool_bytes(row))
                                                for row in rows if row.get("reserved_bytes", 0) > 0)

    def _space(self, additional):
        used = self._accounted_bytes()
        if used + additional > self.policy.limits().max_staging_bytes:
            raise _error("quota_exceeded", "Staging and retained metadata exceed the quota; operator maintenance or an explicit quota change is required. Completion records are never deleted automatically.")
        if shutil.disk_usage(self.path).free < additional:
            raise _error("space_unavailable", "Insufficient staging disk space.")

    def stage(self, actor, file, target_id, version_directory, expected_sha256):
        _actor(actor)
        _name(version_directory)
        if not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
            raise _error("hash_required", "Supply the original archive SHA256 in lowercase hexadecimal.")
        with self._locked():
            if self._closed:
                raise _error("closed", "Delivery receiver is stopping.")
            self._clean_expired(clean_private=True)
            self._clean_completed_private()
            target = self.policy.resolve(target_id)
            self.policy.revalidate(target)
            intent = hashlib.sha256(_json([actor, target_id, version_directory, expected_sha256]).encode()).hexdigest()
            existing = self.db.execute("SELECT body FROM deliveries WHERE intent=?", (intent,)).fetchone()
            limits = self.policy.limits()
            reservation = self._reservation(target, limits)
            reserve = reservation["reserved_bytes"]
            if existing:
                row = json.loads(existing[0])
                self._check_policy(row)
                with _ACTIVE_LOCK:
                    active = (str(self.path), row["delivery_id"]) in _ACTIVE
                if row["status"] == "receiving" and not active and not self._receiving_live(row["delivery_id"]):
                    row["status"] = "interrupted"
                    self._put(row)
                if (row["status"] == "expired" and row.get("reserved_bytes") == 0
                        and not row.get("temporary_name") and not row.get("published_identity")):
                    # This explicit write request renews reception, not publication.
                    # Never revive anything that entered the publication phase.
                    with self.policy.open_parent(target) as parent_fd:
                        try:
                            os.stat(version_directory, dir_fd=parent_fd, follow_symlinks=False)
                        except FileNotFoundError:
                            pass
                        else:
                            raise _error("target_conflict", "Target now exists; expired delivery will not be revived.") from None
                    row.update(status="interrupted", expires_at=time.time() + limits.staging_ttl_seconds,
                               renewed_at=time.time(), manifest=[])
                    row.pop("staging_identity", None)
                if row["status"] != "interrupted":
                    result = self._inspect(row)
                    if row["status"] == "completed":
                        self._release_completed(row)
                    return result
                if active or self._receiving_live(row["delivery_id"]):
                    return self._base(row)
                self._space(max(0, reserve - row["reserved_bytes"]))
            else:
                self._space(reserve)
                now = time.time()
                row = dict(delivery_id=secrets.token_hex(16), intent=intent, actor=actor,
                           target=_snapshot(target), version_directory=version_directory,
                           archive_sha256=expected_sha256, manifest=[], created_at=now,
                           expires_at=now + limits.staging_ttl_seconds, status="receiving",
                           request_id=audit_request_id.get())
            lease = self._receive_lease(row["delivery_id"])
            row.update(status="receiving", error_code=None, **reservation)
            self._put(row)
            key = (str(self.path), row["delivery_id"])
            with _ACTIVE_LOCK:
                _ACTIVE.add(key)
            # URLs remain in this short-lived memory job only, never in the database.
            self._worker.submit(self._receive, actor, row["delivery_id"], file, limits, lease)
            return self._base(row)

    def _receive(self, actor, delivery_id, file, limits, lease):
        key = (str(self.path), delivery_id)
        try:
            from .package_input import download_archive, extract_package
            with self._locked():
                row = self._get(actor, delivery_id)
                self._check_policy(row)
                directory = self.path / delivery_id
                if directory.exists():
                    self._remove_staging(row)
                directory.mkdir(mode=0o700)
                row["staging_directory_identity"] = _identity(directory.stat())
                self._put(row)
            archive = directory / "archive.zip"
            receiver = self.downloader or download_archive
            sources = self.policy.sources()
            self._event(row, "download_started")
            receive_started = time.monotonic()
            result = receiver(file, archive, row["archive_sha256"], sources, limits)
            if sources != self.policy.sources():
                raise _error("download_policy_changed", "File-source policy changed during intake; retry after review.")
            if result["sha256"] != row["archive_sha256"]:
                raise _error("archive_mismatch", "Downloaded archive does not match the source hash.")
            self._event(row, "download_verified", size_bytes=result['size_bytes'],
                        elapsed_ms=round((time.monotonic() - receive_started) * 1000))
            manifest = extract_package(archive, directory / "payload", limits)
            if _manifest_bytes(manifest) > limits.max_manifest_bytes:
                raise _error("manifest_too_large", "Package manifest exceeds the control-message limit.")
            with self._locked():
                row = self._get(actor, delivery_id)
                self._check_policy(row)
                if sources != self.policy.sources():
                    raise _error("download_policy_changed", "File-source policy changed during intake; retry after review.")
                if row["expires_at"] <= time.time():
                    raise _error("staging_expired", "Staging expired; this delivery cannot be published.")
                fd = os.open(directory / "payload", _DIR)
                try:
                    self._verify_tree(fd, manifest)
                    row["staging_identity"] = _identity(os.fstat(fd))
                finally:
                    os.close(fd)
                archive.unlink()
                reservation = self._reservation(_target(row["target"]), limits, manifest=manifest,
                                                spool_bytes=self._spool_bytes(row))
                # Recheck even when shrinking: concurrent metadata growth or a
                # changed operator quota must not turn an estimate into permission.
                self._space(reservation["reserved_bytes"] - row["reserved_bytes"])
                row.update(status="ready", manifest=manifest, **reservation)
                self._put(row)
                self._event(row, "package_verified", file_count=len(manifest),
                            size_bytes=sum(item['size_bytes'] for item in manifest))
        except Exception as exc:
            with self._locked():
                row = self._get(actor, delivery_id)
                code = exc.code if isinstance(exc, AccessError) else "delivery_receive_interrupted"
                # A source can be safely re-fetched with the same immutable expected hash.
                source_review = code in {"file_source_not_approved", "file_source_nonpublic"}
                retry = source_review or not isinstance(exc, AccessError) or any(x in code for x in ("network", "download", "timeout", "unavailable"))
                if source_review:
                    # Emitted only after strict URL validation; never retain signed paths/queries.
                    row['source_host'] = urlsplit(file.download_url).hostname
                row.update(status="interrupted" if retry else "failed", error_code=code)
                self._put(row)
        finally:
            os.close(lease)
            with _ACTIVE_LOCK:
                _ACTIVE.discard(key)

    @staticmethod
    def _verify_tree(root_fd, manifest):
        expected = {entry["path"]: entry for entry in manifest}
        directories = {"/".join(path.split("/")[:i]) for path in expected for i in range(1, len(path.split("/")))}
        seen = set()

        def visit(fd, prefix=""):
            before = os.fstat(fd)
            for name in os.listdir(fd):
                path = prefix + name
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode) and path in directories:
                    child = os.open(name, _DIR, dir_fd=fd)
                    try:
                        if _identity(info) != _identity(os.fstat(child)):
                            raise _error("content_changed", "Package directory changed during verification.")
                        visit(child, path + "/")
                        if _identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) != _identity(info):
                            raise _error("content_changed", "Package directory changed during verification.")
                    finally:
                        os.close(child)
                elif path in expected and stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    reader = os.open(name, _READ, dir_fd=fd)
                    try:
                        start = os.fstat(reader)
                        entry = expected[path]
                        if _version(start) != _version(info) or start.st_size != entry["size_bytes"]:
                            raise _error("content_changed", "Package file changed or has unexpected size.")
                        digest = hashlib.sha256()
                        count = 0
                        while chunk := os.read(reader, 65536):
                            count += len(chunk)
                            if count > entry["size_bytes"]:
                                raise _error("content_changed", "Package file grew during verification.")
                            digest.update(chunk)
                        if (count != entry["size_bytes"] or digest.hexdigest() != entry["sha256"]
                                or _version(os.fstat(reader)) != _version(start)
                                or _version(os.stat(name, dir_fd=fd, follow_symlinks=False)) != _version(start)):
                            raise _error("content_changed", "Package bytes do not match the frozen manifest.")
                        seen.add(path)
                    finally:
                        os.close(reader)
                else:
                    raise _error("content_changed", "Package contains an unexpected or linked entry.")
            after = os.fstat(fd)
            if (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns):
                raise _error("content_changed", "Package directory changed during verification.")
        visit(root_fd)
        if seen != set(expected):
            raise _error("content_changed", "Package is missing files from the frozen manifest.")

    @contextmanager
    def _payload(self, row):
        directory_fd = os.open(self.path / row["delivery_id"], _DIR)
        try:
            fd = os.open("payload", _DIR, dir_fd=directory_fd)
            try:
                if _identity(os.fstat(fd)) != row["staging_identity"]:
                    raise _error("content_changed", "Staged package directory changed.")
                self._verify_tree(fd, row["manifest"])
                yield fd
            finally:
                os.close(fd)
        finally:
            os.close(directory_fd)

    @staticmethod
    @contextmanager
    def _open_file(root_fd, path):
        parts = path.split("/")
        if any(not p or p in {".", ".."} or "\\" in p for p in parts):
            raise _error("file_not_found", "File is not in this delivery.")
        fd = os.dup(root_fd)
        try:
            for part in parts[:-1]:
                child = os.open(part, _DIR, dir_fd=fd)
                os.close(fd)
                fd = child
            reader = os.open(parts[-1], _READ, dir_fd=fd)
            try:
                yield reader
            finally:
                os.close(reader)
        finally:
            os.close(fd)

    def _base(self, row):
        value = {key: row[key] for key in ("delivery_id", "status", "archive_sha256", "version_directory")}
        value.update(target_id=row["target"]["target_id"], error_code=row.get("error_code"),
                     retryable=row["status"] in {"interrupted", "committing"},
                     published=True if row["status"] == "completed" else None if row.get("temporary_name") else False,
                     staging_expires_at=row['expires_at'])
        if row.get('error_code') in {'file_source_not_approved', 'file_source_nonpublic'}:
            value.update(operator_action_required=True, file_source_host=row.get('source_host'),
                         retry_instruction='Review the exact HTTPS provider/egress policy before retrying this delivery.')
        return value

    def _preparation(self, row, expires):
        bound = {k: row[k] for k in ("delivery_id", "actor", "target", "version_directory", "archive_sha256", "manifest")}
        body = base64.urlsafe_b64encode(_json({"digest": hashlib.sha256(_json(bound).encode()).hexdigest(), "expires": expires}).encode()).decode()
        return body + "." + hmac.new(self._key, body.encode(), hashlib.sha256).hexdigest()

    def _check_preparation(self, row, preparation):
        try:
            if not isinstance(preparation, str) or len(preparation) > 2048:
                raise ValueError()
            body, signature = preparation.split(".")
            data = json.loads(base64.b64decode(body, altchars=b"-_", validate=True))
            expires = data["expires"]
            if not isinstance(expires, int) or expires <= time.time() or not hmac.compare_digest(preparation, self._preparation(row, expires)):
                raise ValueError()
        except (ValueError, KeyError, TypeError, UnicodeError):
            raise _error("preview_invalid", "Preparation is invalid or expired; inspect and review the exact delivery again.") from None

    def _published(self, row, parent_fd):
        try:
            fd = os.open(row["version_directory"], _DIR, dir_fd=parent_fd)
        except FileNotFoundError:
            if row["status"] == "completed":
                raise _error("published_missing", "Previously published directory is missing; it will not be recreated.") from None
            return False
        except OSError:
            raise _error("target_conflict", "Target is occupied by a non-directory or link; nothing will be overwritten.") from None
        try:
            expected = row.get("published_identity") or row.get("temporary_identity")
            if expected is None or _identity(os.fstat(fd)) != expected:
                raise _error("target_conflict", "Target exists with a different identity; nothing will be overwritten.")
            self._verify_tree(fd, row["manifest"])
            self._check_policy(row)
            if _identity(os.stat(row["version_directory"], dir_fd=parent_fd, follow_symlinks=False)) != expected:
                raise _error("content_changed", "Published directory changed during verification.")
            row.update(status="completed", published_identity=expected, error_code=None)
            self._put(row)
            return True
        finally:
            os.close(fd)

    def _release_completed(self, row):
        self._remove_staging(row)
        row["reserved_bytes"] = 0
        self._put(row)

    def _inspect(self, row, file_path="", offset=0, limit=20000):
        target = self._check_policy(row)
        if row["status"] in {"committing", "completed"}:
            with self.policy.open_parent(target) as parent_fd:
                self._published(row, parent_fd)
        value = self._base(row)
        if row["status"] not in {"ready", "committing", "completed"}:
            return value
        value.update(manifest=row["manifest"], size_bytes=sum(x["size_bytes"] for x in row["manifest"]),
                     absolute_path=str(target.root.joinpath(*target.parent_parts, row["version_directory"])),
                     classification="unexecuted_original_files", user_confirmation_required=row["status"] != "completed")
        if row["status"] != "completed":
            with self._payload(row):
                pass
            expires = min(int(time.time()) + self.policy.limits().preview_ttl_seconds, int(row["expires_at"]))
            value["preparation_expires_at"] = expires
            value["commit_arguments"] = {key: row[key] for key in ("delivery_id", "version_directory", "manifest", "archive_sha256")}
            value["commit_arguments"].update(target_id=target.target_id, destination=value["absolute_path"],
                                             preparation=self._preparation(row, expires))
            value["review"] = "Review the exact target and manifest; inspect each file before confirming this write. Preparation does not prove approval. Existing files are never overwritten."
        if file_path:
            entry = next((x for x in row["manifest"] if x["path"] == file_path), None)
            if entry is None:
                raise _error("file_not_found", "File is not in this delivery.")
            if row["status"] == "completed":
                with self.policy.open_parent(target) as parent_fd:
                    fd = os.open(row["version_directory"], _DIR, dir_fd=parent_fd)
                    try:
                        if _identity(os.fstat(fd)) != row["published_identity"]:
                            raise _error("content_changed", "Published directory changed before preview.")
                        value["file"] = self._page(fd, entry, offset, limit)
                    finally:
                        os.close(fd)
            else:
                with self._payload(row) as fd:
                    value["file"] = self._page(fd, entry, offset, limit)
        self._check_policy(row)
        return value

    def _page(self, root_fd, entry, offset, limit):
        path = entry["path"]
        with self._open_file(root_fd, path) as fd:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != entry["size_bytes"]:
                raise _error("content_changed", "File changed before preview.")
            digest, count, selected = hashlib.sha256(), 0, bytearray()
            while chunk := os.read(fd, 65536):
                digest.update(chunk)
                start = max(0, offset - count)
                end = min(len(chunk), offset + limit - count)
                if end > start:
                    selected.extend(chunk[start:end])
                count += len(chunk)
                if count > entry["size_bytes"]:
                    raise _error("content_changed", "File grew during preview.")
            raw = bytes(selected)
            if count != entry["size_bytes"] or digest.hexdigest() != entry["sha256"] or _version(os.fstat(fd)) != _version(before):
                raise _error("content_changed", "File changed during preview.")
        # Trim only a trailing partial UTF-8 sequence. The next page starts at the
        # same original bytes; a caller-supplied non-boundary start remains explicit.
        decoded = None
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            if exc.reason == "unexpected end of data" and exc.end == len(raw) and exc.start > 0:
                raw = raw[:exc.start]
                decoded = raw.decode("utf-8")
        result = dict(path=path, offset_bytes=offset, returned_bytes=len(raw), total_bytes=before.st_size,
                      next_offset=offset + len(raw) if offset + len(raw) < before.st_size else None,
                      bytes_base64=base64.b64encode(raw).decode())
        if decoded is not None:
            result["text"] = decoded
        else:
            result["text_encoding"] = "Use bytes_base64; this byte page splits a UTF-8 sequence."
        return result

    def inspect(self, actor, delivery_id, file_path="", offset=0, limit=20000):
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 20000:
            raise _error("page_invalid", "Byte offset must be nonnegative and limit must be 1–20000.")
        with self._locked():
            self._get(actor, delivery_id)
            self._clean_expired(selected_id=delivery_id)
            row = self._get(actor, delivery_id)
            with _ACTIVE_LOCK:
                active = (str(self.path), row["delivery_id"]) in _ACTIVE
            if row["status"] == "receiving" and not active and not self._receiving_live(row["delivery_id"]):
                row.update(status="interrupted", error_code="delivery_receive_interrupted")
                self._put(row)
            return self._inspect(row, file_path, offset, limit)

    def _copy(self, row, source_fd, destination_fd):
        manifest = row["manifest"]
        created = row.setdefault("temporary_entries", {})
        for entry in manifest:
            parts = entry["path"].split("/")
            parent = os.dup(destination_fd)
            try:
                for index, part in enumerate(parts[:-1]):
                    key = "/".join(parts[:index + 1]) + "/"
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=parent)
                    except FileExistsError:
                        if key not in created:
                            raise _error("target_conflict", "Publication staging contains an unrecorded directory.") from None
                    else:
                        created[key] = _identity(os.stat(part, dir_fd=parent, follow_symlinks=False))
                        self._put(row)
                    child = os.open(part, _DIR, dir_fd=parent)
                    if _identity(os.fstat(child)) != created[key]:
                        os.close(child)
                        raise _error("target_conflict", "Publication staging directory identity changed.")
                    os.close(parent)
                    parent = child
                try:
                    output = os.open(parts[-1], os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
                except FileExistsError:
                    if entry["path"] not in created:
                        raise _error("target_conflict", "Publication staging contains an unrecorded file.") from None
                    output = os.open(parts[-1], os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                else:
                    created[entry["path"]] = _identity(os.fstat(output))
                    self._put(row)
                try:
                    current = os.fstat(output)
                    if (not stat.S_ISREG(current.st_mode) or current.st_nlink != 1
                            or _identity(current) != created[entry["path"]] or current.st_size > entry["size_bytes"]):
                        raise _error("target_conflict", "Publication staging file identity or size changed.")
                    with self._open_file(source_fd, entry["path"]) as source:
                        # Resume only an exact prefix in the inode this delivery created.
                        count = current.st_size
                        remaining = count
                        while remaining:
                            prefix = os.read(output, min(65536, remaining))
                            if not prefix or prefix != os.read(source, len(prefix)):
                                raise _error("content_changed", "Partial publication bytes changed; they will not be overwritten.")
                            remaining -= len(prefix)
                        while chunk := os.read(source, 65536):
                            count += len(chunk)
                            if count > entry["size_bytes"]:
                                raise _error("content_changed", "Staged source grew during publication.")
                            view = memoryview(chunk)
                            while view:
                                written = os.write(output, view)
                                view = view[written:]
                    os.fsync(output)
                finally:
                    os.close(output)
                os.fsync(parent)
            finally:
                os.close(parent)
        self._verify_tree(destination_fd, manifest)
        self._fsync_directories(destination_fd)

    def _fsync_directories(self, fd):
        for name in os.listdir(fd):
            if stat.S_ISDIR(os.stat(name, dir_fd=fd, follow_symlinks=False).st_mode):
                child = os.open(name, _DIR, dir_fd=fd)
                try:
                    self._fsync_directories(child)
                finally:
                    os.close(child)
        os.fsync(fd)

    def commit(self, actor, delivery_id, target_id, version_directory, manifest, archive_sha256, preparation, *, destination):
        with self._locked():
            row = self._get(actor, delivery_id)
            target = self._check_policy(row)
            if (_manifest_bytes(manifest) > self.policy.limits().max_manifest_bytes
                    or destination != str(target.root.joinpath(*target.parent_parts, row["version_directory"]))
                    or (target_id, version_directory, manifest, archive_sha256) !=
                    (target.target_id, row["version_directory"], row["manifest"], row["archive_sha256"])):
                raise _error("confirmation_mismatch", "Commit arguments differ from the frozen delivery; nothing was published.")
            self._check_preparation(row, preparation)
            if row["status"] not in {"ready", "committing", "completed"}:
                raise _error("not_ready", "Delivery is not ready for publication; inspect its state.")
            with self.policy.open_parent(target) as parent_fd:
                if self._published(row, parent_fd):
                    self._release_completed(row)
                    return self._inspect(row)
                size = row["target_reserved_bytes"]
                free = os.fstatvfs(parent_fd)
                if free.f_bavail * free.f_frsize < size:
                    raise _error("space_unavailable", "Insufficient target filesystem space; nothing was published.")
                if row["status"] == "ready":
                    row.update(status="committing", temporary_name=INTERNAL_DELIVERY_PREFIX + secrets.token_hex(16))
                    self._put(row)
                    os.mkdir(row["temporary_name"], mode=0o700, dir_fd=parent_fd)
                    info = os.stat(row["temporary_name"], dir_fd=parent_fd, follow_symlinks=False)
                    row["temporary_identity"] = _identity(info)
                    self._put(row)
                # Recovery only resumes recorded inodes with matching byte prefixes.
                temporary = os.open(row["temporary_name"], _DIR, dir_fd=parent_fd)
                try:
                    if _identity(os.fstat(temporary)) != row.get("temporary_identity"):
                        raise _error("target_conflict", "Uncertain publication staging identity; manual inspection is required.")
                    with self._payload(row) as source:
                        self._copy(row, source, temporary)
                finally:
                    os.close(temporary)
                self._check_policy(row)
                with self.policy.open_parent(target) as fresh_parent:
                    if _identity(os.fstat(fresh_parent)) != _identity(os.fstat(parent_fd)):
                        raise _error("scope_changed", "Target parent identity changed before publication.")
                if _identity(os.stat(row["temporary_name"], dir_fd=parent_fd, follow_symlinks=False)) != row["temporary_identity"]:
                    raise _error("target_conflict", "Publication staging was replaced.")
                try:
                    publish_exclusive(parent_fd, row["temporary_name"], version_directory)
                except FileExistsError:
                    raise _error("target_conflict", "Target already exists; it was not overwritten.") from None
                os.fsync(parent_fd)
                self._check_policy(row)
                self._published(row, parent_fd)
                self._release_completed(row)
            return self._inspect(row)

    def cleanup_expired(self, actor, delivery_id):
        """Local operator maintenance only; never registered as a read MCP tool.

        No publication is performed. Only expired, recorded temporary entries are
        eligible, and unknown or changed entries are retained for manual review.
        """
        with self._locked():
            row = self._get(actor, delivery_id)
            if row["expires_at"] > time.time():
                raise _error("not_expired", "Active delivery data cannot be cleaned by expiry maintenance.")
            self._clean_expired(clean_private=True, clean_target=True, selected_id=delivery_id)
            return self._base(self._get(actor, delivery_id))

    def close(self):
        with self._locked():
            self._closed = True
        self._worker.shutdown(wait=True)
        with self._locked():
            self.db.close()
