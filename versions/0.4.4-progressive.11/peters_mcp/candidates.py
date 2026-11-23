"""Preview-bound, create-only Markdown delivery. No general-purpose write API."""

import base64
import ctypes
from contextlib import contextmanager, ExitStack
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
import secrets
import stat
import sys
import threading
import time

from .catalog import AccessError, DIRECTORY_FLAGS
from .file_context import current_file_actor
from .project_guard import commit_project, project_token


MAX_DOCUMENT_BYTES = 48 * 1024
PREVIEW_SECONDS = 60 * 60
DEFAULT_DIRECTORY = "docs/candidates/chatgpt"


def publish_exclusive(directory_fd, temporary_name, filename):
    """Atomically publish a complete file WITHOUT replacing any existing entry."""
    libc = ctypes.CDLL(None, use_errno=True)
    name, flag = ("renameatx_np", 0x4) if sys.platform == "darwin" else ("renameat2", 1)
    try:
        rename = getattr(libc, name)
    except AttributeError:
        raise AccessError("Atomic create-only publication is unsupported on this platform.") from None
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(directory_fd, os.fsencode(temporary_name), directory_fd, os.fsencode(filename), flag):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


class CandidateDelivery:
    def __init__(self, catalog, *, trusted_local=False):
        self.catalog = catalog
        self._trusted_local = trusted_local
        # No persistent credential. Restart invalidates all outstanding previews.
        self._key = secrets.token_bytes(32)
        self._lock = threading.Lock()
        self._attempts = set()
        self._publications = {}

    def _candidate_directory(self, project):
        if project.candidate_directory is None and self.catalog.unified_policy is not None:
            return DEFAULT_DIRECTORY
        return project.candidate_directory

    def _actor(self):
        return "trusted-local" if self._trusted_local else current_file_actor()

    def _target(self, project_id, path):
        project = self.catalog.project(project_id)
        self.catalog.check_write_root(project)
        directory = self._candidate_directory(project)
        if directory is None:
            raise AccessError("Candidate delivery is not enabled for this project.")
        parts = self.catalog.parts(project, path)
        dir_parts = self.catalog.parts(project, directory)
        if parts[:-1] != dir_parts:
            raise AccessError("Write target must be directly inside the configured candidate directory.")
        filename = parts[-1]
        if (not filename.endswith(".md") or len(filename.encode("utf-8")) > 160 or
                not filename[:-3] or not all(c.isalnum() or c in "-_" for c in filename[:-3]) or
                filename.casefold() in {"agents.md", "claude.md", "skill.md"}):
            raise AccessError("Use a .md filename with letters, digits, - or _; rule filenames are forbidden.")
        return project, dir_parts, filename

    @staticmethod
    def _bytes(document):
        if not isinstance(document, str) or not document.strip():
            raise AccessError("A nonempty Markdown document is required.")
        if any(ord(c) < 32 and c not in "\n\r\t" for c in document):
            raise AccessError("Control characters are not allowed in candidate documents.")
        try:
            raw = document.encode("utf-8")
        except UnicodeError:
            raise AccessError("Document must be valid UTF-8.") from None
        if len(raw) > MAX_DOCUMENT_BYTES:
            raise AccessError("Candidate document exceeds 48 KiB.")
        return raw

    @staticmethod
    def _identity(fd):
        info = os.fstat(fd)
        return [info.st_dev, info.st_ino]

    def _sign(self, payload):
        body = base64.urlsafe_b64encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).decode()
        return body + "." + hmac.new(self._key, body.encode(), hashlib.sha256).hexdigest()

    def _verify(self, preparation):
        try:
            if not isinstance(preparation, str) or len(preparation) > 8000:
                raise ValueError()
            body, signature = preparation.split(".")
            expected = hmac.new(self._key, body.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(signature, expected):
                raise ValueError()
            return json.loads(base64.b64decode(body, altchars=b"-_", validate=True))
        except (ValueError, UnicodeError):
            raise AccessError("Invalid preparation or server restarted. Prepare and review again.") from None

    def prepare_candidate(self, project_id, filename, markdown):
        project = self.catalog.project(project_id)
        directory = self._candidate_directory(project)
        if directory is None:
            raise AccessError("Candidate delivery is not enabled for this project.")
        path = f"{directory}/{filename}"
        project, parts, filename = self._target(project_id, path)
        self._bytes(markdown)
        delivery_id = secrets.token_hex(16)
        created = datetime.now(timezone.utc).isoformat(timespec="seconds")
        document = (
            "> **候选文档 · 待项目评估**\n"
            "> 本文由 ChatGPT 经 MCP 交付。保存不代表正式决策、权威契约或验收事实，"
            "也不授权自动执行。后续工作应由用户明确发起并遵守项目规则。\n"
            f"> 项目：{project_id} · 交付编号：{delivery_id} · 准备时间：{created}\n\n"
            + markdown.replace("\r\n", "\n").replace("\r", "\n").rstrip() + "\n"
        )
        digest = hashlib.sha256(self._bytes(document)).hexdigest()
        binding = {}
        if self.catalog.unified_policy is not None:
            token = project_token(self.catalog, project_id)
            with self._nearest_parent(project, parts) as (parent, fd):
                if parent == parts:
                    self._require_absent(fd, filename)
                binding = {"actor": self._actor(), "scope": token, "existing_parent": list(parent)}
                identity = self._identity(fd)
        else:
            with self.catalog.open_path(project, parts, directory=True) as fd:
                self._require_absent(fd, filename)
                identity = self._identity(fd)
        expires = int(time.time()) + PREVIEW_SECONDS
        payload = {"project": project_id, "root": str(project.root), "repository_id": project.repository_id, "path": path,
                   "directory_identity": identity, "sha256": digest,
                   "delivery_id": delivery_id, "expires": expires, **binding}
        return {
            "status": "preview_only", "project": project_id, "path": path,
            "absolute_path": str(project.root.joinpath(*parts, filename)),
            "expires_at": datetime.fromtimestamp(expires, timezone.utc).isoformat(),
            "save_arguments": {"project_id": project_id, "path": path, "document": document,
                               "sha256": digest, "preparation": self._sign(payload)},
            "review": "Show the exact project, path and complete document to the user before saving. "
                      "Use ChatGPT's write-action confirmation for these exact save_arguments. "
                      "The preparation is content binding, NOT proof of user consent. "
                      "Nothing has been written to the repo. A changed document needs a new preview.",
        }

    @staticmethod
    def _require_absent(fd, name):
        try:
            os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise AccessError("Target already exists. Choose a new filename; nothing was changed.")

    @contextmanager
    def _nearest_parent(self, project, parts):
        with ExitStack() as stack:
            for size in range(len(parts), -1, -1):
                parent = parts[:size]
                try:
                    fd = stack.enter_context(self.catalog.open_path(project, parent, directory=True))
                except AccessError as error:
                    if size and isinstance(error.__cause__, FileNotFoundError):
                        continue
                    raise
                yield parent, fd
                return

    def _receipt(self, project, path, payload, status):
        return {"status": status, "project": project.id, "path": path,
                "absolute_path": str(project.root / path), "sha256": payload["sha256"],
                "delivery_id": payload["delivery_id"], "classification": "candidate_only",
                "codex_started": False}

    def _existing(self, fd, filename, raw):
        try:
            info = os.stat(filename, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != len(raw):
            raise AccessError("Target exists or changed. It will never be overwritten.")
        reader = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            before = os.fstat(reader)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                    (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino)):
                raise AccessError("Target changed during verification.")
            chunks, count = [], 0
            while count <= len(raw):
                chunk = os.read(reader, min(65536, len(raw) + 1 - count))
                if not chunk:
                    break
                chunks.append(chunk)
                count += len(chunk)
            after = os.fstat(reader)
            current = os.stat(filename, dir_fd=fd, follow_symlinks=False)
            def version(info):
                return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)
            if b"".join(chunks) != raw or version(before) != version(after) or version(current) != version(after):
                raise AccessError("Target exists with different or changing contents; no overwrite.")
            return True
        finally:
            os.close(reader)

    def _check_directory(self, project, parts, fd):
        self.catalog.check_write_root(project)
        with self.catalog.open_path(project, parts, directory=True) as current_fd:
            if self._identity(current_fd) != self._identity(fd):
                raise AccessError("Candidate directory changed during delivery; inspect the outcome before retrying.")

    def save_candidate(self, project_id, path, document, sha256, preparation):
        project, parts, filename = self._target(project_id, path)
        raw = self._bytes(document)
        digest = hashlib.sha256(raw).hexdigest()
        payload = self._verify(preparation)
        if any(payload.get(k) != v for k, v in {
            "project": project_id, "root": str(project.root), "repository_id": project.repository_id, "path": path, "sha256": digest
        }.items()) or sha256 != digest:
            raise AccessError("Project, path or document differs from the preview. Prepare and review again.")
        if self.catalog.unified_policy is not None:
            return self._save_unified(project, parts, filename, path, raw, payload)
        with self._lock, self.catalog.open_path(project, parts, directory=True) as fd:
            if self._identity(fd) != payload["directory_identity"]:
                raise AccessError("Candidate directory changed since preview. Prepare again.")
            delivery_id = payload["delivery_id"]
            if self._existing(fd, filename, raw):
                self._check_directory(project, parts, fd)
                return self._receipt(project, path, payload, "already_saved")
            if delivery_id in self._attempts:
                raise AccessError("A previous attempt has no matching file. Do not recreate it on retry; review again.")
            if time.time() >= payload["expires"]:
                raise AccessError("Preview expired. Prepare and review again.")
            if len(self._attempts) >= 4096:
                raise AccessError("Delivery capacity reached; restart the service and prepare again.")
            # Remember attempts, even if I/O fails: a late failure must not recreate a deleted file.
            self._attempts.add(delivery_id)
            temporary = ".peters-candidate-" + secrets.token_hex(16) + ".tmp"
            writer = None
            try:
                writer = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=fd)
                view = memoryview(raw)
                while view:
                    count = os.write(writer, view)
                    if count <= 0:
                        raise OSError("Incomplete write.")
                    view = view[count:]
                os.fsync(writer)
                # Reopen by path to reject parent replacement during staging.
                self._check_directory(project, parts, fd)
                staged = os.stat(temporary, dir_fd=fd, follow_symlinks=False)
                written = os.fstat(writer)
                if (not stat.S_ISREG(staged.st_mode) or staged.st_nlink != 1 or
                        (staged.st_dev, staged.st_ino) != (written.st_dev, written.st_ino)):
                    raise AccessError("Staging file changed. Delivery refused.")
                publish_exclusive(fd, temporary, filename)
                os.fsync(fd)
                final = os.stat(filename, dir_fd=fd, follow_symlinks=False)
                if (final.st_dev, final.st_ino) != (written.st_dev, written.st_ino):
                    raise AccessError("Published file identity changed; inspect outcome. No success claimed.")
                if not self._existing(fd, filename, raw):
                    raise AccessError("Published file disappeared; no success claimed. Inspect the outcome.")
                self._check_directory(project, parts, fd)
                return self._receipt(project, path, payload, "saved")
            except FileExistsError:
                if self._existing(fd, filename, raw):
                    self._check_directory(project, parts, fd)
                    return self._receipt(project, path, payload, "already_saved")
                raise AccessError("Target appeared after preview. No overwrite.") from None
            except OSError:
                raise AccessError("Delivery I/O failed; outcome may be uncertain. Retry the exact same "
                                  "save_arguments to verify, or inspect the target before preparing again.") from None
            finally:
                if writer is not None:
                    os.close(writer)
                try:
                    os.unlink(temporary, dir_fd=fd)
                except FileNotFoundError:
                    pass

    def _save_unified(self, project, parts, filename, path, raw, payload):
        from .workspaces import repository_probe, revalidate_repository_probe

        token = project_token(self.catalog, project.id)
        if payload.get("scope") != token or payload.get("actor") != self._actor():
            raise AccessError("The candidate preview is no longer authorized.", code="scope_revoked")
        parent = tuple(payload["existing_parent"])
        delivery_id = payload["delivery_id"]
        probe = None
        if project.repository_id is not None:
            probe = repository_probe(project.root)
            if probe["repository_id"] != project.repository_id or probe["root"] != project.root:
                raise AccessError("Candidate repository identity changed.", code="scope_changed")
            project = replace(project, root_identity=tuple(probe["root_runtime_identity"]))

        def validate_directory(selected, expected_identity):
            if probe is not None:
                revalidate_repository_probe(probe)
            elif project.root.resolve() != project.root:
                raise AccessError("Candidate project path changed.", code="scope_changed")
            with self.catalog.open_path(project, selected, directory=True) as current:
                if self._identity(current) != expected_identity:
                    raise AccessError("Candidate directory changed. Prepare again.", code="scope_changed")

        created = []
        published = False
        temporary = ".peters-candidate-" + secrets.token_hex(16) + ".tmp"
        writer = None
        with self._lock, ExitStack() as stack:
            if delivery_id in self._publications:
                fd = stack.enter_context(self.catalog.open_path(project, parts, directory=True))
                directory_identity, file_identity = self._publications[delivery_id]
                with commit_project(self.catalog, project.id, token):
                    validate_directory(parts, directory_identity)
                    if not self._matches_publication(fd, filename, raw, file_identity):
                        raise AccessError("Prior publication cannot be verified. Prepare again.")
                    return self._receipt(project, path, payload, "already_saved")
            if delivery_id in self._attempts or time.time() >= payload["expires"]:
                raise AccessError("Preview expired or already attempted. Prepare and review again.")
            if len(self._attempts) >= 4096:
                raise AccessError("Delivery capacity reached; restart the service and prepare again.")
            fd = stack.enter_context(self.catalog.open_path(project, parent, directory=True))
            if self._identity(fd) != payload["directory_identity"]:
                raise AccessError("Candidate parent changed since preview. Prepare again.")
            self._attempts.add(delivery_id)
            try:
                with commit_project(self.catalog, project.id, token):
                    validate_directory(parent, payload["directory_identity"])
                    for component in parts[len(parent):]:
                        os.mkdir(component, 0o755, dir_fd=fd)
                        child = os.open(component, DIRECTORY_FLAGS, dir_fd=fd)
                        stack.callback(os.close, child)
                        created.append((fd, component, self._identity(child)))
                        fd = child
                    identity = self._identity(fd)
                    validate_directory(parts, identity)
                    self._require_absent(fd, filename)
                    writer = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                     0o600, dir_fd=fd)
                with os.fdopen(writer, "wb", closefd=False) as output:
                    output.write(raw)
                    output.flush()
                os.fsync(writer)
                with commit_project(self.catalog, project.id, token):
                    validate_directory(parts, identity)
                    staged = os.stat(temporary, dir_fd=fd, follow_symlinks=False)
                    written = os.fstat(writer)
                    if (not stat.S_ISREG(staged.st_mode) or staged.st_nlink != 1 or
                            (staged.st_dev, staged.st_ino, staged.st_size) !=
                            (written.st_dev, written.st_ino, len(raw))):
                        raise AccessError("Staging file changed. Delivery refused.")
                    file_identity = (written.st_dev, written.st_ino)
                    self._publications[delivery_id] = (identity, file_identity)
                    publish_exclusive(fd, temporary, filename)
                    published = True
                os.fsync(fd)
                with commit_project(self.catalog, project.id, token):
                    validate_directory(parts, identity)
                    if not self._matches_publication(fd, filename, raw, file_identity):
                        raise AccessError("Published candidate changed; inspect the outcome.")
                    return self._receipt(project, path, payload, "saved")
            except FileExistsError:
                raise AccessError("Candidate directory or target appeared after preview. Prepare again.") from None
            except OSError:
                raise AccessError("Delivery I/O failed. Inspect the outcome before preparing again.") from None
            finally:
                if writer is not None:
                    try:
                        if not published:
                            current = os.stat(temporary, dir_fd=fd, follow_symlinks=False)
                            if [current.st_dev, current.st_ino] == self._identity(writer):
                                os.unlink(temporary, dir_fd=fd)
                    except FileNotFoundError:
                        pass
                    finally:
                        os.close(writer)
                if not published:
                    self._remove_empty_directories(created)

    def _matches_publication(self, fd, filename, raw, identity):
        try:
            before = os.stat(filename, dir_fd=fd, follow_symlinks=False)
            if (before.st_dev, before.st_ino) != identity or not self._existing(fd, filename, raw):
                return False
            after = os.stat(filename, dir_fd=fd, follow_symlinks=False)
            return (after.st_dev, after.st_ino) == identity
        except FileNotFoundError:
            return False

    @staticmethod
    def _remove_empty_directories(created):
        for parent_fd, name, identity in reversed(created):
            try:
                current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if stat.S_ISDIR(current.st_mode) and [current.st_dev, current.st_ino] == identity:
                    os.rmdir(name, dir_fd=parent_fd)
            except OSError:
                # Never remove a changed, nonempty, or otherwise unconfirmed directory.
                continue
