"""Preview-bound, create-only Markdown delivery. No general-purpose write API."""

import base64
import ctypes
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

from .catalog import AccessError


MAX_DOCUMENT_BYTES = 48 * 1024
PREVIEW_SECONDS = 60 * 60


def publish_exclusive(directory_fd, temporary_name, filename):
    """Atomically publish a complete file WITHOUT replacing any existing entry."""
    libc = ctypes.CDLL(None, use_errno=True)
    name, flag = ("renameatx_np", 0x4) if sys.platform == "darwin" else ("renameat2", 1)
    try:
        rename = getattr(libc, name)
    except AttributeError:
        raise AccessError("Atomic create-only publication is unsupported on this platform.",
                          code="candidate_platform_unsupported") from None
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(directory_fd, os.fsencode(temporary_name), directory_fd, os.fsencode(filename), flag):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


class CandidateDelivery:
    def __init__(self, catalog):
        self.catalog = catalog
        # No persistent credential. Restart invalidates all outstanding previews.
        self._key = secrets.token_bytes(32)
        self._lock = threading.Lock()
        self._attempts = set()

    def _target(self, project_id, path):
        project = self.catalog.project(project_id)
        self.catalog.check_write_root(project)
        directory = project.candidate_directory
        if directory is None:
            raise AccessError("Candidate delivery is not enabled for this project.", code="candidate_delivery_disabled")
        parts = self.catalog.parts(project, path)
        dir_parts = self.catalog.parts(project, directory)
        if parts[:-1] != dir_parts:
            raise AccessError("Write target must be directly inside the configured candidate directory.",
                              code="candidate_target_rejected")
        filename = parts[-1]
        segments = filename[:-3].split(".")
        if (not filename.endswith(".md") or len(filename.encode("utf-8")) > 160 or
                not all(segment and all(c.isalnum() or c in "-_" for c in segment) for segment in segments) or
                filename.casefold() in {"agents.md", "claude.md", "skill.md"}):
            raise AccessError("Use a .md filename with letters, digits, - or _, optionally separated by single dots "
                              "(for example plan-v2.1.md); rule filenames are forbidden.",
                              code="candidate_filename_invalid")
        return project, dir_parts, filename

    @staticmethod
    def _bytes(document):
        if not isinstance(document, str) or not document.strip():
            raise AccessError("A nonempty Markdown document is required.", code="candidate_document_invalid")
        if any(ord(c) < 32 and c not in "\n\r\t" for c in document):
            raise AccessError("Control characters are not allowed in candidate documents.", code="candidate_document_invalid")
        try:
            raw = document.encode("utf-8")
        except UnicodeError:
            raise AccessError("Document must be valid UTF-8.", code="candidate_document_invalid") from None
        if len(raw) > MAX_DOCUMENT_BYTES:
            raise AccessError("Candidate document exceeds 48 KiB.", code="candidate_document_too_large")
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
            raise AccessError("Invalid preparation or server restarted. Prepare and review again.",
                              code="candidate_preview_invalid") from None

    def prepare_candidate(self, project_id, filename, markdown):
        project = self.catalog.project(project_id)
        if project.candidate_directory is None:
            raise AccessError("Candidate delivery is not enabled for this project.", code="candidate_delivery_disabled")
        path = f"{project.candidate_directory}/{filename}"
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
        with self.catalog.open_path(project, parts, directory=True) as fd:
            try:
                os.stat(filename, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise AccessError("Target already exists. Choose a new filename; nothing was changed.",
                                  code="candidate_target_exists")
            identity = self._identity(fd)
        expires = int(time.time()) + PREVIEW_SECONDS
        payload = {"project": project_id, "root": str(project.root), "repository_id": project.repository_id, "path": path,
                   "directory_identity": identity, "sha256": digest,
                   "delivery_id": delivery_id, "expires": expires}
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
            raise AccessError("Target exists or changed. It will never be overwritten.", code="candidate_target_changed")
        reader = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            before = os.fstat(reader)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                    (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino)):
                raise AccessError("Target changed during verification.", code="candidate_target_changed")
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
                raise AccessError("Target exists with different or changing contents; no overwrite.",
                                  code="candidate_target_changed")
            return True
        finally:
            os.close(reader)

    def _check_directory(self, project, parts, fd):
        self.catalog.check_write_root(project)
        with self.catalog.open_path(project, parts, directory=True) as current_fd:
            if self._identity(current_fd) != self._identity(fd):
                raise AccessError("Candidate directory changed during delivery; inspect the outcome before retrying.",
                                  code="candidate_directory_changed")

    def save_candidate(self, project_id, path, document, sha256, preparation):
        project, parts, filename = self._target(project_id, path)
        raw = self._bytes(document)
        digest = hashlib.sha256(raw).hexdigest()
        payload = self._verify(preparation)
        if any(payload.get(k) != v for k, v in {
            "project": project_id, "root": str(project.root), "repository_id": project.repository_id, "path": path, "sha256": digest
        }.items()) or sha256 != digest:
            raise AccessError("Project, path or document differs from the preview. Prepare and review again.",
                              code="candidate_preview_mismatch")
        with self._lock, self.catalog.open_path(project, parts, directory=True) as fd:
            if self._identity(fd) != payload["directory_identity"]:
                raise AccessError("Candidate directory changed since preview. Prepare again.", code="candidate_directory_changed")
            delivery_id = payload["delivery_id"]
            if self._existing(fd, filename, raw):
                self._check_directory(project, parts, fd)
                return self._receipt(project, path, payload, "already_saved")
            if delivery_id in self._attempts:
                raise AccessError("A previous attempt has no matching file. Do not recreate it on retry; review again.",
                                  code="candidate_outcome_uncertain")
            if time.time() >= payload["expires"]:
                raise AccessError("Preview expired. Prepare and review again.", code="candidate_preview_expired")
            if len(self._attempts) >= 4096:
                raise AccessError("Delivery capacity reached; restart the service and prepare again.",
                                  code="candidate_capacity_exhausted")
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
                    raise AccessError("Staging file changed. Delivery refused.", code="candidate_staging_changed")
                publish_exclusive(fd, temporary, filename)
                os.fsync(fd)
                final = os.stat(filename, dir_fd=fd, follow_symlinks=False)
                if (final.st_dev, final.st_ino) != (written.st_dev, written.st_ino):
                    raise AccessError("Published file identity changed; inspect outcome. No success claimed.",
                                      code="candidate_outcome_uncertain")
                if not self._existing(fd, filename, raw):
                    raise AccessError("Published file disappeared; no success claimed. Inspect the outcome.",
                                      code="candidate_outcome_uncertain")
                self._check_directory(project, parts, fd)
                return self._receipt(project, path, payload, "saved")
            except FileExistsError:
                if self._existing(fd, filename, raw):
                    self._check_directory(project, parts, fd)
                    return self._receipt(project, path, payload, "already_saved")
                raise AccessError("Target appeared after preview. No overwrite.", code="candidate_target_exists") from None
            except OSError:
                raise AccessError("Delivery I/O failed; outcome may be uncertain. Retry the exact same "
                                  "save_arguments to verify, or inspect the target before preparing again.",
                                  code="candidate_io_error") from None
            finally:
                if writer is not None:
                    os.close(writer)
                try:
                    os.unlink(temporary, dir_fd=fd)
                except FileNotFoundError:
                    pass
