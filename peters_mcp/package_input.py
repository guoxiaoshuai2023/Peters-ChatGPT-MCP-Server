"""Bounded original-byte ZIP input for an explicitly enabled delivery service.

The caller owns a private staging directory. Downloads create one exclusive file
and remove it on failure. Extraction creates a new exclusive directory; on any
failure its partial contents remain private for the caller's staging cleanup.
Neither operation writes to a project, follows redirects, or executes content.
"""

import codecs
from contextlib import contextmanager
from fnmatch import fnmatchcase
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import time
import unicodedata
from urllib.parse import urlsplit
import zipfile
import zlib

from .catalog import AccessError, BLOCKED_NAMES, BLOCKED_PATTERNS
from .delivery_types import DeliveryLimits, OpenAIFile


_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_CHUNK_BYTES = 65536
_TEXT_SUFFIXES = {".md", ".txt", ".rst", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".csv", ".tsv"}
_RULE_NAMES = {"agents", "claude", "skill"}
_RESERVED_NAMES = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}


def _fail(code, message):
    raise AccessError(message, code=code) from None


@contextmanager
def _directory(path):
    """Open every absolute path component without following a symlink."""
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        _fail("staging_path_invalid", "Staging requires an absolute, non-traversing path.")
    fd = os.open("/", _DIRECTORY_FLAGS)
    try:
        for part in path.parts[1:]:
            child = os.open(part, _DIRECTORY_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def _public_address(value):
    try:
        address = ipaddress.ip_address(value)
        if (not address.is_global or address.is_multicast or address.is_unspecified
                or address.is_reserved or getattr(address, "ipv4_mapped", None)
                or getattr(address, "sixtofour", None) or getattr(address, "teredo", None)
                or (address.version == 6 and any(address in network for network in (
                    ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))))):
            raise ValueError
        return str(address)
    except ValueError:
        _fail("file_source_nonpublic", "File source addresses must be ordinary public addresses.")


def _source(file, sources):
    url = file.download_url
    if (not isinstance(url, str) or len(url) > 16384 or "\\" in url
            or any(ord(c) < 33 or ord(c) == 127 for c in url)):
        _fail("file_reference_invalid", "Invalid file reference.")
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        if (parsed.scheme != "https" or not host or not host.isascii()
                or not re.fullmatch(r"[a-z0-9]+(?:[a-z0-9.-]*[a-z0-9])?", host)
                or parsed.username is not None or parsed.password is not None
                or parsed.port not in (None, 443) or parsed.fragment):
            raise ValueError
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError
    except ValueError:
        _fail("file_reference_invalid", "File references must use an approved HTTPS host.")
    if (not file.file_id or len(file.file_id) > 512 or len(file.file_name) > 240
            or len(file.mime_type) > 160
            or any(ord(c) < 32 or ord(c) == 127 for c in file.file_id + file.file_name + file.mime_type)):
        _fail("file_reference_invalid", "Invalid file reference metadata.")
    if host not in sources:
        _fail("file_source_not_approved", "The file provider has not been approved by the operator.")
    approved = sources[host]
    if approved is None:
        approved = tuple({item[4][0] for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)})
    if not isinstance(approved, tuple) or not approved:
        _fail("file_source_unavailable", "No approved file source address is available.")
    # Validate every returned address, not merely the address selected to connect.
    addresses = sorted({_public_address(address) for address in approved},
                       key=lambda address: (ipaddress.ip_address(address).version, address))
    return parsed, addresses[0]


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, address, timeout=10):
        super().__init__(host, port=443, timeout=timeout, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        connection = socket.create_connection((self.address, 443), self.timeout)
        try:
            self.sock = self._context.wrap_socket(connection, server_hostname=self.host)
        except BaseException:
            connection.close()
            raise


def download_archive(file: OpenAIFile, destination: Path, expected_sha256: str,
                     sources: dict[str, tuple[str, ...] | None], limits: DeliveryLimits) -> dict:
    """Download a native file reference to a new file; never persist its URL/ID.

Failed transfers are safely restarted as a whole by the caller. There is no
range resume, proxy discovery, redirect, or automatic retry using another URL.
"""
    if not isinstance(expected_sha256, str) or not re.fullmatch("[a-f0-9]{64}", expected_sha256):
        _fail("archive_hash_invalid", "An exact lowercase SHA256 is required.")
    connection = None
    try:
        parsed, address = _source(file, sources)
        destination = Path(destination)
        with _directory(destination.parent) as parent:
            descriptor = os.open(destination.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=parent)
            identity = os.fstat(descriptor)
            complete = False
            try:
                with os.fdopen(descriptor, "wb") as output:
                    connection = _PinnedHTTPS(parsed.hostname, address)
                    started = time.monotonic()
                    target = (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")
                    connection.request("GET", target, headers={"Accept-Encoding": "identity", "User-Agent": "MCP-Package-Input/1"})
                    response = connection.getresponse()
                    if 300 <= response.status < 400:
                        _fail("file_redirect_rejected", "File downloads cannot follow redirects.")
                    if response.status != 200:
                        _fail("file_download_rejected", "File download was rejected or its reference expired.")
                    if response.getheader("Content-Encoding", "identity").lower() != "identity":
                        _fail("file_encoding_rejected", "Encoded HTTP downloads are not supported.")
                    length = response.getheader("Content-Length")
                    if length is not None:
                        if not re.fullmatch(r"[0-9]+", length):
                            _fail("file_download_invalid", "Invalid download length.")
                        length = int(length)
                        if length > limits.max_archive_bytes:
                            _fail("archive_size_limit", "The archive exceeds the configured input limit.")
                    count, digest = 0, hashlib.sha256()
                    while True:
                        if time.monotonic() - started > 120:
                            _fail("file_download_timeout", "File download timed out; retry the original delivery.")
                        chunk = response.read(min(_CHUNK_BYTES, limits.max_archive_bytes + 1 - count))
                        if not chunk:
                            break
                        count += len(chunk)
                        if count > limits.max_archive_bytes:
                            _fail("archive_size_limit", "The archive exceeds the configured input limit.")
                        digest.update(chunk)
                        output.write(chunk)
                    if length is not None and count != length:
                        _fail("file_download_incomplete", "File download ended before its declared length.")
                    if digest.hexdigest() != expected_sha256:
                        _fail("archive_hash_mismatch", "The original archive SHA256 did not match.")
                    output.flush()
                    os.fsync(output.fileno())
                complete = True
                return {"size_bytes": count, "sha256": digest.hexdigest()}
            finally:
                if not complete:
                    try:
                        current = os.stat(destination.name, dir_fd=parent, follow_symlinks=False)
                        if (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
                            os.unlink(destination.name, dir_fd=parent)
                    except FileNotFoundError:
                        pass
    except AccessError:
        raise
    except FileExistsError:
        _fail("staging_exists", "The staging file already exists; it was not overwritten.")
    except (OSError, ValueError, http.client.HTTPException):
        _fail("file_source_unavailable", "File transfer could not complete; no verified archive was received.")
    finally:
        if connection is not None:
            try:
                connection.close()
            except OSError:
                pass


def _parts(name, limits):
    if (not name or len(name.encode("utf-8")) > 2048 or "\\" in name
            or any(unicodedata.category(c).startswith("C") for c in name)):
        _fail("package_path_invalid", "The package contains an invalid path.")
    parts = name.split("/")
    if len(parts) > limits.max_depth:
        _fail("package_depth_limit", "The package exceeds the configured directory depth.")
    for part in parts:
        canonical = unicodedata.normalize("NFKC", part).casefold()
        if (not part or part in (".", "..") or part.startswith(".")
                or len(part.encode("utf-8")) > 240 or part.endswith((" ", "."))
                or any(c in canonical for c in '/\\:<>"|?*') or canonical.startswith(".")
                or canonical.split(".")[0] in _RESERVED_NAMES):
            _fail("package_path_invalid", "The package contains an unsafe or ambiguous path.")
        if (canonical in BLOCKED_NAMES or canonical.split(".")[0] in _RULE_NAMES
                or any(fnmatchcase(canonical, pattern) for pattern in BLOCKED_PATTERNS)):
            _fail("package_path_forbidden", "Authentication and instruction files cannot be delivered.")
    return parts


def _file_type(name):
    if Path(name).suffix.casefold() not in _TEXT_SUFFIXES and name.casefold() != "manifest.sha256":
        _fail("package_type_forbidden", "Only supported document, configuration, and checksum text files can be delivered.")


def _entries(package, limits):
    infos = package.infolist()
    if len(infos) > limits.max_files * (limits.max_depth + 1):
        _fail("package_entry_limit", "The package contains too many directory entries.")
    explicit, paths, files, total = set(), {}, [], 0
    directories = []
    for info in infos:
        if info.orig_filename != info.filename:
            _fail("package_path_invalid", "The package contains a truncated filename.")
        directory = info.is_dir()
        name = info.filename[:-1] if directory else info.filename
        parts = _parts(name, limits)
        if info.flag_bits & 1:
            _fail("package_encrypted", "Encrypted archives are not supported.")
        if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            _fail("package_compression_unsupported", "Only stored and DEFLATE ZIP compression are supported.")
        mode = info.external_attr >> 16
        kind = stat.S_IFMT(mode)
        if (kind not in (0, stat.S_IFDIR if directory else stat.S_IFREG)
                or (not directory and info.external_attr & 0x10)):
            _fail("package_special_file", "Archive links and special files cannot be delivered.")
        if directory and (info.file_size or info.compress_size):
            # Empty DEFLATE directory entries may have compressed framing bytes.
            if info.file_size:
                _fail("package_directory_payload", "Archive directories cannot contain payloads.")
        canonical_parts = [unicodedata.normalize("NFKC", part).casefold() for part in parts]
        key = "/".join(canonical_parts)
        if key in explicit:
            _fail("package_name_conflict", "Archive names conflict after platform normalization.")
        explicit.add(key)
        for index in range(1, len(parts) + 1):
            prefix = "/".join(canonical_parts[:index])
            original = "/".join(parts[:index])
            is_directory = index < len(parts) or directory
            prior = paths.get(prefix)
            if prior is not None and prior != (original, is_directory):
                _fail("package_name_conflict", "Archive file and directory names conflict.")
            paths[prefix] = (original, is_directory)
        if directory:
            directories.append(parts)
            continue
        _file_type(parts[-1])
        files.append((info, parts))
        total += info.file_size
        if len(files) > limits.max_files:
            _fail("package_file_limit", "The package contains too many files.")
        if info.file_size > limits.max_file_bytes or total > limits.max_package_bytes:
            _fail("package_size_limit", "The package exceeds configured expanded size limits.")
        if info.file_size > max(info.compress_size, 1) * limits.max_compression_ratio:
            _fail("package_ratio_limit", "The archive compression ratio exceeds the configured limit.")
    for parts in directories:
        if not any(len(file_parts) > len(parts) and file_parts[:len(parts)] == parts
                   for _, file_parts in files):
            _fail("package_empty_directory_unsupported", "Empty directories cannot be represented in a file delivery manifest.")
    if not files:
        _fail("package_empty", "A package must contain at least one supported file.")
    return files


@contextmanager
def _create_parent(root, parts):
    fd = os.dup(root)
    try:
        for part in parts:
            try:
                os.mkdir(part, 0o700, dir_fd=fd)
            except FileExistsError:
                pass
            child = os.open(part, _DIRECTORY_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def _validate_text(chunk, decoder, *, final=False):
    try:
        text = decoder.decode(chunk, final=final)
    except UnicodeError:
        _fail("package_encoding_invalid", "Package files must contain UTF-8 text; original bytes are preserved.")
    if any((ord(c) < 32 and c not in "\t\r\n") or ord(c) == 127 for c in text):
        _fail("package_binary_rejected", "Binary and control-character payloads cannot be delivered.")


def _verify_manifest(raw, manifest, limits):
    if len(raw) > limits.max_manifest_bytes:
        _fail("package_manifest_limit", "The checksum manifest exceeds its configured limit.")
    by_name = {entry["path"]: entry["sha256"] for entry in manifest}
    seen = set()
    for line in raw.decode("utf-8-sig").splitlines():
        if not line:
            continue
        match = re.fullmatch(r"([0-9a-fA-F]{64}) [ *](.+)", line)
        if match is None:
            _fail("package_manifest_invalid", "The checksum manifest is not in SHA256 checksum format.")
        digest, name = match.groups()
        _parts(name, limits)
        if name in seen or by_name.get(name) != digest.lower():
            _fail("package_manifest_mismatch", "A checksum manifest entry did not match the original file bytes.")
        seen.add(name)


def _invalid_json_constant(value):
    raise ValueError("Nonstandard JSON constant")


def extract_package(archive: Path, destination: Path, limits: DeliveryLimits) -> list[dict]:
    """Extract into a new private directory, returning a complete sorted manifest.

No final delivery directory is published here. If validation fails, callers must
discard the private partial directory rather than treating it as a valid package.
"""
    try:
        archive, destination = Path(archive), Path(destination)
        with _directory(archive.parent) as parent:
            archive_fd = os.open(archive.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(archive_fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                _fail("archive_not_regular", "The archive must be a single regular staging file.")
            if info.st_size > limits.max_archive_bytes:
                _fail("archive_size_limit", "The archive exceeds the configured input limit.")
            with zipfile.ZipFile(stream) as package:
                files = _entries(package, limits)
                with _directory(destination.parent) as parent:
                    os.mkdir(destination.name, 0o700, dir_fd=parent)
                    root = os.open(destination.name, _DIRECTORY_FLAGS, dir_fd=parent)
                try:
                    manifest, supplied_manifest, total = [], None, 0
                    for entry, parts in files:
                        with _create_parent(root, parts[:-1]) as parent:
                            fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                         0o600, dir_fd=parent)
                        digest, count = hashlib.sha256(), 0
                        decoder = codecs.getincrementaldecoder("utf-8")("strict")
                        retained = bytearray() if parts[-1].casefold() == "manifest.sha256" or Path(parts[-1]).suffix.casefold() == ".json" else None
                        with os.fdopen(fd, "wb") as output, package.open(entry) as source:
                            while True:
                                chunk = source.read(_CHUNK_BYTES)
                                if not chunk:
                                    break
                                count += len(chunk)
                                total += len(chunk)
                                if count > limits.max_file_bytes or total > limits.max_package_bytes:
                                    _fail("package_size_limit", "Actual expanded bytes exceed configured limits.")
                                if parts[-1].casefold() == "manifest.sha256" and count > limits.max_manifest_bytes:
                                    _fail("package_manifest_limit", "The checksum manifest exceeds its configured limit.")
                                if count > max(entry.compress_size, 1) * limits.max_compression_ratio:
                                    _fail("package_ratio_limit", "Actual expanded bytes exceed the compression ratio limit.")
                                if count == len(chunk) and chunk.removeprefix(codecs.BOM_UTF8).startswith(b"#!"):
                                    _fail("package_code_rejected", "Executable script payloads cannot be delivered.")
                                _validate_text(chunk, decoder)
                                digest.update(chunk)
                                output.write(chunk)
                                if retained is not None:
                                    retained.extend(chunk)
                            _validate_text(b"", decoder, final=True)
                            if count != entry.file_size:
                                _fail("package_size_mismatch", "Actual file size does not match the archive directory.")
                            output.flush()
                            os.fsync(output.fileno())
                        if Path(parts[-1]).suffix.casefold() == ".json":
                            try:
                                json.loads(bytes(retained).decode("utf-8-sig"), parse_constant=_invalid_json_constant)
                            except (ValueError, RecursionError):
                                _fail("package_json_invalid", "A JSON file is invalid; no original bytes were changed.")
                        if parts[-1].casefold() == "manifest.sha256":
                            if len(parts) != 1 or supplied_manifest is not None:
                                _fail("package_manifest_invalid", "Only one top-level checksum manifest is supported.")
                            supplied_manifest = bytes(retained)
                        manifest.append({"path": "/".join(parts), "size_bytes": count, "sha256": digest.hexdigest()})
                    if supplied_manifest is not None:
                        _verify_manifest(supplied_manifest, manifest, limits)
                    os.fsync(root)
                    return sorted(manifest, key=lambda item: item["path"])
                finally:
                    os.close(root)
    except AccessError:
        raise
    except FileExistsError:
        _fail("staging_exists", "The staging destination already exists; it was not overwritten.")
    except (OSError, ValueError, zipfile.BadZipFile, NotImplementedError, RuntimeError, EOFError, zlib.error):
        _fail("package_invalid", "The archive could not be safely read and validated.")
