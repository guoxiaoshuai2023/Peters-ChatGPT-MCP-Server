import codecs
from dataclasses import replace
import hashlib
import http.client
import io
import os
from pathlib import Path
import socket
import stat
import struct
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import warnings
import zipfile

from peters_mcp.catalog import AccessError
from peters_mcp.delivery_types import DeliveryLimits, OpenAIFile
from peters_mcp.package_input import download_archive, extract_package, _PinnedHTTPS


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def archive_bytes(files, *, compression=zipfile.ZIP_STORED, comment=b""):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=compression) as package:
        for name, raw in files:
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", message="Duplicate name:", category=UserWarning)
                package.writestr(name, raw)
        package.comment = comment
    return stream.getvalue()


class PackageInputTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.archive = self.root / "archive.zip"
        self.destination = self.root / "expanded"
        self.limits = DeliveryLimits()

    def extract(self, files, *, compression=zipfile.ZIP_STORED, limits=None):
        self.archive.write_bytes(archive_bytes(files, compression=compression))
        return extract_package(self.archive, self.destination, limits or self.limits)

    def rejected(self, files, code, **kwargs):
        with self.assertRaises(AccessError) as raised:
            self.extract(files, **kwargs)
        self.assertEqual(raised.exception.code, code)

    def test_six_file_original_bytes_and_exact_regression_sizes(self):
        main = "# 合成方案 v1.0\r\n".encode()
        main += b"A" * (58438 - len(main))
        files = [
            ("00-README.md", codecs.BOM_UTF8 + "# 合成资料\r\n".encode()),
            ("01-plan-v1.0.md", main),
            ("步骤/02-start-v1.0.md", "中文原文\n".encode()),
            ("03-config.json", codecs.BOM_UTF8 + b'{\r\n  "enabled": true\r\n}\r\n'),
            ("04-checks.txt", b"one\r\ntwo\nthree\r\n"),
        ]
        checksums = "".join(f"{digest(raw)}  {name}\n" for name, raw in files).encode()
        files.append(("MANIFEST.sha256", checksums))
        initial = archive_bytes(files)
        raw = archive_bytes(files, comment=b"p" * (85010 - len(initial)))
        self.assertEqual(len(raw), 85010)
        self.archive.write_bytes(raw)
        manifest = extract_package(self.archive, self.destination, self.limits)
        self.assertEqual(len(manifest), 6)
        self.assertEqual(manifest, sorted(manifest, key=lambda item: item["path"]))
        for item in manifest:
            self.assertEqual(set(item), {"path", "size_bytes", "sha256"})
            actual = (self.destination / item["path"]).read_bytes()
            self.assertEqual(actual, dict(files)[item["path"]])
            self.assertEqual(item["size_bytes"], len(actual))
            self.assertEqual(item["sha256"], digest(actual))
            self.assertEqual(stat.S_IMODE((self.destination / item["path"]).stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.destination / "步骤").stat().st_mode), 0o700)

    def test_limits_at_boundary_and_above(self):
        limits = replace(self.limits, max_file_bytes=10, max_package_bytes=20, max_files=2)
        result = self.extract([("a.txt", b"a" * 10), ("b.txt", b"b" * 10)], limits=limits)
        self.assertEqual(sum(item["size_bytes"] for item in result), 20)
        for files, changes, code in [
            ([("a.txt", b"a" * 11)], {}, "package_size_limit"),
            ([("a.txt", b"a" * 10), ("b.txt", b"b" * 10)], {"max_package_bytes": 19}, "package_size_limit"),
            ([("a.txt", b"a"), ("b.txt", b"b"), ("c.txt", b"c")], {}, "package_file_limit"),
            ([("a/b.txt", b"a")], {"max_depth": 1}, "package_depth_limit"),
        ]:
            self.destination = self.root / ("limit-" + str(len(list(self.root.iterdir()))))
            self.rejected(files, code, limits=replace(limits, **changes))
            self.assertFalse(self.destination.exists())

    def test_archive_size_limit(self):
        self.rejected([("a.md", b"hello")], "archive_size_limit", limits=replace(self.limits, max_archive_bytes=10))

    def test_default_single_file_limit_exact_and_one_byte_over(self):
        raw = b"a" * self.limits.max_file_bytes
        result = self.extract([("large.md", raw)])
        self.assertEqual(result[0]["sha256"], digest(raw))
        self.destination = self.root / "over-limit"
        self.rejected([("large.md", raw + b"b")], "package_size_limit")
        self.assertFalse(self.destination.exists())

    def test_traversal_unsafe_paths_and_sensitive_files(self):
        for name in ("../escape.txt", "/absolute.txt", "a/../escape.md", "a\\b.md", "C:evil.md",
                     "a//b.md", "a/./b.md", "bad\x01.md", "bad\u202e.md", "a. /b.md", "CON.txt",
                     "a.\uFF0F../b.md", ".env", ".git/config", ".github/workflows/x.yml"):
            with self.subTest(name=name):
                self.rejected([(name, b"text")], "package_path_invalid")
                self.assertFalse(self.destination.exists())
        for name in ("AGENTS.md", "claude.MD", "docs/SKILL.md", "credentials.json", "secret.key", "id_rsa"):
            with self.subTest(name=name):
                self.rejected([(name, b"text")], "package_path_forbidden")
        self.assertFalse((self.root / "escape.txt").exists())

    def test_platform_collisions_and_prefix_conflicts(self):
        for names in (("a.md", "a.md"), ("a.md", "A.md"), ("é.md", "e\u0301.md"),
                      ("a.md", "ａ.md"), ("a.md", "a.md/b.txt"), ("a.md/b.txt", "a.md"),
                      ("Dir/a.txt", "dir/b.txt"), ("Dir/", "dir/a.md")):
            with self.subTest(names=names):
                self.rejected([(name, b"" if name.endswith("/") else b"x") for name in names], "package_name_conflict")
                self.assertFalse(self.destination.exists())

    def test_directory_entries_and_executable_permissions(self):
        info = zipfile.ZipInfo("nested/a.md")
        info.external_attr = (stat.S_IFREG | 0o777) << 16
        self.archive.write_bytes(archive_bytes([("nested/", b""), (info, b"# text\n")]))
        manifest = extract_package(self.archive, self.destination, self.limits)
        self.assertEqual(manifest[0]["path"], "nested/a.md")
        self.assertEqual(stat.S_IMODE((self.destination / "nested/a.md").stat().st_mode), 0o600)

    def test_explicit_empty_directories_are_rejected_before_extraction(self):
        for files in ([('empty/', b'')],
                      [('a.md', b'text'), ('empty/', b'')],
                      [('nested/', b''), ('nested/empty/', b''), ('nested/a.md', b'text')]):
            with self.subTest(names=[name for name, _ in files]):
                self.rejected(files, "package_empty_directory_unsupported")
                self.assertFalse(self.destination.exists())

    def test_explicit_nonempty_ancestor_directories_preserve_structure(self):
        manifest = self.extract([('nested/', b''), ('nested/deep/', b''),
                                 ('nested/deep/a.md', b'text')])
        self.assertEqual(manifest[0]['path'], 'nested/deep/a.md')
        self.assertEqual((self.destination / 'nested/deep/a.md').read_bytes(), b'text')

    def test_links_special_files_and_encryption_rejected(self):
        for mode in (stat.S_IFLNK, stat.S_IFIFO, stat.S_IFCHR, stat.S_IFSOCK):
            info = zipfile.ZipInfo("link.txt")
            info.external_attr = (mode | 0o600) << 16
            self.rejected([(info, b"../outside")], "package_special_file")
        raw = bytearray(archive_bytes([("a.md", b"text")]))
        central = raw.index(b"PK\x01\x02")
        struct.pack_into("<H", raw, central + 8, 1)
        self.archive.write_bytes(raw)
        with self.assertRaises(AccessError) as raised:
            extract_package(self.archive, self.destination, self.limits)
        self.assertEqual(raised.exception.code, "package_encrypted")

    def test_nul_filename_is_not_silently_truncated(self):
        raw = archive_bytes([("evilX.txt", b"text")]).replace(b"evilX.txt", b"evil\0.txt")
        self.archive.write_bytes(raw)
        with self.assertRaises(AccessError) as raised:
            extract_package(self.archive, self.destination, self.limits)
        self.assertEqual(raised.exception.code, "package_path_invalid")
        self.assertFalse(self.destination.exists())

    def test_types_encoding_scripts_and_json_validation(self):
        cases = [("a.py", b"print(1)", "package_type_forbidden"),
                 ("a.exe", b"MZ", "package_type_forbidden"),
                 ("a.txt", b"bad\x00text", "package_binary_rejected"),
                 ("a.txt", b"\xff", "package_encoding_invalid"),
                 ("a.txt", b"#!/bin/sh\n", "package_code_rejected"),
                 ("a.json", b"{bad}", "package_json_invalid"),
                 ("a.json", b"{\"bad\":NaN}", "package_json_invalid")]
        for index, (name, raw, code) in enumerate(cases):
            self.destination = self.root / f"bad-{index}"
            self.rejected([(name, raw)], code)

    def test_compression_bomb_and_crc_failure_remain_private(self):
        self.rejected([("a.txt", b"a" * 100000)], "package_ratio_limit", compression=zipfile.ZIP_DEFLATED)
        # Corrupt the second payload unambiguously, leaving central metadata intact.
        raw = archive_bytes([("first.md", b"first payload"), ("second.md", b"second payload")])
        raw = raw.replace(b"second payload", b"second payloae", 1)
        self.archive.write_bytes(raw)
        with self.assertRaises(AccessError) as raised:
            extract_package(self.archive, self.destination, self.limits)
        self.assertEqual(raised.exception.code, "package_invalid")
        self.assertTrue((self.destination / "first.md").exists())
        self.assertEqual(set(self.root.iterdir()), {self.archive, self.destination})

    def test_unsupported_compression_and_manifest_limit(self):
        self.rejected([("a.md", b"hi")], "package_compression_unsupported", compression=zipfile.ZIP_BZIP2)
        self.rejected([("MANIFEST.sha256", b"\n" * 11)], "package_manifest_limit",
                      limits=replace(self.limits, max_manifest_bytes=10))

    def test_checksum_mismatch_and_malformed_manifest_reject(self):
        for index, raw in enumerate((b"bad checksum\n", b"0" * 64 + b"  a.md\n",
                                     digest(b"hi").encode() + b"  missing.md\n")):
            self.destination = self.root / f"manifest-{index}"
            self.rejected([("a.md", b"hi"), ("MANIFEST.sha256", raw)],
                          "package_manifest_invalid" if index == 0 else "package_manifest_mismatch")

    def test_existing_destination_and_linked_archive_or_parent_not_followed(self):
        self.archive.write_bytes(archive_bytes([("a.md", b"new")]))
        self.destination.mkdir()
        (self.destination / "a.md").write_bytes(b"original")
        with self.assertRaises(AccessError) as raised:
            extract_package(self.archive, self.destination, self.limits)
        self.assertEqual(raised.exception.code, "staging_exists")
        self.assertEqual((self.destination / "a.md").read_bytes(), b"original")
        linked = self.root / "linked.zip"
        linked.symlink_to(self.archive)
        with self.assertRaises(AccessError):
            extract_package(linked, self.root / "no-create", self.limits)
        linked.unlink()
        os.link(self.archive, linked)
        with self.assertRaises(AccessError) as raised:
            extract_package(linked, self.root / "no-create", self.limits)
        self.assertEqual(raised.exception.code, "archive_not_regular")
        linked.unlink()
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(AccessError):
            extract_package(self.archive, alias / "no-create", self.limits)
        self.assertFalse((self.root / "no-create").exists())


class DownloadTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.destination = self.root / "received.zip"
        self.raw = archive_bytes([("a.md", b"hello")])
        self.file = OpenAIFile(download_url="https://files.example.test/blob?signature=PRIVATE", file_id="PRIVATE-ID")
        self.sources = {"files.example.test": ("93.184.216.34",)}
        self.limits = DeliveryLimits()
        self.connection = MagicMock()
        self.response = self.connection.getresponse.return_value
        self.response.status = 200
        self.response.getheader.side_effect = lambda name, default=None: {"Content-Length": str(len(self.raw))}.get(name, default)
        self.response.read.side_effect = [self.raw, b""]
        self.constructor = patch("peters_mcp.package_input._PinnedHTTPS", return_value=self.connection).start()
        self.addCleanup(patch.stopall)

    def download(self, **kwargs):
        return download_archive(kwargs.get("file", self.file), self.destination,
                                kwargs.get("expected_sha256", digest(self.raw)),
                                kwargs.get("sources", self.sources), kwargs.get("limits", self.limits))

    def rejected(self, code, **kwargs):
        with self.assertRaises(AccessError) as raised:
            self.download(**kwargs)
        self.assertEqual(raised.exception.code, code)
        self.assertNotIn("PRIVATE", str(raised.exception))
        self.assertNotIn("example.test", str(raised.exception))
        self.assertFalse(self.destination.exists())

    def test_original_bytes_hash_private_mode_and_pinned_address(self):
        result = self.download()
        self.assertEqual(result, {"size_bytes": len(self.raw), "sha256": digest(self.raw)})
        self.assertEqual(self.destination.read_bytes(), self.raw)
        self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), 0o600)
        self.constructor.assert_called_once_with("files.example.test", "93.184.216.34")
        self.connection.request.assert_called_once_with("GET", "/blob?signature=PRIVATE", headers={"Accept-Encoding": "identity", "User-Agent": "MCP-Package-Input/1"})

    def test_only_approved_https_hosts(self):
        for url in ("http://files.example.test/x", "https://127.0.0.1/x", "https://[::1]/x",
                    "https://files.example.test:444/x", "https://user:password@files.example.test/x",
                    "https://files.example.test/x#secret", "https://files.example.test/\r\nHeader:x",
                    "https://files.example.test\\@elsewhere.test/x"):
            with self.subTest(url=url):
                self.rejected("file_reference_invalid", file=self.file.model_copy(update={"download_url": url}))
        self.rejected("file_source_not_approved", sources={})
        self.constructor.assert_not_called()

    def test_no_nonpublic_addresses_even_explicit_or_mixed_dns(self):
        for address in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "198.18.2.100", "224.0.0.1", "::1", "::ffff:127.0.0.1", "fc00::1", "64:ff9b::7f00:1"):
            with self.subTest(address=address):
                self.rejected("file_source_nonpublic", sources={"files.example.test": (address,)})
        with patch("peters_mcp.package_input.socket.getaddrinfo", return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]):
            self.rejected("file_source_nonpublic", sources={"files.example.test": None})
        self.constructor.assert_not_called()

    def test_checked_dns_is_resolved_once_before_pinned_connection(self):
        with patch("peters_mcp.package_input.socket.getaddrinfo", return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]) as resolve:
            self.download(sources={"files.example.test": None})
        resolve.assert_called_once_with("files.example.test", 443, type=socket.SOCK_STREAM)
        self.constructor.assert_called_once_with("files.example.test", "93.184.216.34")

    def test_rejection_redirect_encoding_expiry_and_hash_cleanup(self):
        for status, code in ((302, "file_redirect_rejected"), (403, "file_download_rejected")):
            self.response.status = status
            self.rejected(code)
        self.response.status = 200
        self.response.getheader.side_effect = lambda name, default=None: "gzip" if name == "Content-Encoding" else default
        self.rejected("file_encoding_rejected")
        self.response.getheader.side_effect = lambda name, default=None: default
        self.rejected("archive_hash_mismatch", expected_sha256="0" * 64)

    def test_interrupted_transfer_and_wrong_length_cleanup(self):
        self.response.read.side_effect = [self.raw[:10], http.client.IncompleteRead(b"secret")]
        self.rejected("file_source_unavailable")
        self.response.read.side_effect = [self.raw[:10], b""]
        self.rejected("file_download_incomplete")

    def test_timeout_and_dns_failure_do_not_expose_provider_reference(self):
        with patch("peters_mcp.package_input.time.monotonic", side_effect=[0, 121]):
            self.rejected("file_download_timeout")
        with patch("peters_mcp.package_input.socket.getaddrinfo", side_effect=OSError("PRIVATE-DNS")):
            self.rejected("file_source_unavailable", sources={"files.example.test": None})

    def test_declared_actual_size_limits_and_invalid_length(self):
        self.rejected("archive_size_limit", limits=replace(self.limits, max_archive_bytes=10))
        self.response.getheader.side_effect = lambda name, default=None: "bad" if name == "Content-Length" else default
        self.rejected("file_download_invalid")
        self.response.getheader.side_effect = lambda name, default=None: default
        self.rejected("archive_size_limit", limits=replace(self.limits, max_archive_bytes=10))

    def test_existing_destination_and_symlink_are_not_overwritten(self):
        self.destination.write_bytes(b"previous")
        with self.assertRaises(AccessError) as raised:
            self.download()
        self.assertEqual(raised.exception.code, "staging_exists")
        self.assertEqual(self.destination.read_bytes(), b"previous")
        self.destination.unlink()
        original = self.root / "original"
        original.write_bytes(b"keep")
        self.destination.symlink_to(original)
        with self.assertRaises(AccessError):
            self.download()
        self.assertEqual(original.read_bytes(), b"keep")
        self.constructor.assert_not_called()

    def test_connection_uses_ip_and_original_tls_hostname(self):
        # Test the actual connection class without opening a socket or using env proxies.
        instance = _PinnedHTTPS("files.example.test", "93.184.216.34", 7)
        raw_socket = MagicMock()
        context = MagicMock()
        instance._context = context
        with patch.dict(os.environ, {"HTTPS_PROXY": "http://127.0.0.1:1"}), patch(
                "peters_mcp.package_input.socket.create_connection", return_value=raw_socket) as create:
            instance.connect()
        create.assert_called_once_with(("93.184.216.34", 443), 7)
        context.wrap_socket.assert_called_once_with(raw_socket, server_hostname="files.example.test")


if __name__ == "__main__":
    unittest.main()
