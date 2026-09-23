import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from peters_mcp.catalog import AccessError, Catalog, MAX_FILE_BYTES, Project


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "repo"
        self.root.mkdir()
        self.catalog = Catalog([Project("demo", "中文项目", self.root, (".jq-workflow",))])
        self.write("README.md", "第一行\nNeedle and evidence\n最后一行\n")

    def write(self, path, content):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return target

    def test_project_names_do_not_expose_absolute_paths(self):
        result = self.catalog.list_projects()
        self.assertNotIn(str(self.root), json.dumps(result))

    def test_published_checksum_manifest_can_be_read_and_searched(self):
        from hashlib import sha256
        raw = ('0' * 64 + '  report.md\n').encode()
        self.write('MANIFEST.sha256', raw.decode())
        result = self.catalog.read_file('demo', 'MANIFEST.sha256')
        self.assertEqual(result['text'], raw.decode())
        self.assertEqual(result['sha256'], sha256(raw).hexdigest())
        self.assertTrue(next(x for x in self.catalog.list_files('demo')['entries']
                             if x['path'] == 'MANIFEST.sha256')['format_supported'])
        self.assertEqual(self.catalog.search('demo', 'report.md')['matches'][0]['path'], 'MANIFEST.sha256')

    def test_unicode_pagination_and_version_binding(self):
        first = self.catalog.read_file("demo", "README.md", limit=5)
        second = self.catalog.read_file("demo", "README.md", offset=first["next_offset"],
                                        expected_sha256=first["sha256"])
        self.assertEqual(first["text"] + second["text"], (self.root / "README.md").read_text())
        self.write("README.md", "changed")
        with self.assertRaisesRegex(AccessError, "version changed"):
            self.catalog.read_file("demo", "README.md", expected_sha256=first["sha256"])

    def test_traversal_absolute_and_invalid_paths(self):
        for path in ("../outside.md", "/etc/passwd", "a/../../b.md", "a//b.md", "a/./b.md",
                     "a\\b.md", "a\x00.md", "", "a\n.md"):
            with self.subTest(path=path), self.assertRaises(AccessError):
                self.catalog.read_file("demo", path)

    def test_unknown_project_and_bad_pagination(self):
        with self.assertRaises(AccessError):
            self.catalog.read_file("other", "README.md")
        for value in (-1, True, 40001):
            with self.assertRaises(AccessError):
                self.catalog.read_file("demo", "README.md", limit=value)
        with self.assertRaises(AccessError):
            self.catalog.read_file("demo", "README.md", offset=500)

    def test_sensitive_sources_are_excluded_everywhere(self):
        for path in (".env", ".env.local", "nested/credentials.json", "secrets.yaml",
                     ".git/config", "private.key"):
            self.write(path, "needle sensitive")
            with self.subTest(path=path), self.assertRaises(AccessError):
                self.catalog.read_file("demo", path)
        result = self.catalog.search("demo", "sensitive")
        self.assertEqual(result["matches"], [])
        self.assertEqual([x["path"] for x in self.catalog.list_files("demo")["entries"]],
                         ["nested", "README.md"])

    def test_ordinary_hidden_material_is_readable_without_extra_grants(self):
        self.write(".jq-workflow/runs/result.json", '{"value": "needle"}')
        self.write(".other/note.md", "needle")
        paths = [r["path"] for r in self.catalog.search("demo", "needle")["matches"]]
        self.assertIn(".jq-workflow/runs/result.json", paths)
        self.assertIn(".other/note.md", paths)

    def test_file_directory_and_internal_symlinks_are_rejected(self):
        outside = self.base / "outside.md"
        outside.write_text("needle outside")
        (self.root / "link.md").symlink_to(outside)
        (self.root / "internal.md").symlink_to(self.root / "README.md")
        (self.root / "linked-dir").symlink_to(self.base, target_is_directory=True)
        for path in ("link.md", "internal.md", "linked-dir/outside.md"):
            with self.subTest(path=path), self.assertRaises(AccessError):
                self.catalog.read_file("demo", path)
        self.assertEqual(len(self.catalog.search("demo", "needle")["matches"]), 1)

    def test_directory_swap_to_symlink_cannot_escape_root(self):
        self.write("docs/note.md", "local")
        outside = self.base / "external"
        outside.mkdir()
        (outside / "note.md").write_text("outside")
        original_open = os.open

        def swapping_open(path, flags, *args, **kwargs):
            if path == "docs":
                (self.root / "docs").rename(self.root / "old-docs")
                (self.root / "docs").symlink_to(outside)
            return original_open(path, flags, *args, **kwargs)

        with patch("peters_mcp.catalog.os.open", side_effect=swapping_open):
            with self.assertRaises(AccessError):
                self.catalog.read_file("demo", "docs/note.md")

    def test_hardlinks_and_fifo_are_not_read(self):
        outside = self.base / "outside.md"
        outside.write_text("sensitive")
        os.link(outside, self.root / "hard.md")
        os.mkfifo(self.root / "pipe.txt")
        for path in ("hard.md", "pipe.txt"):
            with self.subTest(path=path), self.assertRaises(AccessError):
                self.catalog.read_file("demo", path)

    def test_binary_non_utf8_and_unsupported_formats(self):
        for name, raw in (("binary.txt", b"a\x00b"), ("encoding.md", b"\xff"),
                          ("report.pdf", b"%PDF")):
            (self.root / name).write_bytes(raw)
            with self.subTest(name=name), self.assertRaises(AccessError):
                self.catalog.read_file("demo", name)

    def test_oversized_file_fails_without_reading_content(self):
        with (self.root / "big.log").open("wb") as stream:
            stream.truncate(MAX_FILE_BYTES + 1)
        with patch("peters_mcp.catalog.os.read", side_effect=AssertionError("must not read")):
            with self.assertRaisesRegex(AccessError, "8 MiB"):
                self.catalog.read_file("demo", "big.log")

    def test_change_during_read_is_rejected(self):
        original_read = os.read
        changed = False

        def changing_read(fd, count):
            nonlocal changed
            result = original_read(fd, count)
            if not changed:
                changed = True
                self.write("README.md", "different contents with a different size")
            return result

        with patch("peters_mcp.catalog.os.read", side_effect=changing_read):
            with self.assertRaisesRegex(AccessError, "changed during"):
                self.catalog.read_file("demo", "README.md")

    def test_search_is_literal_bounded_and_reports_skipped_files(self):
        self.write("docs/note.md", "needle\nneedle\n[a-z]\n")
        result = self.catalog.search("demo", "needle", directory="docs", limit=1)
        self.assertFalse(result["complete"])
        self.assertEqual(result["stopped_reason"], "result_limit")
        self.assertEqual(result["matches"][0]["line"], 1)
        self.assertEqual(len(self.catalog.search("demo", "[a-z]")["matches"]), 1)
        self.assertEqual(self.catalog.search("demo", "NEEDLE", case_sensitive=True)["matches"], [])
        (self.root / "bad.txt").write_bytes(b"\xff")
        result = self.catalog.search("demo", "unmatched")
        self.assertFalse(result["complete"])
        self.assertEqual(result["skipped"], 1)

    def test_project_specific_exclusions(self):
        self.write("private/note.md", "needle")
        c = Catalog([Project("demo", "Demo", self.root, exclude=("private",))])
        with self.assertRaises(AccessError):
            c.read_file("demo", "private/note.md")
        self.assertNotIn("private/note.md", [x["path"] for x in c.search("demo", "needle")["matches"]])

    def test_config_validation(self):
        path = self.base / "config.json"
        valid = {"id": "demo", "name": "Demo", "root": str(self.root)}
        path.write_text(json.dumps({"projects": [valid]}))
        self.assertIn("demo", Catalog.from_config(path).projects)
        for data in ({"projects": []}, {"projects": [valid, valid]},
                     {"projects": [{**valid, "root": "/"}]},
                     {"projects": [{**valid, "extra": True}]}):
            path.write_text(json.dumps(data))
            with self.assertRaises(AccessError):
                Catalog.from_config(path)


if __name__ == "__main__":
    unittest.main()
