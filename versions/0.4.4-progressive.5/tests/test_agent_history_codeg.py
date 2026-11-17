"""Representative Codeg 0.45.0 index and ACP-native transcript fixtures."""

from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from peters_mcp.agent_history_codeg import Adapter
from peters_mcp.agent_history_source import SourceRoot
from peters_mcp.catalog import AccessError


_SCHEMA = """
    CREATE TABLE folder (
        id INTEGER PRIMARY KEY, path TEXT NOT NULL, kind TEXT NOT NULL,
        parent_id INTEGER, deleted_at TEXT
    );
    CREATE TABLE conversation (
        id INTEGER PRIMARY KEY, title TEXT, updated_at TEXT NOT NULL,
        agent_type TEXT NOT NULL, external_id TEXT, origin_cwd TEXT,
        folder_id INTEGER NOT NULL, kind TEXT NOT NULL, parent_id INTEGER, deleted_at TEXT
    );
"""


def text(value):
    return {"type": "text", "text": value}


def prompt(value, *extra, at=1000):
    return {"t": at, "k": "prompt", "p": [text(value), *extra]}


def update(kind, content, at=1100):
    return {"t": at, "k": "update", "p": {"sessionUpdate": kind, "content": content}}


def answer(value, at=1100):
    return update("agent_message_chunk", text(value), at=at)


def end(at=1200):
    return {"t": at, "k": "turn_end", "p": {"stopReason": "end_turn"}}


class CodegAdapterTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.database = self.root / "codeg.db"
        self.project = self.root / "project"
        self.project.mkdir()
        with closing(sqlite3.connect(self.database)) as db:
            db.executescript(_SCHEMA)
            db.execute("INSERT INTO folder VALUES (1, ?, 'regular', NULL, NULL)", (str(self.project),))
            db.commit()
        self.adapter = Adapter(SourceRoot(self.root), "0.45.0")

    def _conversation(self, row_id, *, native="session-1", agent="custom:goose", title="Thread",
                      kind="regular", folder=1, origin=None, parent=None, deleted=None):
        with closing(sqlite3.connect(self.database)) as db:
            db.execute(
                "INSERT INTO conversation VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (row_id, title, "2026-10-10T03:00:00+00:00", agent, native, origin,
                 folder, kind, parent, deleted),
            )
            db.commit()

    def _transcript(self, session, *records, previous=None, cwd=None, agent="custom:goose", version=1):
        path = self.root / "acp-transcripts" / "goose" / (session + ".jsonl")
        path.parent.mkdir(parents=True, exist_ok=True)
        header = {"v": version, "kind": "header", "agent": agent,
                  "session_id": session, "cwd": str(cwd or self.project), "started_at_ms": 1000}
        if previous is not None:
            header["continues_from"] = previous
        path.write_text("".join(json.dumps(record) + "\n" for record in (header, *records)), encoding="utf-8")
        return path

    def test_ui_text_filters_route_echo_attachments_and_thought(self):
        marker = '\x1e{"kind":"codeg_internal_agent_routes","version":3}\nroute secret\x1e'
        self._conversation(1, title="Release plan " + marker)
        path = self._transcript(
            "session-1",
            prompt("Question one", text(marker), {"type": "resource", "text": "ATTACHMENT"},
                   text("another internal block")),
            update("user_message_chunk", text("Question one")),
            update("agent_thought_chunk", text("hidden chain")),
            update("tool_call", {"rawOutput": "tool secret"}),
            update("agent_message_chunk", {"type": "text", "text": "internal output",
                                            "annotations": {"audience": ["assistant"]}}),
            answer("First"), answer(" reply"), answer(" \x1e{"),
            answer('"kind":"codeg_internal_assistant_brief"}\nassistant brief\x1e'), end(),
            prompt("Question two", at=2000), answer("Second reply", at=2100), end(2200),
        )
        thread, = self.adapter.discover()
        self.assertEqual(thread.title, "Release plan")
        self.assertEqual(thread.agent, "custom:goose")
        self.assertEqual(thread.contexts, (str(self.project),))
        projection = self.adapter.snapshot(thread)
        self.assertEqual([(message.role, message.text) for message in projection.messages], [
            ("user", "Question one"), ("assistant", "First reply"),
            ("user", "Question two"), ("assistant", "Second reply"),
        ])
        first, first_answer, second, second_answer = projection.messages
        self.assertTrue(first.position)
        self.assertEqual(first.turn_id, first_answer.turn_id)
        self.assertEqual(second.turn_id, second_answer.turn_id)
        self.assertNotEqual(first.turn_id, second.turn_id)
        self.assertTrue(projection.context_complete)
        data = path.read_bytes()
        self.assertEqual(projection.prefix, (str(path.relative_to(self.root)), len(data), hashlib.sha256(data).hexdigest()))
        self.assertEqual(projection.revision, projection.prefix[2])

    def test_codeg_native_aliases_are_metadata_and_omit_non_workspace_threads(self):
        self._conversation(1, agent="deepseek", native="deepseek-session", origin="/projects/original")
        self._conversation(2, agent="codex", native="f8c692fb-5ac0-499e-8d3d-b8d341d9d58d")
        self._conversation(3, agent="deepseek", deleted="2025-10-01")
        self._conversation(4, agent="codex", kind="delegate", parent=2)
        self._conversation(5, agent="antigravity", native="acp-is-another-store")
        self._conversation(6, agent="custom:../path", native="session-6")
        self._conversation(7, agent="custom:goose", native="../unsafe")
        self._conversation(8, agent="custom:goose", native=None)
        self._conversation(9, agent="deepseek", native="session~003Awith~0040id")
        self._conversation(10, agent="deepseek", native="not~0061canonical")
        found = tuple(self.adapter.discover())
        self.assertEqual([thread.native_id for thread in found], ["1", "2", "9"])
        deepseek, codex, encoded = found
        self.assertEqual(deepseek.agent, "deepseek_harness")
        self.assertEqual(deepseek.native_link, ("deepseek_harness", "deepseek-session"))
        self.assertEqual(deepseek.contexts, (str(self.project), "/projects/original"))
        self.assertEqual(codex.native_link, ("codex", "f8c692fb-5ac0-499e-8d3d-b8d341d9d58d"))
        self.assertEqual(encoded.native_link, ("deepseek_harness", "session:with@id"))
        self.assertIsNone(self.adapter.describe("3"))
        self.assertIsNone(self.adapter.describe("5 OR 1=1"))
        with self.assertRaises(AccessError) as caught:
            self.adapter.snapshot(deepseek)
        self.assertEqual(caught.exception.code, "source_unavailable")

    def test_wal_snapshot_sees_committed_rows_and_leaves_original_bytes_intact(self):
        def digests():
            return {path.name: (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns)
                    for path in self.root.glob("codeg.db*")}

        with closing(sqlite3.connect(self.database)) as db:
            self.assertEqual(db.execute("PRAGMA journal_mode=WAL").fetchone(), ("wal",))
            db.execute("PRAGMA wal_autocheckpoint=0")
            db.execute("""
                INSERT INTO conversation VALUES (
                    1, 'Wal thread', '2026-10-10T03:00:00Z', 'deepseek', 'wal-committed',
                    NULL, 1, 'regular', NULL, NULL
                )
            """)
            db.commit()
            originals = digests()
            self.assertIn("codeg.db-wal", originals)
            self.assertEqual(self.adapter.describe("1").native_link, ("deepseek_harness", "wal-committed"))
            self.assertEqual(digests(), originals)

    def test_missing_codeg_profile_does_not_fall_back_to_another_device(self):
        self._conversation(1, agent="deepseek", native="registered-device")
        missing = self.root / "another-device"
        missing.mkdir()
        disconnected = Adapter(SourceRoot(missing), "0.45.0")
        with self.assertRaises(AccessError) as caught:
            tuple(disconnected.discover())
        self.assertEqual(caught.exception.code, "source_unavailable")
        self.assertEqual(self.adapter.describe("1").native_link, ("deepseek_harness", "registered-device"))

    def test_continuation_conveys_prior_project_and_checks_soft_deleted_ancestor(self):
        self._conversation(1, native="older")
        self._conversation(2, native="newer")
        old_worktree = self.project / "past"
        old_worktree.mkdir()
        self._transcript("older", prompt("Old question"), answer("Old answer"), end(), cwd=old_worktree)
        self._transcript("newer", prompt("New question"), answer("New answer"), end(), previous="older")
        thread = self.adapter.describe("2")
        projection = self.adapter.snapshot(thread)
        self.assertEqual([message.text for message in projection.messages],
                         ["Old question", "Old answer", "New question", "New answer"])
        self.assertIn(str(old_worktree), projection.contexts)
        self.assertEqual(projection.ancestors, ("older", "1"))
        self.assertIsNone(projection.prefix)
        with closing(sqlite3.connect(self.database)) as db:
            db.execute("UPDATE conversation SET deleted_at = ? WHERE id = 1", ("2025-10-01",))
            db.commit()
        with self.assertRaises(AccessError) as caught:
            self.adapter.snapshot(thread)
        self.assertEqual(caught.exception.code, "source_unavailable")

    def test_replayed_user_shaped_chunks_cannot_grant_inheritance(self):
        self._conversation(1)
        self._transcript(
            "session-1", update("user_message_chunk", text("Unverified inherited text")),
            answer("Unverified associated answer"),
            prompt("Independent input"), answer("Visible reply"), end(),
        )
        projection = self.adapter.snapshot(self.adapter.describe("1"))
        self.assertEqual([message.text for message in projection.messages], ["Independent input", "Visible reply"])
        self.assertFalse(projection.context_complete)
        self.assertIn("unverified_acp_history_omitted", projection.warnings)

    def test_incomplete_tail_is_not_in_prefix_and_rewrite_changes_identity(self):
        self._conversation(1)
        path = self._transcript("session-1", prompt("Known question"), answer("Known answer"), end())
        original = path.read_bytes()
        with path.open("ab") as stream:
            stream.write(b'{"t":2000,"k":"prompt"')
        thread = self.adapter.describe("1")
        partial = self.adapter.snapshot(thread)
        self.assertEqual(partial.prefix[1], len(original))
        self.assertIn("incomplete_acp_tail", partial.warnings)
        replacement = path.with_suffix(".temp")
        replacement.write_bytes(original)
        replacement.replace(path)
        copied = self.adapter.snapshot(thread)
        self.assertNotEqual(partial.identity, copied.identity)
        self.assertEqual(partial.revision, copied.revision)

    def test_rejects_bad_header_version_cycle_and_unrecognized_records(self):
        self._conversation(1)
        thread = self.adapter.describe("1")
        for options, records in (
            ({"version": 2}, []),
            ({"previous": "session-1"}, []),
            ({"previous": "../escape"}, []),
            ({"agent": "custom:other"}, []),
            ({}, [{"t": 3000, "k": "other", "p": {}}]),
        ):
            with self.subTest(options=options, records=records):
                self._transcript("session-1", *records, **options)
                with self.assertRaises(AccessError) as caught:
                    self.adapter.snapshot(thread)
                self.assertEqual(caught.exception.code, "unsupported_format")
        with self.assertRaises(AccessError) as caught:
            Adapter(SourceRoot(self.root), "0.46.0")
        self.assertEqual(caught.exception.code, "unsupported_format")
