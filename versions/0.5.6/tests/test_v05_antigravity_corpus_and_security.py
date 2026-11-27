"""WS1 / D2 / S2 / S4 tests: Antigravity sanitized real-structure corpus & negative security matrix."""

from contextlib import closing
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
import uuid

from peters_mcp.agent_history_antigravity import Adapter, INDEX
from peters_mcp.agent_history_antigravity_native import capture
from peters_mcp.agent_history_path_migration import reviewed_document
from peters_mcp.agent_history_source import SourceRoot
from peters_mcp.catalog import AccessError
from peters_mcp.fs_identity import persistent_identity
from tests import test_agent_history_antigravity_native as native


CHILD_ID = str(uuid.UUID(int=99))
CHILD_TRAJ = str(uuid.UUID(int=100))
CHILD_EXEC = str(uuid.UUID(int=101))


def _write_child_db(root, child_id, child_traj, project_uri, *, parent_id=native.SESSION,
                    killed=0, planner_config=b"", extra_user_step=False,
                    fork_field_16=False, created=(native.SECONDS, 0)):
    db_path = root / "conversations" / f"{child_id}.db"
    if db_path.exists():
        db_path.unlink()
    with closing(sqlite3.connect(db_path)) as db:
        db.executescript(
            """PRAGMA user_version=1;
            CREATE TABLE trajectory_meta(trajectory_id TEXT, cascade_id TEXT, trajectory_type INTEGER, source INTEGER);
            CREATE TABLE trajectory_metadata_blob(id TEXT, data BLOB);
            CREATE TABLE steps(idx INTEGER PRIMARY KEY, step_type INTEGER, status INTEGER,
                has_subtrajectory INTEGER, metadata BLOB, step_payload BLOB, step_format INTEGER);
            CREATE TABLE executor_metadata(idx INTEGER PRIMARY KEY, data BLOB);
            CREATE TABLE gen_metadata(idx INTEGER PRIMARY KEY, data BLOB);
            CREATE TABLE parent_references(idx INTEGER PRIMARY KEY, data BLOB);
            CREATE TABLE battle_mode_infos(idx INTEGER PRIMARY KEY, data BLOB);"""
        )
        db.execute("INSERT INTO trajectory_meta VALUES(?,?,4,1)", (child_traj, child_id))
        extra_hdr = ((16, b"forked-bytes"),) if fork_field_16 else ()
        hdr = native.message(
            (1, native.message((1, project_uri))),
            (2, native.message((1, created[0]), (2, created[1]))),
            (3, native.INIT),
            (6, child_id),
            (7, project_uri),
            (18, native.PROJECT),
            *extra_hdr,
        )
        db.execute("INSERT INTO trajectory_metadata_blob VALUES('main',?)", (hdr,))
        start = native.message((1, created[0]), (2, created[1]))
        # Step 0: agent_message (or forbidden USER_INPUT)
        origin0 = native.message((1, child_traj), (2, 0), (3, 0), (4, child_id))
        lc0 = native.message((1, native.message((1, 3), (2, start))))
        if extra_user_step:
            meta0 = native.message((1, start), (3, 4), (12, CHILD_EXEC), (20, origin0), (26, lc0))
            pub0 = native.message((2, "Injected external user input"), (3, native.message((1, "Injected external user input"))),
                                  (18, native.desktop_spec()))
            pay0 = native.message((1, 14), (4, 3), (5, meta0), (19, pub0))
            db.execute("INSERT INTO steps VALUES(0, 14, 3, 0, ?, ?, 0)", (meta0, pay0))
        else:
            meta0 = native.message((1, start), (3, 3), (12, CHILD_EXEC), (20, origin0), (26, lc0))
            msg0 = native.message((1, parent_id), (2, "Research the authorized codebase"))
            pay0 = native.message((1, 16), (4, 3), (5, meta0), (21, msg0))
            db.execute("INSERT INTO steps VALUES(0, 16, 3, 0, ?, ?, 0)", (meta0, pay0))
        # Step 1: PLANNER_RESPONSE
        origin1 = native.message((1, child_traj), (2, 1), (3, 0), (4, child_id))
        lc1 = native.message((1, native.message((1, 8), (2, start))), (1, native.message((1, 3), (2, start))))
        meta1 = native.message((1, start), (3, 2), (6, start), (7, start), (8, start),
                               (12, CHILD_EXEC), (20, origin1), (26, lc1))
        pub1 = native.message((1, "Child research summary"), (3, "hidden"), (8, "Child research summary"))
        pay1 = native.message((1, 15), (4, 3), (5, meta1), (20, pub1))
        db.execute("INSERT INTO steps VALUES(1, 15, 3, 0, ?, ?, 0)", (meta1, pay1))
        exec_fields = [
            (1, 4), (2, 1), (3, 1), (9, CHILD_EXEC),
            (16, native.message((1, native.desktop_spec()), (3, b""))),
        ]
        if planner_config:
            exec_fields.append((10, planner_config))
        db.execute("INSERT INTO executor_metadata VALUES(0, ?)", (native.message(*exec_fields),))
        db.commit()
    return db_path


class AntigravityV05CorpusAndSecurityTests(unittest.TestCase):
    def _fixture(self):
        fx = native.AntigravityNativeTests()
        fx.setUp()
        self.addCleanup(fx.doCleanups)
        return fx

    def test_version_semver_and_schema_probing_accepts_233_plus_and_rejects_bad_versions_or_schema(self):
        fx = self._fixture()
        root = fx.reader.root
        for ok_ver in (None, "2.32.1", "2.33.0", "2.33.1", "2.34.0"):
            adapter = Adapter(root, ok_ver)
            self.assertIsNotNone(adapter.describe(native.SESSION))
        for bad_ver in ("1.9.0", "2.31.9", "3.0.0", "2.33", "not-a-version"):
            with self.subTest(bad_ver=bad_ver), self.assertRaises(AccessError) as err:
                Adapter(root, bad_ver)
            self.assertEqual(err.exception.code, "unsupported_format")

        # Corrupt PRAGMA user_version in conversation_summaries.db -> must fail closed!
        fx.index.execute("PRAGMA user_version=99")
        fx.index.commit()
        with self.assertRaises(AccessError) as err:
            Adapter(root, "2.33.1").describe(native.SESSION)
        self.assertEqual(err.exception.code, "unsupported_format")

    def test_discover_project_233_plus_honest_partition_completeness(self):
        fx = self._fixture()
        rows = tuple(fx.reader.discover_project((str(fx.project),)))
        self.assertEqual([r.native_id for r in rows], [native.SESSION])
        self.assertTrue(fx.reader.project_partition_complete)
        self.assertEqual(fx.reader.warnings, ())

        # Insert an unparseable workspace_uris top-level row -> must degrade honestly!
        bad_id = str(uuid.UUID(int=77))
        fx.index.execute(
            "INSERT INTO conversation_summaries VALUES(?,?,?,?, '',0,?,1,0,0,'CASCADE_RUN_STATUS_IDLE')",
            (bad_id, "Corrupt URI", native.TIME, "NOT-JSON-URIS", native.PROJECT),
        )
        fx.index.commit()
        rows_after = tuple(fx.reader.discover_project((str(fx.project),)))
        self.assertEqual([r.native_id for r in rows_after], [native.SESSION])
        self.assertFalse(fx.reader.project_partition_complete)
        self.assertEqual(fx.reader.warnings, ("association_unverified",))

    def test_turn_ids_compacted_status5_checkpoint_slash_cmd_and_attachments_dual_track(self):
        fx = self._fixture()
        # Add companion transcript_full.jsonl matching the 2 turns, with slash command inside <USER_REQUEST> on turn 0
        # and mark DB steps 0 & 1 as Checkpoint-compacted (status=5) with a CHECKPOINT step (type=23) at idx 2,
        # plus repeated USER_INPUT.3 items and USER_INPUT.9 attachment on step 0!
        user0_full = "/generative_ui 请生成架构图\n第二行内容"
        wrapped0 = f"<USER_REQUEST>\n{user0_full}\n</USER_REQUEST>\n<ADDITIONAL_METADATA>host</ADDITIONAL_METADATA>"
        fx.logs[0]["content"] = wrapped0
        # Shift turn 1 steps to idx 3 & 4, inserting CHECKPOINT (type=23) at idx 2
        fx.logs[2]["step_index"] = 3
        fx.logs[3]["step_index"] = 4
        fx.write_logs()
        full_path = fx.transcript.with_name("transcript_full.jsonl")
        full_path.write_bytes(fx.transcript.read_bytes())

        # Rewrite steps in DB:
        # idx 0: USER_INPUT status=5 (compacted), repeated field 3 items + field 9 attachment
        # idx 1: PLANNER_RESPONSE status=5 (compacted)
        # idx 2: CHECKPOINT (step_type=23)
        # idx 3 & 4: Turn 1 normal DONE (status=3)
        fx.db.execute("DELETE FROM steps")
        fx.db.execute("DELETE FROM executor_metadata")
        fx.db.execute("DELETE FROM gen_metadata")
        start = native.message((1, native.SECONDS), (2, 0))
        lc_u = native.message((1, native.message((1, 3), (2, start))))
        lc_p = native.message((1, native.message((1, 8), (2, start))), (1, native.message((1, 3), (2, start))))

        # Step 0 (compacted status=5) with repeated field 3 + attachment field 9 + slash command
        o0 = native.message((1, native.TRAJECTORY), (2, 0), (3, 0), (4, native.SESSION))
        m0 = native.message((1, start), (3, 4), (12, native.FIRST), (20, o0), (26, lc_u))
        pub0 = native.message(
            (2, "请生成架构图\n第二行内容"),
            (3, native.message((1, "请生成架构图"))),
            (3, native.message((1, "\n第二行内容"))),
            (9, native.message((1, "/tmp/chart.png"))),
            (18, native.desktop_spec()),
        )
        p0 = native.message((1, 14), (4, 5), (5, m0), (19, pub0))
        fx.db.execute("INSERT INTO steps VALUES(0, 14, 5, 0, ?, ?, 0)", (m0, p0))

        # Step 1 (compacted status=5)
        o1 = native.message((1, native.TRAJECTORY), (2, 1), (3, 0), (4, native.SESSION))
        m1 = native.message((1, start), (3, 2), (6, start), (7, start), (8, start),
                            (12, native.FIRST), (20, o1), (26, lc_p))
        pub1 = native.message((1, "Visible Gemini answer 0"), (3, "hidden"), (8, "Visible Gemini answer 0"))
        p1 = native.message((1, 15), (4, 5), (5, m1), (20, pub1))
        fx.db.execute("INSERT INTO steps VALUES(1, 15, 5, 0, ?, ?, 0)", (m1, p1))

        # Step 2 (CHECKPOINT type=23)
        o2 = native.message((1, native.TRAJECTORY), (2, 2), (3, 0), (4, native.SESSION))
        m2 = native.message((1, start), (3, 3), (12, native.FIRST), (20, o2), (26, lc_u))
        p2 = native.message((1, 23), (4, 3), (5, m2))
        fx.db.execute("INSERT INTO steps VALUES(2, 23, 3, 0, ?, ?, 0)", (m2, p2))

        # Steps 3 & 4 (Turn 1)
        o3 = native.message((1, native.TRAJECTORY), (2, 3), (3, 1), (4, native.SESSION))
        m3 = native.message((1, start), (3, 4), (12, native.SECOND), (20, o3), (26, lc_u))
        pub3 = native.message((2, "问题 1"), (3, native.message((1, "问题 1"))), (18, native.desktop_spec()))
        p3 = native.message((1, 14), (4, 3), (5, m3), (19, pub3))
        fx.db.execute("INSERT INTO steps VALUES(3, 14, 3, 0, ?, ?, 0)", (m3, p3))

        o4 = native.message((1, native.TRAJECTORY), (2, 4), (3, 1), (4, native.SESSION))
        m4 = native.message((1, start), (3, 2), (6, start), (7, start), (8, start),
                            (12, native.SECOND), (20, o4), (26, lc_p))
        pub4 = native.message((1, "Visible Gemini answer 1"), (3, "hidden"), (8, "Visible Gemini answer 1"))
        p4 = native.message((1, 15), (4, 3), (5, m4), (20, pub4))
        fx.db.execute("INSERT INTO steps VALUES(4, 15, 3, 0, ?, ?, 0)", (m4, p4))

        fx.db.execute("INSERT INTO executor_metadata VALUES(0, ?)", (fx.executor(native.FIRST, 2),))
        fx.db.execute("INSERT INTO executor_metadata VALUES(1, ?)", (fx.executor(native.SECOND, 4),))
        # Post-checkpoint gen_metadata: idx 0 retains turn 0 generation (step 1), idx 1 retains turn 1 (step 4)
        # while turn 0 prompt was compacted out of turn 1's chat prompt window by the CHECKPOINT at step 2!
        wrapped1 = "<USER_REQUEST>\n问题 1\n</USER_REQUEST>\n<ADDITIONAL_METADATA>host</ADDITIONAL_METADATA>"
        fx.db.execute("INSERT INTO gen_metadata VALUES(0, ?)", (fx.invocation(native.FIRST, 1, wrapped0, 0),))
        fx.db.execute("INSERT INTO gen_metadata VALUES(1, ?)", (fx.invocation(native.SECOND, 4, wrapped1, 3),))
        fx.db.commit()
        fx.index.execute("UPDATE conversation_summaries SET step_count=5 WHERE conversation_id=?", (native.SESSION,))
        fx.index.commit()
        fx.thread = fx.reader.describe(native.SESSION)

        assessment, proj = capture(fx.reader, fx.thread)
        self.assertEqual(assessment.state, "workspace_verified")
        self.assertIn("compacted_steps_from_transcript", proj.warnings)
        self.assertEqual([(m.role, m.text, m.turn_id) for m in proj.messages], [
            ("user", user0_full, "turn:0"),
            ("assistant", "Visible Gemini answer 0", "turn:0"),
            ("user", "问题 1", "turn:3"),
            ("assistant", "Visible Gemini answer 1", "turn:3"),
        ])

        # NEGATIVE: tamper transcript_full.jsonl on step 0 -> MUST fail closed (never swallow disagreement)!
        tampered_logs = [dict(row) for row in fx.logs]
        tampered_logs[0]["content"] = "<USER_REQUEST>\nFORGED TEXT\n</USER_REQUEST>"
        full_path.write_bytes(b"".join(json.dumps(r, ensure_ascii=False).encode() + b"\n" for r in tampered_logs))
        self.assertEqual(fx.reader.inspect_native(fx.thread).state, "unverified")

    def test_active_running_thread_and_killed_top_level_rejection(self):
        fx = self._fixture()
        fx.index.execute(
            "UPDATE conversation_summaries SET status='CASCADE_RUN_STATUS_RUNNING', not_fully_idle=1 WHERE conversation_id=?",
            (native.SESSION,),
        )
        fx.index.commit()
        fx.thread = fx.reader.describe(native.SESSION)
        assessment, proj = capture(fx.reader, fx.thread)
        self.assertEqual(assessment.state, "workspace_verified")
        self.assertIn("thread_in_progress", proj.warnings)
        self.assertEqual(len(proj.messages), 4)

        # NEGATIVE: top-level killed=1 MUST STILL be rejected!
        fx.index.execute(
            "UPDATE conversation_summaries SET status='CASCADE_RUN_STATUS_IDLE', not_fully_idle=0, killed=1 WHERE conversation_id=?",
            (native.SESSION,),
        )
        fx.index.commit()
        self.assertEqual(fx.reader.inspect_native(fx.thread).state, "unverified")

    def test_child_subagent_containment_positive_and_negative_matrix(self):
        fx = self._fixture()
        root = Path(fx.db_path).parents[1]
        # Register a same-project killed=1 research child with benign empty planner.42.15=''
        benign_cfg = native.message((1, native.message((42, native.message((15, ""))))))
        _write_child_db(root, CHILD_ID, CHILD_TRAJ, fx.project.as_uri(), killed=1, planner_config=benign_cfg)
        fx.index.execute(
            "INSERT INTO conversation_summaries VALUES(?,?,?,?,?,1,?,2,0,1,'CASCADE_RUN_STATUS_IDLE')",
            (CHILD_ID, "Child Research", native.TIME, json.dumps([fx.project.as_uri()]), native.SESSION, native.PROJECT),
        )
        fx.index.execute("INSERT INTO conversation_parents VALUES(?, ?)", (CHILD_ID, native.SESSION))
        fx.index.commit()

        # Positive: verified same-project killed child passes!
        assessment, proj = capture(fx.reader, fx.thread)
        self.assertEqual(assessment.state, "workspace_verified")
        self.assertIn(CHILD_ID, proj.related_threads)

        # Negative 1: excluded_related (explicitly denied child) -> MUST reject!
        with self.assertRaises(Exception):
            capture(fx.reader, fx.thread, excluded_related={CHILD_ID})

        # Negative 2: child with workspace override planner.42.11 -> MUST reject!
        bad_cfg = native.message((1, native.message((42, native.message((11, "/outside/secret"))))))
        _write_child_db(root, CHILD_ID, CHILD_TRAJ, fx.project.as_uri(), planner_config=bad_cfg)
        self.assertEqual(fx.reader.inspect_native(fx.thread).state, "unverified")

        # Negative 3: child with discovery override planner.57.6 -> MUST reject!
        bad_disc = native.message((1, native.message((57, native.message((6, "/outside/override"))))))
        _write_child_db(root, CHILD_ID, CHILD_TRAJ, fx.project.as_uri(), planner_config=bad_disc)
        self.assertEqual(fx.reader.inspect_native(fx.thread).state, "unverified")

        # Negative 4: child with external USER_INPUT -> MUST reject!
        _write_child_db(root, CHILD_ID, CHILD_TRAJ, fx.project.as_uri(), extra_user_step=True)
        self.assertEqual(fx.reader.inspect_native(fx.thread).state, "unverified")

        # Negative 5: child with fork field 16 -> MUST reject!
        _write_child_db(root, CHILD_ID, CHILD_TRAJ, fx.project.as_uri(), fork_field_16=True)
        self.assertEqual(fx.reader.inspect_native(fx.thread).state, "unverified")

        # Negative 6: cross-project child workspace URI -> MUST reject!
        other_uri = (fx.project.parent / "other-project").as_uri()
        _write_child_db(root, CHILD_ID, CHILD_TRAJ, other_uri)
        self.assertEqual(fx.reader.inspect_native(fx.thread).state, "unverified")

    def test_parent_dynamic_workspace_override_and_missing_idle_executor_rejected(self):
        fx = self._fixture()
        # Negative 1: parent dynamic workspace override in executor_metadata.10 (planner.42.11)
        bad_cfg = native.message((42, native.message((11, "/etc"))))
        fx.db.execute("UPDATE executor_metadata SET data=? WHERE idx=0", (fx.executor(native.FIRST, 1, config=bad_cfg),))
        fx.db.commit()
        self.assertEqual(fx.reader.inspect_native(fx.thread).state, "unverified")

        # Negative 2: IDLE thread with deleted executor_metadata row -> MUST fail closed!
        fx2 = self._fixture()
        fx2.db.execute("DELETE FROM executor_metadata WHERE idx=1")
        fx2.db.commit()
        self.assertEqual(fx2.reader.inspect_native(fx2.thread).state, "unverified")

    def test_path_migration_skips_children_of_migrated_parent_and_flags_orphans(self):
        fx = self._fixture()
        root = Path(fx.db_path).parents[1]
        old_root = fx.project.parent / "former-moved-root"
        old_uri = old_root.as_uri()
        # Rewrite top-level session & child to point to absent old_root, plus an orphan child with unknown parent!
        fx.index.execute("UPDATE conversation_summaries SET workspace_uris=? WHERE conversation_id=?",
                         (json.dumps([old_uri]), native.SESSION))
        fx.db.execute("UPDATE trajectory_metadata_blob SET data=? WHERE id='main'", (fx.header(roots=[old_uri]),))
        fx.db.commit()
        _write_child_db(root, CHILD_ID, CHILD_TRAJ, old_uri)
        fx.index.execute(
            "INSERT INTO conversation_summaries VALUES(?,?,?,?,?,1,?,2,0,0,'CASCADE_RUN_STATUS_IDLE')",
            (CHILD_ID, "Child Of Migrated Parent", native.TIME, json.dumps([old_uri]), native.SESSION, native.PROJECT),
        )
        fx.index.execute("INSERT INTO conversation_parents VALUES(?, ?)", (CHILD_ID, native.SESSION))
        orphan_id = str(uuid.UUID(int=202))
        fx.index.execute(
            "INSERT INTO conversation_summaries VALUES(?,?,?,?,?,1,?,2,0,0,'CASCADE_RUN_STATUS_IDLE')",
            (orphan_id, "Orphan Child", native.TIME, json.dumps([old_uri]), str(uuid.UUID(int=999)), native.PROJECT),
        )
        fx.index.commit()

        doc = {
            "version": 2,
            "projects": [{
                "id": "migrated",
                "name": "Migrated Project",
                "root": str(fx.project),
                "directory_identity": persistent_identity(fx.project),
            }],
            "sources": {
                "antigravity": {
                    "adapter": "antigravity",
                    "root": str(root),
                    "root_identity": persistent_identity(root),
                    "format": "2.33.0",
                    "enabled": True,
                    "instance_id": "antigravity",
                    "denied_threads": [],
                    "exceptions": {},
                    "path_aliases": [{
                        "project_id": "migrated",
                        "source_instance": "antigravity",
                        "native_project_id": native.PROJECT,
                        "old_root": str(old_root),
                        "target_root": str(fx.project),
                        "target_identity": persistent_identity(fx.project),
                    }],
                },
            },
            "legacy_history": None,
        }
        updated, report = reviewed_document(doc, "antigravity", str(old_root), "2026-01-02T00:00:00+00:00")
        self.assertEqual(report["proposed"], [native.SESSION])
        # Child of migrated parent is skipped cleanly; orphan child stays in pending!
        pending_ids = [item["native_id"] for item in report["pending"]]
        self.assertNotIn(CHILD_ID, pending_ids)
        self.assertIn(orphan_id, pending_ids)
        self.assertIn(native.SESSION, updated["sources"]["antigravity"]["exceptions"])


if __name__ == "__main__":
    unittest.main()
