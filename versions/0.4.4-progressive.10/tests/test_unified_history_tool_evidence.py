"""Tool output grants never establish project ownership in unified history."""

from copy import deepcopy
from pathlib import Path
import sqlite3
import unittest

from tests import test_unified_history_delivery as delivery
from tests.test_history import encode, message, record


_OUTSIDE = "a1234567-1234-4234-8234-123456789abc"
_TOOL_TEXT = "verified synthetic command output"
_OUTSIDE_TEXT = "unshared synthetic command output"


def _tool(output):
    return record("event_msg", {"type": "item_completed", "turn_id": "synthetic-turn", "item": {
        "type": "CommandExecution", "id": "synthetic-command", "command": "python -m unittest",
        "status": "completed", "exit_code": 0, "stdout": output, "stderr": ""}})


class UnifiedToolEvidenceTests(unittest.TestCase):
    setUp = delivery.UnifiedDeliveryTests.setUp
    call = delivery.UnifiedDeliveryTests.call
    complete = delivery.UnifiedDeliveryTests.complete

    def _prepare_evidence(self):
        home = Path(self.document["legacy_history"]["codex_home"])
        original = home / "sessions" / f"rollout-synthetic-{delivery.THREAD}.jsonl"
        with original.open("ab") as stream:
            stream.write(encode([_tool(_TOOL_TEXT)]))
        outside = home.parent / "outside"
        outside.mkdir()
        foreign = home / "sessions" / f"rollout-synthetic-{_OUTSIDE}.jsonl"
        foreign.write_bytes(encode([record("session_meta", {"id": _OUTSIDE, "cwd": str(outside)}),
                                   message("unshared prompt"), _tool(_OUTSIDE_TEXT)]))
        with sqlite3.connect(home / "state_5.sqlite") as connection:
            connection.execute("INSERT INTO threads VALUES (?,?,?,?,?,?)",
                               (_OUTSIDE, str(foreign), str(outside), "Foreign thread", 200, 0))
        self.document["legacy_history"]["tool_evidence"] = [
            {"id": native, "allow_tool_results": True, "mcp_tools": []}
            for native in (delivery.THREAD, _OUTSIDE)]
        self.epoch = self.store.activate(self.document, expected_digest=self.epoch)

    def test_evidence_grant_preserves_verified_body_and_cannot_grant_foreign_thread(self):
        self._prepare_evidence()
        error, page = self.complete("read_codex_thread", {"thread_id": delivery.THREAD, "include_tool_refs": True})
        self.assertFalse(error, page)
        self.assertIn(delivery.FIRST_TEXT, [entry.get("text") for entry in page["entries"]])
        reference = next(entry for entry in page["entries"] if entry["kind"] == "tool_reference")
        self.assertNotIn(_TOOL_TEXT, str(page))
        error, evidence = self.complete("read_codex_thread_item", {"thread_id": delivery.THREAD,
                                                                   "item_id": reference["item_id"]})
        self.assertFalse(error, evidence)
        self.assertIn(_TOOL_TEXT, evidence["text"])
        error, found = self.complete("find_codex_threads", {})
        self.assertFalse(error, found)
        self.assertEqual([row["thread_id"] for row in found["threads"]], [delivery.THREAD])
        for name, arguments in (
            ("read_codex_thread", {"thread_id": _OUTSIDE, "include_tool_refs": True}),
            ("read_codex_thread_item", {"thread_id": _OUTSIDE, "item_id": reference["item_id"]}),
        ):
            with self.subTest(name=name):
                denied, detail = self.complete(name, arguments)
                self.assertTrue(denied, detail)
                self.assertNotIn(_OUTSIDE_TEXT, str(detail))

    def test_tool_evidence_revocation_invalidates_preexisting_item(self):
        self._prepare_evidence()
        error, page = self.complete("read_codex_thread", {"thread_id": delivery.THREAD, "include_tool_refs": True})
        self.assertFalse(error, page)
        reference = next(entry for entry in page["entries"] if entry["kind"] == "tool_reference")
        updated = deepcopy(self.document)
        updated["legacy_history"]["tool_evidence"] = []
        self.epoch = self.store.activate(updated, expected_digest=self.epoch)
        denied, detail = self.complete("read_codex_thread_item", {"thread_id": delivery.THREAD,
                                                                  "item_id": reference["item_id"]})
        self.assertTrue(denied, detail)
        self.assertNotIn(_TOOL_TEXT, str(detail))
        error, body = self.complete("read_codex_thread", {"thread_id": delivery.THREAD})
        self.assertFalse(error, body)
        self.assertIn(delivery.FIRST_TEXT, [entry.get("text") for entry in body["entries"]])


if __name__ == "__main__":
    unittest.main()
