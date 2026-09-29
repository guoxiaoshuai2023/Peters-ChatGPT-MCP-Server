"""Projection compatibility, privacy and adversarial work bounds."""
import json
import subprocess
import sys
import unittest
from unittest.mock import patch

from peters_mcp.catalog import AccessError
from peters_mcp.history_projection import ProjectionBuilder, project_rollout, sanitize

THREAD = "11111111-1111-4111-8111-111111111111"


def record(kind, payload):
    return {"type": kind, "payload": payload, "timestamp": "2026-01-01T00:00:00Z"}


def message(text, native="same", turn=None, event=False):
    if event:
        return record("event_msg", {"type": "item_completed", "turn_id": turn,
                      "item": {"type": "UserMessage", "id": native, "content": text}})
    return record("response_item", {"type": "message", "role": "user", "id": native, "content": text})


def builder():
    value = ProjectionBuilder(THREAD)
    value.add_record(record("session_meta", {"id": THREAD}), 1)
    return value


class ProjectionStreamTests(unittest.TestCase):
    def test_disabled_tool_refs_do_not_consume_public_item_budget(self):
        value = ProjectionBuilder(THREAD, max_items=1, include_tool_refs=False)
        value.add_record(record('session_meta', {'id': THREAD}), 1)
        value.add_record(message('one public message'), 2)
        for number in range(3, 100):
            value.add_record(record('event_msg', {'type':'item_completed', 'item':{
                'type':'CommandExecution','stdout':'private tool payload'}}), number)
        result=value.finish()
        self.assertEqual(len(result['messages']),1)
        self.assertEqual(result['tools'],{})

    def test_empty_latest_declared_turn_is_preserved(self):
        value = builder()
        value.add_record(record("turn_context", {"turn_id": "completed"}), 2)
        value.add_record(message("older public text"), 3)
        value.add_record(record("event_msg", {"type": "task_started", "turn_id": "pending"}), 4)
        # A late mirror of the previous turn must not rewind the new boundary.
        value.add_record(message("older public text", turn="completed", event=True), 5)
        result = value.finish()
        self.assertEqual(result["turn_ids"], ["completed", "pending"])
        self.assertEqual(result["latest_turn_id"], "pending")
        self.assertEqual(result["ambiguous_turn_ids"], [])
        self.assertEqual(result["last_recorded_status"], "recorded_in_progress")
        self.assertFalse(any(item["turn_id"] == "pending" for item in result["messages"]))

    def test_missing_turn_id_does_not_invent_a_turn(self):
        value = builder()
        value.add_record(record("event_msg", {"type": "task_started"}), 2)
        value.add_record(record("turn_context", {"turn_id": ""}), 3)
        value.add_record(message("no reliable turn"), 4)
        result = value.finish()
        self.assertEqual(result["turn_ids"], [])
        self.assertIsNone(result["latest_turn_id"])
        self.assertEqual(result["ambiguous_turn_ids"], [])

    def test_repeated_context_for_active_turn_is_not_ambiguous(self):
        value = builder()
        value.add_record(record("event_msg", {"type": "task_started", "turn_id": "active"}), 2)
        value.add_record(record("turn_context", {"turn_id": "active"}), 3)
        value.add_record(message("public"), 4)
        value.add_record(record("turn_context", {"turn_id": "active"}), 5)
        result = value.finish()
        self.assertEqual(result["turn_ids"], ["active"])
        self.assertEqual(result["latest_turn_id"], "active")
        self.assertEqual(result["ambiguous_turn_ids"], [])
        self.assertEqual(result["warnings"], {})

    def test_noncontinuous_declared_reuse_is_ambiguous(self):
        value = builder()
        for number, turn in enumerate(("first", "second", "first"), 2):
            value.add_record(record("turn_context", {"turn_id": turn}), number)
        result = value.finish()
        self.assertEqual(result["turn_ids"], ["first", "second"])
        self.assertEqual(result["latest_turn_id"], "first")
        self.assertEqual(result["ambiguous_turn_ids"], ["first"])

    def test_fork_metadata_segment_reuse_is_ambiguous(self):
        parent = "22222222-2222-4222-8222-222222222222"
        value = ProjectionBuilder(THREAD)
        value.add_record(record("session_meta", {"id": THREAD, "forked_from_id": parent}), 1)
        value.add_record(record("turn_context", {"turn_id": "reused"}), 2)
        value.add_record(message("child public"), 3)
        value.add_record(record("session_meta", {"id": parent}), 4)
        value.add_record(record("turn_context", {"turn_id": "reused"}), 5)
        value.add_record(message("inherited public"), 6)
        result = value.finish()
        self.assertEqual(result["turn_ids"], ["reused"])
        self.assertEqual(result["ambiguous_turn_ids"], ["reused"])
        self.assertEqual([item["turn_id"] for item in result["messages"]], ["reused", "reused"])
        self.assertEqual(result["warnings"], {})

    def test_explicit_item_ids_supply_fallback_without_declared_boundaries(self):
        value = builder()
        value.add_record(message("first", turn="one", event=True), 2)
        value.add_record(message("second", turn="two", event=True), 3)
        result = value.finish()
        self.assertEqual(result["turn_ids"], ["one", "two"])
        self.assertEqual(result["latest_turn_id"], "two")
        self.assertEqual(result["ambiguous_turn_ids"], [])

    def test_turn_index_shares_item_budget(self):
        value = ProjectionBuilder(THREAD, max_items=2)
        value.add_record(record("session_meta", {"id": THREAD}), 1)
        value.add_record(record("turn_context", {"turn_id": "one"}), 2)
        value.add_record(record("turn_context", {"turn_id": "two"}), 3)
        with self.assertRaises(AccessError) as raised:
            value.add_record(record("turn_context", {"turn_id": "three"}), 4)
        self.assertEqual(raised.exception.code, "resource_exhausted")
        with self.assertRaises(AccessError):
            value.finish()

    def test_stream_matches_legacy_and_does_not_retain_tool_payload(self):
        records = [record("session_meta", {"id": THREAD}),
                   record("turn_context", {"turn_id": "first"}),
                   message("原文 🌍\nline two"), message("原文 🌍\nline two", turn="first", event=True),
                   record("event_msg", {"type": "item_completed", "item": {
                       "type": "CommandExecution", "stdout": "PRIVATE_TOOL_BODY", "command": "synthetic"}}),
                   record("compacted", {}),
                   record("event_msg", {"type": "item_completed", "item": {"type": "CollabAgentToolCall"}}),
                   record("event_msg", {"type": "item_completed", "item": {"type": "ContextCompaction"}})]
        value = ProjectionBuilder(THREAD)
        raw, offset = b"", 0
        for line, item in enumerate(records, 1):
            encoded = (json.dumps(item, ensure_ascii=False) + "\n").encode()
            value.add_record(item, line, offset, len(encoded))
            offset += len(encoded)
            raw += encoded
        projected = value.finish()
        self.assertNotIn("PRIVATE_TOOL_BODY", json.dumps(projected))
        self.assertGreater(projected["tools"][5]["_offset"], 0)
        self.assertGreater(projected["tools"][5]["_length"], 0)
        for tool in projected["tools"].values():
            tool.pop("_offset")
            tool.pop("_length")
        expected = project_rollout(raw, THREAD)
        for tool in expected["tools"].values():
            tool.pop("_item")
        self.assertEqual(projected, expected)
        self.assertEqual(projected["warnings"]["unknown_event_item_excluded"], 2)

    def test_mirrors_are_one_to_one_and_real_repetition_survives(self):
        value = builder()
        for number in range(2, 5):
            value.add_record(message("repeat"), number)
        for number in range(5, 7):
            value.add_record(message("repeat", event=True), number)
        result = value.finish()
        self.assertEqual([m["source_line"] for m in result["messages"]], [2, 3, 4])
        self.assertEqual(result["mirrored_messages_deduplicated"], 2)

    def test_native_id_turn_wildcards_and_literal_all_turn_do_not_collide(self):
        value = builder()
        value.add_record(record("turn_context", {"turn_id": "other"}), 2)
        value.add_record(message("same"), 3)
        value.add_record(record("turn_context", {"turn_id": "all"}), 4)
        value.add_record(message("same"), 5)
        value.add_record(message("same", turn="all", event=True), 6)
        value.add_record(record("turn_context", {"turn_id": ""}), 7)
        value.add_record(message("empty turn"), 8)
        value.add_record(message("empty turn", turn="specified", event=True), 9)
        result = value.finish()
        self.assertEqual(result["mirrored_messages_deduplicated"], 2)
        self.assertEqual([m["source_line"] for m in result["messages"]], [3, 5, 8])
        self.assertEqual(result["messages"][-1]["turn_id"], "specified")

    def test_conflict_warning_respects_consumed_candidates_and_turn(self):
        value = builder()
        value.add_record(record("turn_context", {"turn_id": "first"}), 2)
        value.add_record(message("original"), 3)
        value.add_record(message("different turn", turn="other", event=True), 4)
        value.add_record(message("conflict", turn="first", event=True), 5)
        value.add_record(message("original", turn="first", event=True), 6)
        value.add_record(message("after consumed", turn="first", event=True), 7)
        result = value.finish()
        self.assertEqual(result["warnings"]["mirrored_message_text_disagrees"], 1)
        self.assertEqual([m["text"] for m in result["messages"]],
                         ["original", "different turn", "conflict", "after consumed"])

    def test_digest_collision_does_not_delete_distinct_text(self):
        value = builder()
        value.add_record(message("alpha"), 2)
        value.add_record(message("bravo"), 3)
        value.add_record(message("bravo", event=True), 4)
        value.add_record(message("alpha", event=True), 5)
        value.add_record(message("delta", event=True), 6)
        with patch("peters_mcp.history_projection.hashlib.sha256") as digest:
            digest.return_value.digest.return_value = b"same digest"
            result = value.finish()
        self.assertEqual(result["mirrored_messages_deduplicated"], 2)
        self.assertEqual([m["text"] for m in result["messages"]], ["alpha", "bravo", "delta"])

    def test_concentrated_conflicting_id_does_not_compare_every_pair(self):
        class Counted(str):
            comparisons = 0
            __hash__ = str.__hash__

            def __eq__(self, other):
                Counted.comparisons += 1
                return super().__eq__(other)

        value = builder()
        count = 1000
        for index in range(count):
            value.add_record(message("original-" + str(index)), index + 2)
            value.add_record(message("conflict-" + str(index), event=True), count + index + 2)
        for item in value.messages + value.events:
            item["text"] = Counted(item["text"])
        result = value.finish()
        self.assertEqual(len(result["messages"]), 2 * count)
        self.assertEqual(result["warnings"]["mirrored_message_text_disagrees"], count)
        self.assertLess(Counted.comparisons, count * 4)

    def test_character_budget_is_charged_before_mirror_deduplication(self):
        value = builder()
        with patch("peters_mcp.history_projection.MAX_PUBLIC_CHARS", 6):
            value.add_record(message("four"), 2)
            with self.assertRaises(AccessError) as raised:
                value.add_record(message("four", event=True), 3)
        self.assertEqual(raised.exception.code, "projection_limit_exceeded")
        with self.assertRaises(AccessError):
            value.finish()

    def test_item_budget_counts_tool_references_and_both_mirrors(self):
        value = ProjectionBuilder(THREAD, max_items=2)
        value.add_record(record("session_meta", {"id": THREAD}), 1)
        value.add_record(message("same"), 2)
        value.add_record(message("same", event=True), 3)
        with self.assertRaises(AccessError) as raised:
            value.add_record(record("event_msg", {"type": "item_completed", "item": {
                "type": "CommandExecution", "stdout": "not retained"}}), 4)
        self.assertEqual(raised.exception.code, "resource_exhausted")
        with self.assertRaises(AccessError):
            value.finish()

    def test_internal_wrapper_filtering_preserves_complete_and_unfinished_semantics(self):
        cases = {
            "a<SYSTEM mode='x'>hidden</system>b": "a[OMITTED: internal context]b",
            "a<system>hidden": "a[OMITTED: internal context]",
            "a<system><system>hidden</system>b": "a[OMITTED: internal context]b",
            "a<systemish>ordinary</systemish>": "a<systemish>ordinary</systemish>",
            "a<system missing": "a<system missing",
            "<system>a</system>x<system>b": "[OMITTED: internal context]x[OMITTED: internal context]",
        }
        for original, expected in cases.items():
            with self.subTest(original=original):
                self.assertEqual(sanitize(original)[0], expected)

    def test_repeated_unclosed_wrappers_complete_under_external_timeout(self):
        # Run out of process so a regression cannot hang the test runner.
        code = (
            "from peters_mcp.history_projection import sanitize; "
            "value, count = sanitize('<system>' * 32000); "
            "assert value == '[OMITTED: internal context]' and count == 1; "
            "value, count = sanitize('<system ' * 32000); "
            "assert count == 0"
        )
        subprocess.run([sys.executable, "-B", "-c", code], check=True, timeout=3,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_malformed_shapes_fail_closed_without_unhashable_type_crash(self):
        value = builder()
        malformed = [None, [], record([], {}), record("response_item", {"type": []}),
                     record("event_msg", {"type": "item_completed", "item": {"type": []}}),
                     record("response_item", {"type": "message", "role": [], "content": "hidden"}),
                     record("response_item", {"type": "message", "role": "user", "content": [
                         {"type": [], "text": "hidden"}]})]
        for number, item in enumerate(malformed, 2):
            value.add_record(item, number)
        result = value.finish()
        self.assertNotIn("hidden", json.dumps(result))
        self.assertFalse(result["complete_public_projection"])

    def test_deep_json_and_partial_tail_have_explicit_warnings(self):
        header = (json.dumps(record("session_meta", {"id": THREAD})) + "\n").encode()
        deep = b'[' * 2000 + b'0' + b']' * 2000 + b'\n'
        result = project_rollout(header + deep + b'{"unfinished":', THREAD)
        self.assertEqual(result["source_lines"], 2)
        self.assertEqual(sum(result["warnings"].get(key, 0) for key in
                             ("malformed_record_excluded", "unknown_record_shape")), 1)
        self.assertEqual(result["warnings"]["incomplete_tail_excluded"], 1)

    def test_oversized_legacy_record_does_not_hide_following_valid_record(self):
        header = (json.dumps(record("session_meta", {"id": THREAD})) + "\n").encode()
        tail = (json.dumps(message("valid after large record")) + "\n").encode()
        result = project_rollout(header + b' ' * (8 * 1024 * 1024) + b'0\n' + tail, THREAD)
        self.assertEqual(result["warnings"]["oversized_record_excluded"], 1)
        self.assertEqual([m["text"] for m in result["messages"]], ["valid after large record"])
        self.assertEqual(result["source_lines"], 3)


if __name__ == "__main__":
    unittest.main()
