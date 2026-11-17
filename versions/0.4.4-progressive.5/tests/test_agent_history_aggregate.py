"""Aggregate history task isolation, delivery checks and stable pagination."""

import hashlib
import json
from types import SimpleNamespace
import unittest

from peters_mcp.agent_history import AgentHistoryCore
from peters_mcp.agent_history_aggregate import AggregateFind
from peters_mcp.catalog import AccessError


_ACTOR = {"actor": "a" * 64, "policy_actor": "local"}
_OTHER = {"actor": "b" * 64, "policy_actor": "local"}


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def hit(source, native, updated_at, *, logical_id=None, primary=True):
    return {"summary": {"source_id": source, "agent": "deepseek_harness", "surface": "local",
                       "stable_thread_id": digest(source + native), "title": native, "updated_at": updated_at,
                       "project_id": "fixture", "thread_ref": "thread-ref-" + native,
                       "source_adapter": source, "match": {"in": "project"}},
            "canonical": digest(native if logical_id is None else logical_id), "primary": primary,
            "vouchers": [[source, native, digest(native + ":proof")]]}


def scan(source, *rows):
    return {"status": "ready", "rows": list(rows),
            "coverage": {"source_id": source, "warnings": [], "coverage_complete": True}}


class FixtureCore(AgentHistoryCore):
    def __init__(self, routes):
        super().__init__(None, None, None, b"aggregate-fixture-token-key")
        self.routes = routes
        self.policy_revision = 0

    def _configuration(self, project, actor, policy_actor):
        return SimpleNamespace(key=digest(str((project, actor, policy_actor, self.policy_revision))))

    def _sources(self, scope, source_id, agent):
        return self.routes


class AggregateFindTests(unittest.TestCase):
    def _ready(self, broker, cursor="", *, query="", limit=10, actor=_ACTOR):
        for _ in range(40):
            page = broker.find("fixture", query, "", cursor, limit, actor)
            if page["status"] != "processing":
                return page
            self.assertNotIn("threads", page)
            cursor = page["next_cursor"]
        self.fail("The aggregate search exceeded its bounded continuation.")

    def test_hung_source_is_bounded_and_healthy_sources_are_deduplicated(self):
        calls, validated = [], set()
        native = hit("deepseek", "native", "2026-10-10T00:00:00+00:00")
        alias = hit("codeg", "alias", "2026-10-11T00:00:00+00:00", logical_id="native", primary=False)

        def runner(source, operation, cursor, arguments):
            calls.append((source, operation, cursor))
            if operation == "validate_agent_hits":
                validated.update(tuple(item) for item in json.loads(arguments["vouchers"]))
                return {"status": "ready"}
            if source == "hung":
                return {"status": "processing", "next_cursor": "source-private-cursor"}
            return scan(source, native if source == "deepseek" else alias)

        broker = AggregateFind(FixtureCore(("hung", "deepseek", "codeg")), runner)
        page = self._ready(broker)
        self.assertEqual(page["status"], "ready")
        self.assertFalse(page["coverage_complete"])
        first, = page["threads"]
        self.assertEqual(first["title"], "native")
        self.assertEqual(first["matched_sources"], ["codeg", "deepseek"])
        self.assertNotIn("vouchers", first)
        self.assertNotIn("canonical", first)
        self.assertEqual(validated, {tuple(native["vouchers"][0]), tuple(alias["vouchers"][0])})
        self.assertEqual([item[0] for item in calls[:3]], ["hung", "deepseek", "codeg"])
        attempts = [cursor for source, _, cursor in calls if source == "hung"]
        self.assertEqual(attempts[0], "")
        self.assertTrue(attempts[1:])
        self.assertTrue(all(cursor == "source-private-cursor" for cursor in attempts[1:]))
        self.assertEqual(page["coverage"][0]["warnings"], ["processing_timeout"])

    def test_exhausted_pending_sources_release_slots_for_third_source(self):
        stalled = {"first", "second"}
        held = set()
        abandoned = set()

        def runner(source, operation, cursor, arguments):
            if operation == "validate_agent_hits":
                return {"status": "ready"}
            if source in stalled:
                held.add(source)
                return {"status": "waiting_source_stable", "next_cursor": source + "-pending"}
            if len(held) == 2:
                return {"status": "busy"}
            return scan(source, hit(source, "healthy body", ""))

        def abandon(source, cursor):
            self.assertEqual(cursor, source + "-pending")
            held.remove(source)
            abandoned.add(source)

        broker = AggregateFind(FixtureCore(("first", "second", "third")), runner, abandon)
        page = self._ready(broker)
        self.assertEqual(abandoned, stalled)
        self.assertEqual([row["title"] for row in page["threads"]], ["healthy body"])
        self.assertFalse(page["coverage_complete"])

    def test_failed_validation_rebuilds_first_page_without_stale_hits(self):
        validated = []
        stale = hit("broken", "stale", "2026-10-11T00:00:00+00:00")
        healthy = hit("healthy", "healthy", "2026-10-10T00:00:00+00:00")

        def runner(source, operation, cursor, arguments):
            if operation == "scan_agent_source":
                return scan(source, stale if source == "broken" else healthy)
            if source == "broken":
                raise TimeoutError()
            validated.append(json.loads(arguments["vouchers"]))
            return {"status": "ready"}

        broker = AggregateFind(FixtureCore(("broken", "healthy")), runner)
        page = self._ready(broker, limit=1)
        self.assertEqual([row["title"] for row in page["threads"]], ["healthy"])
        self.assertEqual(validated, [healthy["vouchers"]])
        self.assertEqual(page["coverage"][0]["warnings"], ["processing_timeout"])
        self.assertFalse(page["has_more"])

    def test_cursor_cannot_cross_actor_or_binding_and_pages_are_revalidated(self):
        native = hit("native", "newest", "2026-10-12T00:00:00+00:00")
        older = hit("native", "older", "2026-10-11T00:00:00+00:00")
        validated = []

        def runner(source, operation, cursor, arguments):
            if operation == "scan_agent_source":
                return scan(source, older, native)
            validated.append(json.loads(arguments["vouchers"]))
            return {"status": "ready"}

        core = FixtureCore(("native",))
        broker = AggregateFind(core, runner)
        pending = broker.find("fixture", "", "", "", 1, _ACTOR)
        cursor = pending["next_cursor"]
        with self.assertRaises(AccessError) as wrong_actor:
            self._ready(broker, cursor, limit=1, actor=_OTHER)
        self.assertEqual(wrong_actor.exception.code, "restart_required")
        with self.assertRaises(AccessError) as wrong_request:
            self._ready(broker, cursor, limit=1, query="different")
        self.assertEqual(wrong_request.exception.code, "invalid_cursor")
        first = self._ready(broker, cursor, limit=1)
        self.assertEqual([row["title"] for row in first["threads"]], ["newest"])
        second = self._ready(broker, first["next_cursor"], limit=1)
        self.assertEqual([row["title"] for row in second["threads"]], ["older"])
        self.assertEqual(validated, [native["vouchers"], older["vouchers"]])
        self.assertFalse(second["has_more"])

    def test_scope_changed_during_validation_blocks_delivery(self):
        core = FixtureCore(("native",))

        def runner(source, operation, cursor, arguments):
            if operation == "scan_agent_source":
                return scan(source, hit(source, "old-authorization", ""))
            core.policy_revision += 1
            return {"status": "ready"}

        with self.assertRaises(AccessError) as revoked:
            self._ready(AggregateFind(core, runner))
        self.assertEqual(revoked.exception.code, "restart_required")

    def test_earlier_source_is_revalidated_after_other_source_continuation(self):
        sources = ("first", "second")
        validated = []
        first_reparented = False

        def runner(source, operation, cursor, arguments):
            if operation == "scan_agent_source":
                return scan(source, hit(source, source, ""))
            validated.append((source, cursor))
            if source == "first" and first_reparented:
                raise AccessError("Thread ownership changed.", code="restart_required")
            if source == "second" and not cursor:
                return {"status": "processing", "next_cursor": "second-validation-cursor"}
            return {"status": "ready"}

        broker = AggregateFind(FixtureCore(sources), runner)
        cursor = ""
        while len(validated) < 2:
            pending = broker.find("fixture", "", "", cursor, 10, _ACTOR)
            self.assertEqual(pending["status"], "processing")
            self.assertNotIn("threads", pending)
            cursor = pending["next_cursor"]
        self.assertEqual(validated, [("first", ""), ("second", "")])
        first_reparented = True
        with self.assertRaises(AccessError) as changed:
            broker.find("fixture", "", "", cursor, 10, _ACTOR)
        self.assertEqual(changed.exception.code, "restart_required")
        self.assertEqual(validated[-1], ("first", ""))

    def test_bad_child_result_does_not_hide_healthy_results(self):
        malformed = hit("malformed", "must not render", "")
        malformed["summary"]["match"] = {"in": ["wrong type"]}

        def runner(source, operation, cursor, arguments):
            if operation == "validate_agent_hits":
                return {"status": "ready"}
            return scan(source, malformed if source == "malformed" else hit(source, "public", ""))

        broker = AggregateFind(FixtureCore(("malformed", "native")), runner)
        page = self._ready(broker)
        self.assertEqual([row["title"] for row in page["threads"]], ["public"])
        self.assertEqual(page["coverage"][0]["warnings"], ["history_processing_failed"])

    def test_invalid_search_fails_before_workers_and_empty_sources_are_explicit(self):
        def runner(*args):
            self.fail("No worker should be called")

        broker = AggregateFind(FixtureCore(()), runner)
        with self.assertRaises(AccessError) as malformed:
            broker.find("fixture", "term", "invalid filter", "", 3, _ACTOR)
        self.assertEqual(malformed.exception.code, "invalid_arguments")
        page = self._ready(broker)
        self.assertEqual(page["status"], "no_enabled_sources")
        self.assertFalse(page["coverage_complete"])
