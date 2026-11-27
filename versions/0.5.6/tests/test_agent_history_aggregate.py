"""Aggregate history task isolation, delivery checks and stable pagination."""

import hashlib
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

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

    def test_admission_wait_has_its_own_deadline(self):
        clock, calls = [0.0], {}

        def runner(source, operation, cursor, arguments):
            if operation == "validate_agent_hits":
                return {"status": "ready"}
            calls[source] = calls.get(source, 0) + 1
            clock[0] += 0.5
            if source == "blocked" or calls[source] <= 8:
                return {"status": "busy"}
            return scan(source, hit(source, source, ""))

        with patch("peters_mcp.agent_history_aggregate.time.monotonic", side_effect=lambda: clock[0]):
            broker = AggregateFind(FixtureCore(("waiting", "blocked")), runner)
            cursor = ""
            for _ in range(70):
                page = broker.find("fixture", "", "", cursor, 10, _ACTOR)
                if page["status"] == "ready":
                    break
                cursor = page["next_cursor"]
            self.assertEqual(page["status"], "ready")
        self.assertEqual([row["title"] for row in page["threads"]], ["waiting"])
        self.assertEqual([row["warnings"] for row in page["coverage"]], [[], ["busy"]])

    def test_queued_sources_inherit_no_wait_from_their_own_admitted_scans(self):
        routes = ("a", "b", "c", "d")
        clock, active = [0.0], {}

        def runner(source, operation, cursor, arguments):
            if operation == "validate_agent_hits":
                return {"status": "ready"}
            if source not in active and len(active) == 2:
                return {"status": "busy"}
            active[source] = active.get(source, 0) + 1
            if source in routes[:2] and active[source] < 6:
                clock[0] += 4
                return {"status": "processing", "next_cursor": source}
            active.pop(source)
            return scan(source, hit(source, source, ""))

        with patch("peters_mcp.agent_history_aggregate.time.monotonic", side_effect=lambda: clock[0]):
            page = self._ready(AggregateFind(FixtureCore(routes), runner))
        self.assertTrue(page["coverage_complete"])
        self.assertEqual({row["title"] for row in page["threads"]}, set(routes))

    def test_indivisible_multi_source_hit_completes_or_reports_its_bound(self):
        routes = ("codeg-a", "codeg-b", "harness")
        for cost, exhausted in ((4.0, False), (10.0, True)):
            with self.subTest(cost=cost):
                clock, steps, owners, released = [0.0], {}, set(), []

                def runner(source, operation, cursor, arguments):
                    owners.add(arguments["search_key"])
                    row = hit(source, source, "2", logical_id="shared", primary=source == "harness")
                    if operation == "scan_agent_source":
                        return scan(source, row, hit(source, "next", "1")) if source == "harness" else scan(source, row)
                    if json.loads(arguments["vouchers"])[0][1] == "next":
                        return {"status": "ready"}
                    steps[source] = steps.get(source, 0) + 1
                    if source != "codeg-a" and steps[source] < 3:
                        clock[0] += cost
                        return {"status": "processing", "next_cursor": source}
                    return {"status": "ready"}

                with patch("peters_mcp.agent_history_aggregate.time.monotonic", side_effect=lambda: clock[0]):
                    broker = AggregateFind(FixtureCore(routes), runner, lambda s, c: released.append((s, c)))
                    first = self._ready(broker, limit=1)
                    self.assertEqual(first["coverage_complete"], not exhausted)
                    if exhausted:
                        self.assertEqual(first["threads"], [])
                        self.assertTrue(all(r["warnings"] == ["resource_exhausted"] for r in first["coverage"]))
                        self.assertEqual(released, [("harness", "harness")])
                    else:
                        row, = first["threads"]
                        self.assertEqual(row["matched_sources"], list(routes))
                    self.assertTrue(first["has_more"])
                    second = self._ready(broker, first["next_cursor"], limit=1)
                self.assertEqual([row["title"] for row in second["threads"]], ["next"])
                self.assertFalse(second["has_more"])
                self.assertEqual(len(owners), 1)

    def test_aborted_and_evicted_searches_release_only_their_own_demands(self):
        owners, releases = [], []

        def runner(source, operation, cursor, arguments):
            owner = arguments["search_key"]
            if source == "first":
                owners.append(owner)
                return {"status": "processing", "next_cursor": owner}
            raise AccessError("Permission was withdrawn.", code="unauthorized")

        broker = AggregateFind(FixtureCore(("first", "revoked")), runner, lambda s, c: releases.append(c))
        first = broker.find("fixture", "", "", "", 10, _ACTOR)
        with self.assertRaises(AccessError):
            broker.find("fixture", "", "", first["next_cursor"], 10, _ACTOR)
        self.assertEqual(releases, owners)
        for _ in range(13):
            broker.find("fixture", "", "", "", 10, _ACTOR)
        self.assertEqual(len(set(owners)), 14)
        self.assertEqual(releases, owners[:2])

    def test_exhausted_indivisible_row_releases_the_last_rotated_cursor(self):
        issued, released = [], []

        def runner(source, operation, cursor, arguments):
            if operation == "scan_agent_source":
                return scan(source, hit(source, "slow", ""))
            issued.append(str(len(issued) + 1))
            return {"status": "processing", "next_cursor": issued[-1]}

        broker = AggregateFind(FixtureCore(("source",)), runner, lambda s, c: released.append(c))
        page = self._ready(broker)
        self.assertFalse(page["coverage_complete"])
        self.assertEqual(page["threads"], [])
        self.assertEqual(released, [issued[-1]])

    def test_slow_merged_row_on_later_page_keeps_next_page_reachable(self):
        routes = ("a", "b", "c", "d")
        for tail_cost, omitted in ((0, False), (16, True)):
            with self.subTest(tail_cost=tail_cost):
                clock, polls = [0.0], [0]

                def runner(source, operation, cursor, arguments):
                    if operation == "scan_agent_source":
                        shared = hit(source, source, "2", logical_id="merged", primary=source == "c")
                        extras = (hit(source, "first", "3"), hit(source, "last", "1")) if source == "c" else ()
                        return scan(source, shared, *extras)
                    native = json.loads(arguments["vouchers"])[0][1]
                    if native == "c":
                        polls[0] += 1
                        if polls[0] < 7:
                            clock[0] += 4
                            return {"status": "processing", "next_cursor": "held"}
                        clock[0] += 1
                    if native == "d":
                        clock[0] += tail_cost  # Final host-side ownership check.
                    return {"status": "ready"}

                with patch("peters_mcp.agent_history_aggregate.time.monotonic", side_effect=lambda: clock[0]):
                    broker = AggregateFind(FixtureCore(routes), runner)
                    first = self._ready(broker, limit=1)
                    middle = self._ready(broker, first["next_cursor"], limit=1)
                    last = self._ready(broker, middle["next_cursor"], limit=1)
                self.assertEqual(first["threads"][0]["title"], "first")
                self.assertEqual(middle["coverage_complete"], not omitted)
                if omitted:
                    self.assertEqual(middle["threads"], [])
                    self.assertTrue(all("resource_exhausted" in item["warnings"] for item in middle["coverage"]))
                else:
                    self.assertEqual(middle["threads"][0]["matched_sources"], list(routes))
                self.assertEqual(last["threads"][0]["title"], "last")
                self.assertFalse(last["has_more"])

    def test_slow_validation_preserves_all_matches_and_rechecks_each_returned_page(self):
        # A worker can deliver only to a live demand. A late poll must reload
        # its evidence; an immediate continuation can join the current check.
        routes = ("ag", "codeg", "codex", "harness")
        rows = {source: [hit(source, source + str(i), str(99 - i)) for i in range(5)]
                for source in routes}
        rows["codeg"][0] = hit("codeg", "alias", "99", logical_id="harness0", primary=False)
        pending, clock, attested = {}, [0.0], set()

        def runner(source, operation, cursor, arguments):
            if operation == "scan_agent_source":
                return scan(source, *rows[source])
            vouchers = [tuple(item) for item in json.loads(arguments["vouchers"])]
            key = (source, tuple(vouchers))
            duration = len(vouchers) * {"ag": .4, "codeg": 1.1, "codex": 2.8, "harness": .5}[source]
            if not cursor or pending.get(key, 0) <= clock[0]:
                pending[key] = clock[0] + duration
            if pending[key] - clock[0] > 4:
                clock[0] += 4
                return {"status": "processing", "next_cursor": source + "-pending"}
            clock[0] = pending.pop(key)
            attested.update(vouchers)
            return {"status": "ready"}

        with patch("peters_mcp.agent_history_aggregate.time.monotonic", side_effect=lambda: clock[0]):
            broker = AggregateFind(FixtureCore(routes), runner)
            cursor, delivered, sizes = "", [], []
            for _ in range(100):
                attested.clear()
                page = broker.find("fixture", "", "", cursor, 20, _ACTOR)
                if page["status"] == "ready":
                    self.assertTrue(page["coverage_complete"], page["coverage"])
                    self.assertEqual({row["source_id"] for row in page["coverage"]}, set(routes))
                    expected = {tuple(item["vouchers"][0]) for row in page["threads"]
                                for source in row["matched_sources"] for item in rows[source]
                                if item["canonical"] == digest(row["title"])}
                    self.assertEqual(attested, expected)
                    delivered.extend(page["threads"])
                    sizes.append(len(page["threads"]))
                    if not page["has_more"]:
                        break
                cursor = page["next_cursor"]
            else:
                self.fail("Healthy sources should finish within the aggregate lifetime")
        titles = [row["title"] for row in delivered]
        self.assertEqual(len(titles), 19)
        self.assertEqual(len(set(titles)), 19)
        self.assertEqual(delivered, sorted(delivered, key=lambda row: (row["updated_at"],
                                                                      row["stable_thread_id"]), reverse=True))
        self.assertGreater(len(sizes), 1)
        merged = next(row for row in delivered if row["title"] == "harness0")
        self.assertEqual(merged["matched_sources"], ["codeg", "harness"])

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
        # Fast scans complete page 1 in a single bounded call rather than forcing a processing round-trip.
        first = broker.find("fixture", "", "", "", 1, _ACTOR)
        self.assertEqual(first["status"], "ready")
        self.assertEqual([row["title"] for row in first["threads"]], ["newest"])
        self.assertTrue(first["has_more"])
        cursor = first["next_cursor"]
        with self.assertRaises(AccessError) as wrong_actor:
            self._ready(broker, cursor, limit=1, actor=_OTHER)
        self.assertEqual(wrong_actor.exception.code, "restart_required")
        with self.assertRaises(AccessError) as wrong_request:
            self._ready(broker, cursor, limit=1, query="different")
        self.assertEqual(wrong_request.exception.code, "invalid_cursor")
        second = self._ready(broker, cursor, limit=1)
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
