"""Actual spawned worker checks; synthetic metadata only, no live Codex data."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from peters_mcp.catalog import AccessError
from peters_mcp.history_process import IsolatedHistory, REQUEST_BYTES, RESPONSE_BYTES, _frame


class SyntheticEngine:
    def __init__(self, spec):
        self.path = spec["config_path"]
        self.calls = 0

    def operation_iter(self, operation, arguments):
        self.calls += 1
        marker = arguments.get("thread_id", arguments.get("query", ""))
        if marker == "hang":
            while True:
                time.sleep(0.01)
        if marker == "transient_peak":
            temporary = bytearray(128 * 1024 * 1024)
            del temporary
        if marker == "allocate":
            self.large = bytearray(300 * 1024 * 1024)
            time.sleep(2)
        for _ in range(15 if marker.startswith("slow") else 1):
            time.sleep(0.04)
            yield None
        if marker == "oversize":
            return {"text": "a" * (RESPONSE_BYTES + 1)}
        if marker == "source_changed":
            raise AccessError("Synthetic source changed.", code="source_changed")
        if marker == "unstable_operation" and self.calls == 1:
            raise AccessError("Synthetic source is still changing.", code="waiting_source_stable")
        if marker == "unexpected":
            raise RuntimeError("THIS_PRIVATE_BODY_MUST_NOT_APPEAR")
        return {"status": "ready", "pid": os.getpid(), "calls": self.calls,
                "original_cursor": arguments.get("cursor"), "operation": operation}

    def revalidate_result_iter(self, operation, arguments, result):
        if arguments.get("thread_id") == "unstable_validation" and result["calls"] == 1:
            time.sleep(0.04)
            yield None
            raise AccessError("Synthetic source is still changing.", code="waiting_source_stable")
        if self.path and json.loads(Path(self.path).read_text()).get("slow_validation"):
            for _ in range(20):
                time.sleep(0.04)
                yield None
        if self.path and not json.loads(Path(self.path).read_text())["allowed"]:
            raise AccessError("Synthetic authorization revoked.", code="unauthorized")
        return result


class HistoryProcessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.policy = Path(self.temp.name) / "policy.json"
        self.policy.write_text('{"allowed":true}')
        self.facades = []

    def tearDown(self):
        for facade in self.facades:
            facade.close()
        self.temp.cleanup()

    def facade(self, **kwargs):
        core = SimpleNamespace(config_path=self.policy, project_ids=set(), catalog=None)
        value = IsolatedHistory(core, _factory=SyntheticEngine, **kwargs)
        self.facades.append(value)
        return value

    def finish(self, facade, arguments, response=None):
        deadline = time.monotonic() + 6
        response = response or facade.read_codex_thread(**arguments)
        while response.get("status") == "processing" and time.monotonic() < deadline:
            response = facade.read_codex_thread(**{**arguments, "cursor": response["next_cursor"]})
        self.assertEqual(response["status"], "ready", response)
        return response

    def test_spawn_is_separate_and_close_reaps_process(self):
        facade = self.facade(wait_seconds=1)
        result = self.finish(facade, {"thread_id": "normal"})
        self.assertNotEqual(result["pid"], os.getpid())
        process = facade._process
        facade.close()
        self.assertIsNone(facade._process)
        with self.assertRaises(ValueError):
            process.is_alive()

    def test_continuation_restores_original_page_cursor_and_arguments(self):
        facade = self.facade(wait_seconds=0.1)
        args = {"thread_id": "slow", "cursor": "original-third-page", "view": "turn", "turn_id": "t"}
        initial = facade.read_codex_thread(**args)
        self.assertEqual(initial["status"], "processing")
        result = self.finish(facade, args, initial)
        self.assertEqual(result["original_cursor"], "original-third-page")
        self.assertEqual(result["calls"], 1)

    def test_continuation_rejects_forgery_method_or_parameters(self):
        facade = self.facade(wait_seconds=0.05)
        response = facade.read_codex_thread("slow")
        token = response["next_cursor"]
        for call in (
            lambda: facade.read_codex_thread("slow", cursor=token[:-1] + ("0" if token[-1] != "0" else "1")),
            lambda: facade.find_codex_threads(cursor=token),
            lambda: facade.read_codex_thread("other", cursor=token),
            lambda: facade.read_codex_thread("slow", cursor=token, limit=1),
        ):
            with self.assertRaises(AccessError) as caught:
                call()
            self.assertEqual(caught.exception.code, "invalid_cursor")

    def test_delayed_pickup_revalidates_and_blocks_revoked_result(self):
        facade = self.facade(wait_seconds=0.05)
        response = facade.read_codex_thread("slow")
        time.sleep(0.9)
        self.policy.write_text('{"allowed":false}')
        with self.assertRaises(AccessError) as caught:
            self.finish(facade, {"thread_id": "slow"}, response)
        self.assertEqual(caught.exception.code, "unauthorized")
        self.assertEqual(str(caught.exception).count("[unauthorized]"), 1)

    def test_repeated_pickup_revalidates_previously_delivered_result(self):
        facade = self.facade(wait_seconds=1)
        self.finish(facade, {"thread_id": "normal"})
        self.policy.write_text('{"allowed":false}')
        with self.assertRaises(AccessError) as caught:
            facade.read_codex_thread("normal")
        self.assertEqual(caught.exception.code, "unauthorized")
        self.assertEqual(str(caught.exception).count("[unauthorized]"), 1)

    def test_timeout_reaps_actual_process_and_allows_recovery(self):
        facade = self.facade(wait_seconds=1, step_seconds=0.2)
        result = facade.read_codex_thread("hang")
        self.assertEqual(result["status"], "processing_timeout")
        self.assertIsNone(facade._process)
        self.finish(facade, {"thread_id": "normal"})

    def test_worker_restart_invalidates_all_prior_tokens(self):
        facade = self.facade(wait_seconds=0.05, step_seconds=0.2)
        response = facade.read_codex_thread("slow")
        facade.read_codex_thread("hang")
        time.sleep(0.6)
        result = facade.read_codex_thread("slow", cursor=response["next_cursor"])
        self.assertEqual(result["status"], "restart_required")
        self.finish(facade, {"thread_id": "normal"})

    def test_inflight_equal_requests_merge_and_queue_is_bounded(self):
        facade = self.facade(wait_seconds=0.005)
        first = facade.read_codex_thread("slow-0")
        facade.read_codex_thread("slow-0")
        self.assertEqual(len(facade._tasks), 1)
        for n in range(1, 5):
            facade.read_codex_thread(f"slow-{n}")
        result = facade.read_codex_thread("slow-5")
        self.assertEqual(result["status"], "busy")
        self.assertEqual(len(facade._tasks), 5)
        facade._wait_seconds = 0.3
        self.finish(facade, {"thread_id": "slow-0"}, first)

    def test_ipc_request_response_limits_and_safe_unexpected_error(self):
        facade = self.facade(wait_seconds=1)
        with self.assertRaises(AccessError) as caught:
            facade.read_codex_thread("a" * REQUEST_BYTES)
        self.assertEqual(caught.exception.code, "resource_exhausted")
        self.assertIsNone(facade._process)
        with self.assertRaises(AccessError) as caught:
            facade.read_codex_thread("oversize")
        self.assertEqual(caught.exception.code, "resource_exhausted")
        with self.assertRaises(AccessError) as caught:
            facade.read_codex_thread("unexpected")
        self.assertNotIn("PRIVATE_BODY", str(caught.exception))
        self.assertEqual(caught.exception.code, "history_processing_failed")
        self.finish(facade, {"thread_id": "normal"})

    def test_rss_guard_terminates_during_unyielding_allocation(self):
        facade = self.facade(wait_seconds=1, step_seconds=3, worker_rss=128 * 1024 * 1024)
        result = facade.read_codex_thread("allocate")
        self.assertEqual(result["status"], "resource_exhausted")
        self.assertIsNone(facade._process)
        self.finish(facade, {"thread_id": "normal"})

    def test_delivered_initial_request_does_not_pin_future_reads_to_old_snapshot(self):
        facade = self.facade(wait_seconds=1)
        first = self.finish(facade, {"thread_id": "normal"})
        second = self.finish(facade, {"thread_id": "normal"})
        self.assertEqual((first["calls"], second["calls"]), (1, 2))

    def test_processing_slices_allow_other_task_to_complete(self):
        facade = self.facade(wait_seconds=0.05)
        slow = facade.read_codex_thread("slow")
        facade._wait_seconds = 1
        normal = facade.read_codex_thread("normal")
        self.assertEqual(normal["status"], "ready")
        self.assertFalse(facade._tasks[next(t for t, v in facade._tasks.items()
                                          if v["arguments"]["thread_id"] == "slow")]["complete"])
        self.finish(facade, {"thread_id": "slow"}, slow)

    def test_peak_memory_control_record_catches_short_unsampled_allocations(self):
        facade = self.facade(wait_seconds=1)
        with patch("peters_mcp.history_process._rss_bytes", return_value=0):
            result = self.finish(facade, {"thread_id": "transient_peak"})
        self.assertGreaterEqual(facade._peak_rss, 128 * 1024 * 1024)
        self.assertNotIn("peak_rss_bytes", result)

    def test_short_peak_over_limit_is_rejected_even_when_live_sampler_misses_it(self):
        facade = self.facade(wait_seconds=1, worker_rss=96 * 1024 * 1024)
        with patch("peters_mcp.history_process._rss_bytes", return_value=0):
            result = facade.read_codex_thread("transient_peak")
        self.assertEqual(result["status"], "resource_exhausted")
        self.assertIsNone(facade._process)
        self.finish(facade, {"thread_id": "normal"})

    def test_delayed_validations_reserve_queue_slots_and_ignore_old_completions(self):
        facade = self.facade(wait_seconds=0.005)
        prepared = []
        for n in range(6):
            thread_id = f"normal-{n}"
            first = facade.read_codex_thread(thread_id)
            self.assertEqual(first["status"], "processing")
            task_id = facade._verify(first["next_cursor"], "read_codex_thread")["id"]
            deadline = time.monotonic() + 2
            while not facade._tasks[task_id]["complete"] and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(facade._tasks[task_id]["complete"])
            prepared.append((thread_id, first["next_cursor"], task_id))
        self.policy.write_text('{"allowed":true,"slow_validation":true}')
        facade._wait_seconds = 1
        with ThreadPoolExecutor(max_workers=5) as callers:
            futures = [callers.submit(facade.read_codex_thread, thread_id, cursor=token)
                       for thread_id, token, _ in prepared[:5]]
            deadline = time.monotonic() + 0.5
            while any(facade._tasks[tid]["revision"] < 2 for _, _, tid in prepared[:5]):
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.005)
            # Reproduce completions already on the transport when later
            # delivery demands reserve these same tasks again.
            with facade._lock:
                self.assertFalse(facade._incoming)
                for _, _, task_id in prepared[:5]:
                    old_revision = facade._tasks[task_id]["revision"] - 1
                    facade._incoming.extend(_frame({"type": "complete", "id": task_id,
                                                    "revision": old_revision}, RESPONSE_BYTES))
            time.sleep(0.03)
            self.assertEqual(sum(not task["complete"] for task in facade._tasks.values()), 5)
            thread_id, token, _ = prepared[5]
            self.assertEqual(facade.read_codex_thread(thread_id, cursor=token)["status"], "busy")
            for future in futures:
                self.assertEqual(future.result()["status"], "processing")

    def test_waiting_source_retains_original_page_and_restarts_only_when_requested(self):
        facade = self.facade(wait_seconds=0.01)
        arguments = {"thread_id": "unstable_validation", "cursor": "original-third-page"}
        response = facade.read_codex_thread(**arguments)
        self.assertEqual(response["status"], "processing")
        deadline = time.monotonic() + 3
        while response["status"] == "processing" and time.monotonic() < deadline:
            facade._wait_seconds = 0.2
            response = facade.read_codex_thread(**{**arguments, "cursor": response["next_cursor"]})
        self.assertEqual(response["status"], "waiting_source_stable")
        self.assertNotIn("original-third-page", json.dumps(response))
        tid = facade._verify(response["next_cursor"], "read_codex_thread")["id"]
        time.sleep(0.1)
        self.assertTrue(facade._tasks[tid]["retry"])
        self.assertEqual(facade._tasks[tid]["attempt"], 0)
        result = self.finish(facade, {**arguments, "cursor": response["next_cursor"]})
        self.assertEqual(result["original_cursor"], "original-third-page")
        self.assertEqual(result["calls"], 2)

    def test_same_initial_arguments_retry_temporary_error_and_merge_waiters(self):
        facade = self.facade(wait_seconds=1)
        with ThreadPoolExecutor(max_workers=2) as callers:
            pending = [callers.submit(facade.read_codex_thread, "unstable_operation", cursor="original-page")
                       for _ in range(2)]
            first = [future.result() for future in pending]
        self.assertEqual([result["status"] for result in first], ["waiting_source_stable"] * 2)
        self.assertEqual(len(facade._tasks), 1)
        with ThreadPoolExecutor(max_workers=2) as callers:
            pending = [callers.submit(facade.read_codex_thread, "unstable_operation", cursor="original-page")
                       for _ in range(2)]
            recovered = [future.result() for future in pending]
        self.assertEqual([result["calls"] for result in recovered], [2, 2])
        self.assertEqual([result["original_cursor"] for result in recovered], ["original-page"] * 2)

    def test_source_changed_error_does_not_get_retry_status(self):
        facade = self.facade(wait_seconds=1)
        with self.assertRaises(AccessError) as caught:
            facade.read_codex_thread("source_changed")
        self.assertEqual(caught.exception.code, "source_changed")
        self.assertFalse(facade._tasks)

    def test_expired_in_memory_continuation_reports_explicit_restart(self):
        facade = self.facade(wait_seconds=0.005, ttl=0.1)
        response = facade.read_codex_thread("slow")
        time.sleep(0.2)
        with self.assertRaises(AccessError) as caught:
            facade.read_codex_thread("slow", cursor=response["next_cursor"])
        self.assertEqual(caught.exception.code, "invalid_cursor")


if __name__ == "__main__":
    unittest.main()
