"""Synthetic real-engine limits; run --performance for the larger measurement matrix."""
import hashlib
import json
import os
from pathlib import Path
import resource
import sys
import threading
import time
import unittest

from peters_mcp.catalog import AccessError
from peters_mcp.history_process import IsolatedHistory, _rss_bytes
from tests import test_history as fixtures

MIB = 1024 * 1024


class SyntheticHistory:
    """Compose the existing fixture without inheriting its entire test suite."""
    def __init__(self):
        self.fixture = fixtures.HistoryTests()
        self.fixture.setUp()
        self.facade = None
        self.records = self.maximum_record = self.raw_bytes = 0

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        if self.facade is not None:
            self.facade.close()
        self.fixture.history.close()
        self.fixture.doCleanups()

    def write(self, stream, record):
        raw = fixtures.encode([record])
        stream.write(raw)
        self.records += 1
        self.maximum_record = max(self.maximum_record, len(raw))
        self.raw_bytes += len(raw)

    def header(self, stream):
        self.write(stream, fixtures.record("session_meta", {"id": fixtures.FIRST, "cwd": "/synthetic/repo"}))
        self.write(stream, fixtures.record("turn_context", {"turn_id": "turn-one", "cwd": "/synthetic/repo"}))

    def raw_tools(self, target_bytes, payload_bytes):
        with self.fixture.path.open("wb") as stream:
            self.header(stream)
            self.write(stream, fixtures.message("public before", native_id="before"))
            raw = fixtures.encode([fixtures.record("response_item", {
                "type": "function_call_output", "call_id": "synthetic", "output": "x" * payload_bytes})])
            while self.raw_bytes < target_bytes:
                stream.write(raw)
                self.raw_bytes += len(raw)
                self.records += 1
                self.maximum_record = max(self.maximum_record, len(raw))
            self.write(stream, fixtures.message("public after", native_id="after"))
        return len("public beforepublic after")

    def public_text(self, character, total_chars):
        expected = hashlib.sha256()
        with self.fixture.path.open("wb") as stream:
            self.header(stream)
            remaining, index = total_chars, 0
            while remaining:
                count = min(MIB, remaining)
                text = character * count
                expected.update(text.encode("utf-8"))
                self.write(stream, fixtures.message(text, native_id="message-" + str(index)))
                remaining -= count
                index += 1
        return expected.hexdigest()

    def start(self):
        self.facade = IsolatedHistory(self.fixture.history)
        return self.facade


def complete(facade, arguments, metrics=None, timeout=120):
    cursor = arguments.get("cursor", "")
    deadline = time.monotonic() + timeout
    while True:
        started = time.monotonic()
        result = facade.read_codex_thread(**{**arguments, "cursor": cursor})
        if metrics is not None:
            metrics["request_seconds"].append(time.monotonic() - started)
        if result.get("status") != "processing":
            return result
        if metrics is not None:
            metrics["processing_responses"] += 1
        if time.monotonic() >= deadline:
            raise AssertionError("Synthetic preparation did not complete within measurement deadline")
        cursor = result["next_cursor"]


class ParentMemory:
    def __enter__(self):
        self.baseline = _rss_bytes(os.getpid())
        self.peak = self.baseline
        self.highwater_before = self.highwater()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.sample, daemon=True)
        self.thread.start()
        return self

    def highwater(self):
        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(value if sys.platform == "darwin" else value * 1024)

    def sample(self):
        while not self.stop.wait(0.05):
            self.peak = max(self.peak, _rss_bytes(os.getpid()))

    def __exit__(self, *unused):
        self.peak = max(self.peak, _rss_bytes(os.getpid()))
        self.stop.set()
        self.thread.join(1)
        self.highwater_after = self.highwater()

    def report(self):
        return {"parent_live_baseline_bytes": self.baseline, "parent_sampled_peak_bytes": self.peak,
                "parent_sampled_increment_bytes": max(0, self.peak - self.baseline),
                "parent_lifetime_ru_maxrss_before_bytes": self.highwater_before,
                "parent_lifetime_ru_maxrss_after_bytes": self.highwater_after,
                "parent_lifetime_peak_increase_bytes": max(0, self.highwater_after - self.highwater_before)}


def measure_raw(size, payload):
    with SyntheticHistory() as fixture:
        public_chars = fixture.raw_tools(size, payload)
        metrics = {"kind": "large_raw", "target_bytes": size, "payload_bytes": payload,
                   "record_count": fixture.records, "maximum_record_bytes": fixture.maximum_record,
                   "raw_bytes": fixture.raw_bytes, "public_characters": public_chars,
                   "mirrors": 0, "processing_responses": 0, "request_seconds": []}
        with ParentMemory() as memory:
            facade = fixture.start()
            started = time.monotonic()
            page = complete(facade, {"thread_id": fixtures.FIRST}, metrics)
            metrics["first_read_seconds"] = time.monotonic() - started
            metrics["status"] = page.get("status")
            assert page["status"] == "ready", page
            assert [entry["text"] for entry in page["entries"]] == ["public before", "public after"]
            hot = []
            for _ in range(10):
                started = time.monotonic()
                page = complete(facade, {"thread_id": fixtures.FIRST}, metrics)
                hot.append(time.monotonic() - started)
                assert page["status"] == "ready"
            metrics["hot_request_p95_seconds"] = sorted(hot)[-1]
            metrics["worker_peak_rss_bytes"] = facade._peak_rss
            facade.close()
            assert facade._process is None
        metrics.update(memory.report())
        metrics["combined_measured_increment_bytes"] = metrics["worker_peak_rss_bytes"] + metrics["parent_sampled_increment_bytes"]
        assert metrics["worker_peak_rss_bytes"] <= 256 * MIB, metrics
        assert metrics["parent_sampled_increment_bytes"] <= 128 * MIB, metrics
        assert metrics["combined_measured_increment_bytes"] <= 384 * MIB, metrics
        return metrics


def measure_public(character, count):
    with SyntheticHistory() as fixture:
        expected = fixture.public_text(character, count)
        metrics = {"kind": "large_public", "character": "ASCII" if ord(character) < 128 else "CJK",
                   "public_characters": count, "raw_bytes": fixture.raw_bytes,
                   "record_count": fixture.records, "maximum_record_bytes": fixture.maximum_record,
                   "mirrors": 0, "request_seconds": [], "processing_responses": 0}
        with ParentMemory() as memory:
            facade = fixture.start()
            digest, seen, pages, cursor = hashlib.sha256(), 0, 0, ""
            started = time.monotonic()
            try:
                while True:
                    page = complete(facade, {"thread_id": fixtures.FIRST, "cursor": cursor, "max_chars": 40000}, metrics)
                    if page["status"] != "ready":
                        assert page["status"] == "resource_exhausted", page
                        metrics["status"] = page["status"]
                        break
                    if not pages:
                        metrics["first_read_seconds"] = time.monotonic() - started
                    for entry in page["entries"]:
                        digest.update(entry["text"].encode("utf-8"))
                        seen += len(entry["text"])
                    pages += 1
                    if not page["has_more"]:
                        assert seen == count, (seen, count)
                        assert digest.hexdigest() == expected
                        metrics["status"] = "ready_exact_complete"
                        break
                    cursor = page["next_cursor"]
            except AccessError as error:
                assert error.code in ("resource_exhausted", "projection_limit_exceeded"), error
                metrics["status"] = error.code
            metrics.update(total_seconds=time.monotonic()-started, pages=pages,
                           returned_characters=seen, worker_peak_rss_bytes=facade._peak_rss)
            facade.close()
            assert facade._process is None
        metrics.update(memory.report())
        metrics["combined_measured_increment_bytes"] = metrics["worker_peak_rss_bytes"] + metrics["parent_sampled_increment_bytes"]
        if metrics["status"] == "ready_exact_complete":
            assert metrics["worker_peak_rss_bytes"] <= 256 * MIB, metrics
            assert metrics["parent_sampled_increment_bytes"] <= 128 * MIB, metrics
            assert metrics["combined_measured_increment_bytes"] <= 384 * MIB, metrics
        return metrics


class HistoryLimitsTests(unittest.TestCase):
    def test_real_engine_processing_cursor_preserves_page_arguments(self):
        with SyntheticHistory() as fixture:
            fixture.raw_tools(16 * MIB, MIB)
            fixture.facade = IsolatedHistory(fixture.fixture.history, wait_seconds=0.02)
            metrics = {"request_seconds": [], "processing_responses": 0}
            first = complete(fixture.facade, {"thread_id": fixtures.FIRST, "limit": 1}, metrics)
            self.assertGreater(metrics["processing_responses"], 0)
            self.assertEqual(first["status"], "ready")
            self.assertEqual(first["entries"][0]["text"], "public before")
            second = complete(fixture.facade, {"thread_id": fixtures.FIRST, "limit": 1,
                                               "cursor": first["next_cursor"]})
            self.assertEqual(second["entries"][0]["text"], "public after")
            self.assertFalse(second["has_more"])

    def test_over_public_limit_returns_specific_code_and_no_partial_page(self):
        result = measure_public("a", 16 * MIB + 1)
        self.assertEqual(result["status"], "projection_limit_exceeded")
        self.assertEqual(result["returned_characters"], 0)
        self.assertEqual(result["pages"], 0)

    def test_more_than_64_mib_raw_through_actual_isolated_engine(self):
        result = measure_raw(65 * MIB, MIB)
        self.assertEqual(result["status"], "ready")
        self.assertGreater(result["raw_bytes"], 64 * MIB)
        self.assertLess(result["first_read_seconds"], 30)

    def test_large_single_line_is_discarded_without_retaining_it(self):
        with SyntheticHistory() as fixture:
            with fixture.fixture.path.open("wb") as stream:
                fixture.header(stream)
                for _ in range(65):
                    stream.write(b"x" * MIB)
                stream.write(b"\n")
                fixture.write(stream, fixtures.message("after oversized", native_id="after"))
            facade = fixture.start()
            page = complete(facade, {"thread_id": fixtures.FIRST})
            self.assertEqual(page["status"], "ready")
            self.assertEqual([m["text"] for m in page["entries"]], ["after oversized"])
            self.assertEqual(page["warnings"]["oversized_record_excluded"], 1)
            self.assertFalse(page["complete_public_projection"])
            self.assertLess(facade._peak_rss, 128 * MIB)

    def test_deep_json_fails_with_complexity_code_and_worker_recovers(self):
        with SyntheticHistory() as fixture:
            with fixture.fixture.path.open("wb") as stream:
                fixture.header(stream)
                stream.write(b'[' * 10000 + b'0' + b']' * 10000 + b'\n')
            facade = fixture.start()
            with self.assertRaises(AccessError) as caught:
                complete(facade, {"thread_id": fixtures.FIRST})
            self.assertEqual(caught.exception.code, "resource_exhausted")
            fixture.public_text("a", 100)
            self.assertEqual(complete(facade, {"thread_id": fixtures.FIRST})["status"], "ready")

    def test_half_tail_is_excluded_and_reported(self):
        with SyntheticHistory() as fixture:
            fixture.public_text("a", 100)
            with fixture.fixture.path.open("ab") as stream:
                stream.write(b'{"unfinished": "hidden')
            page = complete(fixture.start(), {"thread_id": fixtures.FIRST})
            self.assertEqual(page["status"], "ready")
            self.assertEqual(page["warnings"]["incomplete_tail_excluded"], 1)
            self.assertEqual([m["text"] for m in page["entries"]], ["a" * 100])

    def test_object_count_guard_is_explicit(self):
        with SyntheticHistory() as fixture:
            with fixture.fixture.path.open("wb") as stream:
                fixture.header(stream)
                raw = fixtures.encode([fixtures.message("x", native_id=None)])
                for _ in range(50001):
                    stream.write(raw)
            with self.assertRaises(AccessError) as caught:
                complete(fixture.start(), {"thread_id": fixtures.FIRST})
            self.assertEqual(caught.exception.code, "resource_exhausted")


def performance():
    results = []
    for size in (128 * MIB, 256 * MIB):
        for payload in (MIB, 4096):
            result = measure_raw(size, payload)
            results.append(result)
            print(json.dumps({key: result[key] for key in ("kind", "raw_bytes", "record_count", "first_read_seconds", "worker_peak_rss_bytes")}), flush=True)
    for character in ("a", "界"):
        result = measure_public(character, 16 * MIB - 1)
        results.append(result)
        print(json.dumps({key: result[key] for key in ("kind", "character", "status", "total_seconds", "worker_peak_rss_bytes")}), flush=True)
    result = measure_public("a", 16 * MIB + 1)
    assert result["status"] == "projection_limit_exceeded", result
    results.append(result)
    output = Path("work/history-stage1/synthetic-result.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({"cases": results, "measurement_notes": [
        "All source logs and databases are generated in temporary directories and removed after each case.",
        "Source files were generated immediately before reading; these are warm-filesystem-cache preparation measurements, not cold disk results.",
        "The production 4-second polling budget was used for performance cases; none needed a processing response. A separate integration test uses a shorter wait to exercise continuation.",
        "Parent live baseline is taken after generating the input, so synthetic-input construction is not attributed to serving overhead.",
        "Parent live RSS sampled at 50ms; ru_maxrss is lifetime high water and is reported separately.",
        "Worker peak combines live samples with child ru_maxrss; RSS measurement is not an OS hard limit.",
        "No source files, authorization, production services or network resources were changed."
    ]}, indent=2) + "\n")


if __name__ == "__main__":
    if "--performance" in sys.argv:
        performance()
    else:
        unittest.main()
