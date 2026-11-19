"""Spawned history recovery regressions using synthetic local data only."""

import time
import unittest

from peters_mcp.catalog import AccessError
from peters_mcp.history_process import IsolatedHistory
from tests import test_history as synthetic


class HistoryRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = synthetic.HistoryTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.addCleanup(self.fixture.history.close)
        self.facade = IsolatedHistory(self.fixture.history, wait_seconds=1)
        self.addCleanup(self.facade.close)

    def ready(self, arguments, response=None):
        response = response or self.facade.read_codex_thread(**arguments)
        deadline = time.monotonic() + 8
        while response.get('status') == 'processing':
            self.assertLess(time.monotonic(), deadline, 'Synthetic history preparation did not finish')
            response = self.facade.read_codex_thread(**{**arguments, 'cursor': response['next_cursor']})
        self.assertEqual(response.get('status'), 'ready', response)
        return response

    def test_delayed_processing_token_survives_twenty_four_later_responses_and_rechecks_authority(self):
        arguments = {'thread_id': synthetic.FIRST, 'limit': 1}
        self.facade._wait_seconds = 0.0001
        pending = self.facade.read_codex_thread(**arguments)
        self.assertEqual(pending['status'], 'processing')
        token = pending['next_cursor']
        task_id = self.facade._verify(token, 'read_codex_thread')['id']
        deadline = time.monotonic() + 5
        while True:
            with self.facade._lock:
                done = self.facade._tasks[task_id]['complete']
            if done:
                break
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.01)
        worker_pid = self.facade._process.pid
        self.facade._wait_seconds = 1
        # Both sources are read repeatedly in one worker while the first
        # processing token is deliberately left uncollected.
        for index in range(24):
            thread_id = synthetic.SECOND if index % 2 else synthetic.FIRST
            page = self.ready({'thread_id': thread_id})
            self.assertEqual(page['thread']['thread_id'], thread_id)
            self.assertEqual(self.facade._process.pid, worker_pid)
        for _ in range(2):
            time.sleep(0.05)
            delivered = self.ready({**arguments, 'cursor': token})
            self.assertEqual(delivered['entries'][0]['text'], '需求：分批读取文档。')
            self.assertEqual(self.facade._process.pid, worker_pid)
        self.fixture.grants = [grant for grant in self.fixture.grants if grant['id'] != synthetic.FIRST]
        self.fixture.save_config()
        with self.assertRaises(AccessError) as failure:
            self.ready({**arguments, 'cursor': token})
        self.assertEqual(failure.exception.code, 'authorization_changed')
        self.assertEqual(self.facade._process.pid, worker_pid)
        self.assertEqual(self.ready({'thread_id': synthetic.SECOND})['entries'][0]['text'], '第二个任务')

    def test_same_worker_append_retains_old_page_and_exposes_new_page_without_duplicate_snapshots(self):
        first = self.ready({'thread_id': synthetic.FIRST, 'limit': 1})
        worker_pid = self.facade._process.pid
        self.ready({'thread_id': synthetic.SECOND})
        with self.fixture.path.open('ab') as stream:
            stream.write(synthetic.encode([synthetic.message('new synthetic append', native_id='append-one')]))
        current_id = None
        for _ in range(12):
            old = self.ready({'thread_id': synthetic.FIRST, 'limit': 1, 'cursor': first['next_cursor']})
            new = self.ready({'thread_id': synthetic.FIRST})
            self.assertEqual(old['snapshot'], first['snapshot'])
            self.assertEqual(old['entries'][0]['text'], '公开进度')
            self.assertTrue(old['appended_since_snapshot'])
            self.assertEqual(new['entries'][-1]['text'], 'new synthetic append')
            current_id = current_id or new['snapshot']['id']
            self.assertEqual(new['snapshot']['id'], current_id)
            self.assertEqual(self.facade._process.pid, worker_pid)
        self.fixture.grants = [grant for grant in self.fixture.grants if grant['id'] != synthetic.FIRST]
        self.fixture.save_config()
        with self.assertRaises(AccessError):
            self.ready({'thread_id': synthetic.FIRST, 'limit': 1, 'cursor': first['next_cursor']})
        self.assertEqual(self.ready({'thread_id': synthetic.SECOND})['entries'][0]['text'], '第二个任务')
        self.assertEqual(self.facade._process.pid, worker_pid)


if __name__ == '__main__':
    unittest.main()
