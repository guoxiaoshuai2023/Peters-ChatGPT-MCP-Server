"""Actual MCP history routing, continuation and event-loop isolation."""

import asyncio
import json
import time
import unittest
from unittest.mock import patch

from mcp.client import Client
from peters_mcp.catalog import Catalog, Project
from peters_mcp.history_process import IsolatedHistory
from peters_mcp.server import create_server
from tests import test_history as historical

FIRST, record, message, encode = historical.FIRST, historical.record, historical.message, historical.encode


class BriefWaitHistory(IsolatedHistory):
    def __init__(self, history):
        super().__init__(history, wait_seconds=0.02)


class SlowEngine:
    def __init__(self, spec):
        pass

    def operation_iter(self, operation, arguments):
        time.sleep(0.8)
        yield {}
        return {'status': 'ready', 'threads': []}

    def revalidate_result_iter(self, operation, arguments, result):
        yield {}
        return result


class SlowHistory(IsolatedHistory):
    def __init__(self, history):
        super().__init__(history, _factory=SlowEngine)


class HistoryIntegrationTests(unittest.TestCase):
    def fixture(self):
        fixture = historical.HistoryTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    @staticmethod
    def data(result):
        if result.is_error:
            raise AssertionError(result.content)
        return json.loads(result.content[0].text)

    def test_real_mcp_processing_views_and_original_page_continuation(self):
        fixture = self.fixture()
        fixture.path.write_bytes(encode([
            record('session_meta', {'id': FIRST}),
            record('event_msg', {'type': 'task_started', 'turn_id': 'one'}),
            message('first'), message('second', native_id='two'),
            record('event_msg', {'type': 'task_started', 'turn_id': 'empty-latest'}),
        ]))
        catalog = Catalog([Project('project', 'Synthetic', fixture.home)])
        with patch('peters_mcp.history_process.IsolatedHistory', BriefWaitHistory):
            server = create_server(catalog, history=fixture.history)

            async def run():
                async with Client(server) as client:
                    async def complete(args):
                        pending = 0
                        for _ in range(100):
                            result = self.data(await client.call_tool('read_codex_thread', args))
                            if result['status'] != 'processing':
                                self.assertEqual(result['status'], 'ready')
                                return result, pending
                            self.assertNotIn('entries', result)
                            self.assertNotIn('has_more', result)
                            args = {**args, 'cursor': result['next_cursor']}
                            pending += 1
                            await asyncio.sleep(0.01)
                        self.fail('Processing did not finish')

                    first, pending = await complete({'thread_id': FIRST, 'limit': 1})
                    self.assertGreater(pending, 0)
                    self.assertEqual(first['entries'][0]['text'], 'first')
                    second, _ = await complete({'thread_id': FIRST, 'limit': 1, 'cursor': first['next_cursor']})
                    self.assertEqual(second['entries'][0]['text'], 'second')
                    self.assertEqual(first['snapshot'], second['snapshot'])
                    latest, _ = await complete({'thread_id': FIRST, 'view': 'latest_turn'})
                    self.assertEqual(latest['selected_turn_id'], 'empty-latest')
                    self.assertEqual(latest['entries'], [])
                    self.assertEqual(latest['last_recorded_status'], 'recorded_in_progress')
                    changed_args = {'thread_id': FIRST, 'limit': 1, 'view': 'latest_turn',
                                    'cursor': first['next_cursor']}
                    for _ in range(100):
                        changed = await client.call_tool('read_codex_thread', changed_args)
                        if changed.is_error:
                            self.assertIn('different page parameters', changed.content[0].text)
                            break
                        pending = self.data(changed)
                        self.assertEqual(pending['status'], 'processing')
                        self.assertNotIn('entries', pending)
                        changed_args = {**changed_args, 'cursor': pending['next_cursor']}
                        await asyncio.sleep(0.01)
                    else:
                        self.fail('Changed view was not rejected after processing')
            asyncio.run(run())

    def test_history_work_does_not_block_unrelated_mcp_reads(self):
        fixture = self.fixture()
        catalog = Catalog([Project('project', 'Synthetic', fixture.home)])
        with patch('peters_mcp.history_process.IsolatedHistory', SlowHistory):
            server = create_server(catalog, history=fixture.history)

            async def run():
                async with Client(server) as client:
                    history = asyncio.create_task(client.call_tool('find_codex_threads'))
                    await asyncio.sleep(0.05)
                    started = time.monotonic()
                    result = self.data(await client.call_tool('list_projects'))
                    self.assertEqual(result['projects'][0]['id'], 'project')
                    self.assertLess(time.monotonic()-started, 0.5)
                    self.assertEqual(self.data(await history)['status'], 'ready')
            asyncio.run(run())
