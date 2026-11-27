"""The desktop may omit the protobuf scalar index for the first user step."""
import unittest

import test_agent_history_antigravity_native as native


class FirstPromptPositionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = native.AntigravityNativeTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.first = self.fixture.logs[0]['content']
        self.second = self.fixture.logs[2]['content']

    @staticmethod
    def prompt(role, text, index=None):
        position = [] if index is None else [(18, index)]
        return native.message((2, role), (3, text), *position)

    def retained(self, earlier, host=None):
        host_field = [] if host is None else [(1, host)]
        original = native.message(*host_field, (2, earlier))
        replay = native.message((2, self.prompt(1, self.first)), (2, self.prompt(1, self.second, 2)))
        for index, key, model in [(0, native.FIRST, original), (1, native.SECOND, replay)]:
            value = native.message((1, model), (2, bytes([index * 2 + 1])), (4, key))
            self.fixture.db.execute('UPDATE gen_metadata SET data=? WHERE idx=?', (value, index))
        self.fixture.db.commit()
        return self.fixture.result()

    def test_an_earlier_conflicting_prompt_cannot_be_reconciled_by_a_later_correct_copy(self):
        for index in (None, 0):
            for role, text in ((1, 'Different question'), (2, self.first), (2, 'Different question')):
                with self.subTest(index=index, role=role, is_correct_text=text == self.first):
                    result = self.retained(self.prompt(role, text, index))
                    self.assertEqual(result.reason, 'native_visible_message_mismatch')

    def test_omitted_or_explicit_zero_accepts_matching_native_user_bytes(self):
        for index in (None, 0):
            with self.subTest(index=index):
                self.assertEqual(self.retained(self.prompt(1, self.first, index)).state, 'workspace_verified')

    def test_only_an_independently_typed_unindexed_system_prompt_is_unrelated_to_step_zero(self):
        host = 'Synthetic host instruction'
        self.assertEqual(self.retained(self.prompt(5, host), host).state, 'workspace_verified')
        for role, text, index in ((5, 'Different host text', None), (1, host, None), (5, host, 0)):
            with self.subTest(role=role, index=index):
                self.assertEqual(self.retained(self.prompt(role, text, index), host).state, 'unverified')
