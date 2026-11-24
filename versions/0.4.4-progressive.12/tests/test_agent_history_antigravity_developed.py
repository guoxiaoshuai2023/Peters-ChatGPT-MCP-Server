"""Desktop 2.33 development sessions with retained and pruned generation context."""

import json
import sqlite3
import unittest
from hashlib import sha256
from pathlib import PurePosixPath

from peters_mcp import agent_history_antigravity_native as native
from peters_mcp.agent_history_antigravity_events import NativeEvents, verified_arguments
import test_agent_history_antigravity_native as sample
from test_agent_history_antigravity_native import FIRST, SECOND, SESSION, SECONDS, TRAJECTORY, message


def tool(name=b'write_file', component=1, original=None, declared=b'FileEdit', changed_args=False, default=False,
         path='/synthetic/note', extra=()):
    args = {'Path': path, 'Content': 'private fixture', 'Overwrite': False}
    if default:
        del args['Overwrite']
    entries = [(1, message((1, k), (2, v if isinstance(v, str) else json.dumps(v))))
               for k, v in args.items()]
    if changed_args:
        args['Path'] = '/synthetic/different'
    call = [(1, 'call_1'), (2, name), (3, json.dumps(args))]
    if original is not None:
        call.append((9, original))
    metadata = native.Fields(message((4, message(*call)), (38, component)), {4, 38})
    typed = message((1, 2), (2, path), (3, 'opaque'), (4, 'opaque'), *extra)
    envelope = message((1, b'type.googleapis.com/exa.cortex.core.tools.' + declared), (2, typed))
    result = message((1, 'private synthetic result'), (3, b''), (6, envelope), (7, 'file:///private/reference'))
    return metadata, message(*entries, (2, result))


class DevelopedDesktopTests(unittest.TestCase):
    def fixture(self):
        fixture = sample.AntigravityNativeTests(methodName='runTest')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def test_committed_native_write_is_recognized(self):
        self.assertIsNone(native._tool(*tool()))
        self.assertIsNone(native._tool(*tool(default=True)))

    def test_artifact_marker_is_limited_to_the_same_native_session(self):
        root = PurePosixPath('/synthetic/brain') / SESSION
        self.assertIsNone(native._tool(*tool(path=str(root/'plan.md'), extra=((6, 1),)), artifact_root=root))
        for path in (root, root/'..'/'other', root.parent/'other'/'plan.md'):
            with self.subTest(path=path), self.assertRaises(native.EvidenceIssue):
                native._tool(*tool(path=str(path), extra=((6, 1),)), artifact_root=root)

    def test_wrong_provider_name_original_payload_and_args_never_vouch_for_a_write(self):
        for options in ({'component': 3}, {'name': b'unknown_tool'}, {'original': b'edit_file'},
                        {'declared': b'InvokeSubagent'}, {'changed_args': True}):
            with self.subTest(options=options), self.assertRaises(native.EvidenceIssue):
                native._tool(*tool(**options))

    def test_operations_with_the_same_builtin_do_not_authorize_unknown_variants(self):
        events = NativeEvents(SESSION)
        task = SESSION+'/task-4'
        events.tasks[task.encode()] = (4, FIRST, b'', (SECONDS,0))
        def verify(name, args, concrete, payload, *, index=8):
            call = message((1,'id'),(2,name),(3,json.dumps(args)))
            meta = native.Fields(message((4,call),(38,1)),{4,38})
            pairs = [(1,message((1,k),(2,v))) for k,v in args.items()]
            result = message((6,message((1,'type.googleapis.com/exa.cortex.core.tools.'+concrete),(2,payload))))
            native._tool(meta,message(*pairs,(2,result)),events=events,index=index)
        verify('search_web', {'query':'demo'}, 'SearchWeb', message((1,'demo')))
        verify('manage_task', {'Action':'kill','TaskId':task}, 'ManageTask', message((1,'kill'),(2,task)))
        spec = message((1,'tester'),(2,'audit'),(3,'nonce'),(4,1),(7,1),(12,'qa'))
        child = message((1,SECOND),(2,'title'),(3,'details'))
        spawn = {'TypeName':'tester','Role':'audit','Prompt':'nonce','Model':'qa'}
        verify('invoke_subagent',spawn,'InvokeSubagent',message((1,spec),(2,child)))
        progress = message((1,SECOND),(2,14))
        verify('manage_subagents',{'Action':'list'},'ManageSubagents',message((1,'list'),(2,SECOND),(3,progress)))
        for name,args,typ,raw in (
            ('search_web',{'query':'demo','workspace':'elsewhere'},'SearchWeb',message((1,'demo'))),
            ('search_web',{'query':'demo'},'SearchWeb',message((1,'changed'))),
            ('manage_task',{'Action':'kill','TaskId':SECOND},'ManageTask',message((1,'kill'),(2,SECOND))),
            ('manage_subagents',{'Action':'list'},'ManageSubagents',message((1,'list'),(2,FIRST))),
            ('manage_subagents',{'Action':'list'},'ManageSubagents',message((1,'list'),(2,SECOND),
                                                                           (3,message((1,FIRST),(2,14))))),
            ('manage_subagents',{'Action':'switch'},'ManageSubagents',message((1,'switch'))),
            ('invoke_subagent',spawn,'InvokeSubagent',message((1,spec+message((99,'unbounded'))),(2,child))),
        ):
            with self.subTest(action=name), self.assertRaises(native.EvidenceIssue):
                verify(name,args,typ,raw)

    def test_duplicate_or_nonboolean_argument_is_rejected_even_if_string_mirror_matches(self):
        pairs = message((1,message((1,'Overwrite'),(2,'false'))))
        for text in ('{"Overwrite":"false"}','{"Overwrite":true,"Overwrite":false}'):
            call = message((1,'id'),(2,'write_file'),(3,text))
            with self.subTest(text=text), self.assertRaises(native.EvidenceIssue):
                verified_arguments(b'write_file',call,pairs,{'Overwrite'},bool_keys={'Overwrite'})

    def test_contradictory_retained_entry_is_not_rescued_by_a_later_match(self):
        db = sqlite3.connect(':memory:')
        self.addCleanup(db.close)
        db.execute('CREATE TABLE gen_metadata(idx INTEGER PRIMARY KEY, data BLOB)')
        body = b'<USER_REQUEST>\nqa\n</USER_REQUEST>'
        def invocation(key, position, text):
            prompt = message((2, 1), (3, text), (18, 0))
            return message((1, message((2, prompt))), (2, bytes([position])), (4, key))
        db.executemany('INSERT INTO gen_metadata VALUES(?,?)', [
            (0, invocation(FIRST, 1, body+b'changed')),
            (1, invocation(SECOND, 3, body)),
        ])
        with self.assertRaisesRegex(native.EvidenceIssue, 'native_visible_message_mismatch'):
            native._generations(db, [FIRST,FIRST,SECOND,SECOND], {1:0,3:1}, {0:sha256(body).digest()},
                                {FIRST:1,SECOND:1}, {}, sha256())

    def test_write_in_second_turn_returns_both_public_turns_without_any_tool_data(self):
        fx = self.fixture()
        tool_meta, generic = tool()
        now = message((1, SECONDS))
        lifecycle = message(*[(1, message((1, state), (2, now))) for state in (1, 2, 3)])
        origin = message((1, TRAJECTORY), (2, 4), (3, 1), (4, SESSION))
        meta = message((1, now), (3, 2), (4, bytes(tool_meta.one(4))), (6, now), (7, now), (8, now),
                       (12, SECOND), (20, origin), (26, lifecycle), (38, 1))
        answer = fx.logs[3].copy()
        fx.logs[3]['content'] = ''
        fx.logs.extend([dict(answer, step_index=4, type='GENERIC', content='PRIVATE TOOL RESULT'),
                        dict(answer, step_index=5)])
        fx.write_step(3, SECOND, 1, '')
        fx.write_step(5, SECOND, 1, answer['content'])
        fx.db.execute('INSERT INTO steps VALUES(4,132,3,0,?,?,0)',
                      (meta, message((1, 132), (4, 3), (5, meta), (140, generic))))
        fx.db.execute('UPDATE executor_metadata SET data=? WHERE idx=1', (fx.executor(SECOND, 5),))
        prompt = message((2, 1), (3, fx.logs[2]['content']), (18, 2))
        fx.db.execute('UPDATE gen_metadata SET data=? WHERE idx=1',
                      (message((1, message((2, prompt))), (2, bytes([3,4,5])), (4, SECOND)),))
        fx.index.execute('UPDATE conversation_summaries SET step_count=6')
        fx.index.commit()
        fx.db.commit()
        fx.write_logs()
        actual = fx.reader.snapshot_for_inheritance(fx.thread)
        self.assertEqual([(msg.role,msg.text) for msg in actual.messages],
                         [('user','问题 0'),('assistant','Visible Gemini answer 0'),
                          ('user','问题 1'),('assistant','Visible Gemini answer 1')])

    def test_later_model_context_preserves_old_user_body_after_pruning(self):
        fx = self.fixture()
        first_prompt = message((2, 1), (3, fx.logs[0]['content']))  # Zero native position omitted.
        later_prompt = message((2, 1), (3, fx.logs[2]['content']), (18, 2))
        fx.db.execute('UPDATE gen_metadata SET data=? WHERE idx=0', (message((1,b''),(2,b'\x01'),(4,FIRST)),))
        def retained(*prompts):
            model = message(*[(2, p) for p in prompts])
            fx.db.execute('UPDATE gen_metadata SET data=? WHERE idx=1', (message((1,model),(2,b'\x03'),(4,SECOND)),))
            fx.db.commit()
        retained(first_prompt,later_prompt)
        snap = fx.reader.snapshot_for_inheritance(fx.thread)
        self.assertEqual([row.text for row in snap.messages if row.role=='user'], ['问题 0','问题 1'])
        retained(later_prompt)  # Absence everywhere cannot certify the old transcript wrapper.
        self.assertEqual(fx.result().reason,'native_visible_message_mismatch')
        retained(message((2,2),(3,fx.logs[0]['content'])),first_prompt,later_prompt)
        self.assertEqual(fx.result().reason,'native_visible_message_mismatch')

    def test_failed_generation_must_point_to_its_own_terminal_error(self):
        db = sqlite3.connect(':memory:')
        self.addCleanup(db.close)
        db.execute('CREATE TABLE gen_metadata(idx INTEGER PRIMARY KEY, data BLOB)')
        def run(error_positions, error_map):
            db.execute('DELETE FROM gen_metadata')
            db.executemany('INSERT INTO gen_metadata VALUES(?,?)', [
                (0, message((1,b''),(2,bytes(error_positions)),(4,FIRST),(5,'model failed'))),
                (1, message((1,b''),(2,b'\x03'),(4,FIRST)))])
            native._generations(db,[FIRST]*4,{1:0,3:1},{},{FIRST:1},{},sha256(),errors=error_map)
        run([1,2], {2:0})
        for indices, failures in (([1],{2:0}),([1,2],{2:1}),([2,1],{2:0}),([1,2],{})):
            with self.subTest(indices=indices,failures=failures), self.assertRaises(native.EvidenceIssue):
                run(indices,failures)

    def test_local_task_notification_requires_original_sender_step_call_and_terminal(self):
        events = NativeEvents(SESSION)
        task = SESSION+'/task-2'
        at = message((1,SECONDS))
        call = message((1,'native-call'),(2,'run_command'),(3,'{}'))
        events.background_task(2,FIRST,call,message((1,task),(8,at)),(SECONDS,0),(SECONDS,0))
        def notify(origin=SESSION, sender=task, operation=call, position=2, kind='task_notification', extra=()):
            source = message((1,origin),(2,position),(3,operation))
            agent = message((1,SECOND),(2,SESSION),(3,sender),(4,'private output'),(6,at),(10,b''),
                            (11,1),(12,message((1,source))),*extra)
            return message((1,'private system event'),(2,message((4,1))),(3,kind),(4,agent))
        for invalid in (notify(origin=SECOND),notify(sender='elsewhere'),notify(operation=message((2,'run_command'))),
                        notify(position=1),notify(kind='unrecognized'),notify(extra=[(9,'opaque step payload')])):
            with self.subTest(case=sha256(invalid).hexdigest()[:6]), self.assertRaises(native.EvidenceIssue):
                events.system(invalid,3,FIRST,(SECONDS,0),(SECONDS,0))
        events.system(notify(),3,FIRST,(SECONDS,0),(SECONDS,0))
        self.assertEqual(events.closed_tasks, {task.encode()})
        with self.assertRaises(native.EvidenceIssue):
            events.system(notify(),4,FIRST,(SECONDS,0),(SECONDS,0))

    def test_incoming_child_message_binds_recipient_source_spawn_and_unique_tool_send(self):
        events = NativeEvents(SESSION)
        spawn_digest = sha256(b'parent invoke').hexdigest()
        events.spawns[SECOND] = (2,spawn_digest)
        at = message((1,SECONDS))
        def notification(sender=SECOND, origin=SECOND, target=SESSION, sent='private child answer',
                         display='private child answer', identifier=TRAJECTORY, extra=()):
            arguments = json.dumps({'Recipient':target,'Message':sent})
            call = message((1,'send-id'),(2,'send_message'),(3,arguments))
            tool = message((1,origin),(2,12),(3,call))
            agent = message((1,identifier),(2,SESSION),(3,sender),(4,display),(6,at),(10,b''),
                            (12,message((1,tool))),*extra)
            return message((1,'private notification'),(2,b''),(3,'agent_message'),(4,agent)), sha256(call).hexdigest()
        for bad in (dict(sender=FIRST),dict(origin=FIRST),dict(target=FIRST),dict(display='different'),
                    dict(extra=[(9,'unknown embedded command')])):
            with self.subTest(changed=tuple(bad)), self.assertRaises(native.EvidenceIssue):
                events.system(notification(**bad)[0],5,FIRST,(SECONDS,0),(SECONDS,7))
        body,call = notification()
        events.system(body,5,FIRST,(SECONDS,0),(SECONDS,7))
        self.assertEqual(events.relations,[(SECOND,12,call,2,spawn_digest,(SECONDS,7))])
        with self.assertRaises(native.EvidenceIssue):
            events.system(notification(identifier=FIRST)[0],6,FIRST,(SECONDS,0),(SECONDS,8))
