"""Regression checks for a native parent/child send receipt in one project."""
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

from peters_mcp.agent_history_antigravity_native import EvidenceIssue
from peters_mcp.agent_history import AgentHistoryCore
from peters_mcp.agent_history_source import Projection, SourceRoot, Thread
from peters_mcp.catalog import AccessError
from test_agent_history_antigravity_native import message, varint, SECONDS

PARENT, CHILD, PROJECT, TRAJECTORY, EXECUTION, INIT, MSG = (str(uuid.UUID(int=i)) for i in range(101, 108))
TIME = message((1, SECONDS))
SPAWN = message((1, 'inv-7'), (2, 'invoke_subagent'), (3, '{}'), (9, 'invoke_subagent'))
ARGS = {'Recipient': PARENT, 'Message': 'Synthetic child receipt'}
SEND = message((1, 'send-2'), (2, 'send_message'), (3, json.dumps(ARGS)), (9, 'send_message'))


class SenderReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name).resolve()
        self.folder = base / 'project'
        self.folder.mkdir()
        root = base / 'source'
        (root / 'conversations').mkdir(parents=True)
        (base / 'scratch').mkdir(mode=0o700)
        self.root = SourceRoot(root, scratch=base / 'scratch')
        self.thread = Thread(PARENT, contexts=(str(self.folder),), native_project_id=PROJECT)
        self.index = sqlite3.connect(root / 'conversation_summaries.db')
        self.addCleanup(self.index.close)
        self.index.executescript('''PRAGMA user_version=3;
            CREATE TABLE conversation_summaries(conversation_id, project_id, workspace_uris,
                parent_conversation_id, nesting_depth, step_count, not_fully_idle, status, killed);
            CREATE TABLE conversation_parents(conversation_id, parent_id);''')
        self.index.execute('INSERT INTO conversation_summaries VALUES (?,?,?,?,1,4,0,?,0)',
                           (CHILD, PROJECT, json.dumps([self.folder.as_uri()]), PARENT, 'CASCADE_RUN_STATUS_IDLE'))
        self.index.commit()
        self.db = sqlite3.connect(root / 'conversations' / (CHILD + '.db'))
        self.addCleanup(self.db.close)
        self.db.executescript('''PRAGMA user_version=1;
            CREATE TABLE trajectory_meta(trajectory_id,cascade_id,trajectory_type,source);
            CREATE TABLE parent_references(idx,data); CREATE TABLE battle_mode_infos(idx,data);
            CREATE TABLE trajectory_metadata_blob(id,data);
            CREATE TABLE steps(idx integer primary key,step_type,status,has_subtrajectory,metadata,step_payload,step_format);
            CREATE TABLE executor_metadata(idx integer primary key,data); CREATE TABLE gen_metadata(idx integer primary key,data);''')
        self.db.execute('INSERT INTO trajectory_meta VALUES(?,?,4,1)', (TRAJECTORY, CHILD))
        self.header()
        mirror = message((1,PARENT), (2,7), (3,SPAWN))
        agent = message((1, MSG), (2,CHILD), (3,PARENT), (4,'synthetic task'), (6,TIME),
                        (10,message((1,'fixture'))), (12,message((1,mirror))))
        self.step(0,101,message((1,'fixture'), (2,b''), (3,'agent_message'), (4,agent)))
        self.step(1,15,message((7,SEND)))
        generic = message(*[(1,message((1,k),(2,v))) for k,v in ARGS.items()],
                          (2,message((6,message((1,'type.googleapis.com/exa.cortex.core.tools.SendMessage'),
                                                (2,message((1,PARENT),(2,'fixture'),(3,ARGS['Message']))))))))
        self.step(2,132,generic,call=SEND)
        self.step(3,15,message((1,'ok'), (8,'ok'), (12,2)))
        self.db.execute('INSERT INTO executor_metadata VALUES(0,?)',(message((1,4),(2,2),(3,3),(9,EXECUTION)),))
        for pos, indices in enumerate(((1,2),(3,))):
            self.db.execute('INSERT INTO gen_metadata VALUES(?,?)', (pos,message((2,b''.join(varint(i) for i in indices)),(4,EXECUTION))))
        self.db.commit()
        self.relation=(CHILD,2,hashlib.sha256(SEND).hexdigest(),7,hashlib.sha256(SPAWN).hexdigest(),(SECONDS, 0))

    def header(self, *, extra=()):
        static=message((11,b''),(18,message((1,b''),(3,b''),(4,b''))))
        meta=message((1,message((1,self.folder.as_uri()))),(2,TIME),(3,INIT),(4,message((1,'self'),(7,static))),
                     (5,PARENT),(6,PARENT),(7,self.folder.as_uri()),
                     (8,message((1,'self'),(4,1),(7,1))), (10,static),(17,1),(18,PROJECT), *extra)
        self.db.execute('DELETE FROM trajectory_metadata_blob')
        self.db.execute('INSERT INTO trajectory_metadata_blob VALUES(?,?)',('main',meta))
        self.db.commit()

    def step(self, idx, kind, body, *, call=None, origin=CHILD, finished=TIME, invocation=None):
        source={101:5,15:2,132:2}[kind]
        fields={101:114,15:20,132:140}
        states={101:(3,),15:(8,3),132:(1,2,3)}[kind]
        gen=(1 if idx==3 else 0) if invocation is None else invocation
        timeline=message(*[(1,message((1,state),(2,finished if state == 3 else TIME))) for state in states])
        extra=[(4,call),(38,1)] if call else []
        meta=message((1,TIME),(3,source),(8,finished),(12,EXECUTION),
                     (20,message((1,TRAJECTORY),(2,idx),(3,gen),(4,origin))), (26,timeline),*extra)
        self.db.execute('INSERT OR REPLACE INTO steps VALUES(?,?,3,0,?,?,0)',
                        (idx,kind,meta,message((1,kind),(4,3),(5,meta),(fields[kind],body))))
        self.db.commit()

    def verify(self, rel=None):
        from peters_mcp.agent_history_antigravity_relations import verify_senders
        return verify_senders(self.root,self.thread,self.thread.contexts,[self.relation if rel is None else rel],
                              (SECONDS,0),(SECONDS,1))

    def test_two_native_ends_agree(self):
        self.assertEqual(32,len(self.verify()))

    def test_two_separate_sends_from_same_inherited_run(self):
        from peters_mcp.agent_history_antigravity_relations import verify_senders
        args = {'Recipient': PARENT, 'Message': 'Second synthetic receipt'}
        call = message((1, 'send-4'), (2, 'send_message'), (3, json.dumps(args)), (9, 'send_message'))
        result = message((1, PARENT), (2, 'fixture'), (3, args['Message']))
        typed = message((1, 'type.googleapis.com/exa.cortex.core.tools.SendMessage'), (2, result))
        generic = message(*[(1, message((1, key), (2, val))) for key, val in args.items()],
                          (2, message((6, typed))))
        self.step(3, 15, message((7, call)), invocation=1)
        self.step(4, 132, generic, call=call, invocation=1)
        self.step(5, 15, message((8, 'done'), (12, 2)), invocation=2)
        self.index.execute('UPDATE conversation_summaries SET step_count=6')
        self.index.commit()
        self.db.execute('UPDATE executor_metadata SET data=? WHERE idx=0',
                        (message((1, 4), (2, 3), (3, 5), (9, EXECUTION)),))
        for idx, positions in ((1, (3,4)), (2, (5,))):
            self.db.execute('INSERT OR REPLACE INTO gen_metadata VALUES(?,?)',
                            (idx, message((2, bytes(positions)), (4, EXECUTION))))
        self.db.commit()
        second = (CHILD, 4, hashlib.sha256(call).hexdigest(), *self.relation[3:])
        evidence = verify_senders(self.root, self.thread, self.thread.contexts, [self.relation, second],
                                  (SECONDS,0), (SECONDS,1))
        self.assertEqual(32, len(evidence))

    def test_preceding_work_cannot_finish_after_its_send(self):
        self.step(1,15,message((7,SEND)),finished=message((1,SECONDS+20)))
        with self.assertRaises(EvidenceIssue):
            self.verify()

    def test_sender_final_cannot_extend_past_the_parents_committed_range(self):
        self.step(3, 15, message((1, 'done'), (8, 'done'), (12, 2)), finished=message((1, SECONDS+1)))
        with self.assertRaises(EvidenceIssue):
            self.verify()

    def test_duplicate_receipt_and_source_replacement_are_rejected(self):
        from peters_mcp.agent_history_antigravity_relations import verify_senders
        with self.assertRaises(EvidenceIssue):
            verify_senders(self.root,self.thread,self.thread.contexts,[self.relation]*2,(SECONDS,0),(SECONDS,1))
        self.step(1,15,message((7,SEND)),origin=PARENT)
        with self.assertRaises(EvidenceIssue):
            self.verify()

    def test_sender_in_other_project_is_rejected_before_trajectory_open(self):
        self.index.execute('UPDATE conversation_summaries SET project_id=?',(str(uuid.UUID(int=909)),))
        self.index.commit()
        native_sqlite=self.root.sqlite
        def only_index(name):
            self.assertEqual('conversation_summaries.db',name)
            return native_sqlite(name)
        with patch.object(self.root,'sqlite',side_effect=only_index), self.assertRaises(EvidenceIssue):
            self.verify()

    def test_core_rechecks_the_policy_for_each_contributing_sender(self):
        projection = Projection((), 'revision', 'identity', related_threads=(CHILD,))
        scope = SimpleNamespace(project='allowed')
        core = AgentHistoryCore(None, None, None, b'')
        for denied, pins in (({CHILD},{}), (set(),{CHILD:'different-project'})):
            source = SimpleNamespace(denied=denied, threads=pins)
            with self.subTest(denied=bool(denied)), self.assertRaises(AccessError) as failure:
                core._binding(scope, source, self.thread, projection)
            self.assertEqual(failure.exception.code, 'unauthorized')

    def test_fork_or_different_native_call_is_rejected(self):
        with self.assertRaises(EvidenceIssue):
            self.verify((*self.relation[:2], '0'*64, *self.relation[3:]))
        self.header(extra=((16,1),))
        with self.assertRaises(EvidenceIssue):
            self.verify()

    def test_child_cannot_receive_a_later_external_continuation(self):
        self.step(1,101,message((3,'agent_message')))
        with self.assertRaises(EvidenceIssue):
            self.verify()
