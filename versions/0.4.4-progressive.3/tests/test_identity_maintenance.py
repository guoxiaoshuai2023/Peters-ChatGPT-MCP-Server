"""Offline synthetic migration, durable barriers and phase-aware runtime fallback."""
import copy
from contextlib import redirect_stdout
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import sqlite3
import shutil
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1] / 'tools'
sys.path.insert(0, str(TOOLS))
import identity_maintenance as maintenance
from peters_mcp.fs_identity import persistent_identity
from peters_mcp.workspaces import repository_probe, repository_pin_v1


class FakeHost:
    def __init__(self):
        self.is_disabled, self.is_loaded = False, True
        self.starts, self.stops = 0, 0
        self.pid = 100

    def disabled(self):
        return self.is_disabled

    def loaded(self):
        return self.is_loaded

    def disable(self):
        self.is_disabled = True

    def enable(self):
        self.is_disabled = False

    def quiescent(self, plan):
        if not self.is_disabled or self.is_loaded:
            maintenance.fail('origin_not_persistently_quiescent', 3)

    def stop(self, plan):
        self.stops += 1
        self.disable()
        self.is_loaded = False

    def start(self, plan):
        self.enable()
        self.starts += 1
        self.pid += 1
        self.is_loaded = True

    def matches(self, plan, bundle):
        settings = plistlib.loads(Path(plan['targets']['origin']['path']).read_bytes())
        return self.is_loaded and settings['WorkingDirectory'] == plan['packages'][bundle]['root']

    def identity(self, plan, bundle):
        if not self.matches(plan, bundle):
            maintenance.fail('origin_process_not_selected_bundle', 4)
        return {'boot': maintenance.boot_session_id(), 'pid': self.pid, 'uid': os.getuid(),
                'start_sec': self.pid, 'start_usec': 0}


class Fixture:
    def __init__(self, root):
        self.root = root
        self.control = root / 'control'
        self.spool = root / 'spool'
        self.project = root / 'project'
        for path in (self.control, self.spool, self.project):
            path.mkdir(mode=0o700)
        for name in ('private-roots.lock', 'file-jobs.lock'):
            path = self.control / name
            path.write_bytes(b'')
            path.chmod(0o600)
        self.legacy_payload = self.spool / 'legacy-failed-payload'
        self.legacy_payload.write_bytes(b'preserve original failed attempt')
        self.legacy_payload.chmod(0o600)
        subprocess.run(['/usr/bin/git', 'init', '-q', str(self.project)], check=True, capture_output=True)
        self.old_dev = self.control.stat().st_dev + 17
        probe = repository_probe(self.project)
        old_pin = repository_pin_v1(probe['common'], self.old_dev, probe['common_runtime_identity'][1])
        self.projects = root / 'projects.json'
        self.json(self.projects, {'projects': [{'id': 'synthetic', 'name': 'Synthetic',
                    'root': str(self.project), 'repository_id': old_pin}]})
        identity = lambda path: [self.old_dev, path.stat().st_ino]
        self.manifest = self.control / 'private-roots.json'
        self.json(self.manifest, {'version': 1, 'generation': 4, 'control_identity': identity(self.control),
                  'lock_identity': identity(self.control / 'private-roots.lock'),
                  'roots': [{'path': str(self.spool), 'status': 'active',
                             'parent_identity': identity(self.spool.parent), 'identity': identity(self.spool)}]})
        self.policy = root / 'files.json'
        self.json(self.policy, {'version': 1, 'enabled': True, 'control_directory': str(self.control),
                               'spool_roots': [str(self.spool)]})
        self.access = root / 'access.json'
        self.json(self.access, {'synthetic': True})
        old = root / 'old'
        old.mkdir()
        self.plist = root / (maintenance.LABEL + '.plist')
        settings = {'Label': maintenance.LABEL, 'WorkingDirectory': str(old),
                    'ProgramArguments': [sys.executable, '-B', str(old / 'run_release.py'),
                                         '--access-config', str(self.access), '--config', str(self.projects),
                                         '--file-config', str(self.policy), '--port', '8766'],
                    'KeepAlive': True, 'RunAtLoad': True,
                    'EnvironmentVariables': {'PYTHONDONTWRITEBYTECODE': '1'}}
        self.plist.write_bytes(plistlib.dumps(settings))
        self.plist.chmod(0o600)
        self.database = self.control / 'file-jobs.sqlite3'
        connection = sqlite3.connect(self.database)
        connection.executescript('''CREATE TABLE jobs(id TEXT PRIMARY KEY, actor TEXT NOT NULL,
             request_key TEXT NOT NULL, intent TEXT NOT NULL, body TEXT NOT NULL, UNIQUE(actor,request_key));
             CREATE TABLE ledger(key TEXT PRIMARY KEY,generation INTEGER NOT NULL,valid INTEGER NOT NULL);
             CREATE TABLE requests(job TEXT PRIMARY KEY,cancel_requested INTEGER NOT NULL);
             PRAGMA user_version=1;''')
        for index in range(19):
            row = {'state': 'completed' if index < 16 else 'failed', 'writer_exited': True,
                   'published': index < 16, 'durability': 'confirmed' if index < 16 else 'none',
                   'verification': 'matched' if index < 16 else 'none'}
            connection.execute('INSERT INTO jobs VALUES (?,?,?,?,?)',
                               (str(index), 'actor', str(index), 'intent', json.dumps(row)))
        connection.commit()
        connection.close()
        self.database.chmod(0o600)
        self.host = FakeHost()
        self.snapshot = maintenance.inspect_origin(self.plist, self.host)
        self.packages = root / 'packages'
        self.packages.mkdir()
        for mode in ('candidate', 'rollback'):
            self.package(self.packages / mode, mode)
        self.maintenance = root / 'maintenance'
        self.maintenance.mkdir()
        rows = []
        for name in ('identity_maintenance.py', 'migrate_persistent_identity.py', 'switch_identity_release.py'):
            raw = (TOOLS / name).read_bytes()
            (self.maintenance / name).write_bytes(raw)
            rows.append({'path': name, 'bytes': len(raw), 'sha256': maintenance.sha(raw)})
        self.json(self.maintenance / 'manifest.json', {'format_version': 1, 'python': list(sys.version_info[:2]),
                  'dependencies': {mode: maintenance.package_info(self.packages / mode)['fingerprint'] for mode in ('candidate', 'rollback')},
                  'files': rows})
        self.plan = maintenance.make_plan(self.snapshot, self.packages / 'candidate', self.packages / 'rollback',
                                          self.maintenance / 'manifest.json', 'synthetic-operation')
        self.digest = maintenance.sha(maintenance.canonical(self.plan))
        self.plan_path = root / 'plan.json'
        self.json(self.plan_path, self.plan)
        self.initial_database = self.database.read_bytes()

    def json(self, path, value):
        path.write_bytes(maintenance.canonical(value))
        path.chmod(0o600)

    def package(self, root, mode):
        root.mkdir()
        files = {'run_release.py': b'# synthetic launcher\n'}
        for name in ('cloudflare', 'private_roots', 'fs_identity', 'workspaces', 'file_jobs', 'file_config'):
            files['peters_mcp/' + name + '.py'] = b'# synthetic package metadata fixture\n'
        files['peters_mcp/_file_release_mode.py'] = ('# Generated immutable release mode.\nINSPECTION_ONLY = ' +
              ('True' if mode == 'rollback' else 'False') + '\nREQUIRE_PRIVATE_CONFIG = True\n').encode()
        rows = []
        for name, raw in sorted(files.items()):
            path = root / name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(raw)
            rows.append({'path': name, 'bytes': len(raw), 'sha256': maintenance.sha(raw)})
        self.json(root / 'manifest.json', {'bundle_mode': mode, 'files': rows,
                  'content_fingerprint': maintenance.sha(maintenance.canonical(rows)), 'require_private_config': True})

    def migrated(self):
        maintenance.switch_stop(self.plan, self.digest, self.host)
        return maintenance.migration_apply(self.plan, self.digest, self.host)

    def started(self, switch='initial'):
        self.migrated()
        return maintenance.runtime_switch(self.plan, self.digest, 'candidate', switch, self.host)

    def receipt(self, challenge, switch):
        root = Path(self.plan['packages'][challenge['bundle']]['root'])
        work = root / 'work'
        work.mkdir(exist_ok=True)
        audit = {'time': datetime.now(timezone.utc).isoformat(), 'tool': 'list_projects', 'ok': True}
        line = json.dumps(audit).encode()
        (work / 'remote-audit.jsonl').write_bytes(line + b'\n')
        path = self.root / ('health-' + switch + '.json')
        self.json(path, {**challenge, 'authenticated': True, 'tool': 'list_projects', 'ok': True,
                        'received_at_unix': time.time(), 'audit_record_sha256': maintenance.sha(line),
                        'result': {'projects': [{'id': 'synthetic'}]}})
        return path


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='identity-maintenance-')
        self.addCleanup(self.temporary.cleanup)
        self.fixture = Fixture(Path(self.temporary.name).resolve())
        self.addCleanup(setattr, maintenance, 'FAULT', None)

    def test_full_migration_retains_database_and_protected_objects(self):
        f = self.fixture
        before = {path: path.stat().st_ino for path in (f.control, f.control / 'private-roots.lock', f.control / 'file-jobs.lock', f.spool)}
        result = f.migrated()
        self.assertEqual(result['state'], 'committed')
        self.assertEqual(f.database.read_bytes(), f.initial_database)
        self.assertEqual({path: path.stat().st_ino for path in before}, before)
        self.assertFalse((f.control / maintenance.PENDING).exists())
        self.assertEqual(json.loads(f.manifest.read_bytes())['version'], 2)
        self.assertTrue(json.loads(f.projects.read_bytes())['projects'][0]['repository_id'].startswith('git-v2-'))
        self.assertTrue(maintenance.migration_verify(f.plan, f.digest, f.host)['verified'])
        self.assertTrue(maintenance.migration_apply(f.plan, f.digest, f.host)['idempotent'])

    def test_external_disable_is_not_adopted_without_owned_stop_journal(self):
        f = self.fixture
        f.host.stop(f.plan)
        with self.assertRaisesRegex(maintenance.MaintenanceError, 'owned_maintenance_intent_required'):
            maintenance.migration_apply(f.plan, f.digest, f.host)
        for target in f.plan['targets'].values():
            self.assertEqual(maintenance.sha(Path(target['path']).read_bytes()), target['sha256'])
        self.assertFalse((f.control / maintenance.PENDING).exists())
        self.assertEqual(f.database.read_bytes(), f.initial_database)
        self.assertTrue(f.host.disabled())

    def test_native_disabled_word_and_boolean_formats_are_strictly_parsed(self):
        host = maintenance.LaunchCtl()
        for value, expected in [('disabled', True), ('enabled', False), ('true', True), ('false', False)]:
            with self.subTest(value=value), patch.object(host, 'command', return_value=SimpleNamespace(
                    stdout='disabled services = {\n "' + maintenance.LABEL + '" => ' + value + '\n}\n')):
                self.assertEqual(host.disabled(), expected)
        with patch.object(host, 'command', return_value=SimpleNamespace(stdout='disabled services = {}\n')):
            self.assertFalse(host.disabled())
        with patch.object(host, 'command', return_value=SimpleNamespace(stdout='"' + maintenance.LABEL + '" => unknown\n')):
            with self.assertRaisesRegex(maintenance.MaintenanceError, 'origin_disabled_state_unverifiable'):
                host.disabled()

    def test_start_waits_for_real_process_and_listener_instead_of_only_loaded_label(self):
        f = self.fixture
        f.migrated()
        host = maintenance.LaunchCtl()
        connection = SimpleNamespace(settimeout=lambda value: None, connect_ex=lambda value: 0)
        with patch.object(host, 'enable') as enable, patch.object(host, 'disable') as disable, \
                patch.object(host, 'command', return_value=SimpleNamespace(returncode=0)), \
                patch.object(host, 'loaded', return_value=True), \
                patch.object(host, 'identity', side_effect=[maintenance.MaintenanceError('origin_running_pid_unconfirmed'),
                                                         {'pid': 123}]) as identity, \
                patch.object(maintenance.socket, 'socket') as socket_factory, patch.object(maintenance.time, 'sleep'):
            socket_factory.return_value.__enter__.return_value = connection
            host.start(f.plan)
        self.assertEqual(identity.call_count, 2)
        enable.assert_called_once()
        disable.assert_not_called()

    def test_known_owned_pre_target_stop_can_resume_with_new_frozen_plan(self):
        f = self.fixture
        previous_operation = maintenance.ensure_operation(f.plan, f.digest)
        maintenance.journal_append(previous_operation / 'journal.jsonl', 'MAINTENANCE_INTENT', f.digest,
                                   original_effective_enabled=True)
        f.host.stop(f.plan)  # Stop succeeded, parser failure interrupted its receipt.
        snapshot = maintenance.inspect_origin(f.plist, f.host, f.plan_path, f.digest)
        resumed = maintenance.make_plan(snapshot, f.packages / 'candidate', f.packages / 'rollback',
                                        f.maintenance / 'manifest.json', 'resumed-owned-operation')
        digest = maintenance.sha(maintenance.canonical(resumed))
        for role, target in f.plan['targets'].items():
            self.assertEqual(resumed['targets'][role]['sha256'], target['sha256'])
            self.assertEqual(resumed['targets'][role]['after_sha256'], target['after_sha256'])
        def crash(name):
            if name == 'after_sync:journal:MAINTENANCE_INTENT':
                raise RuntimeError('new intent durable, prior stop not retired')
        maintenance.FAULT = crash
        with self.assertRaises(RuntimeError):
            maintenance.switch_stop(resumed, digest, f.host)
        maintenance.FAULT = None
        maintenance.switch_stop(resumed, digest, f.host)
        self.assertIn('SUPERSEDED_BEFORE_TARGETS', maintenance.events(previous_operation / 'journal.jsonl'))
        self.assertEqual(maintenance.migration_apply(resumed, digest, f.host)['state'], 'committed')
        self.assertEqual(f.database.read_bytes(), f.initial_database)
        with self.assertRaisesRegex(maintenance.MaintenanceError, 'maintenance_operation_superseded'):
            maintenance.require_owned_maintenance(f.plan, f.digest)

    def test_owned_resume_cannot_adopt_external_stop_or_changed_targets(self):
        f = self.fixture
        f.host.stop(f.plan)
        with self.assertRaises((maintenance.MaintenanceError, OSError)):
            maintenance.inspect_origin(f.plist, f.host, f.plan_path, f.digest)
        operation = maintenance.ensure_operation(f.plan, f.digest)
        maintenance.journal_append(operation / 'journal.jsonl', 'MAINTENANCE_INTENT', f.digest,
                                   original_effective_enabled=True)
        f.json(f.projects, {'projects': []})
        with self.assertRaisesRegex(maintenance.MaintenanceError, 'owned_stop_targets_not_before'):
            maintenance.inspect_origin(f.plist, f.host, f.plan_path, f.digest)

    def test_owned_resume_cannot_change_after_bytes_or_equal_fingerprint_package_path(self):
        f = self.fixture
        operation = maintenance.ensure_operation(f.plan, f.digest)
        maintenance.journal_append(operation / 'journal.jsonl', 'MAINTENANCE_INTENT', f.digest,
                                   original_effective_enabled=True)
        f.host.stop(f.plan)
        snapshot = maintenance.inspect_origin(f.plist, f.host, f.plan_path, f.digest)
        duplicate = f.root / 'candidate-copy'
        shutil.copytree(f.packages / 'candidate', duplicate)
        self.assertEqual(maintenance.package_info(duplicate)['fingerprint'], f.plan['packages']['candidate']['fingerprint'])
        with self.assertRaisesRegex(maintenance.MaintenanceError, 'owned_stop_resume_scope_changed'):
            maintenance.make_plan(snapshot, duplicate, f.packages / 'rollback', f.maintenance / 'manifest.json', 'bad-resume')
        resumed = maintenance.make_plan(snapshot, f.packages / 'candidate', f.packages / 'rollback',
                                        f.maintenance / 'manifest.json', 'scope-bound-resume')
        changed = copy.deepcopy(resumed)
        settings = plistlib.loads(maintenance.decoded(changed['definitions']['candidate']['raw']))
        settings['KeepAlive'] = False
        changed['definitions']['candidate']['raw'] = maintenance.encoded(plistlib.dumps(settings))
        changed['definitions']['candidate']['sha256'] = maintenance.sha(plistlib.dumps(settings))
        with self.assertRaisesRegex(maintenance.MaintenanceError, 'owned_stop_resume_scope_changed'):
            maintenance.switch_stop(changed, maintenance.sha(maintenance.canonical(changed)), f.host)
        for target in f.plan['targets'].values():
            self.assertEqual(maintenance.sha(Path(target['path']).read_bytes()), target['sha256'])

    def test_intent_without_completed_disable_requires_stop_recovery(self):
        f = self.fixture
        operation = maintenance.ensure_operation(f.plan, f.digest)
        maintenance.journal_append(operation / 'journal.jsonl', 'MAINTENANCE_INTENT', f.digest,
                                   original_effective_enabled=True)
        f.host.stop(f.plan)
        with self.assertRaisesRegex(maintenance.MaintenanceError, 'owned_disable_phase_required'):
            maintenance.migration_apply(f.plan, f.digest, f.host, recover=True)
        maintenance.switch_stop(f.plan, f.digest, f.host)
        self.assertEqual(maintenance.migration_apply(f.plan, f.digest, f.host)['state'], 'committed')

    def test_marker_is_durable_before_first_replace(self):
        f = self.fixture
        trace = []
        maintenance.FAULT = trace.append
        f.migrated()
        self.assertLess(trace.index('after_sync:' + maintenance.PENDING), trace.index('before_replace:' + f.plist.name))
        self.assertLess(trace.index('after_create:' + maintenance.PENDING), trace.index('before_replace:' + f.plist.name))
        self.assertLess(trace.index('after_sync:journal:PREPARED'), trace.index('before_replace:' + f.plist.name))

    def test_marker_before_prepared_crash_recovers(self):
        f = self.fixture
        maintenance.switch_stop(f.plan, f.digest, f.host)
        def crash(name):
            if name == 'after_create:' + maintenance.PENDING:
                raise RuntimeError('synthetic crash')
        maintenance.FAULT = crash
        with self.assertRaisesRegex(RuntimeError, 'synthetic crash'):
            maintenance.migration_apply(f.plan, f.digest, f.host)
        maintenance.FAULT = None
        self.assertTrue((f.control / maintenance.PENDING).exists())
        self.assertNotIn('PREPARED', maintenance.events(Path(f.plan['operation_directory']) / 'journal.jsonl'))
        self.assertEqual(maintenance.migration_apply(f.plan, f.digest, f.host, recover=True)['state'], 'committed')

    def test_visible_commit_record_is_synced_before_pending_is_removed(self):
        f = self.fixture
        maintenance.switch_stop(f.plan, f.digest, f.host)
        def crash(name):
            if name == 'before_sync:journal:COMMITTED':
                raise RuntimeError('commit visible but not synced')
        maintenance.FAULT = crash
        with self.assertRaises(RuntimeError):
            maintenance.migration_apply(f.plan, f.digest, f.host)
        self.assertTrue((f.control / maintenance.PENDING).exists())
        def barrier_failure(name):
            if name == 'before_sync:confirm:journal.jsonl':
                raise RuntimeError('recovery journal confirmation interrupted')
        maintenance.FAULT = barrier_failure
        with self.assertRaises(RuntimeError):
            maintenance.migration_apply(f.plan, f.digest, f.host, recover=True)
        self.assertTrue((f.control / maintenance.PENDING).exists())
        trace = []
        maintenance.FAULT = trace.append
        self.assertEqual(maintenance.migration_apply(f.plan, f.digest, f.host, recover=True)['state'], 'committed')
        self.assertLess(trace.index('after_sync:confirm:journal.jsonl'), trace.index('before_sync:pending_removed'))

    def test_existing_frozen_plan_and_activation_get_durable_barriers(self):
        f = self.fixture
        def plan_failure(name):
            if name == 'before_sync:plan.json':
                raise RuntimeError('plan visible not synced')
        maintenance.FAULT = plan_failure
        with self.assertRaises(RuntimeError):
            maintenance.switch_stop(f.plan, f.digest, f.host)
        trace = []
        maintenance.FAULT = trace.append
        maintenance.switch_stop(f.plan, f.digest, f.host)
        self.assertLess(trace.index('after_sync:confirm:plan.json'), trace.index('before_sync:journal:MAINTENANCE_INTENT'))
        maintenance.FAULT = None
        maintenance.migration_apply(f.plan, f.digest, f.host)
        def activation_failure(name):
            if name == 'before_sync:activation.json':
                raise RuntimeError('activation visible not synced')
        maintenance.FAULT = activation_failure
        with self.assertRaises(RuntimeError):
            maintenance.runtime_switch(f.plan, f.digest, 'candidate', 'initial', f.host)
        trace = []
        maintenance.FAULT = trace.append
        maintenance.runtime_switch(f.plan, f.digest, 'candidate', 'initial', f.host, recover=True)
        self.assertLess(trace.index('after_sync:confirm:activation.json'), trace.index('before_sync:journal:READY_TO_ENABLE'))

    def test_visible_old_retirement_is_synced_before_new_disable_authority(self):
        f = self.fixture
        previous = maintenance.ensure_operation(f.plan, f.digest)
        maintenance.journal_append(previous / 'journal.jsonl', 'MAINTENANCE_INTENT', f.digest,
                                   original_effective_enabled=True)
        f.host.stop(f.plan)
        snapshot = maintenance.inspect_origin(f.plist, f.host, f.plan_path, f.digest)
        resumed = maintenance.make_plan(snapshot, f.packages / 'candidate', f.packages / 'rollback',
                                        f.maintenance / 'manifest.json', 'retire-barrier-resume')
        digest = maintenance.sha(maintenance.canonical(resumed))
        def retire_failure(name):
            if name == 'before_sync:journal:SUPERSEDED_BEFORE_TARGETS':
                raise RuntimeError('retirement visible not synced')
        maintenance.FAULT = retire_failure
        with self.assertRaises(RuntimeError):
            maintenance.switch_stop(resumed, digest, f.host)
        trace = []
        maintenance.FAULT = trace.append
        maintenance.switch_stop(resumed, digest, f.host)
        self.assertLess(trace.index('after_sync:confirm_parent:' + previous.name),
                        trace.index('before_sync:journal:DISABLED'))
        maintenance.FAULT = None
        self.assertEqual(maintenance.migration_apply(resumed, digest, f.host)['state'], 'committed')

    def test_existing_pending_marker_is_confirmed_before_prepared(self):
        f = self.fixture
        maintenance.switch_stop(f.plan, f.digest, f.host)
        def marker_failure(name):
            if name == 'before_sync:' + maintenance.PENDING:
                raise RuntimeError('pending visible not synced')
        maintenance.FAULT = marker_failure
        with self.assertRaises(RuntimeError):
            maintenance.migration_apply(f.plan, f.digest, f.host)
        trace = []
        maintenance.FAULT = trace.append
        maintenance.migration_apply(f.plan, f.digest, f.host, recover=True)
        self.assertLess(trace.index('after_sync:confirm:' + maintenance.PENDING),
                        trace.index('before_sync:journal:PREPARED'))

    def test_each_partial_target_replace_recovers_without_database_restore(self):
        # A real child exits without finally/atexit, releasing OS locks only.
        f = self.fixture
        maintenance.switch_stop(f.plan, f.digest, f.host)
        script = '''import os,sys,json
from pathlib import Path
sys.path.insert(0,sys.argv[1]);import identity_maintenance as m
plan=json.loads(Path(sys.argv[2]).read_bytes());digest=m.sha(m.canonical(plan))
class Host:
 def quiescent(self,plan):pass
def crash(name):
 if name==sys.argv[3]:os._exit(29)
m.FAULT=crash
m.migration_apply(plan,digest,Host())
'''
        result = subprocess.run([sys.executable, '-B', '-c', script, str(TOOLS), str(f.plan_path),
                                 'after_replace:' + f.manifest.name], capture_output=True, text=True)
        self.assertEqual(result.returncode, 29, result.stderr)
        self.assertTrue((f.control / maintenance.PENDING).exists())
        self.assertEqual(maintenance.migration_apply(f.plan, f.digest, f.host, recover=True)['state'], 'committed')
        self.assertEqual(f.database.read_bytes(), f.initial_database)

    def test_other_target_crash_points_and_lost_unsynced_marker(self):
        for role in ('origin', 'projects'):
            with self.subTest(role=role), tempfile.TemporaryDirectory(prefix='identity-crash-') as name:
                f = Fixture(Path(name).resolve())
                maintenance.switch_stop(f.plan, f.digest, f.host)
                target_name = Path(f.plan['targets'][role]['path']).name
                def crash(point):
                    if point == 'after_replace:' + target_name:
                        raise RuntimeError('synthetic crash')
                maintenance.FAULT = crash
                with self.assertRaises(RuntimeError):
                    maintenance.migration_apply(f.plan, f.digest, f.host)
                maintenance.FAULT = None
                self.assertEqual(maintenance.migration_apply(f.plan, f.digest, f.host, recover=True)['state'], 'committed')
                self.assertEqual(f.database.read_bytes(), f.initial_database)
        f = self.fixture
        maintenance.switch_stop(f.plan, f.digest, f.host)
        def marker_crash(point):
            if point == 'after_sync:' + maintenance.PENDING:
                raise RuntimeError('marker parent entry not synced')
        maintenance.FAULT = marker_crash
        with self.assertRaises(RuntimeError):
            maintenance.migration_apply(f.plan, f.digest, f.host)
        maintenance.FAULT = None
        # Simulate losing the last unsynced marker directory entry, while the
        # prior backup barrier and all BEFORE inputs survive.
        (f.control / maintenance.PENDING).unlink()
        self.assertEqual(maintenance.migration_apply(f.plan, f.digest, f.host, recover=True)['state'], 'committed')

    def test_locked_verification_does_not_release_private_exclusion(self):
        f = self.fixture
        f.migrated()
        original = maintenance.validate_manifest_v2
        blocked = []
        def validate(*args, **kwargs):
            script = '''import sys,os,fcntl
fd=os.open(sys.argv[1],os.O_RDONLY)
try:fcntl.flock(fd,fcntl.LOCK_SH|fcntl.LOCK_NB)
except BlockingIOError:sys.exit(23)
sys.exit(0)
'''
            result = subprocess.run([sys.executable, '-B', '-c', script, str(f.control / 'private-roots.lock')])
            blocked.append(result.returncode == 23)
            return original(*args, **kwargs)
        with patch.object(maintenance, 'validate_manifest_v2', side_effect=validate):
            maintenance.migration_verify(f.plan, f.digest, f.host)
        self.assertEqual(blocked, [True])

    def test_legacy_spool_changes_are_not_adopted(self):
        f = self.fixture
        maintenance.switch_stop(f.plan, f.digest, f.host)
        f.legacy_payload.write_bytes(b'changed after approval')
        with self.assertRaisesRegex(maintenance.MaintenanceError, 'legacy_spool_scene_changed'):
            maintenance.migration_apply(f.plan, f.digest, f.host)
        for target in f.plan['targets'].values():
            self.assertEqual(maintenance.sha(Path(target['path']).read_bytes()), target['sha256'])
        self.assertFalse((f.control / maintenance.PENDING).exists())

    def test_ready_and_health_reject_changed_disk_startup_definition(self):
        f = self.fixture
        challenge = f.started()
        receipt = f.receipt(challenge, 'initial')
        settings = plistlib.loads(f.plist.read_bytes())
        settings['KeepAlive'] = False
        f.plist.write_bytes(plistlib.dumps(settings))
        # The selected process is still alive with its old launchctl definition;
        # disk bytes are independently authoritative for the next boot.
        with self.assertRaisesRegex(maintenance.MaintenanceError, 'runtime_input_not_approved:origin'):
            maintenance.runtime_switch(f.plan, f.digest, 'candidate', 'initial', f.host, recover=True)
        self.assertTrue(f.host.disabled())
        f.host.is_loaded, f.host.is_disabled = True, False
        with self.assertRaisesRegex(maintenance.MaintenanceError, 'runtime_input_not_approved:origin'):
            maintenance.attest_health(f.plan, f.digest, 'initial', receipt, f.host)
        self.assertTrue(f.host.disabled())
        self.assertFalse(f.host.loaded())

    def test_ready_health_and_healthy_shortcuts_reject_other_changed_inputs(self):
        f = self.fixture
        challenge = f.started()
        receipt = f.receipt(challenge, 'initial')
        changed = json.loads(f.projects.read_bytes())
        changed['projects'][0]['name'] = 'changed after approval'
        f.json(f.projects, changed)
        with self.assertRaisesRegex(maintenance.MaintenanceError, 'runtime_input_not_approved:projects'):
            maintenance.runtime_switch(f.plan, f.digest, 'candidate', 'initial', f.host, recover=True)
        self.assertTrue(f.host.disabled())
        f.host.is_loaded, f.host.is_disabled = True, False
        with self.assertRaisesRegex(maintenance.MaintenanceError, 'runtime_input_not_approved:projects'):
            maintenance.attest_health(f.plan, f.digest, 'initial', receipt, f.host)
        self.assertTrue(f.host.disabled())
        f.projects.write_bytes(maintenance.decoded(f.plan['targets']['projects']['after']))
        challenge = maintenance.runtime_switch(f.plan, f.digest, 'candidate', 'initial', f.host, recover=True)
        receipt = f.receipt(challenge, 'initial')
        maintenance.attest_health(f.plan, f.digest, 'initial', receipt, f.host)
        f.json(f.access, {'changed': True})
        with self.assertRaisesRegex(maintenance.MaintenanceError, 'nonmigration_configuration_changed'):
            maintenance.runtime_switch(f.plan, f.digest, 'candidate', 'initial', f.host)
        self.assertTrue(f.host.disabled())

    def test_launchctl_definition_and_native_argv_require_exact_arguments(self):
        f = self.fixture
        f.migrated()
        expected = plistlib.loads(maintenance.decoded(f.plan['definitions']['candidate']['raw']))
        def printed(arguments, cwd):
            return ('service = {\n\tprogram = ' + expected['ProgramArguments'][0] +
                    '\n\targuments = {\n' + ''.join('\t\t' + value + '\n' for value in arguments) +
                    '\t}\n\tworking directory = ' + cwd + '\n\tpid = 123\n}\n')
        host = maintenance.LaunchCtl()
        raw = printed(expected['ProgramArguments'], expected['WorkingDirectory'] + '-unapproved')
        with patch.object(host, 'command', return_value=SimpleNamespace(returncode=0, stdout=raw)):
            self.assertFalse(host.matches(f.plan, 'candidate'))
        raw = printed(expected['ProgramArguments'], expected['WorkingDirectory'])
        changed = list(expected['ProgramArguments'])
        changed[2] += '-unapproved'
        with patch.object(host, 'command', return_value=SimpleNamespace(returncode=0, stdout=raw)), \
                patch.object(host, 'process_arguments', return_value=(expected['ProgramArguments'][0], changed)), \
                patch('peters_mcp.file_receiver.process_identity', return_value={'pid': 123}):
            self.assertTrue(host.matches(f.plan, 'candidate'))
            with self.assertRaisesRegex(maintenance.MaintenanceError, 'origin_process_command_mismatch'):
                host.identity(f.plan, 'candidate')
        changed_pid = raw.replace('pid = 123', 'pid = 124')
        with patch.object(host, 'command', side_effect=[SimpleNamespace(returncode=0, stdout=raw),
                                                       SimpleNamespace(returncode=0, stdout=changed_pid)]), \
                patch.object(host, 'process_arguments', return_value=(expected['ProgramArguments'][0], expected['ProgramArguments'])), \
                patch('peters_mcp.file_receiver.process_identity', return_value={'pid': 123}):
            with self.assertRaisesRegex(maintenance.MaintenanceError, 'origin_process_command_mismatch'):
                host.identity(f.plan, 'candidate')
        arguments = [sys.executable, '-B', '-c', 'import time;time.sleep(5)']
        process = subprocess.Popen(arguments)
        try:
            executable, actual = maintenance.LaunchCtl.process_arguments(process.pid)
            self.assertEqual(actual, arguments)
            self.assertEqual(Path(executable).resolve(), Path(sys.executable).resolve())
        finally:
            process.terminate()
            process.wait(timeout=5)

    def test_replaced_jobs_lock_is_not_adopted(self):
        f = self.fixture
        maintenance.switch_stop(f.plan, f.digest, f.host)
        path = f.control / 'file-jobs.lock'
        path.unlink()
        path.write_bytes(b'')
        path.chmod(0o600)
        with self.assertRaises(maintenance.MaintenanceError):
            maintenance.migration_apply(f.plan, f.digest, f.host)

    def test_same_stable_identity_device_renumbering_is_accepted(self):
        f = self.fixture
        original = maintenance.object_info
        def changed(path):
            result = original(path)
            result['runtime'][0] += 100
            return result
        with patch.object(maintenance, 'object_info', changed):
            maintenance.check_anchors(f.plan)

    def test_two_operators_cannot_change_launchctl_concurrently(self):
        f = self.fixture
        with maintenance.operator_lock(f.plan, f.digest):
            script = '''import sys,json,fcntl,os
from pathlib import Path
plan=json.loads(Path(sys.argv[1]).read_bytes())
p=Path(plan['control_directory'])/'identity-repair/maintenance.lock'
fd=os.open(p,os.O_RDWR)
try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
except BlockingIOError:sys.exit(23)
sys.exit(0)
'''
            result = subprocess.run([sys.executable, '-B', '-c', script, str(f.plan_path)])
            self.assertEqual(result.returncode, 23)

    def test_bad_health_receipt_disables_origin(self):
        f = self.fixture
        challenge = f.started()
        path = f.receipt(challenge, 'initial')
        data = json.loads(path.read_bytes())
        data['authenticated'] = False
        f.json(path, data)
        with self.assertRaises(maintenance.MaintenanceError):
            maintenance.attest_health(f.plan, f.digest, 'initial', path, f.host)
        self.assertTrue(f.host.disabled())
        self.assertFalse(f.host.loaded())

    def test_health_is_bound_to_switch_process_nonce_and_origin_audit(self):
        f = self.fixture
        challenge = f.started()
        path = f.receipt(challenge, 'initial')
        self.assertEqual(maintenance.attest_health(f.plan, f.digest, 'initial', path, f.host)['state'], 'healthy')
        # A later process cannot inherit a prior process's HEALTHY receipt.
        f.host.pid += 1
        new_challenge = maintenance.runtime_switch(f.plan, f.digest, 'candidate', 'initial', f.host, recover=True)
        self.assertNotEqual(new_challenge['health_nonce'], challenge['health_nonce'])
        with self.assertRaises(maintenance.MaintenanceError):
            maintenance.attest_health(f.plan, f.digest, 'initial', path, f.host)
        self.assertTrue(f.host.disabled())

    def test_live_ready_and_healthy_journal_sync_failures_stop_origin(self):
        f = self.fixture
        challenge = f.started()
        receipt = f.receipt(challenge, 'initial')
        for healthy in (False, True):
            if healthy:
                maintenance.attest_health(f.plan, f.digest, 'initial', receipt, f.host)
            for which in (1, 2):
                with self.subTest(healthy=healthy, journal=which):
                    seen = []
                    def io_failure(name):
                        if name in {'before_sync:confirm:journal.jsonl', 'before_sync:confirm:initial.jsonl'}:
                            seen.append(name)
                            if len(seen) == which:
                                raise OSError(5, 'synthetic sync failure')
                    maintenance.FAULT = io_failure
                    with self.assertRaises(OSError):
                        maintenance.runtime_switch(f.plan, f.digest, 'candidate', 'initial', f.host, recover=True)
                    self.assertTrue(f.host.disabled())
                    self.assertFalse(f.host.loaded())
                    maintenance.FAULT = None
                    # Restore only this synthetic process identity/state; the
                    # real product must obtain a new authenticated receipt.
                    f.host.is_disabled, f.host.is_loaded = False, True

    def test_runtime_fallback_keeps_new_task_and_legacy_rows(self):
        f = self.fixture
        f.started()
        connection = sqlite3.connect(f.database)
        row = {'state': 'completed', 'writer_exited': True, 'published': True,
               'durability': 'confirmed', 'verification': 'matched'}
        connection.execute('INSERT INTO jobs VALUES(?,?,?,?,?)', ('new-job', 'actor', 'new-key', 'new-intent', json.dumps(row)))
        connection.commit()
        connection.close()
        self.assertNotEqual(f.database.read_bytes(), f.initial_database)
        challenge = maintenance.runtime_switch(f.plan, f.digest, 'rollback', 'fallback', f.host)
        receipt = f.receipt(challenge, 'fallback')
        maintenance.attest_health(f.plan, f.digest, 'fallback', receipt, f.host)
        self.assertEqual(maintenance.database_snapshot(f.database)['count'], 20)
        before = f.host.starts
        repeated = maintenance.runtime_switch(f.plan, f.digest, 'rollback', 'fallback', f.host)
        self.assertTrue(repeated['idempotent'])
        self.assertEqual(f.host.starts, before)
        # Migration recovery cannot stop or rewrite a valid active runtime.
        self.assertEqual(maintenance.migration_apply(f.plan, f.digest, f.host, recover=True)['state'], 'committed_runtime_active')
        self.assertTrue(f.host.loaded())

    def test_runtime_recover_at_ready_disabled_enabled_and_already_loaded(self):
        f = self.fixture
        f.migrated()
        def crash(name):
            if name == 'after_sync:journal:READY_TO_ENABLE':
                raise RuntimeError('synthetic crash')
        maintenance.FAULT = crash
        with self.assertRaises(RuntimeError):
            maintenance.runtime_switch(f.plan, f.digest, 'candidate', 'initial', f.host)
        maintenance.FAULT = None
        self.assertTrue(f.host.disabled())
        f.host.enable()  # Simulate interruption between enable and bootstrap.
        challenge = maintenance.runtime_switch(f.plan, f.digest, 'candidate', 'initial', f.host, recover=True)
        self.assertEqual(challenge['state'], 'awaiting_authenticated_health')
        starts = f.host.starts
        same = maintenance.runtime_switch(f.plan, f.digest, 'candidate', 'initial', f.host, recover=True)
        self.assertEqual(same['health_nonce'], challenge['health_nonce'])
        self.assertEqual(f.host.starts, starts)

    def test_documented_recover_command_infers_rollback_bundle(self):
        f = self.fixture
        f.started()
        def crash(name):
            if name == 'after_sync:journal:READY_TO_ENABLE':
                raise RuntimeError('fallback interruption')
        maintenance.FAULT = crash
        with self.assertRaises(RuntimeError):
            maintenance.runtime_switch(f.plan, f.digest, 'rollback', 'fallback', f.host)
        maintenance.FAULT = None
        self.assertTrue(f.host.disabled())
        output = io.StringIO()
        command = ['recover', '--plan', str(f.plan_path), '--expected-plan-sha256', f.digest,
                   '--switch-id', 'fallback', '--mode', 'complete', '--apply']
        with patch.object(maintenance, 'LaunchCtl', return_value=f.host), redirect_stdout(output):
            maintenance.switch_main(command)
        result = json.loads(output.getvalue())
        self.assertEqual(result['bundle'], 'rollback')
        self.assertTrue(f.host.matches(f.plan, 'rollback'))

    def test_visible_desired_rename_is_resynced_before_ready(self):
        f = self.fixture
        f.started()
        def crash(name):
            if name == 'before_sync:target_parent:' + f.plist.name:
                raise RuntimeError('rename visible but not synced')
        maintenance.FAULT = crash
        with self.assertRaises(RuntimeError):
            maintenance.runtime_switch(f.plan, f.digest, 'rollback', 'fallback', f.host)
        maintenance.FAULT = None
        self.assertEqual(maintenance.sha(f.plist.read_bytes()), f.plan['definitions']['rollback']['sha256'])
        trace = []
        maintenance.FAULT = trace.append
        maintenance.runtime_switch(f.plan, f.digest, 'rollback', 'fallback', f.host, recover=True)
        self.assertLess(trace.index('after_sync:existing_target:' + f.plist.name),
                        trace.index('after_sync:target_parent:' + f.plist.name))
        self.assertLess(trace.index('after_sync:target_parent:' + f.plist.name),
                        trace.index('before_sync:journal:READY_TO_ENABLE'))
        self.assertTrue(f.host.matches(f.plan, 'rollback'))

    def test_extra_importable_package_and_maintenance_files_rejected(self):
        f = self.fixture
        extra = f.packages / 'candidate/peters_mcp/unapproved.py'
        extra.write_text('# unapproved\n')
        with self.assertRaisesRegex(maintenance.MaintenanceError, 'unapproved_release_file'):
            maintenance.package_info(f.packages / 'candidate')
        extra.unlink()
        (f.maintenance / 'unapproved.py').write_text('# unapproved\n')
        with self.assertRaisesRegex(maintenance.MaintenanceError, 'unapproved_maintenance_file'):
            maintenance.verify_maintenance(f.maintenance / 'manifest.json')

    def test_unknown_schema_and_backup_corruption_block_recovery(self):
        f = self.fixture
        maintenance.switch_stop(f.plan, f.digest, f.host)
        operation = Path(f.plan['operation_directory'])
        with maintenance.Lease(f.plan, f.digest, f.host):
            maintenance.backup(f.plan, f.digest, operation)
        (operation / 'baseline.json').unlink()
        with self.assertRaises((maintenance.MaintenanceError, OSError)):
            maintenance.check_backups(f.plan, f.digest, operation)
        f.migrated()
        connection = sqlite3.connect(f.database)
        connection.execute('CREATE TABLE unapproved(x)')
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(maintenance.MaintenanceError, 'job_database_schema_changed'):
            maintenance.verify_database(f.plan, False)


if __name__ == '__main__':
    unittest.main()
