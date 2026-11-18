"""Historical receipt lookup against real temporary jobs; no production state."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, ExitStack
import copy
from dataclasses import replace
import hashlib
import json
import threading
import unittest
from unittest.mock import patch

from peters_mcp.catalog import AccessError
from peters_mcp import file_jobs, file_source
from tests import test_file_jobs as fixture

ACTOR = fixture.ACTOR
OTHER_BOOT = '00000000-0000-4000-8000-000000000002'


class FileReceiptReplayTests(unittest.TestCase):
    setUp = fixture.FileJobTests.setUp
    close_services = fixture.FileJobTests.close_services
    service = fixture.FileJobTests.service
    arguments = fixture.FileJobTests.arguments

    def completed(self, *, size=32, expected=True):
        service = self.service()
        pattern = b'\x00\xffsynthetic\r\n'
        payload = (pattern * (size // len(pattern) + 1))[:size]
        args = self.arguments(service, size=size,
                              expected=hashlib.sha256(payload).hexdigest() if expected else None)
        job = service.submit(**args)['job_id']
        service._run(job)
        self.assertTrue(service.status(ACTOR, job_id=job)['saved'])
        return service, args, job

    @staticmethod
    def changed(args, *, host='files.example.invalid'):
        return {**args, 'file': {**args['file'], 'file_id': 'new-actual-selection',
                                'download_url': 'https://' + host + '/new-object?signature=NEW_SECRET'}}

    def replace_body(self, service, row):
        with service._db_lock, service.db:
            service.db.execute('UPDATE jobs SET body=? WHERE id=?',
                               (file_jobs._json(row), row['job_id']))

    def snapshot(self, service):
        with service._db_lock:
            tables = {table: tuple(service.db.execute('SELECT * FROM ' + table + ' ORDER BY 1'))
                      for table in ('jobs', 'requests', 'ledger')}
            changes = service.db.total_changes
        files = tuple((str(path.relative_to(self.root)), hashlib.sha256(path.read_bytes()).hexdigest())
                      for path in sorted(self.root.rglob('*')) if path.is_file())
        return (tables, changes, files, copy.deepcopy(service._sources), dict(service._claims),
                dict(service._active), dict(service._handles), service._thread)

    @contextmanager
    def no_effects(self, service):
        before = self.snapshot(service)
        with ExitStack() as stack:
            for name in ('_put', '_authorize', '_grant_versions', '_policy', '_continuation_guard',
                         'refresh_source', '_receiver', '_run', '_run_claimed', 'start'):
                stack.enter_context(patch.object(service, name, side_effect=AssertionError(name)))
            stack.enter_context(patch.object(service._pool, 'submit', side_effect=AssertionError('worker')))
            stack.enter_context(patch.object(file_jobs.ReceiverHandle, 'spawn', side_effect=AssertionError('receiver')))
            stack.enter_context(patch.object(file_source, '_address', side_effect=AssertionError('source approval/DNS')))
            stack.enter_context(patch.object(file_source.socket, 'getaddrinfo', side_effect=AssertionError('DNS')))
            stack.enter_context(patch.object(file_source.socket, 'create_connection', side_effect=AssertionError('network')))
            yield
        self.assertEqual(self.snapshot(service), before)

    def conflict(self, service, args):
        with self.assertRaises(AccessError) as caught:
            service.submit(**args)
        self.assertEqual(caught.exception.code, 'idempotency_conflict')
        diagnostics = caught.exception.idempotency_diagnostics
        self.assertEqual(set(diagnostics), {'selection_changed', 'nonselection_intent_matches',
                                             'completed_bound_hash_matches'})
        self.assertTrue(all(type(value) is bool for value in diagnostics.values()))
        self.assertNotIn('SECRET', str(caught.exception))
        self.assertNotIn('new-actual-selection', repr(diagnostics))
        return diagnostics

    def test_changed_native_selection_returns_only_nested_original_receipt_without_effects(self):
        service, args, job = self.completed()
        original = service.status(ACTOR, job_id=job)
        new = self.changed(args)
        self.assertNotEqual(file_source.source_identity(args['file']), file_source.source_identity(new['file']))
        with self.no_effects(service):
            result = service.submit(**new)
        self.assertEqual(result, {'operation': 'receipt_lookup', 'subject': 'original_job',
            'match_kind': 'completed_bound_hash', 'job_id': job, 'original_job_status': original,
            'submitted_reference': {'received': False, 'content_verified': False,
                                    'source_policy': 'not_evaluated_no_transfer'}, 'new_job_created': False})
        for field in ('saved', 'published', 'expected_hash_matched', 'bytes',
                      'download_sha256', 'destination_sha256', 'destination_display'):
            self.assertNotIn(field, result)
            self.assertNotIn(field, result['submitted_reference'])

    def test_changed_unapproved_host_is_metadata_only_and_new_transfer_remains_denied(self):
        service, args, job = self.completed()
        new = self.changed(args, host='unapproved.example.invalid')
        new['file']['file_id'] = args['file']['file_id']  # Only the hostname changes selection.
        with self.no_effects(service):
            self.assertEqual(service.submit(**new)['job_id'], job)
        service._receiver = file_source.receive_file
        fresh = self.arguments(service, name='new-receive.bin', key='new-receive', expected=args['expected_sha256'])
        accepted = service.submit(**{**fresh, 'file': new['file']})
        service._run(accepted['job_id'])
        self.assertEqual(service.status(ACTOR, job_id=accepted['job_id'])['error_code'], 'source_not_approved')
        self.assertFalse((self.repo / fresh['path']).exists())

    def test_strict_retry_and_url_only_change_keep_flat_response(self):
        service, args, job = self.completed()
        original = service.status(ACTOR, job_id=job)
        with self.no_effects(service):
            self.assertEqual(service.submit(**args), original)
            self.assertEqual(service.submit(**{**args, 'file': {**args['file'],
                'download_url': 'https://files.example.invalid/a-different-path?q=NEW_SECRET'}}), original)
            self.conflict(service, {**args, 'expected_size_bytes': 1})

    def test_zero_byte_bound_is_valid(self):
        service, args, job = self.completed(size=0)
        with self.no_effects(service):
            result = service.submit(**self.changed(args))
        self.assertEqual(result['job_id'], job)
        self.assertEqual(result['original_job_status']['bytes'], 0)
        self.assertEqual(result['original_job_status']['download_sha256'], hashlib.sha256(b'').hexdigest())

    def test_receipt_does_not_claim_to_verify_the_current_destination(self):
        service, args, _ = self.completed()
        destination = self.repo / args['path']
        destination.write_bytes(b'a later local replacement')
        with self.no_effects(service), patch.object(file_jobs, '_hash_fd', side_effect=AssertionError('current bytes')):
            result = service.submit(**self.changed(args))
        status = result['original_job_status']
        self.assertEqual(status['current_target_observation'], 'not_checked')
        self.assertEqual(status['destination_sha256'], args['expected_sha256'])
        self.assertNotEqual(hashlib.sha256(destination.read_bytes()).hexdigest(), status['destination_sha256'])

    def test_nonselection_changes_and_display_mismatch_cannot_lookup(self):
        service, args, _ = self.completed()
        for field, value in (('project_id', 'other'), ('worktree_id', 'other'), ('path', 'other.bin'),
                             ('target_version', '0' * 64), ('destination_display', args['destination_display'] + '.other'),
                             ('expected_sha256', '0' * 64), ('expected_size_bytes', 31),
                             ('expected_sha256', None), ('expected_size_bytes', None)):
            with self.subTest(field=field, value=value), self.no_effects(service):
                diagnostics = self.conflict(service, {**self.changed(args), field: value})
                self.assertFalse(diagnostics['nonselection_intent_matches'])

    def test_original_unbound_hash_and_length_are_ineligible(self):
        service, args, job = self.completed(expected=False)
        with self.no_effects(service):
            self.conflict(service, self.changed(args))
        row = service._get(job)
        bound_hash = row['complete']['download_sha256']
        row['expected_sha256'] = bound_hash
        row['expected_size_bytes'] = None
        row['intent'] = file_jobs._digest([1, args['project_id'], args['worktree_id'], args['path'],
            args['target_version'], row['source_selection'], bound_hash, None])
        with service._db_lock, service.db:
            service.db.execute('UPDATE jobs SET intent=?,body=? WHERE id=?',
                               (row['intent'], file_jobs._json(row), job))
        with self.no_effects(service):
            self.conflict(service, {**self.changed(args), 'expected_sha256': bound_hash,
                                   'expected_size_bytes': None})

    def test_original_success_and_receipt_fields_fail_closed(self):
        service, args, job = self.completed()
        baseline = service._get(job)
        changes = [({'published': value}, None) for value in (False, 'unknown', 1)]
        changes += [({'writer_exited': value}, None) for value in (False, 1, None)]
        changes += [({'state': value}, None) for value in ('queued', 'receiving', 'failed', 'publication_unverified')]
        changes += [({'durability': 'pending'}, None), ({'verification': 'pending'}, None),
                    ({'destination_sha256': '0' * 64}, None), ({'expected_size_bytes': True}, None),
                    ({'normalization_version': True}, None), ({'normalization_version': 2}, None),
                    ({'source_revision': True}, None)]
        changes += [({}, (field, value)) for field, value in (
            ('bytes', 31), ('bytes', True), ('download_sha256', '0' * 64),
            ('protocol_complete', 1), ('file_fsynced', False), ('writer_exit_verified', 1),
            ('receive_complete_persisted', False), ('expected_hash_matched', 1),
            ('source_revision', True), ('attempt', 'another-attempt'),
            ('expected_hash_provenance', 'other'), ('source_evidence_kind', 'reference_only'))]
        for row_changes, receipt_change in changes:
            with self.subTest(row=row_changes, receipt=receipt_change):
                row = copy.deepcopy(baseline)
                row.update(row_changes)
                if receipt_change:
                    row['complete'][receipt_change[0]] = receipt_change[1]
                self.replace_body(service, row)
                with self.no_effects(service):
                    self.conflict(service, self.changed(args))

    def test_missing_and_unsupported_stored_shapes_fail_closed(self):
        service, args, job = self.completed()
        baseline = service._get(job)
        for field in ('normalization_version', 'source_selection', 'complete', 'writer_exited', 'intent',
                      'expected_sha256', 'expected_size_bytes', 'destination_sha256', 'runtime_epoch'):
            with self.subTest(missing=field):
                row = copy.deepcopy(baseline)
                row.pop(field)
                self.replace_body(service, row)
                with self.no_effects(service):
                    self.conflict(service, self.changed(args))
        for field in ('bytes', 'download_sha256', 'protocol_complete', 'file_fsynced',
                      'writer_exit_verified', 'receive_complete_persisted', 'expected_hash_matched',
                      'source_revision', 'attempt', 'expected_hash_provenance', 'source_evidence_kind'):
            with self.subTest(missing_receipt=field):
                row = copy.deepcopy(baseline)
                row['complete'].pop(field)
                self.replace_body(service, row)
                with self.no_effects(service):
                    self.conflict(service, self.changed(args))
        for selection in (None, [], {'selection_sha256': '0' * 64},
                          {**baseline['source_selection'], 'extra': False},
                          {**baseline['source_selection'], 'content_identity_verified': 0},
                          {**baseline['source_selection'], 'source_evidence_kind': 'other'}):
            with self.subTest(selection=selection):
                row = copy.deepcopy(baseline)
                row['source_selection'] = selection
                self.replace_body(service, row)
                with self.no_effects(service):
                    self.conflict(service, self.changed(args))

    def test_bound_sql_identity_and_original_target_must_be_coherent(self):
        service, args, job = self.completed()
        baseline = service._get(job)
        for field, value in (('actor', 'b' * 64), ('key', '0' * 64), ('job_id', '0' * 32),
                             ('intent', '0' * 64)):
            row = {**copy.deepcopy(baseline), field: value}
            with service._db_lock, service.db:
                service.db.execute('UPDATE jobs SET body=? WHERE id=?', (file_jobs._json(row), job))
            with self.subTest(field=field), self.no_effects(service):
                self.conflict(service, self.changed(args))
        row = copy.deepcopy(baseline)
        row['target']['path'] = 'other.bin'
        self.replace_body(service, row)
        with self.no_effects(service):
            self.conflict(service, self.changed(args))

    def test_other_actor_cannot_borrow_the_original_job(self):
        service, args, job = self.completed()
        other = self.arguments(service, name='other.bin', key=args['request_key'])
        other['actor'] = 'b' * 64
        own_job = service.submit(**other)['job_id']
        with self.no_effects(service):
            self.conflict(service, {**self.changed(args), 'actor': other['actor']})
            self.assertEqual(service.submit(**other)['job_id'], own_job)
            with self.assertRaisesRegex(AccessError, 'not_found'):
                service.status(other['actor'], job_id=job)

    def test_strict_failed_and_unfinished_retries_stay_flat_but_changed_selection_conflicts(self):
        service = self.service()
        args = self.arguments(service, expected='0' * 64)
        job = service.submit(**args)['job_id']
        for run in (False, True):
            if run:
                service._run(job)
                self.assertEqual(service.status(ACTOR, job_id=job)['state'], 'failed')
            with self.no_effects(service):
                strict = service.submit(**args)
                self.assertEqual(strict['job_id'], job)
                self.assertNotIn('operation', strict)
                self.conflict(service, self.changed(args))

    def test_stale_epoch_denies_lookup_while_status_and_strict_replay_stay_available(self):
        service, args, job = self.completed()
        with patch.object(file_jobs, 'boot_session_id', return_value=OTHER_BOOT), self.no_effects(service):
            self.conflict(service, self.changed(args))
            self.assertTrue(service.status(ACTOR, job_id=job)['saved'])
            self.assertEqual(service.submit(**args)['job_id'], job)
        row = service._get(job)
        row['runtime_epoch']['format'] = True
        self.replace_body(service, row)
        with self.no_effects(service):
            self.conflict(service, self.changed(args))

    def test_target_revocation_protection_and_parent_boundary_deny_without_ledger_changes(self):
        service, args, _ = self.completed()
        project = self.catalog.projects['repo']
        for changed_project in (replace(project, exclude=('nested/*',)), None):
            self.catalog.projects.clear()
            if changed_project:
                self.catalog.projects['repo'] = changed_project
            with self.no_effects(service):
                self.conflict(service, self.changed(args))
        self.catalog.projects['repo'] = project
        service.targets.protected_paths = (self.repo / 'nested',)
        with self.no_effects(service):
            self.conflict(service, self.changed(args))
        service.targets.protected_paths = ()
        (self.repo / 'nested' / '.git').mkdir()
        with self.no_effects(service):
            self.conflict(service, self.changed(args))

    def test_private_guard_and_status_redaction_are_fail_closed(self):
        service, args, _ = self.completed()
        with patch.object(service.registry, 'read_guard', side_effect=AccessError('private unavailable')), \
                self.no_effects(service):
            self.conflict(service, self.changed(args))
        revalidate = service.targets.revalidate
        calls = 0

        def deny_status_only(target):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise AccessError('target revoked during status projection')
            return revalidate(target)

        with patch.object(service.targets, 'revalidate', side_effect=deny_status_only), self.no_effects(service):
            self.conflict(service, self.changed(args))
        self.assertEqual(calls, 2)

    def test_invalid_new_native_reference_is_rejected_before_lookup(self):
        service, args, _ = self.completed()
        for reference in ({'file_id': 'new', 'download_url': 'http://files.example.invalid/a'},
                          {'file_id': '', 'download_url': 'https://files.example.invalid/a'},
                          {'file_id': 'new', 'download_url': 'https://user:secret@files.example.invalid/a'},
                          {**args['file'], 'unexpected': True}):
            with self.subTest(reference=reference), self.no_effects(service):
                with self.assertRaisesRegex(AccessError, 'invalid_file_reference'):
                    service.submit(**{**args, 'file': reference})

    def test_simultaneous_compatible_retries_make_no_jobs_claims_or_workers(self):
        service, args, job = self.completed()
        barrier = threading.Barrier(2)

        def submit():
            barrier.wait(5)
            return service.submit(**self.changed(args))

        with self.no_effects(service), ThreadPoolExecutor(max_workers=2) as pool:
            results = [future.result(10) for future in [pool.submit(submit), pool.submit(submit)]]
        self.assertEqual([result['job_id'] for result in results], [job, job])
        self.assertTrue(all(result['operation'] == 'receipt_lookup' for result in results))

    def test_completion_boundary_denies_then_reads_without_receiving_or_taking_over(self):
        service = self.service()
        pattern = b'\x00\xffsynthetic\r\n'
        payload = (pattern * 3)[:32]
        args = self.arguments(service, expected=hashlib.sha256(payload).hexdigest())
        job = service.submit(**args)['job_id']
        reached, release = threading.Event(), threading.Event()

        def pause(phase, current):
            if phase == 'receive_complete' and current == job:
                reached.set()
                self.assertTrue(release.wait(10))

        service.fault_hook = pause
        worker = threading.Thread(target=service._run, args=(job,))
        worker.start()
        try:
            self.assertTrue(reached.wait(10))
            self.assertEqual(service._get(job)['state'], 'ready_to_publish')
            with self.no_effects(service):
                self.conflict(service, self.changed(args))
                self.assertEqual(service.submit(**args)['job_id'], job)
        finally:
            release.set()
        worker.join(10)
        self.assertFalse(worker.is_alive())
        self.assertTrue(service.status(ACTOR, job_id=job)['saved'])
        with self.no_effects(service):
            self.assertEqual(service.submit(**self.changed(args))['job_id'], job)


if __name__ == '__main__':
    unittest.main()
