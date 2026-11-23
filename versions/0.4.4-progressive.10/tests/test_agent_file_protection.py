"""The Agent publisher and listener both anchor existing service privacy paths."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from peters_mcp.agent_file_policy import initialize_agent_file_policy
from peters_mcp.agent_file_protection import build_protections, protected_root_check
from peters_mcp.catalog import AccessError
from peters_mcp.private_roots import PrivateRootRegistry


def document(path, data):
    path.write_text(json.dumps(data))
    path.chmod(0o600)
    return path


class AgentFileProtectionTests(unittest.TestCase):
    def test_legacy_private_and_audit_files_cannot_be_read_through_an_ancestor(self):
        root = Path(self.enterContext(TemporaryDirectory())).resolve()
        installation = root / 'installation'
        private = installation / 'private'
        runtime = installation / 'runtime'
        audit = runtime / 'work'
        history_home = installation / 'legacy-codex'
        control = root / 'control'
        private.mkdir(mode=0o700, parents=True)
        audit.mkdir(mode=0o700, parents=True)
        history_home.mkdir(mode=0o700)
        control.mkdir(mode=0o700)
        old_access = document(private / 'access.json', {'example': 'private canary'})
        (audit / 'remote-audit.jsonl').write_text('private audit canary')
        (history_home / 'sessions.jsonl').write_text('private session canary')
        (installation / 'ordinary.md').write_text('public canary')
        args = SimpleNamespace(
            projects=document(private / 'projects.json', {
                'projects': [{'id': 'broad', 'name': 'Broad installation ancestor', 'root': str(installation)}],
            }),
            legacy_runtime=runtime,
            legacy_access_config=old_access,
            file_config=document(private / 'file.json', {
                'version': 1, 'enabled': False, 'control_directory': str(control), 'spool_roots': [],
                'sources': {}, 'special_exceptions': [], 'min_free_bytes': 0, 'max_workers': 1,
            }),
            history_config=document(private / 'history.json', {'codex_home': str(history_home)}),
            agent_history_config=document(private / 'agent-history.json', {'version': 1, 'sources': {}}),
            state_directory=control / 'agent-read',
            protected_path=[],
        )
        PrivateRootRegistry(control, allowed_roots=()).initialize()
        registry, protections = build_protections(args)
        policy = initialize_agent_file_policy(
            args.projects, args.state_directory,
            check_path=lambda path: protected_root_check(registry, protections, path),
        )
        catalog = policy.catalog_for(policy.snapshot(), private_registry=registry, agent_history_policy=protections)
        self.assertEqual(catalog.read_file('broad', 'ordinary.md')['text'], 'public canary')
        for protected in ('private/access.json', 'runtime/work/remote-audit.jsonl', 'legacy-codex/sessions.jsonl'):
            with self.subTest(protected=protected), self.assertRaises(AccessError) as caught:
                catalog.read_file('broad', protected)
            self.assertEqual(caught.exception.code, 'private_path')
        for protected in (private, runtime, history_home):
            with self.assertRaises(AccessError):
                protected_root_check(registry, protections, protected)
