"""Local preview of finite historical snapshots for an approved directory move."""

from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile

from .agent_history_antigravity import Adapter, INDEX, MAX_INDEX_FIELD_CHARS, _local_workspace, _native_id
from .agent_history_antigravity_native import EvidenceIssue, capture
from .agent_history_source import SourceRoot
from .catalog import AccessError, Catalog
from .fs_identity import persistent_identity_fd


LIMIT = 128


def metadata_digest(thread, alias):
    fields = [thread.native_id, thread.native_project_id, thread.contexts, thread.ancestors,
              thread.ancestor_projects, thread.title, thread.updated_at, thread.agent, thread.surface, alias]
    return hashlib.sha256(json.dumps(fields, ensure_ascii=True, sort_keys=True,
                                     separators=(',', ':')).encode()).hexdigest()


def _bad():
    return AccessError('The historical migration selection is invalid.', code='agent_policy_invalid')


def _time(text):
    if not isinstance(text, str) or not 11 <= len(text) <= 64:
        raise _bad()
    try:
        value = datetime.fromisoformat(text)
        if value.tzinfo is not None:
            return value.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        pass
    raise _bad()


def _cutoff(text):
    value = _time(text)
    if value > datetime.now(timezone.utc):
        raise _bad()
    return value


def _selection(document, source_id, old_root, native_project=None):
    source = document['sources'].get(source_id)
    if not source or source['adapter'] != 'antigravity' or not source['enabled']:
        raise _bad()
    aliases = [a for a in source.get('path_aliases', ()) if a['old_root'] == old_root
               and (native_project is None or a['native_project_id'] == native_project)]
    if len(aliases) != 1:
        raise _bad()
    alias = aliases[0]
    catalog = Catalog._from_document({'projects': document['projects']}, unified=True)
    target = catalog.repositories.discover_all().get(alias['project_id'])
    if not target or not any(row['is_default'] and row['state'] == 'valid' for row in target['worktrees']):
        raise _bad()
    return source, alias, target['fingerprint']


@contextmanager
def _reader(source):
    with tempfile.TemporaryDirectory(prefix='peters-migration-') as scratch:
        root = SourceRoot(Path(source['root']), scratch=Path(scratch).resolve())
        with root.directory() as fd:
            if persistent_identity_fd(fd) != source['root_identity']:
                raise AccessError('The migration source changed.', code='identity_mismatch')
        yield Adapter(root, source['format'])
        with root.directory() as fd:
            if persistent_identity_fd(fd) != source['root_identity']:
                raise AccessError('The migration source changed.', code='identity_mismatch')


def _rows(reader, alias, denied):
    old = alias['old_root']

    def matches(raw):
        try:
            values = json.loads(raw)
            return int(isinstance(values, list) and any(_local_workspace(v) == old for v in values))
        except (TypeError, ValueError, RecursionError):
            return 0
    try:
        with reader.root.sqlite(INDEX) as db:
            reader._index(db)
            db.create_function('migration_path', 1, matches, deterministic=True)
            db.create_function('migration_denied', 1, lambda value: int(value in denied), deterministic=True)
            rows = db.execute('SELECT conversation_id,nesting_depth,parent_conversation_id,'
                              'substr(workspace_uris,1,?) FROM conversation_summaries '
                              'WHERE project_id=? AND migration_path(substr(workspace_uris,1,?)) '
                              'AND NOT migration_denied(conversation_id) ORDER BY conversation_id LIMIT ?',
                              (MAX_INDEX_FIELD_CHARS + 1, alias['native_project_id'], MAX_INDEX_FIELD_CHARS + 1,
                               LIMIT + 1)).fetchall()
    except sqlite3.Error:
        raise AccessError('The source index cannot establish historical project membership.',
                          code='unsupported_format') from None
    if len(rows) > LIMIT:
        raise AccessError('The historical selection exceeds the migration limit.', code='resource_exhausted')
    return rows


def _evidence(reader, thread, alias, fingerprint, cutoff, prior=None):
    if (thread is None or thread.native_project_id != alias['native_project_id']
            or thread.contexts != (alias['old_root'],) or thread.ancestors):
        raise EvidenceIssue('historical_lineage_unverified')
    if _time(thread.updated_at) > cutoff:
        raise EvidenceIssue('updated_after_migration_cutoff')
    if prior is not None and 'migration_metadata_sha256' not in prior:
        # Older reviewed transcript exceptions can still use their original
        # projection and warnings. A path migration must not refresh their cut.
        view = reader.snapshot(thread)
        return {'project_id': alias['project_id'], 'source_identity': view.identity,
                'source_revision': view.revision, 'project_fingerprint': fingerprint}
    _, view = capture(reader, thread)
    if set(view.contexts) != {alias['old_root']} or not view.messages:
        raise EvidenceIssue('historical_workspace_unverified')
    # Native timestamps carry nanoseconds; preserve a conservative closed cutoff.
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    elapsed = cutoff - epoch
    cutoff_ns = ((elapsed.days * 86400 + elapsed.seconds) * 1_000_000 + elapsed.microseconds) * 1000
    if type(view.last_ns) is not int or view.last_ns > cutoff_ns:
        raise EvidenceIssue('updated_after_migration_cutoff')
    return {'project_id': alias['project_id'], 'source_identity': view.identity, 'source_revision': view.revision,
            'project_fingerprint': fingerprint, 'migration_metadata_sha256': metadata_digest(thread, alias)}


def _prior_receipts(document):
    receipts = {}
    for source in (document or {}).get('sources', {}).values():
        if source['adapter'] == 'antigravity':
            for native, evidence in source.get('exceptions', {}).items():
                receipts.setdefault(native, []).append((source, evidence))
    return receipts


def _prior_receipt(refs, source, alias):
    matching = [receipt for former, receipt in refs
                if all(former[key] == source[key] for key in ('instance_id', 'root_identity', 'root', 'format'))
                and alias in former.get('path_aliases', ()) and receipt['project_id'] == alias['project_id']]
    if len(matching) != 1:
        raise EvidenceIssue('previous_approval_drifted')
    return matching[0]


def reviewed_document(document, source_id, old_root, before, *, previous=None, native_project=None):
    """Only the operator's explicit migration preview can propose additional native IDs."""
    result = deepcopy(document)
    cutoff = _cutoff(before)
    source, alias, fingerprint = _selection(result, source_id, old_root, native_project)
    previous_receipts = _prior_receipts(previous)
    exceptions = source.setdefault('exceptions', {})
    former_sources = [former for key, former in (previous or {}).get('sources', {}).items()
                      if former['adapter'] == 'antigravity'
                      and (key == source_id or former['instance_id'] == source['instance_id'])]
    denied = set(source.get('denied_threads', ()))
    for former in former_sources:
        denied.update(former.get('denied_threads', ()))
    if denied:
        source['denied_threads'] = sorted(denied)
    report = {'source_id': source_id, 'old_root': old_root, 'native_project_id': alias['native_project_id'],
              'before': cutoff.isoformat(),
              'proposed': [], 'existing': [], 'pending': []}
    with _reader(source) as reader:
        selected = set()
        rows = _rows(reader, alias, denied)
        top_level_ids = {r[0] for r in rows if type(r[1]) is int and r[1] == 0 and not r[2]}
        for native, depth, parent, raw in rows:
            if not _native_id(native):
                raise _bad()
            # Child subagents of a top-level session in this exact migration batch
            # are verified via capture()'s child-containment check on their parent.
            if type(depth) is int and depth > 0 and parent in top_level_ids:
                continue
            selected.add(native)
            refs = previous_receipts.get(native, ())
            submitted = exceptions.get(native)
            try:
                prior = _prior_receipt(refs, source, alias) if refs else submitted
                if submitted is not None and submitted != prior:
                    raise EvidenceIssue('previous_approval_drifted')
                if type(depth) is not int or depth != 0 or parent:
                    raise EvidenceIssue('historical_parent_requires_review')
                if (not isinstance(raw, str) or len(raw) > MAX_INDEX_FIELD_CHARS
                        or [_local_workspace(v) for v in json.loads(raw)] != [old_root]):
                    raise EvidenceIssue('historical_workspace_unverified')
                evidence = _evidence(reader, reader.describe(native), alias, fingerprint, cutoff, prior)
                if prior is not None and evidence != prior:
                    raise EvidenceIssue('previous_approval_drifted')
                exceptions[native] = evidence
                report['existing' if prior is not None else 'proposed'].append(native)
            except (EvidenceIssue, AccessError) as exc:
                reason = exc.code if isinstance(exc, AccessError) else str(exc)
                if refs or submitted is not None:
                    reason = 'previous_approval_drifted'
                    exceptions.pop(native, None)
                report['pending'].append({'native_id': native, 'reason': reason})
        # If an old receipt was omitted by the template and the index no
        # longer selects its ID, a successful empty scan must not erase it.
        for former in former_sources:
            if not any(a['old_root'] == old_root and a['project_id'] == alias['project_id']
                       for a in former.get('path_aliases', ())):
                continue
            for native, prior in former.get('exceptions', {}).items():
                if (prior['project_id'] == alias['project_id'] and native not in selected and native not in denied
                        and exceptions.get(native) != prior):
                    report['pending'].append({'native_id': native, 'reason': 'previous_approval_drifted'})
    return result, report


def revalidate(document, report):
    """Check only reviewed cuts; later arrivals never enter an approved preview."""
    source, alias, fingerprint = _selection(document, report['source_id'], report['old_root'],
                                           report['native_project_id'])
    cutoff = _cutoff(report['before'])
    with _reader(source) as reader:
        for native in report['proposed'] + report['existing']:
            if native in source.get('denied_threads', ()):
                raise _bad()
            try:
                receipt = source.get('exceptions', {}).get(native)
                current = _evidence(reader, reader.describe(native), alias, fingerprint, cutoff, receipt)
            except (EvidenceIssue, AccessError):
                raise AccessError('An approved historical migration snapshot changed.', code='generation_conflict') from None
            if current != source.get('exceptions', {}).get(native):
                raise AccessError('An approved historical migration snapshot changed.', code='generation_conflict')
