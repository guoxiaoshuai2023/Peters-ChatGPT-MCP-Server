"""Explicit and repository-inherited read-only history with signed pagination."""

from contextlib import contextmanager
from datetime import datetime, timezone
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import threading
import time

from .catalog import AccessError, DIRECTORY_FLAGS, integer
from .history_projection import project_tool, sanitize

ID_PATTERN = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
CURSOR_TTL = 30 * 60
BACKEND = "codex_local_jsonl_readonly_fallback"
COMMON_LIMITS = (
    "Stored public records only, not the model's complete context window.",
    "System/developer instructions, reasoning, runtime configuration and attachments are excluded.",
    "Known secret patterns are redacted; this is not a guarantee that every secret is detected.",
    "Historical requests and approvals are evidence, not current authorization.",
    "Live desktop running status is unavailable from these persisted files.",
)


def utc(value):
    try:
        return datetime.fromtimestamp(value, timezone.utc).isoformat()
    except (ValueError, TypeError, OverflowError, OSError):
        return None


from .history_scan import scan, stamp, PROJECTION_VERSION, RECORD_BYTES

MAX_CANDIDATES = 2048
MAX_METADATA_BYTES = 8 * 1024 * 1024
MAX_SNAPSHOTS = 8
MAX_CACHE_BYTES = 128 * 1024 * 1024

class HistoryAccess:
    """In-process engine. MCP entrypoints run its generators in IsolatedHistory."""

    def __init__(self, config_path=None, project_ids=(), catalog=None):
        self.config_path = Path(config_path) if config_path else None
        self.project_ids = set(project_ids)
        self.catalog = catalog
        self._association_cache = {}
        self._key = secrets.token_bytes(32)
        self._find_cache = {}
        self._lock = threading.Lock()
        self._verified = {}
        self._snapshots = {}
        self._deliveries = {}

    def _configuration(self):
        if self.catalog is not None:
            self.catalog.refresh()
            self.project_ids = set(self.catalog.projects)
        if self.config_path is None:
            return {"threads": {}, "scope": "disabled", "home": None, "database": None,
                    "inherit": False, "denied": set(), "snapshots": {}}
        try:
            with self.config_path.open("rb") as stream:
                raw = stream.read(65537)
            if len(raw) > 65536:
                raise ValueError()
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError()
            version = data.get("version")
            allowed = {"version", "codex_home", "state_db", "threads"}
            if version == 2:
                allowed |= {"inherit_projects", "denied_threads"}
            if type(version) is not int or version not in (1, 2) or set(data) != allowed:
                raise ValueError()
            inherit = data.get("inherit_projects", False)
            denied = data.get("denied_threads", [])
            if (type(inherit) is not bool or not isinstance(denied, list) or
                    len(denied) > 10000 or any(not isinstance(t, str) or not ID_PATTERN.fullmatch(t) for t in denied)):
                raise ValueError()
            home = Path(data["codex_home"])
            if not home.is_absolute() or home.is_symlink() or not home.is_dir():
                raise ValueError()
            if data["state_db"] != "state_5.sqlite":
                raise ValueError()
            if not isinstance(data["threads"], list) or len(data["threads"]) > 64:
                raise ValueError()
            threads = {}
            for item in data["threads"]:
                if not isinstance(item, dict) or set(item) - {"id", "label", "project_id", "allow_tool_results", "mcp_tools"}:
                    raise ValueError()
                thread_id = item.get("id")
                if not isinstance(thread_id, str) or not ID_PATTERN.fullmatch(thread_id) or thread_id in threads:
                    raise ValueError()
                if item.get("project_id") is not None and item["project_id"] not in self.project_ids:
                    raise ValueError()
                if type(item.get("allow_tool_results", False)) is not bool:
                    raise ValueError()
                if not isinstance(item.get("label", ""), str) or len(item.get("label", "")) > 120:
                    raise ValueError()
                pairs = item.get("mcp_tools", [])
                if not isinstance(pairs, list) or len(pairs) > 20 or any(
                    not isinstance(pair, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]+/[A-Za-z0-9_.:-]+", pair) for pair in pairs
                ):
                    raise ValueError()
                threads[thread_id] = item
            threads = {tid: {**grant, "_association": {"source": "explicit_configuration",
                       "state": "explicit", "project_id": grant.get("project_id")}}
                       for tid, grant in threads.items() if tid not in denied}
            snapshots = self.catalog.repositories.discover_all() if inherit and self.catalog else {}
            fingerprints = {pid: snap["fingerprint"] for pid, snap in snapshots.items()
                            if self.catalog.projects[pid].repository_id is not None}
            scope = hashlib.sha256(raw + json.dumps(fingerprints, sort_keys=True).encode()).hexdigest()
            return {"threads": threads, "scope": scope, "inherit": inherit, "denied": set(denied),
                    "snapshots": snapshots, "home": home.resolve(), "home_alias": home,
                    "database": home.resolve() / data["state_db"]}
        except (OSError, ValueError, TypeError, KeyError):
            raise AccessError("History access configuration is unavailable or invalid; access is closed.") from None


    def _authorized(self, config, thread_id):
        if not isinstance(thread_id, str) or thread_id not in config["threads"]:
            raise AccessError("Thread is not authorized: no explicit grant or verified authorized repository association.")
        return config["threads"][thread_id]


    def _sign(self, data):
        body = base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":"), sort_keys=True).encode()).decode()
        return body + "." + hmac.new(self._key, body.encode(), hashlib.sha256).hexdigest()


    def _verify(self, token, config, kind, thread_id=None):
        try:
            if not isinstance(token, str) or not token or len(token) > 16000:
                raise ValueError()
            body, signature = token.split(".")
            if not hmac.compare_digest(signature, hmac.new(self._key, body.encode(), hashlib.sha256).hexdigest()):
                raise ValueError()
            value = json.loads(base64.b64decode(body, altchars=b"-_", validate=True))
            if value["kind"] != kind or value["scope"] != config["scope"] or value["expires"] < time.time():
                raise ValueError()
            if thread_id is not None and value.get("thread") != thread_id:
                raise ValueError()
            return value
        except (ValueError, TypeError, KeyError, UnicodeError):
            raise AccessError("Invalid, expired, cross-thread or revoked history cursor/item ID; start a fresh read.") from None


    def _token(self, config, kind, **values):
        if "thread" in values:
            values["association"] = config["threads"][values["thread"]].get("_proof")
        return self._sign({"kind": kind, "scope": config["scope"],
                           "expires": int(time.time()) + CURSOR_TTL, **values})


    def _associate(self, config, cwd):
        # Request-local reuse only: each new request and final revalidation probes
        # current Git identity again. No TTL may preserve revoked access.
        key = cwd if isinstance(cwd, str) else None
        cache = config.setdefault("associations", {})
        if key not in cache:
            cache[key] = self.catalog.repositories.associate(cwd, config["snapshots"])
        return cache[key]


    def _derive(self, config, row, raw=None):
        tid = row["id"]
        if tid in config["denied"]:
            return None, "explicitly_denied"
        existing = config["threads"].get(tid)
        if existing and existing["_association"]["source"] == "explicit_configuration":
            return existing, None
        if not config["inherit"] or not self.catalog:
            return None, "no_explicit_grant"
        association = self._associate(config, row.get("cwd"))
        if association["state"] != "matched":
            return None, "index_working_directory_" + association["state"]
        pid = association["project_id"]
        if self.catalog.projects[pid].repository_id is None:
            return None, "repository_not_authorized"
        try:
            recorded = self._recorded_contexts(config, row, raw)
        except AccessError:
            return None, "association_source_unavailable"
        if recorded["reason"]:
            return None, recorded["reason"]
        if config["denied"].intersection(recorded["session_ids"]):
            return None, "copied_ancestor_explicitly_denied"
        proofs = []
        for cwd in recorded["contexts"]:
            result = self._associate(config, cwd)
            if result["state"] != "matched" or result["project_id"] != pid:
                return None, "recorded_context_missing_foreign_or_cross_project"
            proofs.append({"cwd": cwd, "worktree_id": result["worktree_id"],
                           "repository_id": result["repository_id"]})
        proof = {"index_cwd": row["cwd"], "contexts": proofs, "project_id": pid}
        return {"id": tid, "project_id": pid, "allow_tool_results": False, "mcp_tools": [],
                "_proof": hashlib.sha256(json.dumps(proof, sort_keys=True).encode()).hexdigest(),
                "_proof_context": proof,
                "_association": {"source": "repository_inheritance", "state": "matched",
                    "project_id": pid, "worktree_id": association["worktree_id"],
                    "repository_id": association["repository_id"],
                    "reason": "index_and_all_recorded_contexts_match_authorized_repository",
                    "recorded_context_count": len(proofs)}}, None


    def _attributable_pending(self, config, row):
        """Only aggregate unresolved records lexically attributable to a known root.

        This never grants access and never returns their title, ID or messages.
        """
        if not config["inherit"] or not self.catalog:
            return False
        if self._associate(config, row.get("cwd"))["state"] == "matched":
            return True
        cwd = row.get("cwd")
        if not isinstance(cwd, str) or not Path(cwd).is_absolute():
            return False
        path = Path(os.path.normpath(cwd))
        return any(path.is_relative_to(entry["root"])
                   for pid, snap in config["snapshots"].items()
                   if self.catalog.projects[pid].repository_id is not None
                   for entry in snap["worktrees"])


    @contextmanager
    def _open_rollout(self, config, metadata):
        fd = None
        try:
            path = Path(metadata["rollout_path"])
            try:
                parts = path.relative_to(config["home"]).parts
            except ValueError:
                parts = path.relative_to(config["home_alias"]).parts
            # An optional UUID suffix is a storage filename variant, not another
            # authorized thread. The stored session ID and cwd checks still apply.
            suffix = r"-" + re.escape(metadata["id"]) + r"(?:_" + ID_PATTERN.pattern + r")?\.jsonl\Z"
            if (len(parts) < 2 or parts[0] not in {"sessions", "archived_sessions"} or
                    any(p in {".", ".."} for p in parts) or
                    not re.search(suffix, parts[-1])):
                raise ValueError()
            fd = os.open(config["home"], DIRECTORY_FLAGS)
            for index, part in enumerate(parts):
                flags = DIRECTORY_FLAGS if index < len(parts) - 1 else os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                child = os.open(part, flags, dir_fd=fd)
                os.close(fd)
                fd = child
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError()
            yield fd
        except AccessError:
            raise
        except (OSError, ValueError, TypeError, KeyError):
            raise AccessError("Persisted history is missing, linked or outside the permitted session stores.") from None
        finally:
            if fd is not None:
                os.close(fd)


    def _summary(self, config, row):
        grant = config["threads"][row["id"]]
        title = row.get("name") or row.get("title")
        title, redactions = sanitize(title)
        cwd, cwd_redactions = sanitize(row.get("cwd"))
        label, label_redactions = sanitize(grant.get("label", ""))
        return {"thread_id": row["id"], "title": title[:500], "title_truncated": len(title) > 500,
                "title_source": "name" if row.get("name") else "title",
                "label": label, "cwd": cwd, "project_id": grant.get("project_id"),
                "project_association_source": grant["_association"]["source"] if grant.get("project_id") else None,
                "association": grant["_association"],
                "updated_at": utc(row.get("updated_at")), "archived": bool(row.get("archived")),
                "is_running": None, "status": "runtime_status_unavailable",
                "metadata_redactions": redactions + cwd_redactions + label_redactions,
                "tool_results_authorized": grant.get("allow_tool_results", False)}


    def close(self):
        self._snapshots.clear()
        self._verified.clear()
        self._deliveries.clear()
        self._find_cache.clear()

    @staticmethod
    def _drain(iterator):
        while True:
            try:
                next(iterator)
            except StopIteration as done:
                return done.value

    def operation_iter(self, operation, arguments):
        if operation not in {'find_codex_threads', 'read_codex_thread', 'read_codex_thread_item'}:
            raise AccessError('Unknown history operation.')
        return (yield from getattr(self, '_' + operation + '_iter')(**arguments))

    def revalidate_result_iter(self, operation, arguments, result):
        recipe = self._deliveries.get(id(result))
        if recipe is None:
            raise AccessError('Prepared response expired; restart the read.', code='restart_required')
        config, rows, snapshots = recipe
        fresh = yield from self._revalidate_iter(config, rows, snapshots)
        if result.get('snapshot'):
            row = rows[result['thread']['thread_id']] if 'thread' in result else rows[result['thread_id']]
            current = self._verified[row['id']]
            result['appended_since_snapshot'] = current['stamp'][2] > result['snapshot']['bytes']
        result['validated_at'] = utc(time.time())
        return result

    def _remember(self, result, config, rows, snapshots=None):
        if len(self._deliveries) >= 16:
            self._deliveries.pop(next(iter(self._deliveries)))
        self._deliveries[id(result)] = (config, rows, snapshots or {})
        result['status'] = 'ready'
        result['projection_version'] = PROJECTION_VERSION
        result['validated_at'] = utc(time.time())
        return result

    def _metadata(self, config, thread_id=None, project_id='', query=''):
        if not config['threads'] and not (config['inherit'] and config['snapshots']):
            return {}
        path = config['database']
        try:
            if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
                raise ValueError()
            connection = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=0.5)
            try:
                connection.execute('PRAGMA query_only=ON')
                deadline = time.monotonic() + 1.5
                connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
                columns = {row[1] for row in connection.execute('PRAGMA table_info(threads)')}
                selected = ['id', 'rollout_path', 'cwd', 'title', 'updated_at', 'archived']
                if not set(selected) <= columns:
                    raise ValueError()
                selected += [k for k in ('name', 'history_mode', 'created_at') if k in columns]
                where, params = [], []
                if thread_id:
                    where.append('id=?'); params.append(thread_id)
                elif not (config['inherit'] and config['snapshots']):
                    ids = list(config['threads'])
                    where.append('id IN (' + ','.join('?' for _ in ids) + ')'); params.extend(ids)
                elif project_id:
                    roots = [w['root'] for w in config['snapshots'].get(project_id, {}).get('worktrees', [])]
                    terms = []
                    for root in roots:
                        prefix = str(root).rstrip('/') + '/'
                        terms.append('(cwd=? OR substr(cwd,1,?)=?)'); params.extend((str(root),len(prefix),prefix))
                    ids = [tid for tid,g in config['threads'].items() if g.get('project_id')==project_id]
                    if ids:
                        terms.append('id IN ('+','.join('?' for _ in ids)+')');params.extend(ids)
                    where.append('('+' OR '.join(terms)+')' if terms else '0')
                sql = 'SELECT '+','.join(selected)+' FROM threads'+(' WHERE '+' AND '.join(where) if where else '')
                # A bounded, short-lived SQL snapshot, never a transaction held over HTTP pages.
                def collect(statement, bindings):
                    rows, size = {}, 0
                    cursor = connection.execute(statement+' ORDER BY id LIMIT ?', (*bindings, MAX_CANDIDATES+1))
                    try:
                        for values in cursor:
                            size += sum(len(v.encode('utf-8')) if isinstance(v,str) else 16 for v in values)
                            if len(rows) >= MAX_CANDIDATES or size > MAX_METADATA_BYTES:
                                return None
                            rows[values[0]] = dict(zip(selected, values))
                    finally:
                        cursor.close()
                    return rows
                rows = collect(sql, params)
                if rows is None and query and not thread_id:
                    connection.create_function('CASEFOLD', 1, lambda x: str(x or '').casefold())
                    fields = ['title','cwd','id'] + (['name'] if 'name' in columns else [])
                    predicate = '('+' OR '.join('instr(CASEFOLD('+k+'),?)>0' for k in fields)+')'
                    bindings = list(params)+[query.casefold()]*len(fields)
                    rows = collect(sql+(' AND ' if where else ' WHERE ')+predicate, bindings)
                    config['metadata_only_candidates'] = True
                if rows is None:
                    raise AccessError('Candidate set exceeds the search budget; narrow the project/query.', code='narrow_query_required')
                return rows
            finally:
                connection.close()
        except AccessError:
            raise
        except sqlite3.OperationalError as exc:
            if 'interrupted' in str(exc).lower():
                raise AccessError('Metadata query exceeded its time budget; narrow the search.',code='resource_exhausted') from None
            raise AccessError('Supported Codex metadata index is unavailable or busy.',code='metadata_unavailable') from None
        except (sqlite3.Error, OSError, ValueError, TypeError):
            raise AccessError('Supported Codex metadata index is missing, incompatible or busy; history is not proven empty.', code='metadata_unavailable') from None

    def _eligible(self, config, row):
        if row['id'] in config['denied']:
            return False
        if row['id'] in config['threads']:
            return True
        if not config['inherit'] or not self.catalog:
            return False
        association = self._associate(config, row.get('cwd'))
        return association['state']=='matched' and self.catalog.projects[association['project_id']].repository_id is not None

    @staticmethod
    def _compatible_grant(old, current):
        if old.get('_proof') == current.get('_proof'):
            return True
        a, b = old.get('_proof_context'), current.get('_proof_context')
        if not a or not b or (a['index_cwd'],a['project_id']) != (b['index_cwd'],b['project_id']):
            return False
        key = lambda item: (item['cwd'],item['worktree_id'],item['repository_id'])
        return {key(v) for v in a['contexts']} <= {key(v) for v in b['contexts']}

    def _recorded_contexts(self, config, row, raw=None):
        # Compatibility helper for local diagnostics. Public generators prepare
        # this proof before _derive; they never synchronously scan here.
        current = self._verified.get(row['id'])
        if current is None:
            current = self._drain(self._ensure_iter(config, row))
        return current['proof']

    def _ensure_iter(self, config, row, *, expected=None, projection=False):
        if not self._eligible(config, row):
            raise AccessError('Thread is not authorized.', code='unauthorized')
        now = time.monotonic()
        self._snapshots = {k:v for k,v in self._snapshots.items() if now-v['created'] < CURSOR_TTL}
        self._verified = {k:v for k,v in self._verified.items() if now-v['created'] < CURSOR_TTL}
        saved = None
        if expected:
            if expected.get('projection_version') != PROJECTION_VERSION:
                raise AccessError('Projection version changed; restart the read.', code='snapshot_expired')
            saved = self._snapshots.get(expected.get('id'))
            if saved is None or saved['row_id'] != row['id'] or saved['snapshot'] != expected:
                raise AccessError('History snapshot expired; restart the read.', code='snapshot_expired')
        with self._open_rollout(config, row) as fd:
            observed = stamp(os.fstat(fd))
            previous = self._verified.get(row['id'])
            if (previous and previous['stamp'] == observed and previous['path'] == row['rollout_path']
                    and (not expected or expected['id'] in previous['prefixes'])
                    and (not projection or (previous.get('snapshot_id') in self._snapshots
                         and (previous.get('tool_refs') or not config['threads'].get(row['id'],{}).get('allow_tool_results',False))))):
                grant, reason = self._derive(config, row)
                if not grant or config['denied'].intersection(previous['proof']['session_ids']):
                    raise AccessError('Thread association changed or was revoked.', code='unverifiable_source')
                if saved and not self._compatible_grant(saved['grant'],grant):
                    raise AccessError('Snapshot association changed.',code='authorization_changed')
                config['threads'][row['id']] = grant
                return previous
            # Cache admission before allocating a new public projection.
            if projection and len(self._snapshots) >= MAX_SNAPSHOTS:
                raise AccessError('Active snapshot budget exhausted; retry after expiry or restart.', code='resource_exhausted')
            current = yield from scan(fd, row['id'], projection=projection, expected=expected,
                                      tool_refs=config['threads'].get(row['id'],{}).get('allow_tool_results',False))
        with self._open_rollout(config, row) as fd:
            if stamp(os.fstat(fd)) != current['stamp']:
                raise AccessError('Source changed during verification; wait for stability.', code='waiting_source_stable')
        current.update(path=row['rollout_path'], created=now, prefixes={expected['id']} if expected else set())
        # Do not keep raw/tool payloads or unlimited per-source versions in memory.
        self._verified[row['id']] = current
        if len(self._verified)>MAX_CANDIDATES:
            self._verified.pop(next(iter(self._verified)))
        grant, reason = self._derive(config, row)
        if not grant:
            self._verified.pop(row['id'], None)
            error = AccessError('Thread is not authorized: source association could not be verified.', code='unverifiable_source')
            error.association_reason = reason
            raise error
        if config['denied'].intersection(current['proof']['session_ids']):
            self._verified.pop(row['id'], None)
            raise AccessError('Stored fork snapshot includes an explicitly revoked conversation.', code='unauthorized')
        config['threads'][row['id']] = grant
        if saved and not self._compatible_grant(saved['grant'],grant):
            raise AccessError('Snapshot association changed.',code='authorization_changed')
        if projection:
            projected = current.pop('projection')
            size = sum(4*len(m['text'])+1024 for m in projected['messages']) + len(projected['tools'])*1024
            if len(self._snapshots) >= MAX_SNAPSHOTS or size + sum(v['weight'] for v in self._snapshots.values()) > MAX_CACHE_BYTES:
                raise AccessError('Public snapshots exceed the memory budget.', code='resource_exhausted')
            snapshot = {'id':secrets.token_hex(12), 'bytes':current['bytes'], 'sha256':current['sha256'],
                        'device':current['device'], 'inode':current['inode'], 'captured_at':utc(time.time()),
                        'projection_version':PROJECTION_VERSION}
            self._snapshots[snapshot['id']]={'row_id':row['id'],'projection':projected,'snapshot':snapshot,'grant':grant,
                                             'weight':size,'created':now}
            current['snapshot_id']=snapshot['id'];current['prefixes'].add(snapshot['id'])
            current['tool_refs']=grant.get('allow_tool_results',False)
        else:
            current.pop('projection',None)
        return current

    def _snapshot(self, config, metadata, expected=None):
        """Return only a fully verified cached projection (also a test injection seam)."""
        current = self._verified[metadata['id']]
        key = expected['id'] if expected else current.get('snapshot_id')
        cached = self._snapshots.get(key)
        if cached is None:
            raise AccessError('Snapshot unavailable; restart the read.', code='snapshot_expired')
        cached['created'] = time.monotonic()
        return cached['projection'],cached['snapshot'],current['stamp'][2]>cached['snapshot']['bytes']

    def _revalidate_iter(self, config, rows, snapshots=None):
        fresh = self._configuration()
        if fresh['scope'] != config['scope']:
            raise AccessError('History authorization or repository topology changed; start a fresh read.',code='authorization_changed')
        for tid,row in rows.items():
            current = self._metadata(fresh, tid).get(tid)
            if current is None:
                raise AccessError('Thread metadata is unavailable.',code='unverifiable_source')
            try:
                yield from self._ensure_iter(fresh,current,expected=(snapshots or {}).get(tid))
                grant, _ = self._derive(fresh,current)
            except AccessError as exc:
                if exc.code in {'unauthorized','unverifiable_source'}:
                    raise AccessError('Thread association changed or was revoked; start a fresh read.',code='authorization_changed') from None
                raise
            old = config['threads'].get(tid)
            if not grant or not old or not self._compatible_grant(old,grant):
                raise AccessError('Thread association changed or was revoked; start a fresh read.',code='authorization_changed')
            fresh['threads'][tid]=grant
            yield {'phase':'authorization_check'}
        # Check config again after any suspended source verification.
        if self._configuration()['scope'] != config['scope']:
            raise AccessError('History authorization changed before return.',code='authorization_changed')
        for tid, row in rows.items():
            latest = self._metadata(fresh,tid).get(tid)
            if not latest or any(latest[k] != row[k] for k in ('cwd','rollout_path')):
                raise AccessError('Thread association changed before return.',code='authorization_changed')
            with self._open_rollout(fresh, row) as fd:
                if stamp(os.fstat(fd)) != self._verified[tid]['stamp']:
                    raise AccessError('Source changed during final checks; retry when stable.', code='waiting_source_stable')
        return fresh

    def read_codex_thread(self, thread_id, cursor='', limit=20, max_chars=16000, include_tool_refs=False,
                          view='all', turn_id=''):
        return self._drain(self._read_codex_thread_iter(thread_id,cursor,limit,max_chars,include_tool_refs,view,turn_id))

    def _read_codex_thread_iter(self, thread_id, cursor='', limit=20, max_chars=16000, include_tool_refs=False,
                               view='all', turn_id=''):
        config = self._configuration()
        integer(limit,'limit',1,50);integer(max_chars,'max_chars',100,40000)
        if not isinstance(thread_id,str) or not ID_PATTERN.fullmatch(thread_id):
            raise AccessError('Thread is not authorized.',code='unauthorized')
        if type(include_tool_refs) is not bool or view not in ('all','latest_turn','turn') or not isinstance(turn_id,str) or len(turn_id)>200:
            raise AccessError('Invalid history view parameters.')
        if (view=='turn') != bool(turn_id):
            raise AccessError('Supply turn_id only for view=turn.')
        rows=self._metadata(config,thread_id);row=rows.get(thread_id)
        if row is None or not self._eligible(config,row):raise AccessError('Thread is not authorized.',code='unauthorized')
        # Verify parameter-bound signatures after current association has been derived.
        yield from self._ensure_iter(config,row)
        grant,reason=self._derive(config,row)
        if not grant:raise AccessError('Thread is not authorized.',code='unverifiable_source')
        config['threads'][thread_id]=grant
        if include_tool_refs and not grant.get('allow_tool_results',False):
            raise AccessError('Tool evidence is separately disabled for this thread.')
        parameters={'limit':limit,'max_chars':max_chars,'include_tool_refs':include_tool_refs,'view':view,'turn_id':turn_id}
        token=self._verify(cursor,config,'messages',thread_id) if cursor else None
        if token and token['parameters']!=parameters:raise AccessError('Read cursor belongs to different page parameters.')
        yield from self._ensure_iter(config,row,expected=token['snapshot'] if token else None,projection=not token)
        projection,snapshot,appended=self._snapshot(config,row,token['snapshot'] if token else None)
        selected=token.get('selected_turn') if token else None
        if view!='all' and selected is None:
            selected=turn_id if view=='turn' else projection.get('latest_turn_id')
            if selected is None or selected not in projection.get('turn_ids',[]) or selected in projection.get('ambiguous_turn_ids',[]):
                raise AccessError('No reliable matching turn; use view=all.',code='turn_unavailable')
        sequence=[m for m in projection['messages'] if view=='all' or m['turn_id']==selected]
        if include_tool_refs:
            sequence.extend(t for t in projection['tools'].values() if view=='all' or t['turn_id']==selected)
            sequence.sort(key=lambda e:e['source_line'])
        position,offset=(token['position'],token['offset']) if token else (0,0)
        start_position,start_offset=position,offset
        page,budget,fragmented=[],max_chars,False
        while position<len(sequence) and len(page)<limit and budget>0:
            entry=sequence[position]
            if entry['kind']=='tool_reference':
                page.append({k:v for k,v in entry.items() if not k.startswith('_')})
                page[-1]['item_id']=self._token(config,'item',thread=thread_id,snapshot=snapshot,line=entry['source_line'])
                budget-=500;position+=1;continue
            text=entry['text'];end=min(len(text),offset+budget)
            page.append({**entry,'text':text[offset:end],'part_offset':offset,'total_characters':len(text),'has_more_text':end<len(text)})
            budget-=end-offset;fragmented|=offset>0 or end<len(text)
            if end<len(text):offset=end;break
            position+=1;offset=0
        more=position<len(sequence)
        yield from self._revalidate_iter(config,rows,{thread_id:snapshot})
        current=self._verified[thread_id]
        result={'thread':self._summary(config,row),'source':BACKEND,'snapshot':snapshot,
                'inherited_context':{'stored_ancestor_headers':projection['inherited_metadata_records'],'followed_other_threads':False},
                'source_cli_version':sanitize(projection['meta'].get('cli_version'))[0][:100],
                'storage_history_mode':projection['meta'].get('history_mode') if projection['meta'].get('history_mode') in ('legacy','paginated') else 'unknown',
                'entries':page,'order':'oldest_first_record_order','view':view,'selected_turn_id':selected,
                'range':{'start_entry':start_position,'start_character':start_offset,'next_entry':position,'next_character':offset,'total_entries':len(sequence)},
                'next_cursor':self._token(config,'messages',thread=thread_id,snapshot=snapshot,position=position,offset=offset,parameters=parameters,selected_turn=selected) if more else None,
                'has_more':more,'text_fragmented':fragmented,'appended_since_snapshot':current['stamp'][2]>snapshot['bytes'],
                'complete_public_projection':projection['complete_public_projection'],'warnings':projection['warnings'],
                'mirrored_messages_deduplicated':projection['mirrored_messages_deduplicated'],'last_recorded_status':projection['last_recorded_status'],
                'is_running':None,'tool_results_included':False,'tool_refs_included':include_tool_refs,'limitations':list(COMMON_LIMITS)}
        return self._remember(result,config,rows,{thread_id:snapshot})

    def read_codex_thread_item(self,thread_id,item_id,cursor='',max_chars=12000):
        return self._drain(self._read_codex_thread_item_iter(thread_id,item_id,cursor,max_chars))

    def _read_codex_thread_item_iter(self,thread_id,item_id,cursor='',max_chars=12000):
        config=self._configuration();integer(max_chars,'max_chars',100,40000)
        if not isinstance(thread_id,str) or not ID_PATTERN.fullmatch(thread_id):raise AccessError('Thread is not authorized.')
        rows=self._metadata(config,thread_id);row=rows.get(thread_id)
        if row is None:raise AccessError('Thread is not authorized.')
        yield from self._ensure_iter(config,row)
        grant,_=self._derive(config,row)
        if not grant or not grant.get('allow_tool_results',False):raise AccessError('Tool evidence is separately disabled for this thread.')
        config['threads'][thread_id]=grant
        reference=self._verify(item_id,config,'item',thread_id)
        token=self._verify(cursor,config,'item_page',thread_id) if cursor else None
        item_hash=hashlib.sha256(item_id.encode()).hexdigest()
        if token and (token['item_hash']!=item_hash or token['max_chars']!=max_chars):raise AccessError('Item cursor does not belong to these parameters.')
        yield from self._ensure_iter(config,row,expected=reference['snapshot'])
        projection,snapshot,appended=self._snapshot(config,row,reference['snapshot'])
        record=projection['tools'].get(reference['line'])
        if record is None:raise AccessError('Item is not a supported saved execution record.')
        with self._open_rollout(config,row) as fd:
            before=stamp(os.fstat(fd))
            if before!=self._verified[thread_id]['stamp']:raise AccessError('Source changed.',code='source_changed')
            raw=os.pread(fd,record['_length'],record['_offset'])
            if len(raw)!=record['_length'] or len(raw)>RECORD_BYTES:raise AccessError('Item source changed.',code='source_changed')
            item=json.loads(raw)['payload']['item']
            value,redactions=project_tool({**record,'_item':item},grant.get('mcp_tools',[]))
            if stamp(os.fstat(fd))!=before:raise AccessError('Source changed.',code='source_changed')
        text=json.dumps(value,ensure_ascii=False,indent=2);original_chars=len(text);text=text[:64000]
        start=token['offset'] if token else 0;end=min(start+max_chars,len(text));more=end<len(text)
        yield from self._revalidate_iter(config,rows,{thread_id:snapshot})
        result={'thread_id':thread_id,'item_id':item_id,'type':record['type'],'turn_id':record['turn_id'],'source_line':record['source_line'],
                'source':BACKEND,'format':'field-whitelisted JSON text, not the raw record','text':text[start:end],'offset':start,
                'returned_through':end,'available_characters':len(text),'original_projected_characters':original_chars,
                'truncated_by_policy':original_chars>64000,'redactions':redactions,'snapshot':snapshot,'appended_since_snapshot':appended,
                'has_more':more,'next_cursor':self._token(config,'item_page',thread=thread_id,item_hash=item_hash,offset=end,max_chars=max_chars) if more else None,
                'limitations':list(COMMON_LIMITS)}
        return self._remember(result,config,rows,{thread_id:snapshot})

    def find_codex_threads(self,query='',project_id='',cursor='',limit=10):
        return self._drain(self._find_codex_threads_iter(query,project_id,cursor,limit))

    def _find_codex_threads_iter(self,query='',project_id='',cursor='',limit=10):
        config=self._configuration();integer(limit,'limit',1,20)
        if not isinstance(query,str) or len(query)>200 or not isinstance(project_id,str):raise AccessError('Invalid search parameters.')
        if project_id and project_id not in self.project_ids:raise AccessError('Unknown project filter.')
        parameters={'query':query,'project_id':project_id,'limit':limit}
        now=time.monotonic()
        self._find_cache={k:v for k,v in self._find_cache.items() if now-v['created']<CURSOR_TTL}
        if cursor:
            token=self._verify(cursor,config,'find')
            if token['parameters']!=parameters:raise AccessError('Search cursor belongs to different parameters.')
            cached=self._find_cache.get(token['snapshot_id'])
            if cached is None:raise AccessError('Search snapshot expired; repeat the search.',code='snapshot_expired')
            start,snapshot_id=token['position'],token['snapshot_id']
            for tid,old in cached['grants'].items():config['threads'][tid]=old
        else:
            rows=self._metadata(config,project_id=project_id,query=query)
            needle=query.casefold()
            candidates=sorted(rows.values(),key=lambda r:(not any(needle in str(r.get(k) or '').casefold() for k in ('name','title','cwd','id')),r['id']))
            results,warnings,used,grants=[],[],{},{}
            unverified = False
            if config.get('metadata_only_candidates'):
                warnings.append({'reason':'candidate_budget_metadata_only_search'})
            content_bytes=0;content_seconds=0
            for row in candidates:
                if not self._eligible(config,row):continue
                begin=time.monotonic()
                try:
                    yield from self._ensure_iter(config,row)
                    grant,reason=self._derive(config,row)
                    if not grant:raise AccessError('Association cannot be verified.',code='unverifiable_source')
                    config['threads'][row['id']]=grant
                    if project_id and grant.get('project_id') != project_id:
                        continue
                    summary=self._summary(config,row)
                    match=not needle or any(needle in str(summary.get(k) or '').casefold() for k in ('title','label','cwd','project_id','thread_id'))
                    if match:
                        summary['match']={'in':'metadata','query':query}
                    elif content_bytes>=128*1024*1024 or content_seconds>=15:
                        warnings.append({'reason':'content_search_budget_exhausted'});continue
                    else:
                        existing_snapshots = set(self._snapshots)
                        try:
                            yield from self._ensure_iter(config,row,projection=True)
                            projected,snap,_=self._snapshot(config,row)
                            content_bytes+=snap['bytes'];content_seconds+=time.monotonic()-begin
                            if projected['warnings']:warnings.append({'reason':'partial_public_projection'})
                            message=next((m for m in projected['messages'] if needle in m['text'].casefold()),None)
                            match=message is not None
                            if match:
                                index=message['text'].casefold().find(needle)
                                summary['match']={'in':'public_message','message_id':message['message_id'],'snippet':message['text'][max(0,index-60):index+180],'snapshot_sha256':snap['sha256']}
                            del projected, message
                        finally:
                            # Search exports a bounded snippet, not a content-page
                            # cursor. Its private temporary projection must not pin
                            # the entire read cache and prevent the selected read.
                            for key in set(self._snapshots)-existing_snapshots:
                                if self._snapshots[key]['row_id']==row['id']:
                                    self._snapshots.pop(key,None)
                    if match:
                        results.append(summary);used[row['id']]=row;grants[row['id']]=grant
                except AccessError as exc:
                    if exc.code=='authorization_changed':raise
                    # No rejected candidate identifiers or titles in output.
                    unverified = True
                yield {'phase':'candidate_scan'}
            counts={}
            for w in warnings:counts[w['reason']]=counts.get(w['reason'],0)+1
            warnings=[{'reason':reason,'count':count} for reason,count in counts.items()]
            if unverified:
                warnings.append({'reason':'coverage_unverified'})
            results.sort(key=lambda r:(r['updated_at'] or '',r['thread_id']),reverse=True)
            if len(self._find_cache)>=16:raise AccessError('Search snapshot budget exhausted.',code='resource_exhausted')
            cached={'results':results,'warnings':warnings,'captured_at':utc(time.time()),'created':now,'rows':used,'grants':grants}
            snapshot_id,start=secrets.token_hex(12),0;self._find_cache[snapshot_id]=cached
        yield from self._revalidate_iter(config,cached['rows'])
        cached['created'] = time.monotonic()
        end=min(start+limit,len(cached['results']));more=end<len(cached['results'])
        result={'source':BACKEND,'threads':cached['results'][start:end],'has_more':more,'results_have_more':more,
                'scan_complete':True,'next_cursor':self._token(config,'find',snapshot_id=snapshot_id,position=end,parameters=parameters) if more else None,
                'search_snapshot_at':cached['captured_at'],'scope_count':len(cached['grants']),
                'coverage_complete':not cached['warnings'],'warnings':cached['warnings'],
                'note':'Fixed bounded metadata candidate set. Only verified results are returned. New threads require a new search; warnings mean coverage is incomplete.'}
        return self._remember(result,config,cached['rows'])
