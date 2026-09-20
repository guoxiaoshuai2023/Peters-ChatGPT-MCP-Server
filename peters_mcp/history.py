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
from .history_projection import accept_session_metadata, project_rollout, project_tool, sanitize

ID_PATTERN = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
MAX_SOURCE_BYTES = 64 * 1024 * 1024
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


class HistoryAccess:
    def __init__(self, config_path=None, project_ids=(), catalog=None):
        self.config_path = Path(config_path) if config_path else None
        self.project_ids = set(project_ids)
        self.catalog = catalog
        self._association_cache = {}
        self._key = secrets.token_bytes(32)
        self._find_cache = {}
        self._lock = threading.Lock()

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
            if thread_id is not None and (value.get("thread") != thread_id or
                    value.get("association") != config["threads"][thread_id].get("_proof")):
                raise ValueError()
            return value
        except (ValueError, TypeError, KeyError, UnicodeError):
            raise AccessError("Invalid, expired, cross-thread or revoked history cursor/item ID; start a fresh read.") from None

    def _token(self, config, kind, **values):
        if "thread" in values:
            values["association"] = config["threads"][values["thread"]].get("_proof")
        return self._sign({"kind": kind, "scope": config["scope"],
                           "expires": int(time.time()) + CURSOR_TTL, **values})

    def _metadata(self, config, thread_id=None):
        """Pure SELECT metadata only. Candidate rows are filtered before any export."""
        if not config["threads"] and not (config["inherit"] and config["snapshots"]):
            return {}
        path = config["database"]
        try:
            if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
                raise ValueError()
            connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=2)
            try:
                connection.execute("PRAGMA query_only=ON")
                columns = {row[1] for row in connection.execute("PRAGMA table_info(threads)")}
                required = {"id", "rollout_path", "cwd", "title", "updated_at", "archived"}
                if not required <= columns:
                    raise ValueError()
                selected = ["id", "rollout_path", "cwd", "title", "updated_at", "archived"]
                selected += [key for key in ("name", "history_mode", "created_at") if key in columns]
                ids = [thread_id] if thread_id else sorted(config["threads"])
                sql = "SELECT " + ",".join(selected) + " FROM threads"
                if thread_id or not (config["inherit"] and config["snapshots"]):
                    sql += " WHERE id IN (" + ",".join("?" for _ in ids) + ")"
                else:
                    ids = []
                return {row[0]: dict(zip(selected, row)) for row in connection.execute(sql, ids)}
            finally:
                connection.close()
        except (sqlite3.Error, OSError, ValueError, TypeError):
            raise AccessError("Supported Codex metadata index is missing, incompatible or busy; history is not proven empty.") from None

    def _recorded_contexts(self, config, row, raw=None):
        """Extract only identity/cwd metadata; never retain unauthorized message bodies."""
        key = None
        if raw is None:
            with self._open_rollout(config, row) as fd:
                before = os.fstat(fd)
                if before.st_size > MAX_SOURCE_BYTES:
                    raise AccessError("Association source exceeds the history size limit.")
                key = (row["id"], before.st_dev, before.st_ino, before.st_size,
                       before.st_mtime_ns, before.st_ctime_ns)
                with self._lock:
                    cached = self._association_cache.get(key)
                if cached is not None:
                    return cached
                raw = self._prefix(fd, before.st_size)
                after = os.fstat(fd)
                if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                    raise AccessError("Association source changed; repeat the request.")
        contexts, session_seen, reason = set(), False, None
        seen_meta, permitted_meta = set(), set()
        for line in raw.splitlines(keepends=True):
            if not line.endswith(b"\n"):
                # An incomplete append cannot introduce an exported record yet.
                continue
            try:
                record = json.loads(line)
            except (ValueError, UnicodeError):
                reason = "malformed_record_cannot_prove_association"
                break
            if not isinstance(record, dict):
                reason = "unknown_record_shape_cannot_prove_association"
                break
            kind = record.get("type")
            if not isinstance(kind, str) or kind not in {
                "session_meta", "turn_context", "response_item", "event_msg", "world_state",
                "token_usage_record", "inter_agent_communication_metadata", "compacted"
            }:
                reason = "unknown_record_type_cannot_prove_association"
                break
            if kind not in {"session_meta", "turn_context"}:
                continue
            payload = record.get("payload")
            if not isinstance(payload, dict):
                reason = "missing_context_metadata"
                break
            if record["type"] == "session_meta":
                try:
                    own = accept_session_metadata(payload, row["id"], seen_meta, permitted_meta)
                except AccessError:
                    reason = "session_identity_mismatch"
                    break
                session_seen = session_seen or own
            cwd = payload.get("cwd")
            if not isinstance(cwd, str) or not cwd or not Path(cwd).is_absolute():
                reason = "missing_recorded_working_directory"
                break
            contexts.add(cwd)
        if not session_seen:
            reason = reason or "missing_session_identity"
        result = {"contexts": sorted(contexts), "reason": reason, "session_ids": sorted(seen_meta)}
        if key is not None:
            with self._lock:
                if len(self._association_cache) > 1024:
                    self._association_cache.clear()
                self._association_cache[key] = result
        return result

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

    def _request(self, thread_id=None):
        config = self._configuration()
        if thread_id is not None and (not isinstance(thread_id, str) or not ID_PATTERN.fullmatch(thread_id)):
            raise AccessError("Thread is not authorized.")
        rows = self._metadata(config, thread_id)
        pending = {}
        for tid, row in rows.items():
            grant, reason = self._derive(config, row)
            if grant:
                config["threads"][tid] = grant
            elif reason != "explicitly_denied" and self._attributable_pending(config, row):
                pending[reason] = pending.get(reason, 0) + 1
        config["pending"] = [{"reason": reason, "count": count} for reason, count in sorted(pending.items())]
        return config, rows

    def _revalidate(self, config, rows):
        """Check hot revocation and current association before returning collected data."""
        fresh = self._configuration()
        if fresh["scope"] != config["scope"]:
            raise AccessError("History authorization or repository topology changed; start a fresh read.")
        for tid, row in rows.items():
            current = self._metadata(fresh, tid).get(tid)
            grant, _ = self._derive(fresh, current) if current else (None, None)
            old = config["threads"].get(tid)
            if not grant or not old or grant.get("_proof") != old.get("_proof"):
                raise AccessError("Thread association changed or was revoked; start a fresh read.")

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

    @staticmethod
    def _prefix(fd, size):
        chunks, offset = [], 0
        while offset < size:
            chunk = os.pread(fd, min(size - offset, 262144), offset)
            if not chunk:
                raise AccessError("History was truncated during reading; restart the read.")
            chunks.append(chunk)
            offset += len(chunk)
        return b"".join(chunks)

    def _snapshot(self, config, metadata, expected=None):
        with self._open_rollout(config, metadata) as fd:
            before = os.fstat(fd)
            size = expected["bytes"] if expected else before.st_size
            if size > MAX_SOURCE_BYTES:
                raise AccessError("History exceeds the 64 MiB source limit; not returned as an empty or complete thread.")
            if expected and (before.st_dev != expected["device"] or before.st_ino != expected["inode"]):
                raise AccessError("History identity changed between pages; restart the read.")
            raw = self._prefix(fd, size)
            after = os.fstat(fd)
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                if self._prefix(fd, size) != raw:
                    raise AccessError("History changed during reading; restart the read.")
            digest = hashlib.sha256(raw).hexdigest()
            if expected and digest != expected["sha256"]:
                raise AccessError("Earlier history changed between pages; restart the read.")
            snapshot = expected or {"bytes": size, "sha256": digest, "device": before.st_dev,
                                    "inode": before.st_ino, "captured_at": utc(time.time())}
            previous = config["threads"][metadata["id"]]
            if previous["_association"]["source"] == "repository_inheritance":
                grant, _ = self._derive(config, metadata, raw)
                if not grant or grant.get("_proof") != previous.get("_proof"):
                    raise AccessError("Read source does not match the verified repository association.")
            projection = project_rollout(raw, metadata["id"])
            if config["denied"].intersection(projection["stored_session_ids"]):
                raise AccessError("Stored fork snapshot includes an explicitly revoked conversation; access denied.")
            return projection, snapshot, after.st_size > size

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

    def find_codex_threads(self, query="", project_id="", cursor="", limit=10):
        config, rows = self._request()
        integer(limit, "limit", 1, 20)
        if not isinstance(query, str) or len(query) > 200 or not isinstance(project_id, str):
            raise AccessError("Use a query of at most 200 characters and a configured project ID.")
        if project_id and project_id not in self.project_ids:
            raise AccessError("Unknown project filter.")
        parameters = {"query": query, "project_id": project_id, "limit": limit}
        if cursor:
            token = self._verify(cursor, config, "find")
            if token["parameters"] != parameters:
                raise AccessError("Search cursor belongs to different query/filter/limit parameters.")
            with self._lock:
                cached = self._find_cache.get(token["snapshot_id"])
            if cached is None:
                raise AccessError("Search snapshot expired or server restarted. Repeat the search.")
            for tid, proof in cached["proofs"].items():
                grant = config["threads"].get(tid)
                if not grant or grant.get("_proof") != proof:
                    raise AccessError("Search snapshot association changed or revoked; start a fresh search.")
            start, snapshot_id = token["position"], token["snapshot_id"]
        else:
            results, warnings = [], list(config["pending"])
            deadline, scanned_bytes = time.monotonic() + 15, 0
            for thread_id, grant in config["threads"].items():
                if project_id and grant.get("project_id") != project_id:
                    continue
                row = rows.get(thread_id)
                if row is None:
                    warnings.append({"thread_id": thread_id, "reason": "metadata_missing_history_not_proven_empty"})
                    continue
                summary = self._summary(config, row)
                needle = query.casefold()
                if not needle or any(needle in str(summary.get(k) or "").casefold() for k in ("title", "label", "cwd", "project_id")):
                    summary["match"] = {"in": "metadata", "query": query}
                    results.append(summary)
                    continue
                if time.monotonic() >= deadline or scanned_bytes > 128 * 1024 * 1024:
                    warnings.append({"thread_id": thread_id, "reason": "content_search_budget_exhausted"})
                    continue
                try:
                    projection, snap, _ = self._snapshot(config, row)
                    scanned_bytes += snap["bytes"]
                    if projection["warnings"]:
                        warnings.append({"thread_id": thread_id, "reason": "partial_public_projection"})
                    match = next((m for m in projection["messages"] if needle in m["text"].casefold()), None)
                    if match:
                        index = match["text"].casefold().find(needle)
                        summary["match"] = {"in": "public_message", "message_id": match["message_id"],
                                            "snippet": match["text"][max(0, index - 60):index + 180],
                                            "snapshot_sha256": snap["sha256"]}
                        results.append(summary)
                except AccessError:
                    warnings.append({"thread_id": thread_id, "reason": "content_unavailable_not_proven_empty"})
            results.sort(key=lambda r: (r["updated_at"] or "", r["thread_id"]), reverse=True)
            cached = {"results": results, "warnings": warnings, "captured_at": utc(time.time()), "created": time.time(),
                      "proofs": {r["thread_id"]: config["threads"][r["thread_id"]].get("_proof") for r in results}}
            snapshot_id, start = secrets.token_hex(12), 0
            with self._lock:
                self._find_cache = {k: v for k, v in self._find_cache.items() if time.time() - v["created"] < CURSOR_TTL}
                if len(self._find_cache) >= 16:
                    self._find_cache.pop(next(iter(self._find_cache)))
                self._find_cache[snapshot_id] = cached
        self._revalidate(config, {tid: rows[tid] for tid in cached["proofs"] if tid in rows})
        end = min(start + limit, len(cached["results"]))
        has_more = end < len(cached["results"])
        return {"source": BACKEND, "threads": cached["results"][start:end], "has_more": has_more,
                "next_cursor": self._token(config, "find", snapshot_id=snapshot_id, position=end, parameters=parameters) if has_more else None,
                "search_snapshot_at": cached["captured_at"], "scope_count": len(config["threads"]),
                "coverage_complete": not cached["warnings"], "warnings": cached["warnings"],
                "note": "Only explicit grants and verified repository-inherited threads are searched. Same titles are distinct IDs; ask the user to choose. "
                        "Search results freeze metadata/matches; content matches use individual file snapshots. "
                        "Unrelated/projectless records are not listed. Unresolved attributable records appear only as aggregate warnings; "
                        "explicit configuration can bind an approved exception. Empty results do not prove no Codex history."}

    def read_codex_thread(self, thread_id, cursor="", limit=20, max_chars=16000, include_tool_refs=False):
        config, rows = self._request(thread_id)
        grant = self._authorized(config, thread_id)
        integer(limit, "limit", 1, 50)
        integer(max_chars, "max_chars", 100, 40000)
        if type(include_tool_refs) is not bool:
            raise AccessError("include_tool_refs must be boolean.")
        if include_tool_refs and not grant.get("allow_tool_results", False):
            raise AccessError("Tool evidence is separately disabled for this thread.")
        parameters = {"limit": limit, "max_chars": max_chars, "include_tool_refs": include_tool_refs}
        token = self._verify(cursor, config, "messages", thread_id) if cursor else None
        if token and token["parameters"] != parameters:
            raise AccessError("Read cursor belongs to different page parameters.")
        row = rows.get(thread_id)
        if row is None:
            raise AccessError("Authorized thread metadata is missing; history is not proven empty.")
        projection, snapshot, appended = self._snapshot(config, row, token["snapshot"] if token else None)
        sequence = list(projection["messages"])
        if include_tool_refs:
            sequence.extend(projection["tools"].values())
            sequence.sort(key=lambda entry: entry["source_line"])
        position, offset = (token["position"], token["offset"]) if token else (0, 0)
        start_position, start_offset = position, offset
        page, budget, fragmented = [], max_chars, False
        while position < len(sequence) and len(page) < limit and budget > 0:
            entry = sequence[position]
            if entry["kind"] == "tool_reference":
                page.append({key: value for key, value in entry.items() if key != "_item"})
                page[-1]["item_id"] = self._token(config, "item", thread=thread_id, snapshot=snapshot, line=entry["source_line"])
                budget -= 500
                position += 1
                continue
            text = entry["text"]
            end = min(len(text), offset + budget)
            page.append({**entry, "text": text[offset:end], "part_offset": offset, "total_characters": len(text),
                         "has_more_text": end < len(text)})
            budget -= end - offset
            fragmented |= offset > 0 or end < len(text)
            if end < len(text):
                offset = end
                break
            position += 1
            offset = 0
        has_more = position < len(sequence)
        self._revalidate(config, {thread_id: row})
        return {"thread": self._summary(config, row), "source": BACKEND, "snapshot": snapshot,
                "inherited_context": {"stored_ancestor_headers": projection["inherited_metadata_records"], "followed_other_threads": False},
                "source_cli_version": sanitize(projection["meta"].get("cli_version"))[0][:100],
                "storage_history_mode": projection["meta"].get("history_mode") if projection["meta"].get("history_mode") in ("legacy", "paginated") else "unknown",
                "entries": page, "order": "oldest_first_record_order", "range": {
                    "start_entry": start_position, "start_character": start_offset,
                    "next_entry": position, "next_character": offset, "total_entries": len(sequence)},
                "next_cursor": self._token(config, "messages", thread=thread_id, snapshot=snapshot,
                                            position=position, offset=offset, parameters=parameters) if has_more else None,
                "has_more": has_more, "text_fragmented": fragmented, "appended_since_snapshot": appended,
                "complete_public_projection": projection["complete_public_projection"], "warnings": projection["warnings"],
                "mirrored_messages_deduplicated": projection["mirrored_messages_deduplicated"],
                "last_recorded_status": projection["last_recorded_status"], "is_running": None,
                "tool_results_included": False, "tool_refs_included": include_tool_refs,
                "limitations": list(COMMON_LIMITS)}

    def read_codex_thread_item(self, thread_id, item_id, cursor="", max_chars=12000):
        config, rows = self._request(thread_id)
        grant = self._authorized(config, thread_id)
        if not grant.get("allow_tool_results", False):
            raise AccessError("Tool evidence is separately disabled for this thread.")
        integer(max_chars, "max_chars", 100, 40000)
        reference = self._verify(item_id, config, "item", thread_id)
        item_hash = hashlib.sha256(item_id.encode()).hexdigest()
        token = self._verify(cursor, config, "item_page", thread_id) if cursor else None
        if token and (token["item_hash"] != item_hash or token["max_chars"] != max_chars):
            raise AccessError("Item cursor does not belong to these parameters.")
        row = rows.get(thread_id)
        if row is None:
            raise AccessError("Authorized thread metadata is missing.")
        projection, snapshot, appended = self._snapshot(config, row, reference["snapshot"])
        record = projection["tools"].get(reference["line"])
        if record is None:
            raise AccessError("Item is not a supported saved execution record.")
        value, redactions = project_tool(record, grant.get("mcp_tools", []))
        text = json.dumps(value, ensure_ascii=False, indent=2)
        original_chars = len(text)
        policy_truncated = original_chars > 64000
        text = text[:64000]
        start = token["offset"] if token else 0
        end = min(start + max_chars, len(text))
        has_more = end < len(text)
        self._revalidate(config, {thread_id: row})
        return {"thread_id": thread_id, "item_id": item_id, "type": record["type"],
                "turn_id": record["turn_id"], "source_line": record["source_line"], "source": BACKEND,
                "format": "field-whitelisted JSON text, not the raw record", "text": text[start:end],
                "offset": start, "returned_through": end, "available_characters": len(text),
                "original_projected_characters": original_chars, "truncated_by_policy": policy_truncated,
                "redactions": redactions, "snapshot": snapshot, "appended_since_snapshot": appended,
                "has_more": has_more, "next_cursor": self._token(config, "item_page", thread=thread_id,
                    item_hash=item_hash, offset=end, max_chars=max_chars) if has_more else None,
                "limitations": list(COMMON_LIMITS)}
