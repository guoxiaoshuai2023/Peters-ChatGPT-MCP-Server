"""Local preview, commit, and forward recovery for Agent file access."""

import argparse
import json
import os
from pathlib import Path
import sys
import time

from .agent_file_policy import (
    ACTIVE_NAME, MAX_DOCUMENT_BYTES, MAX_TRANSACTION_BYTES, PENDING_NAME, WATERMARK_NAME,
    AgentFilePolicy, atomic_write, capture_publication_roots, collect_root_records, credential_digest, decode,
    denied, digest, initialize_agent_file_policy, make_record, optional_read, read_projects, validate_agents,
    validate_record, verify_publication_roots, watermark,
)
from .agent_history_generation import _directory, _read_at, canonical_bytes
from .catalog import AccessError

_KINDS = {"agents", "projects", "worktrees"}
_ROOT_VERIFY_SECONDS = 2


def _input(path, maximum):
    path = Path(path)
    if not path.is_absolute():
        raise denied()
    fd = _directory(path.parent)
    try:
        return _read_at(fd, path.name, maximum)
    finally:
        os.close(fd)


def _ready(policy, state_fd, project_fd, *, allow_mismatch=False):
    if optional_read(state_fd, PENDING_NAME, MAX_TRANSACTION_BYTES) is not None:
        raise denied("agent_file_policy_pending")
    active, record_raw, mark = policy.read_committed(state_fd)
    project_raw, stamp = read_projects(project_fd, policy.projects_path.name)
    if not allow_mismatch and (mark["project_stamp"] != stamp or active["projects"]["sha256"] != digest(project_raw)):
        raise denied("agent_file_policy_mismatch")
    return active, record_raw, mark, project_raw, stamp


def _active_agents(record):
    return {agent["id"]: credential_digest(agent) for agent in record["agents"] if agent["enabled"]}


def _retired(active, agents):
    old = _active_agents(active)
    new = _active_agents({"agents": agents})
    retired = set(active["retired_credentials"]) | {key for name, key in old.items() if new.get(name) != key}
    if retired & set(new.values()):
        raise denied("agent_file_credential_retired")
    return sorted(retired)


def _diff(before, after):
    return {"removed": sorted(set(before) - set(after)), "added": sorted(set(after) - set(before))}


def _summary(active, agents, roots, source_project, target_project):
    old_projects = {entry["project"] for entry in active["roots"]}
    new_projects = {entry["project"] for entry in roots}
    old_agents = _active_agents(active)
    new_agents = _active_agents({"agents": agents})

    def root_keys(records):
        return {entry["project"] + ":" + entry["worktree"] + ":" + entry["path"]: entry for entry in records}

    old_roots, new_roots = root_keys(active["roots"]), root_keys(roots)
    paired_content = active["projects"]["sha256"] == digest(source_project)
    project_changes = {}
    if paired_content:
        before = {row["id"]: row for row in decode(source_project)["projects"]}
        after = {row["id"]: row for row in decode(target_project)["projects"]}
        for project_id in sorted(before.keys() & after.keys()):
            old, new = before[project_id], after[project_id]
            changed = sorted(key for key in old.keys() | new.keys() if old.get(key) != new.get(key))
            if changed:
                project_changes[project_id] = changed
    return {"projects": _diff(old_projects, new_projects), "agents": _diff(old_agents, new_agents),
            "project_fields_changed": project_changes if paired_content else None,
            "published_project_sha256": active["projects"]["sha256"],
            "observed_project_sha256": digest(source_project),
            "target_project_sha256": digest(target_project),
            "rotations": sorted(name for name in old_agents.keys() & new_agents.keys()
                                if old_agents[name] != new_agents[name]),
            "worktrees": {**_diff(old_roots, new_roots),
                          "changed": sorted(key for key in old_roots.keys() & new_roots.keys()
                                            if old_roots[key] != new_roots[key])},
            "before_pairs": len(old_projects) * len(old_agents),
            "target_pairs": len(new_projects) * len(new_agents)}


def preview(policy, kind, *, proposed=None, check_path=None):
    """Produce an operator-reviewed hash without modifying either live file."""
    if kind not in _KINDS or ((proposed is None) != (kind == "worktrees")):
        raise denied()
    with policy.locked() as (state, shared):
        active, active_raw, _, live, stamp = _ready(policy, state, shared, allow_mismatch=kind == "projects")
    target_text = None
    target = live
    if kind == "agents":
        agents = validate_agents(proposed)
        roots = active["roots"]
    else:
        agents = active["agents"]
        target = live if kind == "worktrees" else proposed
        if not isinstance(target, bytes) or len(target) > MAX_DOCUMENT_BYTES:
            raise denied()
        target_text = target.decode("utf-8") if kind == "projects" else None
        roots = collect_root_records(decode(target), check_path=check_path)
    document = {
        "version": 1, "kind": kind, "projects_path": str(policy.projects_path),
        "base_revision": active["activation_id"], "base_record_sha256": digest(active_raw),
        "base_project_sha256": digest(live), "base_project_stamp": stamp, "target_project_text": target_text,
        "agents": agents, "roots": roots, "retired_credentials": _retired(active, agents),
        "summary": _summary(active, agents, roots, live, target),
    }
    return document, digest(canonical_bytes(document))


def _check_preview(policy, document, approval):
    if (not isinstance(document, dict) or set(document) != {
            "version", "kind", "projects_path", "base_revision", "base_record_sha256", "base_project_sha256",
            "base_project_stamp",
            "target_project_text", "agents", "roots", "retired_credentials", "summary"}
            or type(document["version"]) is not int or document["version"] != 1
            or document["kind"] not in _KINDS or document["projects_path"] != str(policy.projects_path)
            or digest(canonical_bytes(document)) != approval):
        raise denied("agent_file_preview_changed")
    kind = document["kind"]
    if ((kind == "projects" and not isinstance(document["target_project_text"], str))
            or (kind != "projects" and document["target_project_text"] is not None)):
        raise denied("agent_file_preview_changed")
    validate_agents(document["agents"])


def _target_text(document, live):
    if document["kind"] != "projects":
        return live
    data = document["target_project_text"].encode("utf-8")
    if len(data) > MAX_DOCUMENT_BYTES:
        raise denied()
    return data


def _review_physical_target(document, live, check_path):
    """Do repository-wide discovery outside the exclusive publication lease."""
    if document["kind"] == "agents":
        if check_path is not None:
            for row in document["roots"]:
                check_path(Path(row["path"]))
        return ()
    projects = decode(_target_text(document, live))
    receipt = capture_publication_roots(document["roots"], projects)
    if collect_root_records(projects, check_path=check_path) != document["roots"]:
        raise denied("agent_file_preview_changed")
    verify_publication_roots(receipt)
    return receipt


def apply(policy, document, approval, *, check_path=None):
    """Publish one exact preview. A prepared intent is recovered only forward."""
    _check_preview(policy, document, approval)
    kind = document["kind"]
    if kind != "agents":
        with policy.locked() as (state, shared):
            _, _, _, live, _ = _ready(policy, state, shared, allow_mismatch=kind == "projects")
    else:
        live = None
    root_receipt = _review_physical_target(document, live, check_path)
    with policy.locked(exclusive=True) as (state, shared):
        active, active_raw, base_mark, live, stamp = _ready(policy, state, shared, allow_mismatch=kind == "projects")
        target = _target_text(document, live)
        if ((document["base_revision"], document["base_record_sha256"], document["base_project_sha256"],
             document["base_project_stamp"]) != (active["activation_id"], digest(active_raw), digest(live), stamp)
                or (kind == "agents" and document["roots"] != active["roots"])
                or (kind != "agents" and document["agents"] != active["agents"])
                or document["retired_credentials"] != _retired(active, document["agents"])
                or document["summary"] != _summary(active, document["agents"], document["roots"], live, target)):
            raise denied("agent_file_preview_changed")
        record = make_record(policy.projects_path, digest(target), document["roots"], document["agents"],
                             active["sequence"] + 1, retired=document["retired_credentials"],
                             approval=approval)
        validate_record(record, policy.projects_path, decode(target))
        if len(canonical_bytes(record)) > MAX_DOCUMENT_BYTES:
            raise denied()
        pending = {"version": 1, "base_watermark": base_mark, "target": record, "preview": document}
        atomic_write(state, PENDING_NAME, canonical_bytes(pending), MAX_TRANSACTION_BYTES)
        with policy.anchor_directory() as anchor:
            return _advance(policy, state, shared, anchor, pending, approval, root_receipt)


def _approved_record(policy, pending, approval):
    if (not isinstance(pending, dict) or set(pending) != {"version", "base_watermark", "target", "preview"}
            or type(pending["version"]) is not int or pending["version"] != 1):
        raise denied("agent_file_preview_changed")
    document = pending["preview"]
    _check_preview(policy, document, approval)
    record = pending["target"]
    validate_record(record, policy.projects_path)
    base_mark = pending["base_watermark"]
    if (approval != record["approval_sha256"] or record["agents"] != document["agents"]
            or record["roots"] != document["roots"]
            or record["retired_credentials"] != document["retired_credentials"]
            or base_mark["record_sha256"] != document["base_record_sha256"]
            or base_mark["activation_id"] != document["base_revision"]):
        raise denied("agent_file_preview_changed")
    return document, record


def _advance(policy, state, shared, anchor, pending, approval, root_receipt):
    document, record = _approved_record(policy, pending, approval)
    base_mark = pending["base_watermark"]
    target_raw = canonical_bytes(record)
    active = _read_at(state, ACTIVE_NAME, MAX_DOCUMENT_BYTES)
    live, stamp = read_projects(shared, policy.projects_path.name)
    marked = decode(_read_at(state, WATERMARK_NAME, 2048))
    external = decode(_read_at(anchor, policy.anchor_name, 2048))
    before, after = document["base_project_sha256"], record["projects"]["sha256"]
    live_target_mark = watermark(record, target_raw, stamp)
    current_matches_target = marked == live_target_mark
    if (record["sequence"] != base_mark["sequence"] + 1
            or (marked != base_mark and not current_matches_target)
            or external not in (base_mark, live_target_mark)
            or (external == live_target_mark and not current_matches_target)
            or digest(active) not in (base_mark["record_sha256"], digest(target_raw))
            or digest(live) not in (before, after)
            or (digest(live) == before and stamp != document["base_project_stamp"])
            or (current_matches_target and (active != target_raw or digest(live) != after))):
        raise denied("agent_file_policy_mismatch")
    target_project = _target_text(document, live)
    if digest(target_project) != after or len(target_project) > MAX_DOCUMENT_BYTES:
        raise denied("agent_file_policy_mismatch")
    validate_record(record, policy.projects_path, decode(target_project))
    if active != target_raw:
        atomic_write(state, ACTIVE_NAME, target_raw)

    def commit_roots():
        deadline = time.monotonic() + _ROOT_VERIFY_SECONDS
        verify_publication_roots(root_receipt, deadline=deadline)

    if digest(live) != after:
        # The unchanged .9 process sees the new project file at this rename.
        # Never overwrite a detected edit that bypassed the publisher lock.
        def before_replace():
            if read_projects(shared, policy.projects_path.name) != (live, stamp):
                raise denied("agent_file_policy_mismatch")
            commit_roots()

        atomic_write(shared, policy.projects_path.name, target_project, before_replace=before_replace)
    elif document["kind"] != "agents":
        commit_roots()
    final_project, final_stamp = read_projects(shared, policy.projects_path.name)
    if (final_project != target_project or _read_at(state, ACTIVE_NAME, MAX_DOCUMENT_BYTES) != target_raw):
        raise denied("agent_file_policy_mismatch")
    target_mark = watermark(record, target_raw, final_stamp)
    encoded_mark = canonical_bytes(target_mark)
    if marked != target_mark:
        atomic_write(state, WATERMARK_NAME, encoded_mark, 2048)
    if external != target_mark:
        if decode(_read_at(anchor, policy.anchor_name, 2048)) != external:
            raise denied("agent_file_policy_mismatch")
        atomic_write(anchor, policy.anchor_name, encoded_mark, 2048)
    os.unlink(PENDING_NAME, dir_fd=state)
    os.fsync(state)
    return record["activation_id"]


def recover(policy, approval, *, check_path=None):
    """Complete the approved pending intent or confirm an already committed one."""
    root_receipt = ()
    with policy.locked() as (state, shared):
        reviewed_raw = optional_read(state, PENDING_NAME, MAX_TRANSACTION_BYTES)
        live, _ = read_projects(shared, policy.projects_path.name)
    if reviewed_raw is not None:
        document, _ = _approved_record(policy, decode(reviewed_raw), approval)
        root_receipt = _review_physical_target(document, live, check_path)
    with policy.locked(exclusive=True) as (state, shared):
        raw = optional_read(state, PENDING_NAME, MAX_TRANSACTION_BYTES)
        if raw is None:
            active, _, _, _ = policy.current_record(state, shared)
            if approval != active["approval_sha256"]:
                raise denied("agent_file_preview_changed")
            return active["activation_id"]
        if reviewed_raw != raw:
            raise denied("agent_file_preview_changed")
        with policy.anchor_directory() as anchor:
            return _advance(policy, state, shared, anchor, decode(raw), approval, root_receipt)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--projects", type=Path, required=True)
    parser.add_argument("--state-directory", type=Path, required=True)
    from .agent_file_protection import build_protections, protected_root_check, protection_arguments
    protection_arguments(parser)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("initialize", help="Initialize a protected store with no enrolled Agents.")
    dry_run = commands.add_parser("preview", help="Render an exact publication for review.")
    target = dry_run.add_mutually_exclusive_group(required=True)
    target.add_argument("--agents-input", type=Path, help="Private JSON file containing an agents array.")
    target.add_argument("--projects-input", type=Path, help="Private legacy project list to publish.")
    target.add_argument("--worktrees", action="store_true", help="Review roots without changing projects or Agents.")
    publish = commands.add_parser("apply", help="Apply an exact reviewed preview.")
    publish.add_argument("--preview", type=Path, required=True)
    publish.add_argument("--sha256", required=True)
    finish = commands.add_parser("recover", help="Complete only the specified approved intent.")
    finish.add_argument("--sha256", required=True)
    opts = parser.parse_args(argv)
    try:
        registry, protections = build_protections(opts)

        def check_path(path):
            protected_root_check(registry, protections, path)

        if opts.command == "initialize":
            policy = initialize_agent_file_policy(opts.projects, opts.state_directory, check_path=check_path)
            print(json.dumps({"revision": policy.snapshot().revision}))
            return 0
        policy = AgentFilePolicy(opts.projects, opts.state_directory)
        if opts.command == "preview":
            if opts.agents_input is not None:
                payload = decode(_input(opts.agents_input, MAX_DOCUMENT_BYTES))
                if not isinstance(payload, dict) or set(payload) != {"agents"}:
                    raise denied()
                document, approval = preview(policy, "agents", proposed=payload["agents"])
            elif opts.projects_input is not None:
                document, approval = preview(policy, "projects", proposed=_input(opts.projects_input, MAX_DOCUMENT_BYTES),
                                             check_path=check_path)
            else:
                document, approval = preview(policy, "worktrees", check_path=check_path)
            print(json.dumps({"preview": document, "sha256": approval}, ensure_ascii=False))
            return 0
        if opts.command == "apply":
            payload = decode(_input(opts.preview, MAX_TRANSACTION_BYTES))
            if not isinstance(payload, dict) or set(payload) != {"preview", "sha256"} or payload["sha256"] != opts.sha256:
                raise denied("agent_file_preview_changed")
            revision = apply(policy, payload["preview"], opts.sha256, check_path=check_path)
        else:
            revision = recover(policy, opts.sha256, check_path=check_path)
        print(json.dumps({"revision": revision}))
        return 0
    except AccessError as error:
        print(error.code, file=sys.stderr)
        return 1
    except (OSError, RuntimeError, ValueError, KeyError, TypeError):
        print("agent_file_policy_invalid", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
