"""Local operator preview and activation. No MCP tool exposes these operations."""

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import stat

from .agent_history_generation import (GenerationStore, canonical_bytes, initialize_store,
                                       _directory, _read_at, _unique)
from .agent_history_policy import (AgentPolicy, _entries, _overlap, _verified_actor, reject_project_overlap,
                                   validate_generation)
from .catalog import AccessError, Catalog, _config_bytes
from .fs_identity import persistent_identity
from .workspaces import _open_path, _pin_matches, repository_probe


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _input(path):
    path = Path(path).absolute()
    raw = _config_bytes(path)
    return {"path": str(path), "sha256": _digest(raw)}, json.loads(raw, object_pairs_hook=_unique)


def _drift():
    return AccessError("Approved project, worktree or source evidence changed.", code="identity_mismatch")


def _physical_stamp(path, kind):
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path:
        raise _drift()
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(info.st_mode):
        raise _drift()
    if kind == "registration" and not stat.S_ISDIR(info.st_mode):
        raise _drift()
    identity = [info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), getattr(info, "st_birthtime", None)]
    if kind == "registration":
        identity.extend([info.st_mtime_ns, info.st_ctime_ns])
    elif kind == "pointer" and stat.S_ISREG(info.st_mode):
        if info.st_size > 4096:
            raise _drift()
        fd, opened = _open_path(path, directory=False)
        try:
            raw = os.read(fd, 4097)
            end = os.fstat(fd)
            if ((opened.st_dev, opened.st_ino, opened.st_mtime_ns, opened.st_ctime_ns)
                    != (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns)
                    or (end.st_size, end.st_mtime_ns, end.st_ctime_ns)
                    != (info.st_size, info.st_mtime_ns, info.st_ctime_ns) or len(raw) != info.st_size):
                raise _drift()
        finally:
            os.close(fd)
        identity.append(_digest(raw))
    return identity


def _approved_physical_scope(document):
    """Use checked Git discovery before taking the publication lock."""
    catalog = Catalog._from_document({"projects": document["projects"]}, unified=True)
    facts = {}
    roots, identities = [], {}

    def collect(path, kind="identity", expected=None, *, absent=False):
        path = str(path)
        stamp = _physical_stamp(path, kind)
        if (expected is not None and (stamp is None or stamp[:2] != list(expected))
                or absent and stamp is not None):
            raise _drift()
        facts[(path, kind)] = stamp

    for project_id, info in catalog.repositories.discover_all().items():
        default = next((member for member in info["worktrees"] if member["is_default"]), None)
        if default is None or default["state"] != "valid":
            raise _drift()
        if info["mode"] == "repository":
            repo = repository_probe(Path(default["root"]))
            if repo["repository_id"] != info["repository_id"]:
                raise _drift()
            common = repo["common"]
            collect(common, expected=repo["common_runtime_identity"])
            collect(common / "worktrees", "registration")
        for member in info["worktrees"]:
            root = Path(member["root"])
            if member["state"] == "missing":
                collect(root, absent=True)
            if member["state"] != "valid":
                continue
            identity = tuple(member["root_identity"])
            if identities.setdefault(identity, project_id) != project_id:
                raise AccessError("Verified project filesystem identities overlap.", code="project_scope_overlap")
            roots.append((project_id, root))
            collect(root, expected=identity)
            if info["mode"] == "repository":
                checked = repository_probe(root)
                if (checked["common"] != common or tuple(checked["root_runtime_identity"]) != identity
                        or checked["repository_id"] != info["repository_id"]):
                    raise _drift()
                pointer = root / ".git"
                collect(pointer, "pointer")
                if pointer.is_file():
                    fd, _ = _open_path(pointer, directory=False)
                    try:
                        value = os.fsdecode(os.read(fd, 4097)).rstrip("\n")
                    finally:
                        os.close(fd)
                    if not value.startswith("gitdir: ") or "\n" in value:
                        raise _drift()
                    admin = Path(value[len("gitdir: "):])
                    admin = (admin if admin.is_absolute() else root / admin).resolve()
                    if admin.parent != common / "worktrees" or not admin.is_dir():
                        raise _drift()
                    collect(admin)
                    collect(admin / "gitdir", "pointer")
                    collect(admin / "commondir", "pointer")
    reject_project_overlap(roots)
    for source in document["sources"].values():
        path = Path(source["root"])
        if any(_overlap(path, root) for _, root in roots):
            raise AccessError("A project scope overlaps a protected history source.", code="project_scope_overlap")
        if source["enabled"]:
            if persistent_identity(path) != source["root_identity"]:
                raise _drift()
            info = path.stat()
            collect(path, expected=(info.st_dev, info.st_ino))
            if persistent_identity(path) != source["root_identity"]:
                raise _drift()
        for alias in source.get("path_aliases", []):
            if source["enabled"] and alias["project_id"] in catalog.projects:
                collect(alias["old_root"], absent=True)
                collect(alias["target_root"])
    return {"extents": [[project, str(root)] for project, root in sorted(roots)],
            "facts": [[path, kind, stamp] for (path, kind), stamp in sorted(facts.items())]}


def _revalidate_physical(approved, snapshot):
    # Only short opens/stats and small pointer reads inside the exclusive gate.
    if any(_physical_stamp(path, kind) != stamp for path, kind, stamp in approved["facts"]):
        raise _drift()
    if any(_overlap(Path(root), Path(retired)) for _, root in approved["extents"]
           for retired, _ in snapshot.retained_sources):
        raise AccessError("A project scope overlaps a retained history source.", code="project_scope_overlap")


def compile_generation(document):
    """Pin newly registered roots, preserve existing pins, and reject stale pins."""
    result = deepcopy(document)
    if not isinstance(result, dict) or not isinstance(result.get("projects"), list):
        raise AccessError("A unified generation needs a projects array.", code="agent_policy_invalid")
    for project in result["projects"]:
        if not isinstance(project, dict) or not isinstance(project.get("root"), str):
            raise AccessError("A project root is required.", code="agent_policy_invalid")
        root = Path(project["root"])
        if not root.is_absolute() or root.resolve() != root or not root.is_dir():
            raise AccessError("Register canonical absolute project roots.", code="identity_mismatch")
        pin = project.get("repository_id")
        if pin is not None:
            probe = repository_probe(root)
            if not _pin_matches(pin, probe):
                raise AccessError("The existing repository pin does not match its root.", code="identity_mismatch")
            project["repository_id"] = probe["repository_id"]
        else:
            identity = persistent_identity(root)
            if "directory_identity" in project and project["directory_identity"] != identity:
                raise AccessError("The registered project directory identity changed.", code="identity_mismatch")
            project["directory_identity"] = identity
    sources = result.get("sources")
    if not isinstance(sources, dict):
        raise AccessError("A unified generation needs source descriptors.", code="agent_policy_invalid")
    projects = {entry["id"] for entry in result["projects"]}
    for source in sources.values():
        if not isinstance(source, dict) or not isinstance(source.get("root"), str):
            raise AccessError("A source root is required.", code="agent_policy_invalid")
        root = Path(source["root"])
        # A disabled registered source keeps its old physical protection pin,
        # even while disconnected. Re-enabling it must verify that pin again.
        if source.get("enabled") is not False or "root_identity" not in source:
            if not root.is_dir():
                raise AccessError("Register an existing source directory.", code="identity_mismatch")
            identity = persistent_identity(root)
            if "root_identity" in source and source["root_identity"] != identity:
                raise AccessError("The registered source identity changed.", code="identity_mismatch")
            source["root_identity"] = identity
        for alias in source.get("path_aliases", []):
            if alias["project_id"] not in projects or source.get("enabled") is False and "target_identity" in alias:
                continue
            old = Path(alias["old_root"])
            if old.resolve() != old or old.exists() or old.is_symlink():
                raise _drift()
            identity = persistent_identity(Path(alias["target_root"]))
            if "target_identity" in alias and alias["target_identity"] != identity:
                raise AccessError("The migrated target directory identity changed.", code="identity_mismatch")
            alias["target_identity"] = identity
    validate_generation(result)
    Catalog._from_document({"projects": result["projects"]}, unified=True)
    return result


def preview_activation(document, *, inputs=(), previous=None):
    """Return the complete target and the changes an operator must review."""
    target = compile_generation(document)
    approved = _approved_physical_scope(target)
    old = previous[0] if previous is not None else {"projects": [], "sources": {}}
    projects = sorted(project["id"] for project in target["projects"])
    old_projects = sorted(project["id"] for project in old["projects"])
    changes = []
    for source_id in sorted(old["sources"].keys() | target["sources"].keys()):
        before = old_projects if old["sources"].get(source_id, {}).get("enabled") else []
        after = projects if target["sources"].get(source_id, {}).get("enabled") else []
        changes.append({"source": source_id, "old_projects": before, "new_projects": after,
                        "added_projects": sorted(set(after) - set(before)),
                        "removed_projects": sorted(set(before) - set(after))})
    preview = {"version": 1, "inputs": list(inputs), "previous_digest": previous[1] if previous else None,
               "document": target, "changes": changes, "physical_scope": approved,
               "candidate_destinations": {item["id"]: item.get("candidate_directory") or "docs/candidates/chatgpt"
                                          for item in target["projects"]}}
    return preview, _digest(canonical_bytes(preview))


def preview_path_migration(document, source_id, old_root, before, *, inputs=(), previous=None,
                           native_project=None):
    from .agent_history_path_migration import reviewed_document
    target, report = reviewed_document(compile_generation(document), source_id, old_root, before,
                                       previous=previous[0] if previous else None,
                                       native_project=native_project)
    preview, _ = preview_activation(target, inputs=inputs, previous=previous)
    preview['path_migration'] = report
    conflicts = [entry for entry in report['pending'] if entry['reason'] == 'previous_approval_drifted']
    if conflicts:
        # A stale template may omit the active receipt. Activating that omission
        # would erase provenance and allow a later retry to silently re-enrol it.
        preview['unresolved'] = conflicts
    return preview, _digest(canonical_bytes(preview))


def _verified_codex_disposition(access, native, project):
    try:
        config = access._configuration(guard_codex=False)
        config.update(threads={}, inherit=True, snapshots=access.catalog.repositories.discover_all())
        row = access._metadata(config, thread_id=native).get(native)
        if row is None or not access._eligible(config, row):
            return None
        access._drain(access._ensure_iter(config, row))
        grant, _ = access._derive(config, row)
        if grant is None or grant.get("project_id") != project:
            return None
        return grant.get("_proof")
    finally:
        access.close()


def _codex_dispositions(projects, legacy_path, legacy_document, dispositions):
    from .history import HistoryAccess

    catalog = Catalog._from_document({"projects": projects}, unified=True)
    dispositions = dispositions or {}
    records = {item["id"]: item for item in legacy_document["threads"]}
    if not isinstance(dispositions, dict) or dispositions.keys() - records.keys():
        raise AccessError("Codex dispositions must identify an original explicit grant.", code="generation_conflict")
    denies = set(legacy_document.get("denied_threads", ()))
    evidence, reviewed, unresolved = [], {}, []
    for native, item in records.items():
        decision = dispositions.get(native)
        if native in denies or decision == "exclude":
            denies.add(native)
            reviewed[native] = "exclude"
            continue
        if (isinstance(decision, str) and decision in catalog.projects
                and item.get("project_id") in (None, decision)):
            try:
                proof = _verified_codex_disposition(HistoryAccess(legacy_path, catalog=catalog), native, decision)
            except (AccessError, OSError, ValueError):
                proof = None
            if proof is not None:
                reviewed[native] = {"project_id": decision, "proof": proof}
                evidence.append({key: value for key, value in item.items() if key != "project_id"})
                continue
        unresolved.append({"source": "codex", "native_id": native, "project_id": item.get("project_id"),
                           "reason": "legacy_binding_requires_verification"})
    return evidence, sorted(denies), reviewed, unresolved


def preview_migration(projects_path, agent_policy_path, legacy_path, principals, *, exceptions=None,
                      dispositions=None, access_path=None):
    """Preview source/project Cartesian scope changes from the current v1 files."""
    projects_input, projects = _input(projects_path)
    sources_input, _ = _input(agent_policy_path)
    existing, _ = _entries(Path(agent_policy_path))
    inputs = [projects_input, sources_input]
    sources = {}
    exceptions = exceptions or {}
    for source_id, source in existing.items():
        sources[source_id] = {"adapter": source.adapter, "root": str(source.root), "format": source.format,
                              "enabled": source.enabled, "instance_id": source_id,
                              "denied_threads": sorted(source.denied),
                              "exceptions": exceptions.get(source_id, {}), "links": dict(source.links),
                              "link_instances": dict(source.links)}
    legacy, legacy_document = None, None
    unresolved, reviewed = [], {}
    if (not principals or any(not _verified_actor(actor) for actor in principals)
            or len(set(principals)) != len(principals)):
        raise AccessError("Supply the verified Access identities for the migration review.", code="generation_conflict")
    if access_path is not None:
        access_input, authenticated = _input(access_path)
        emails = authenticated.get("allowed_emails") if isinstance(authenticated, dict) else None
        if (not isinstance(emails, list) or any(not isinstance(email, str) for email in emails)
                or len({email.casefold() for email in emails}) != len(principals) or "local" in principals):
            raise AccessError("Review all identities on the existing Access allowlist.", code="generation_conflict")
        inputs.append(access_input)
    if legacy_path is not None:
        legacy_input, legacy_document = _input(legacy_path)
        inputs.append(legacy_input)
        # Preserving an explicit Codex grant requires real same-project
        # inheritance proof. An approved exclusion must also survive automatic
        # inheritance, so it becomes an explicit Codex deny.
        pinned_projects = compile_generation({"version": 2, "projects": projects["projects"],
                                              "sources": {}, "legacy_history": None})["projects"]
        evidence, denies, reviewed, unresolved = _codex_dispositions(
            pinned_projects, legacy_path, legacy_document, dispositions)
        legacy = {"codex_home": legacy_document["codex_home"], "state_db": legacy_document["state_db"],
                  "tool_evidence": evidence}
        sources["codex"] = {"adapter": "codex", "root": legacy["codex_home"], "format": "local",
                             "enabled": True, "instance_id": "codex",
                             "denied_threads": denies}
    elif dispositions:
        raise AccessError("Codex dispositions require the original Codex configuration.", code="generation_conflict")
    target = {"version": 2, "projects": projects["projects"], "sources": sources, "legacy_history": legacy}
    preview, _ = preview_activation(target, inputs=inputs)
    project_ids = sorted(project["id"] for project in target["projects"])
    changes = []
    registered_principals = {actor for source in existing.values() for actor in source.actors}
    for actor in sorted(principals):
        for source_id, source in sorted(sources.items()):
            if not source["enabled"]:
                continue
            before = project_ids if source_id == "codex" else sorted(existing[source_id].actors.get(actor, ()))
            inherited = (bool(legacy_document.get("inherit_projects", False)) if source_id == "codex"
                         else existing[source_id].inherit)
            changes.append({"principal": actor, "source": source_id, "old_projects": before,
                            "new_projects": project_ids, "added_projects": sorted(set(project_ids) - set(before)),
                            "removed_projects": sorted(set(before) - set(project_ids)),
                            "new_history_actor": actor not in registered_principals,
                            "old_inherit_projects": inherited, "new_inherit_projects": True})
    for source_id, source in existing.items():
        for native_id, project_id in source.threads.items():
            if native_id not in exceptions.get(source_id, {}):
                unresolved.append({"source": source_id, "native_id": native_id, "project_id": project_id,
                                   "reason": "snapshot_binding_requires_verification"})
    preview["changes"] = changes
    preview["unresolved"] = unresolved
    preview["migration"] = True
    preview["legacy_input"] = str(Path(legacy_path).absolute()) if legacy_path is not None else None
    preview["codex_dispositions"] = reviewed
    preview["required_scope_approvals"] = _scope_requests(preview)
    preview["scope_approvals"] = []
    return preview, _digest(canonical_bytes(preview))


def _scope_requests(preview):
    required = []
    for change in preview["changes"]:
        if change["added_projects"] or change["new_history_actor"] or not change["old_inherit_projects"]:
            material = {"inputs": preview["inputs"], "document": preview["document"], "change": change,
                        "physical_scope": preview["physical_scope"]}
            required.append({"principal": change["principal"], "source": change["source"],
                             "scope_digest": _digest(canonical_bytes(material))})
    return sorted(required, key=lambda item: (item["principal"], item["source"]))


def approve_migration_scope(preview, principal, source, expected_preview_digest):
    """Record an explicit operator decision for one exact migration scope."""
    if (_digest(canonical_bytes(preview)) != expected_preview_digest or not preview.get("migration")
            or preview.get("required_scope_approvals") != _scope_requests(preview)):
        raise AccessError("The migration scope preview changed.", code="generation_conflict")
    requested = next((item for item in preview["required_scope_approvals"]
                      if item["principal"] == principal and item["source"] == source), None)
    if requested is None:
        raise AccessError("That principal and source require no scope decision in this preview.", code="generation_conflict")
    result = deepcopy(preview)
    approved = {item["scope_digest"]: item for item in result["scope_approvals"]}
    approved[requested["scope_digest"]] = requested
    result["scope_approvals"] = sorted(approved.values(), key=lambda item: (item["principal"], item["source"]))
    return result, _digest(canonical_bytes(result))


def activate_preview(store, preview, expected_preview_digest, *, initial=False, recovery=False):
    if _digest(canonical_bytes(preview)) != expected_preview_digest:
        raise AccessError("The activation preview changed.", code="generation_conflict")
    if preview.get("unresolved"):
        raise AccessError("Resolve the migration preview before activation.", code="generation_conflict")
    if preview.get("migration"):
        required = _scope_requests(preview)
        if preview.get("required_scope_approvals") != required or preview.get("scope_approvals") != required:
            raise AccessError("Confirm every requested principal and source scope before activation.", code="generation_conflict")
    for source in preview["inputs"]:
        current, _ = _input(source["path"])
        if current != source:
            raise AccessError("A migration input changed after preview.", code="generation_conflict")
    document = compile_generation(preview["document"])
    approved = _approved_physical_scope(document)
    if document != preview["document"] or approved != preview["physical_scope"]:
        raise _drift()
    if "path_migration" in preview:
        from .agent_history_path_migration import revalidate
        revalidate(document, preview["path_migration"])
    if preview.get("legacy_input") is not None:
        legacy_path = preview["legacy_input"]
        _, legacy = _input(legacy_path)
        selections = {native: evidence if evidence == "exclude" else evidence["project_id"]
                      for native, evidence in preview["codex_dispositions"].items()}
        evidence, denies, reviewed, unresolved = _codex_dispositions(document["projects"], legacy_path, legacy, selections)
        if (unresolved or reviewed != preview["codex_dispositions"] or evidence != document["legacy_history"]["tool_evidence"]
                or denies != document["sources"]["codex"]["denied_threads"]):
            raise _drift()
    if any(_overlap(Path(root), path) for _, root in approved["extents"]
           for path in (store.path, store.anchor_path)):
        raise AccessError("A project scope overlaps the authorization store.", code="project_scope_overlap")
    if recovery:
        return store.recover(document, validate=lambda snapshot: _revalidate_physical(approved, snapshot))
    return store.activate(document, expected_digest=preview["previous_digest"], initial=initial,
                          validate=lambda snapshot: _revalidate_physical(approved, snapshot))


def write_descriptor(path, store):
    """Create the explicit v2 startup descriptor without overwriting a file."""
    path = Path(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(os.dup(descriptor), "wb") as stream:
            stream.write(canonical_bytes({"version": 2, "generation_directory": str(store.path)}))
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def _recovery_store(descriptor, initial_path):
    if initial_path is not None:
        return GenerationStore(initial_path)
    parent = _directory(descriptor.parent)
    try:
        content = _read_at(parent, descriptor.name, 8192)
    finally:
        os.close(parent)
    state = json.loads(content, object_pairs_hook=_unique)
    if not isinstance(state, dict) or set(state) != {"version", "generation_directory"} or state["version"] != 2:
        raise AccessError("The unified policy descriptor is invalid.", code="generation_conflict")
    return GenerationStore(state["generation_directory"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("preview", "preview-migration", "preview-path-migration",
                                              "approve-scope", "activate", "recover", "show"))
    parser.add_argument("--old-root", help="Exact former workspace root of an already configured migration alias")
    parser.add_argument("--native-project", help="Native project identity when more than one alias shares a former root")
    parser.add_argument("--before", help="Latest pre-move timestamp eligible for local review, including UTC offset")
    parser.add_argument("--descriptor", type=Path)
    parser.add_argument("--document", type=Path)
    parser.add_argument("--preview", type=Path)
    parser.add_argument("--preview-sha256")
    parser.add_argument("--initialize", type=Path)
    parser.add_argument("--projects", type=Path)
    parser.add_argument("--agent-v1", type=Path)
    parser.add_argument("--legacy-v1", type=Path)
    parser.add_argument("--principal", action="append", default=[])
    parser.add_argument("--access-config", type=Path,
                        help="Bind the current authenticated origin configuration to the migration review.")
    parser.add_argument("--source")
    parser.add_argument("--exceptions", type=Path)
    parser.add_argument("--codex-dispositions", type=Path,
                        help="Private JSON mapping each old explicit Codex ID to a verified project ID or exclude.")
    arguments = parser.parse_args()
    try:
        if arguments.operation == "preview-migration":
            if arguments.projects is None or arguments.agent_v1 is None or not arguments.principal:
                parser.error("preview-migration requires --projects, --agent-v1 and at least one --principal")
            exceptions = _input(arguments.exceptions)[1] if arguments.exceptions else None
            dispositions = _input(arguments.codex_dispositions)[1] if arguments.codex_dispositions else None
            preview, digest = preview_migration(arguments.projects, arguments.agent_v1, arguments.legacy_v1,
                                                 arguments.principal, exceptions=exceptions, dispositions=dispositions,
                                                 access_path=arguments.access_config)
            print(json.dumps({"sha256": digest, "preview": preview}, ensure_ascii=False, indent=2))
        elif arguments.operation == "approve-scope":
            if (arguments.preview is None or arguments.preview_sha256 is None
                    or len(arguments.principal) != 1 or arguments.source is None):
                parser.error("approve-scope requires --preview, --preview-sha256, one --principal and --source")
            _, value = _input(arguments.preview)
            preview, digest = approve_migration_scope(value.get("preview", value), arguments.principal[0],
                                                       arguments.source, arguments.preview_sha256)
            print(json.dumps({"sha256": digest, "preview": preview}, ensure_ascii=False, indent=2))
        elif arguments.descriptor is None:
            parser.error("This operation requires --descriptor")
        elif arguments.operation == "show":
            document, digest = AgentPolicy(arguments.descriptor, mode="v2").snapshot()
            print(json.dumps({"sha256": digest, "document": document}, ensure_ascii=False, indent=2))
        elif arguments.operation in {"preview", "preview-path-migration"}:
            if arguments.document is None:
                parser.error("preview requires --document")
            input_record, document = _input(arguments.document)
            previous = None if arguments.initialize else AgentPolicy(arguments.descriptor, mode="v2").snapshot()
            if arguments.operation == "preview-path-migration":
                if not arguments.source or not arguments.old_root or not arguments.before:
                    parser.error("preview-path-migration requires --source, --old-root and --before")
                preview, digest = preview_path_migration(document, arguments.source, arguments.old_root,
                                                         arguments.before, inputs=(input_record,), previous=previous,
                                                         native_project=arguments.native_project)
            else:
                preview, digest = preview_activation(document, previous=previous)
            print(json.dumps({"sha256": digest, "preview": preview}, ensure_ascii=False, indent=2))
        else:
            if arguments.preview is None or arguments.preview_sha256 is None:
                parser.error("activate requires --preview and --preview-sha256")
            _, value = _input(arguments.preview)
            preview = value.get("preview", value)
            if arguments.operation == "recover":
                store = _recovery_store(arguments.descriptor, arguments.initialize)
                if arguments.initialize and (arguments.descriptor.exists() or arguments.descriptor.is_symlink()):
                    raise AccessError("The initial recovery descriptor already exists.", code="generation_conflict")
                digest = activate_preview(store, preview, arguments.preview_sha256, recovery=True)
                if arguments.initialize:
                    write_descriptor(arguments.descriptor, store)
            elif arguments.initialize:
                store = initialize_store(arguments.initialize)
                digest = activate_preview(store, preview, arguments.preview_sha256, initial=True)
                write_descriptor(arguments.descriptor, store)
            else:
                store = AgentPolicy(arguments.descriptor, mode="v2").store
                digest = activate_preview(store, preview, arguments.preview_sha256)
            print(json.dumps({"sha256": digest}))
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, str(error) + "\n")


if __name__ == "__main__":
    main()
