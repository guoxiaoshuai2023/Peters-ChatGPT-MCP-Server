"""Local operator preview and activation. No MCP tool exposes these operations."""

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path

from .agent_history_generation import (GenerationStore, canonical_bytes, initialize_store,
                                       _unique)
from .agent_history_policy import AgentPolicy, _entries, validate_generation
from .catalog import AccessError, Catalog, _config_bytes
from .fs_identity import persistent_identity
from .workspaces import _pin_matches, repository_probe


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _input(path):
    path = Path(path).absolute()
    raw = _config_bytes(path)
    return {"path": str(path), "sha256": _digest(raw)}, json.loads(raw, object_pairs_hook=_unique)


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
    for source in sources.values():
        if not isinstance(source, dict) or not isinstance(source.get("root"), str):
            raise AccessError("A source root is required.", code="agent_policy_invalid")
        root = Path(source["root"])
        if not root.is_dir():
            raise AccessError("Register an existing source directory.", code="identity_mismatch")
        identity = persistent_identity(root)
        if "root_identity" in source and source["root_identity"] != identity:
            raise AccessError("The registered source identity changed.", code="identity_mismatch")
        source["root_identity"] = identity
        for alias in source.get("path_aliases", []):
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
    old = previous[0] if previous is not None else {"principals": [], "projects": [], "sources": {}}
    projects = sorted(project["id"] for project in target["projects"])
    old_projects = sorted(project["id"] for project in old["projects"])
    changes = []
    for actor in sorted(target["principals"]):
        for source_id, source in sorted(target["sources"].items()):
            if not source["enabled"]:
                continue
            prior = old.get("sources", {}).get(source_id)
            existed = actor in old["principals"] and prior is not None and prior["enabled"]
            before = old_projects if existed else []
            changes.append({"principal": actor, "source": source_id, "old_projects": before,
                            "new_projects": projects, "added_projects": sorted(set(projects) - set(before))})
    preview = {"version": 1, "inputs": list(inputs), "previous_digest": previous[1] if previous else None,
               "document": target, "changes": changes}
    return preview, _digest(canonical_bytes(preview))


def preview_migration(projects_path, agent_policy_path, legacy_path, principals, *, exceptions=None):
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
    legacy = None
    legacy_document = None
    if legacy_path is not None:
        legacy_input, legacy_document = _input(legacy_path)
        inputs.append(legacy_input)
        legacy = {"codex_home": legacy_document["codex_home"], "state_db": legacy_document["state_db"],
                  "tool_evidence": [{key: value for key, value in item.items() if key != "project_id"}
                                    for item in legacy_document["threads"]]}
        sources["codex"] = {"adapter": "codex", "root": legacy["codex_home"], "format": "local",
                             "enabled": True, "instance_id": "codex",
                             "denied_threads": legacy_document.get("denied_threads", []),
                             "exceptions": exceptions.get("codex", {})}
    target = {"version": 2, "projects": projects["projects"], "principals": list(principals),
              "sources": sources, "legacy_history": legacy}
    preview, _ = preview_activation(target, inputs=inputs)
    project_ids = sorted(project["id"] for project in target["projects"])
    changes = []
    unresolved = []
    registered_principals = {actor for source in existing.values() for actor in source.actors}
    for actor in sorted(principals):
        if actor not in registered_principals:
            unresolved.append({"principal": actor, "reason": "principal_not_previously_registered"})
        for source_id, source in sorted(sources.items()):
            if not source["enabled"]:
                continue
            before = project_ids if source_id == "codex" else sorted(existing[source_id].actors.get(actor, ()))
            inherited = (bool(legacy_document.get("inherit_projects", False)) if source_id == "codex"
                         else existing[source_id].inherit)
            changes.append({"principal": actor, "source": source_id, "old_projects": before,
                            "new_projects": project_ids, "added_projects": sorted(set(project_ids) - set(before)),
                            "old_inherit_projects": inherited, "new_inherit_projects": True})
    for source_id, source in existing.items():
        for native_id, project_id in source.threads.items():
            if native_id not in exceptions.get(source_id, {}):
                unresolved.append({"source": source_id, "native_id": native_id, "project_id": project_id,
                                   "reason": "snapshot_binding_requires_verification"})
    if legacy_document is not None:
        for item in legacy_document["threads"]:
            unresolved.append({"source": "codex", "native_id": item["id"],
                               "project_id": item.get("project_id"), "reason": "legacy_binding_requires_verification"})
    preview["changes"] = changes
    preview["unresolved"] = unresolved
    preview["migration"] = True
    preview["required_scope_approvals"] = _scope_requests(preview)
    preview["scope_approvals"] = []
    return preview, _digest(canonical_bytes(preview))


def _scope_requests(preview):
    required = []
    for change in preview["changes"]:
        if change["added_projects"] or not change["old_inherit_projects"]:
            material = {"inputs": preview["inputs"], "document": preview["document"], "change": change}
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


def activate_preview(store, preview, expected_preview_digest, *, initial=False):
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
    return store.activate(document, expected_digest=preview["previous_digest"], initial=initial)


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("preview", "preview-migration", "approve-scope", "activate", "show"))
    parser.add_argument("--descriptor", type=Path)
    parser.add_argument("--document", type=Path)
    parser.add_argument("--preview", type=Path)
    parser.add_argument("--preview-sha256")
    parser.add_argument("--initialize", type=Path)
    parser.add_argument("--projects", type=Path)
    parser.add_argument("--agent-v1", type=Path)
    parser.add_argument("--legacy-v1", type=Path)
    parser.add_argument("--principal", action="append", default=[])
    parser.add_argument("--source")
    parser.add_argument("--exceptions", type=Path)
    arguments = parser.parse_args()
    try:
        if arguments.operation == "preview-migration":
            if arguments.projects is None or arguments.agent_v1 is None or not arguments.principal:
                parser.error("preview-migration requires --projects, --agent-v1 and at least one --principal")
            exceptions = _input(arguments.exceptions)[1] if arguments.exceptions else None
            preview, digest = preview_migration(arguments.projects, arguments.agent_v1, arguments.legacy_v1,
                                                 arguments.principal, exceptions=exceptions)
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
        elif arguments.operation == "preview":
            if arguments.document is None:
                parser.error("preview requires --document")
            _, document = _input(arguments.document)
            previous = None if arguments.initialize else AgentPolicy(arguments.descriptor, mode="v2").snapshot()
            preview, digest = preview_activation(document, previous=previous)
            print(json.dumps({"sha256": digest, "preview": preview}, ensure_ascii=False, indent=2))
        else:
            if arguments.preview is None or arguments.preview_sha256 is None:
                parser.error("activate requires --preview and --preview-sha256")
            _, value = _input(arguments.preview)
            preview = value.get("preview", value)
            if arguments.initialize:
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
