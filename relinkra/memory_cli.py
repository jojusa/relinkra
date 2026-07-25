"""Relinkra memory CLI — save/query/supersede shared memories.

JSON output only; nonzero exit on errors; stderr is redacted.

    python -m relinkra.memory_cli save ...
    python -m relinkra.memory_cli query ...
    python -m relinkra.memory_cli supersede ...

Project/workspace resolution: pass --project-id (and --workspace-id)
directly, or --path with --registry to resolve them from the R1B
Registry. repository_identity comes from the registry project when
resolvable, from --repository-identity otherwise.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from . import identity as identity_mod
from .engram_adapter import EngramCLIAdapter
from .memory import (
    MemoryError,
    MemoryNotFoundError,
    MemoryService,
    MemoryStoreError,
    MemoryValidationError,
    sanitize_error,
    validate_project_id,
)
from .registry import DEFAULT_REGISTRY_PATH, Registry, RegistryError

DEFAULT_REGISTRY = DEFAULT_REGISTRY_PATH


def _emit(obj: object, fh=None) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True), file=fh or sys.stdout)


def _fail(message: str, code: int = 1) -> int:
    _emit({"error": sanitize_error(message)}, fh=sys.stderr)
    return code


def _build_service(args: argparse.Namespace, store=None) -> MemoryService:
    if store is None:
        store = EngramCLIAdapter(engram_bin=getattr(args, "engram_bin", "engram"))
    return MemoryService(store)


def _resolve_context(args: argparse.Namespace) -> tuple[str, Optional[str], dict]:
    """Resolve (project_id, workspace_id, repository_identity).

    Registry resolution (--path + --registry) wins for workspace binding;
    --project-id is always authoritative when given. Without a registry
    project, --repository-identity (canonical R1B value) is required so a
    memory is never bound to a bare path/branch/HEAD.
    """
    project_id = getattr(args, "project_id", None)
    workspace_id = getattr(args, "workspace_id", None)
    repo_identity = None

    path = getattr(args, "path", None)
    if path:
        try:
            registry = Registry(getattr(args, "registry", DEFAULT_REGISTRY))
        except RegistryError as exc:
            raise MemoryValidationError(str(exc)) from exc
        canonical = identity_mod.canonicalize_path(path)
        match = None
        for workspace in registry.workspaces.values():
            if workspace.canonical_path == canonical:
                match = workspace
                break
        if match is None:
            raise MemoryNotFoundError(
                "path is not registered in the registry; run "
                "`python -m relinkra.cli register` first"
            )
        workspace_id = workspace_id or match.workspace_id
        if project_id is None:
            project_id = match.project_id
        elif project_id != match.project_id:
            raise MemoryValidationError(
                "--project-id does not match the registry project for --path"
            )
        project = registry.projects.get(project_id)
        if project is not None:
            repo_identity = project.repository_identity.to_dict()

    if project_id is None:
        raise MemoryValidationError(
            "project binding required: pass --project-id or --path"
        )
    project_id = validate_project_id(project_id)

    if repo_identity is None:
        raw = getattr(args, "repository_identity", None)
        if not raw:
            raise MemoryValidationError(
                "repository identity required: pass --repository-identity "
                "(canonical remote://git/..., explicit://..., or "
                "local-root://... value) or resolve via --path/--registry"
            )
        raw = raw.strip()
        kind = (
            "remote"
            if raw.startswith("remote://git/")
            else "explicit"
            if raw.startswith("explicit://")
            else "local_root"
            if raw.startswith("local-root://")
            else ""
        )
        if not kind:
            raise MemoryValidationError(
                "repository identity must be a canonical R1B identity value"
            )
        repo_identity = {"kind": kind, "value": raw, "trust": "strong"}

    return project_id, workspace_id, repo_identity


def _git_metadata(path: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    if not path:
        return None, None
    try:
        branch = identity_mod.git_branch(path) or None
        head = identity_mod.git_head_sha(path)
        return branch, head
    except Exception:
        return None, None


def _cmd_save(args: argparse.Namespace, store=None) -> int:
    try:
        project_id, workspace_id, repo_identity = _resolve_context(args)
        branch, commit_sha = _git_metadata(getattr(args, "path", None))
        service = _build_service(args, store)
        memory, deduplicated, superseded = service.save(
            project_id=project_id,
            memory_type=args.memory_type,
            title=args.title,
            body=args.content,
            repository_identity=repo_identity,
            scope=args.scope,
            workspace_id=workspace_id,
            agent_id=args.agent_id or "",
            agent_type=args.agent_type or "",
            branch=args.branch or branch,
            commit_sha=args.commit_sha or commit_sha,
            confidence=args.confidence,
            source_tool=args.source_tool or "relinkra-cli",
        )
    except MemoryNotFoundError as exc:
        return _fail(str(exc), code=2)
    except (MemoryError, ValueError) as exc:
        return _fail(str(exc))
    _emit(
        {
            "memory": memory.to_dict(),
            "deduplicated": deduplicated,
            "superseded": superseded,
        }
    )
    return 0


def _cmd_query(args: argparse.Namespace, store=None) -> int:
    try:
        project_id = validate_project_id(args.project_id or "")
        service = _build_service(args, store)
        result = service.query(
            project_id=project_id,
            scope=args.scope,
            workspace_id=args.workspace_id,
            agent_type=args.agent_type,
            text=args.text,
            memory_type=args.memory_type,
            include_history=args.include_history,
            limit=args.limit,
        )
    except (MemoryError, ValueError) as exc:
        return _fail(str(exc))
    _emit(result.to_dict())
    return 0


def _cmd_supersede(args: argparse.Namespace, store=None) -> int:
    try:
        project_id = validate_project_id(args.project_id or "")
        service = _build_service(args, store)
        memory, superseded = service.supersede(
            memory_id=args.memory_id,
            project_id=project_id,
            title=args.title,
            body=args.content,
            obsolete=args.obsolete,
            agent_id=args.agent_id or "",
            source_tool=args.source_tool or "relinkra-cli",
        )
    except MemoryNotFoundError as exc:
        return _fail(str(exc), code=2)
    except (MemoryError, ValueError) as exc:
        return _fail(str(exc))
    _emit({"memory": memory.to_dict(), "superseded": superseded})
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="relinkra-memory", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    def _common(p, needs_project=True):
        p.add_argument("--registry", default=DEFAULT_REGISTRY)
        p.add_argument("--engram-bin", default="engram")

    p_save = sub.add_parser("save", help="save a memory")
    _common(p_save)
    p_save.add_argument("--project-id", default=None)
    p_save.add_argument("--path", default=None)
    p_save.add_argument("--workspace-id", default=None)
    p_save.add_argument("--repository-identity", default=None)
    p_save.add_argument("--scope", default="project_shared")
    p_save.add_argument("--memory-type", required=True)
    p_save.add_argument("--title", required=True)
    p_save.add_argument("--content", required=True)
    p_save.add_argument("--agent-id", default=None)
    p_save.add_argument("--agent-type", default=None)
    p_save.add_argument("--branch", default=None)
    p_save.add_argument("--commit-sha", default=None)
    p_save.add_argument("--confidence", type=float, default=None)
    p_save.add_argument("--source-tool", default=None)
    p_save.set_defaults(func=_cmd_save)

    p_query = sub.add_parser("query", help="query memories by scope policy")
    _common(p_query)
    p_query.add_argument("--project-id", required=True)
    p_query.add_argument("--scope", default="project_shared")
    p_query.add_argument("--workspace-id", default=None)
    p_query.add_argument("--agent-type", default=None)
    p_query.add_argument("--text", default=None)
    p_query.add_argument("--memory-type", default=None)
    p_query.add_argument("--include-history", action="store_true")
    p_query.add_argument("--limit", type=int, default=50)
    p_query.set_defaults(func=_cmd_query)

    p_sup = sub.add_parser("supersede", help="supersede or obsolete a memory")
    _common(p_sup)
    p_sup.add_argument("memory_id")
    p_sup.add_argument("--project-id", required=True)
    p_sup.add_argument("--title", default=None)
    p_sup.add_argument("--content", default=None)
    p_sup.add_argument("--obsolete", action="store_true")
    p_sup.add_argument("--agent-id", default=None)
    p_sup.add_argument("--source-tool", default=None)
    p_sup.set_defaults(func=_cmd_supersede)

    return parser


def main(argv: Optional[list] = None, store=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args, store=store)
    except MemoryStoreError as exc:
        return _fail(str(exc), code=3)


if __name__ == "__main__":
    sys.exit(main())
