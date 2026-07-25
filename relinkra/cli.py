"""Relinkra CLI — register/list/show workspaces. Prints JSON only."""

from __future__ import annotations

import argparse
import json
import sys

from . import identity as identity_mod
from .cbm import workspace_cbm_record
from .identity import AmbiguousIdentityError, GitError
from .registry import DEFAULT_REGISTRY_PATH, Registry, RegistryError


def _emit(obj: object, fh=None) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True), file=fh or sys.stdout)


def _fail(message: str, code: int = 1) -> int:
    _emit({"error": identity_mod.redact_url(message)}, fh=sys.stderr)
    return code


def _cmd_register(args: argparse.Namespace) -> int:
    path = args.path
    try:
        repository_identity = identity_mod.discover_repository_identity(
            path, remote_url=args.remote_url
        )
        git_info = {
            "branch": identity_mod.git_branch(path),
            "head_sha": identity_mod.git_head_sha(path),
        }
    except (GitError, ValueError) as exc:
        return _fail(str(exc))

    cbm = None
    if args.cbm_project_name:
        if not args.cbm_cache_dir:
            return _fail("--cbm-cache-dir is required with --cbm-project-name")
        cbm = workspace_cbm_record(
            args.cbm_project_name,
            args.cbm_cache_dir,
            version=args.cbm_version,
            sha256=args.cbm_sha256,
        ).to_dict()

    try:
        registry = Registry(args.registry)
        workspace = registry.register_workspace(
            path,
            repository_identity,
            display_name=args.display_name,
            git=git_info,
            cbm=cbm,
            allow_weak_merge=args.allow_weak_merge,
        )
    except AmbiguousIdentityError as exc:
        return _fail(str(exc), code=2)
    except (RegistryError, ValueError) as exc:
        return _fail(str(exc))

    project = registry.projects[workspace.project_id]
    _emit({"project": project.to_dict(), "workspace": workspace.to_dict()})
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    try:
        registry = Registry(args.registry)
    except RegistryError as exc:
        return _fail(str(exc))
    _emit({"projects": registry.list_projects(), "workspaces": registry.list_workspaces()})
    return 0


def _cmd_show(args: argparse.Namespace) -> int:
    try:
        registry = Registry(args.registry)
    except RegistryError as exc:
        return _fail(str(exc))
    workspace = registry.get_workspace(args.workspace_id)
    if workspace is None:
        return _fail(f"unknown workspace_id: {args.workspace_id}")
    project = registry.projects[workspace.project_id]
    _emit({"project": project.to_dict(), "workspace": workspace.to_dict()})
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="relinkra", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_register = sub.add_parser("register", help="register a workspace")
    p_register.add_argument("path", metavar="PATH")
    p_register.add_argument("--registry", default=DEFAULT_REGISTRY_PATH)
    p_register.add_argument("--display-name", default=None)
    p_register.add_argument("--remote-url", default=None)
    p_register.add_argument("--allow-weak-merge", action="store_true")
    p_register.add_argument("--cbm-project-name", default=None)
    p_register.add_argument("--cbm-cache-dir", default=None)
    p_register.add_argument("--cbm-version", default=None)
    p_register.add_argument("--cbm-sha256", default=None)
    p_register.set_defaults(func=_cmd_register)

    p_list = sub.add_parser("list", help="list projects and workspaces")
    p_list.add_argument("--registry", default=DEFAULT_REGISTRY_PATH)
    p_list.set_defaults(func=_cmd_list)

    p_show = sub.add_parser("show", help="show one workspace")
    p_show.add_argument("workspace_id", metavar="WORKSPACE_ID")
    p_show.add_argument("--registry", default=DEFAULT_REGISTRY_PATH)
    p_show.set_defaults(func=_cmd_show)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
