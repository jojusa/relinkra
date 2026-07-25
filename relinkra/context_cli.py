"""Relinkra context packet CLI — build a deterministic Project Context Packet.

JSON (default) or Markdown to stdout; errors are redacted on stderr with a
nonzero exit code.

    python -m relinkra.context_cli --project-id rlk_... [--task "..."]
    python -m relinkra.context_cli --project-id rlk_... --symbol src.calc.add \
        --cbm-bin codebase-memory-mcp --cbm-project-name <slug> --format markdown

Exit codes: 0 ok; 1 invalid input / build error; 2 project mismatch.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional

from .cbm_adapter import CBMCLIAdapter, CBMAdapterError
from .context_builder import (
    ContextBuildError,
    ContextBuilder,
    ContextRequest,
)
from .engram_adapter import EngramCLIAdapter
from .memory import MemoryError, MemoryService, sanitize_error
from .registry import DEFAULT_REGISTRY_PATH, Registry, RegistryError

DEFAULT_REGISTRY = DEFAULT_REGISTRY_PATH


def _emit(obj: object, fh=None) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True), file=fh or sys.stdout)


def _fail(message: str, code: int = 1) -> int:
    _emit({"error": sanitize_error(message)}, fh=sys.stderr)
    return code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="relinkra-context", description=__doc__
    )
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--workspace-id", default=None)
    parser.add_argument("--task", default=None)
    parser.add_argument(
        "--file",
        default=None,
        help="repo-relative POSIX file path to focus",
    )
    parser.add_argument(
        "--symbol",
        default=None,
        help="qualified symbol name, or a CodeReference as a JSON object",
    )
    parser.add_argument("--registry", default=DEFAULT_REGISTRY)
    parser.add_argument("--engram-bin", default="engram")
    parser.add_argument(
        "--engram-project-alias",
        default=None,
        help="physical Engram project alias used for store queries while "
        "the R1C policy still filters the logical envelope project_id",
    )
    parser.add_argument("--cbm-bin", default=None)
    parser.add_argument("--cbm-cache-dir", default=None)
    parser.add_argument("--cbm-project-name", default=None)
    parser.add_argument("--workspace-root", default=None)
    parser.add_argument("--requesting-agent", default="")
    parser.add_argument("--include-agent-private", action="store_true")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--pretty", action="store_true")
    return parser


def _load_registry(path: str) -> Optional[Registry]:
    if not path or not os.path.exists(path):
        return None
    return Registry(path)


def _cbm_project_name(args, registry) -> Optional[str]:
    if args.cbm_project_name:
        return args.cbm_project_name
    if registry is not None and args.workspace_id:
        workspace = registry.get_workspace(args.workspace_id)
        if workspace is not None and workspace.cbm:
            return workspace.cbm.get("project_name")
    return None


def main(
    argv: Optional[list] = None,
    *,
    store=None,
    cbm_adapter=None,
    clock=None,
) -> int:
    args = build_parser().parse_args(argv)
    try:
        registry = _load_registry(args.registry)
    except RegistryError as exc:
        return _fail(str(exc))

    if store is None:
        store = EngramCLIAdapter(
            engram_bin=args.engram_bin,
            project_alias=args.engram_project_alias,
        )
    service = MemoryService(store)

    if cbm_adapter is None and args.cbm_bin:
        try:
            cbm_adapter = CBMCLIAdapter(
                cbm_bin=args.cbm_bin,
                cache_dir=args.cbm_cache_dir,
                cbm_project_name=_cbm_project_name(args, registry),
                workspace_root=args.workspace_root,
            )
        except CBMAdapterError as exc:
            return _fail(str(exc))

    builder_kwargs = {}
    if clock is not None:
        builder_kwargs["clock"] = clock
    builder = ContextBuilder(
        memory_service=service,
        cbm_adapter=cbm_adapter,
        registry=registry,
        workspace_root=args.workspace_root,
        **builder_kwargs,
    )
    request = ContextRequest(
        project_id=args.project_id,
        workspace_id=args.workspace_id,
        task=args.task,
        file=args.file,
        symbol=args.symbol,
        requesting_agent=args.requesting_agent or "",
        include_agent_private=bool(args.include_agent_private),
    )
    try:
        packet = builder.build(request)
    except ContextBuildError as exc:
        return _fail(str(exc), code=exc.exit_code)
    except (MemoryError, ValueError) as exc:
        return _fail(str(exc))

    if args.format == "markdown":
        print(packet.to_markdown())
    else:
        print(packet.to_json(pretty=args.pretty))
    return 0


if __name__ == "__main__":
    sys.exit(main())
