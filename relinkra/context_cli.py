"""Relinkra context packet CLI — build a deterministic Project Context Packet.

JSON (default) or Markdown to stdout; errors are redacted on stderr with a
nonzero exit code.

    python -m relinkra.context_cli --project-id rlk_... [--task "..."]
    python -m relinkra.context_cli --project-id rlk_... --symbol src.calc.add \
        --cbm-bin codebase-memory-mcp --cbm-project-name <slug> --format markdown

Exit codes: 0 ok; 1 invalid input / build error / budget unsatisfiable;
2 project mismatch. With --budget/--max-tokens the packet is bounded by
the R1F accountant (see docs/context-budget.md); --budget-report writes
the audit report JSON to stderr. --relevance ranks the packet with the
R1G deterministic scorer first (see docs/relevance-scoring.md) and
--relevance-report writes the RankedContext JSON to stderr; when both
reports are requested stderr carries ONE combined object. Every stream
carries AT MOST one JSON document: on an unsatisfiable budget stdout
stays empty and stderr gets a single error object (with the reports
embedded when requested).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional

from .cbm_adapter import CBMCLIAdapter, CBMAdapterError
from .context_budget import (
    BudgetValidationError,
    apply_budget,
    resolve_budget,
)
from .context_builder import (
    ContextBuildError,
    ContextBuilder,
    ContextRequest,
    _utcnow,
)
from .engram_adapter import EngramCLIAdapter
from .memory import MemoryError, MemoryService, sanitize_error
from .registry import DEFAULT_REGISTRY_PATH, Registry, RegistryError
from .relevance import RELEVANCE_VERSION, RelevanceError, score_packet

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
    parser.add_argument(
        "--budget",
        choices=("small", "medium", "large"),
        default=None,
        help="apply a fixed R1F budget profile to the built packet",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=None,
        help="explicit estimated-token cap; wins over --budget",
    )
    parser.add_argument(
        "--budget-report",
        action="store_true",
        help="write the budget report JSON to stderr (requires --budget "
        "or --max-tokens)",
    )
    parser.add_argument(
        "--relevance",
        action="store_true",
        help="rank the packet with the R1G deterministic scorer before "
        "budgeting; without --budget/--max-tokens it only annotates "
        "diagnostics",
    )
    parser.add_argument(
        "--relevance-report",
        action="store_true",
        help="write the RankedContext JSON to stderr (requires "
        "--relevance)",
    )
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

    if args.relevance_report and not args.relevance:
        return _fail("--relevance-report requires --relevance")
    ranked = None
    if args.relevance:
        # R1G: deterministic pre-budget ranking. as_of comes from the
        # injected clock (never an implicit wall-clock read inside the
        # scorer); focus derives from the request and the built packet.
        as_of = clock() if clock is not None else _utcnow()
        focus = packet.focus or {}
        focus_file = args.file or focus.get("file_path")
        focus_symbol = None
        if args.symbol and not args.symbol.strip().startswith("{"):
            focus_symbol = args.symbol.strip()
        elif focus.get("reference_kind") == "symbol":
            focus_symbol = focus.get("qualified_name")
        focus_ref_id = None
        if packet.code_references:
            focus_ref_id = packet.code_references[0].provenance.code_reference_id
        try:
            ranked = score_packet(
                packet,
                task=args.task,
                focus_file=focus_file,
                focus_symbol=focus_symbol,
                focus_code_reference_id=focus_ref_id,
                workspace_id=args.workspace_id,
                as_of=as_of,
            )
        except RelevanceError as exc:
            return _fail(str(exc))
        packet.diagnostics["relevance"] = {
            "ranked": True,
            "relevance_version": RELEVANCE_VERSION,
            "as_of": ranked.as_of,
            "counts": {
                section: len(ranked.scores.get(section, ()))
                for section in (
                    "memories", "code_references", "code_facts",
                    "pending", "handoffs",
                )
            },
        }

    budget_requested = args.budget is not None or args.max_tokens is not None
    if args.budget_report and not budget_requested:
        return _fail("--budget-report requires --budget or --max-tokens")
    if budget_requested:
        try:
            budget = resolve_budget(
                profile=args.budget, max_tokens=args.max_tokens
            )
        except BudgetValidationError as exc:
            return _fail(str(exc))
        try:
            result = apply_budget(packet, budget, relevance=ranked)
        except BudgetValidationError as exc:
            return _fail(str(exc))
        if not result.satisfied:
            error_doc = {
                "error": "budget_unsatisfiable",
                "packet_id": result.original_packet_id,
                "max_estimated_tokens": budget.max_estimated_tokens,
            }
            if args.budget_report:
                error_doc["budget_report"] = result.to_dict()
            if args.relevance_report and ranked is not None:
                error_doc["relevance_report"] = ranked.to_dict()
            _emit(error_doc, fh=sys.stderr)
            return 1
        if args.budget_report and args.relevance_report and ranked is not None:
            _emit(
                {
                    "budget_report": result.to_dict(),
                    "relevance_report": ranked.to_dict(),
                },
                fh=sys.stderr,
            )
        elif args.budget_report:
            _emit(result.to_dict(), fh=sys.stderr)
        elif args.relevance_report and ranked is not None:
            _emit(ranked.to_dict(), fh=sys.stderr)
        packet = result.packet
    elif args.relevance_report and ranked is not None:
        _emit(ranked.to_dict(), fh=sys.stderr)

    if args.format == "markdown":
        print(packet.to_markdown())
    else:
        print(packet.to_json(pretty=args.pretty))
    return 0


if __name__ == "__main__":
    sys.exit(main())
