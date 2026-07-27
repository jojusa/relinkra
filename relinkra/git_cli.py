"""Relinkra git intelligence CLI — read-only git facts as sorted-keys JSON.

    python -m relinkra.git_cli status [--path PATH]
    python -m relinkra.git_cli history --file src/f.py [--limit N] [--path PATH]
    python -m relinkra.git_cli cochange --file src/f.py [--limit N] [--path PATH]

Exit codes: 0 ok; 1 usage error / git unavailable / not a repository /
git command failure; 2 internal error. Output is a single sorted-keys
JSON document on stdout; failures are a single redacted {"error": ...}
document on stderr (stdout stays empty). Facts are repo-relative only:
no absolute repository path is ever emitted, and authors are names only
(never emails). See docs/git-intelligence.md.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from .git_intelligence import GitIntelligenceService
from .memory import sanitize_error


def _emit(obj: object, fh=None) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True), file=fh or sys.stdout)


def _fail(message: str, code: int = 1) -> int:
    _emit({"error": sanitize_error(message)}, fh=sys.stderr)
    return code


class _GitCLIParser(argparse.ArgumentParser):
    """Usage errors are exit 1 with a redacted JSON error (spec: 1 = usage
    or git errors, 2 = internal errors)."""

    def error(self, message: str) -> None:
        _emit({"error": sanitize_error(message)}, fh=sys.stderr)
        raise SystemExit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = _GitCLIParser(prog="relinkra-git", description=__doc__)
    sub = parser.add_subparsers(
        dest="subcommand", required=True, parser_class=_GitCLIParser
    )

    p_status = sub.add_parser("status", help="repository state, HEAD and working tree")
    p_status.add_argument("--path", default=".", help="repository path (default: cwd)")

    p_history = sub.add_parser("history", help="commits touching a file, newest first")
    p_history.add_argument("--file", required=True, help="repo-relative POSIX path")
    p_history.add_argument("--limit", type=int, default=None, help="max commits")
    p_history.add_argument("--path", default=".", help="repository path (default: cwd)")

    p_cochange = sub.add_parser("cochange", help="paths co-changed with a file")
    p_cochange.add_argument("--file", required=True, help="repo-relative POSIX path")
    p_cochange.add_argument("--limit", type=int, default=None, help="max entries")
    p_cochange.add_argument("--path", default=".", help="repository path (default: cwd)")

    return parser


def _warnings_dicts(warnings) -> list:
    return [{"code": w.code, "message": w.message} for w in warnings]


def _check_limit(limit: Optional[int]) -> Optional[str]:
    if limit is not None and limit < 1:
        return "--limit must be >= 1"
    return None


def _cmd_status(args: argparse.Namespace, service) -> int:
    capabilities, cap_warnings = service.collect_capabilities(args.path)
    if not (capabilities.git_available and capabilities.repository_detected):
        message = (
            cap_warnings[0].message
            if cap_warnings
            else "git unavailable or not a repository"
        )
        return _fail(message)
    warnings = list(cap_warnings)
    state, state_warnings = service.collect_repository_state(args.path)
    warnings.extend(state_warnings)
    head, head_warnings = service.collect_head_facts(args.path)
    warnings.extend(head_warnings)
    tree, tree_warnings = service.collect_working_tree(args.path)
    warnings.extend(tree_warnings)
    _emit(
        {
            "capabilities": capabilities.to_dict(),
            "head": head.to_dict() if head is not None else None,
            "repository_state": state.to_dict() if state is not None else None,
            "warnings": _warnings_dicts(warnings),
            "working_tree": tree.to_dict() if tree is not None else None,
        }
    )
    return 0


def _cmd_history(args: argparse.Namespace, service) -> int:
    invalid = _check_limit(args.limit)
    if invalid:
        return _fail(invalid)
    commits, warnings = service.collect_file_history(
        args.path, args.file, limit=args.limit
    )
    if warnings:
        return _fail(warnings[0].message)
    _emit(
        {
            "commits": [commit.to_dict() for commit in commits],
            "file": args.file,
            "warnings": [],
        }
    )
    return 0


def _cmd_cochange(args: argparse.Namespace, service) -> int:
    invalid = _check_limit(args.limit)
    if invalid:
        return _fail(invalid)
    facts, warnings = service.collect_cochange(args.path, args.file)
    if warnings:
        return _fail(warnings[0].message)
    entries = facts[: args.limit] if args.limit is not None else facts
    _emit(
        {
            "anchor": args.file,
            "co_changed": [fact.to_dict() for fact in entries],
            "warnings": [],
        }
    )
    return 0


_COMMANDS = {
    "status": _cmd_status,
    "history": _cmd_history,
    "cochange": _cmd_cochange,
}


def main(argv: Optional[list] = None, *, git_service=None, clock=None) -> int:
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:  # usage error (1) or --help (0)
        return int(exc.code or 0)
    service = git_service if git_service is not None else GitIntelligenceService()
    try:
        return _COMMANDS[args.subcommand](args, service)
    except ValueError as exc:  # hostile --file paths, invalid input
        return _fail(str(exc))
    except Exception as exc:  # noqa: BLE001 - internal error boundary
        return _fail(str(exc), code=2)


if __name__ == "__main__":
    sys.exit(main())
