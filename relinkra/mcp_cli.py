"""Relinkra MCP server entry point (stdio transport).

    python -m relinkra.mcp_cli --workspace-root . --registry .relinkra/registry.json

stdout carries JSON-RPC frames and NOTHING else — a stray print would
corrupt the stream — so every diagnostic goes to stderr.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Optional

from .app_service import RelinkraServices, ServiceConfig
from .mcp_server import MCPServer
from .registry import DEFAULT_REGISTRY_PATH

ENV_PREFIX = "RELINKRA_"


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    return os.environ.get(ENV_PREFIX + name, default)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="relinkra-mcp", description=__doc__
    )
    parser.add_argument(
        "--workspace-root",
        default=_env("WORKSPACE_ROOT"),
        help="repository root this server is bound to (server-owned; "
        "tool callers can never point Relinkra at another path)",
    )
    parser.add_argument(
        "--registry", default=_env("REGISTRY", DEFAULT_REGISTRY_PATH)
    )
    parser.add_argument("--engram-bin", default=_env("ENGRAM_BIN", "engram"))
    parser.add_argument(
        "--engram-project-alias", default=_env("ENGRAM_PROJECT_ALIAS")
    )
    parser.add_argument("--cbm-bin", default=_env("CBM_BIN"))
    parser.add_argument("--cbm-cache-dir", default=_env("CBM_CACHE_DIR"))
    parser.add_argument("--cbm-project-name", default=_env("CBM_PROJECT_NAME"))
    parser.add_argument("--project-id", default=_env("PROJECT_ID"))
    parser.add_argument("--workspace-id", default=_env("WORKSPACE_ID"))
    return parser


def build_services(args) -> RelinkraServices:
    config = ServiceConfig(
        workspace_root=args.workspace_root,
        registry_path=args.registry,
        engram_bin=args.engram_bin,
        engram_project_alias=args.engram_project_alias,
        cbm_bin=args.cbm_bin,
        cbm_cache_dir=args.cbm_cache_dir,
        cbm_project_name=args.cbm_project_name,
        default_project_id=args.project_id,
        default_workspace_id=args.workspace_id,
    )
    return RelinkraServices(config=config)


def main(argv: Optional[list] = None) -> int:
    # Force UTF-8 and '\n' framing on both streams BEFORE argparse runs.
    # On Windows the default text mode would translate '\n' to '\r\n',
    # which some MCP clients reject as a malformed frame; doing it first
    # also keeps --help and argparse errors from mojibaking on a cp1252
    # console.
    for stream in (sys.stdin, sys.stdout):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                # errors="replace" matters: without it the stream keeps
                # its inherited handler, and one non-UTF-8 byte on stdin
                # would raise mid-iteration — outside every per-message
                # guard — killing the server for all in-flight calls.
                # Replaced bytes simply fail JSON parsing, which the
                # protocol already answers with a parse error.
                reconfigure(encoding="utf-8", newline="\n", errors="replace")
            except (ValueError, OSError):
                pass

    args = build_parser().parse_args(argv)
    services = build_services(args)
    server = MCPServer(services)
    try:
        return server.serve()
    except KeyboardInterrupt:
        return 0
    except BrokenPipeError:
        # The host closed the pipe. That is a normal shutdown.
        return 0


if __name__ == "__main__":
    sys.exit(main())
