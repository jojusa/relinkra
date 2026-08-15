"""Connector registry, launch contract and plan builder (R4B).

This is where host knowledge lives. Everything below is declarative: a
:class:`ConnectorSpec` states where a host keeps its configuration, what
shape an MCP entry takes there, how to recognise an entry as Relinkra's,
and — separately — how much of that has actually been VERIFIED against a
real configuration file rather than assumed from documentation.

Adding a future agent means appending one ``ConnectorSpec`` to
:data:`CONNECTORS`. Nothing in the CLI enumerates connector ids, so no
dispatch code changes.

Honesty is enforced structurally. ``format_verified`` is set only where
the shape was read out of a real local config, and it gates whether a
plan can be produced at all. ``apply_available`` is a second, stricter
gate, opened per connector only when the write path exists: R4C.1B opens
it for Claude Code and R4C.1C extends it to OpenCode. Even then, a successful apply proves a file
was edited and says nothing about the host launching the server
afterwards — that evidence lives in ``connect_verification``.
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
import sysconfig
from dataclasses import dataclass, field
from pathlib import Path, PurePath
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from .config_formats import adapter_for
from .config_merge import (
    ACTION_ADD,
    ACTION_CONFLICT,
    ACTION_NO_OP,
    ACTION_UPDATE,
    MalformedConfigError,
    MergeError,
    UnsupportedShapeError,
    decide_member,
    ownership_test,
    parse_json_document,
)
from .connector import (
    CONTRACT_VERSION,
    DISCOVERY_CONFIG_MALFORMED,
    DISCOVERY_CONFIG_MISSING,
    DISCOVERY_CONFIG_UNSUPPORTED,
    DISCOVERY_DISCOVERED,
    DISCOVERY_NOT_INSTALLED,
    DISCOVERY_UNVERIFIED,
    DISTRIBUTION_CONSOLE_SCRIPT,
    DISTRIBUTION_INSTALLED_MODULE,
    DISTRIBUTION_SOURCE_CHECKOUT,
    DISTRIBUTION_UNRESOLVED,
    FORMAT_JSON,
    FORMAT_TOML,
    MANAGED_SERVER_NAME,
    OP_ADD_OBJECT_MEMBER,
    OP_BACKUP_FILE,
    OP_CREATE_FILE,
    OP_NO_OP,
    OP_REPLACE_MANAGED_MEMBER,
    OP_REQUEST_RESTART,
    OP_VALIDATE_JSON,
    PLAN_BLOCKED,
    PLAN_READY,
    PLAN_UNAVAILABLE,
    REGISTRATION_ABSENT,
    REGISTRATION_ALREADY_CONNECTED,
    REGISTRATION_CONFLICT,
    REGISTRATION_NEEDS_UPDATE,
    REGISTRATION_UNKNOWN,
    SUPPORT_EXPERIMENTAL,
    SUPPORT_SUPPORTED,
    SUPPORT_UNSUPPORTED,
    TRANSPORT_STDIO,
    CapabilityMatrix,
    ConfigLocation,
    ConnectorPlan,
    ConnectorReport,
    ConnectorWarning,
    LaunchContract,
    PlanOperation,
    UnknownConnectorError,
)
from .host_discovery import (
    SCOPE_USER,
    SCOPE_WORKSPACE,
    DiscoveryEnvironment,
    LocationSpec,
    active_location,
    find_executable,
    probe,
)
from .safe_write import (
    ConfigTooLargeError,
    SafeWriteError,
    read_bounded_text,
)

#: Console script name, if Relinkra is ever installed as a package. Not
#: present in a source checkout, which is why it is probed rather than
#: assumed.
CONSOLE_SCRIPT = "relinkra-mcp"

#: The module a host is asked to run. Also the structural fingerprint
#: used to recognise a Relinkra entry in someone else's config.
SERVER_MODULE = "relinkra.mcp_cli"


# ---------------------------------------------------------------------------
# Launch contract
# ---------------------------------------------------------------------------


def _interpreter(which: Callable[[str], Optional[str]]) -> str:
    """Resolve a Python to hand the host.

    ``sys.executable`` first, because it is the interpreter that already
    imported Relinkra successfully — the only one known to work. It is
    empty in embedded and frozen builds, so PATH is the fallback, and
    ``python3`` is tried before ``python`` since on many Linux distros
    ``python`` is either absent or still Python 2.
    """
    if sys.executable:
        return sys.executable
    for name in ("python3", "python"):
        found = which(name)
        if found:
            return found
    return ""


def _package_root() -> Path:
    """Directory that must be importable for ``relinkra`` to resolve."""
    return Path(__file__).resolve().parent.parent


def _is_installed_package() -> bool:
    """Whether ``relinkra`` resolves without help from ``PYTHONPATH``.

    Compares the package's parent against the interpreter's own library
    directories. A checkout sitting in a user's projects folder is not
    under either, so the launch contract knows it must carry
    ``PYTHONPATH`` — the difference between an MCP server that starts and
    one that dies with ``ModuleNotFoundError`` the first time a host runs
    it from its own working directory.
    """
    root = _package_root()
    for key in ("purelib", "platlib"):
        raw = sysconfig.get_paths().get(key)
        if not raw:
            continue
        try:
            candidate = Path(raw).resolve()
        except OSError:
            continue
        if root == candidate or candidate in root.parents:
            return True
    return False


def server_module_importable() -> bool:
    """Whether the MCP entry point exists in THIS installation.

    Cheap proof that the contract points at something real, and it stays
    a pure import-spec lookup: no process is spawned, so nothing is
    started as a side effect of asking a question.
    """
    try:
        return importlib.util.find_spec(SERVER_MODULE) is not None
    except (ImportError, ValueError):
        return False


def resolve_launch(
    workspace_root,
    registry_path,
    *,
    which: Callable[[str], Optional[str]] = shutil.which,
    force_source_checkout: Optional[bool] = None,
) -> LaunchContract:
    """Build the stdio launch contract for this machine.

    Command and arguments stay separate values all the way through. They
    are never joined into a string, so a workspace root containing a
    space, an ampersand or a quote is inert data rather than something a
    shell would reinterpret. No shell is involved at any point.
    """
    warnings: List[str] = []
    root = str(Path(workspace_root).resolve()) if workspace_root else ""
    registry = str(registry_path) if registry_path else ""

    args: List[str] = []
    env: Dict[str, str] = {}

    script = which(CONSOLE_SCRIPT)
    if script:
        command = script
        distribution = DISTRIBUTION_CONSOLE_SCRIPT
    else:
        command = _interpreter(which)
        if not command:
            return LaunchContract(
                transport=TRANSPORT_STDIO,
                distribution=DISTRIBUTION_UNRESOLVED,
                module=SERVER_MODULE,
                resolved=False,
                warnings=(
                    "no Python interpreter could be resolved for this "
                    "environment; the MCP launch command cannot be built",
                ),
            )
        args.extend(["-m", SERVER_MODULE])
        source_checkout = (
            (not _is_installed_package())
            if force_source_checkout is None
            else force_source_checkout
        )
        if source_checkout:
            distribution = DISTRIBUTION_SOURCE_CHECKOUT
            env["PYTHONPATH"] = str(_package_root())
            warnings.append(
                "Relinkra is running from a source checkout, so the host "
                "must pass PYTHONPATH for the server to import. Installing "
                "Relinkra as a package removes this requirement."
            )
        else:
            distribution = DISTRIBUTION_INSTALLED_MODULE

    if root:
        args.extend(["--workspace-root", root])
    if registry:
        args.extend(["--registry", registry])

    if not server_module_importable():
        warnings.append(
            f"{SERVER_MODULE} is not importable in this environment; the "
            "launch contract cannot be trusted until that is fixed."
        )

    return LaunchContract(
        transport=TRANSPORT_STDIO,
        command=command,
        args=tuple(args),
        env=env,
        distribution=distribution,
        module=SERVER_MODULE,
        resolved=bool(command) and server_module_importable(),
        warnings=tuple(warnings),
    )


def launch_contract_document(launch: LaunchContract) -> dict:
    """The host-neutral contract ``connect generic`` emits (portable)."""
    return {
        "contract_version": CONTRACT_VERSION,
        "server_name": MANAGED_SERVER_NAME,
        "launch": launch.to_dict(),
    }


# ---------------------------------------------------------------------------
# Ownership: recognising a Relinkra entry in someone else's config
# ---------------------------------------------------------------------------


def _basename(token: str) -> str:
    """Last path segment, treating BOTH separators as separators.

    A config written on Windows can be read on Linux and vice versa, so
    ``PurePath`` of the local flavour is the wrong tool here — it would
    not split ``C:\\...\\relinkra-mcp.exe`` when running on POSIX.
    """
    for separator in ("\\", "/"):
        token = token.rsplit(separator, 1)[-1]
    return token


def entry_tokens(entry: Any) -> Tuple[str, ...]:
    """Flatten an MCP entry into the tokens it would execute.

    Handles both shapes seen in real configs: ``command`` as a string
    with a separate ``args`` list (Claude Code, Windsurf), and ``command``
    as a single list holding the program and its arguments (OpenCode).
    """
    if not isinstance(entry, Mapping):
        return ()
    tokens: List[str] = []
    command = entry.get("command")
    if isinstance(command, str):
        tokens.append(command)
    elif isinstance(command, (list, tuple)):
        tokens.extend(str(item) for item in command)
    args = entry.get("args")
    if isinstance(args, (list, tuple)):
        tokens.extend(str(item) for item in args)
    return tuple(tokens)


def _launch_command_and_args(entry: Any) -> Tuple[Optional[str], Tuple[str, ...]]:
    """Return the executable token and argument tokens, without coercion."""
    if not isinstance(entry, Mapping):
        return None, ()
    command = entry.get("command")
    if isinstance(command, str):
        executable = command
        command_args: Tuple[Any, ...] = ()
    elif isinstance(command, (list, tuple)) and command and all(
        isinstance(item, str) for item in command
    ):
        executable = command[0]
        command_args = tuple(command[1:])
    else:
        return None, ()
    args = entry.get("args")
    if args is None:
        extra_args: Tuple[Any, ...] = ()
    elif isinstance(args, (list, tuple)) and all(
        isinstance(item, str) for item in args
    ):
        extra_args = tuple(args)
    else:
        return None, ()
    return executable, tuple(command_args) + extra_args


def _is_python_interpreter(command: str) -> bool:
    """Whether an executable token plausibly names a Python interpreter."""
    base = _basename(command).lower()
    for suffix in (".exe", ".cmd", ".bat"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
            break
    if base in {"py", "pypy", "pypy3"}:
        return True
    for prefix in ("python", "pythonw"):
        if base == prefix:
            return True
        version = base[len(prefix) :]
        if version and version[0].isdigit() and all(
            character.isdigit() or character == "." for character in version
        ):
            return True
    return base.endswith(("-python", "_python"))


def launches_relinkra(entry: Any) -> bool:
    """Structural ownership test: does this entry start Relinkra?

    Chosen over a name check because the name is exactly what a
    coincidental user entry would share. An entry that names the
    Relinkra module or console script IS a Relinkra registration
    whoever wrote it; an entry that does not is someone else's, and
    overwriting it would be the destructive behaviour this refuses.

    Deliberately does not require an exact command match, so a user who
    pinned a different interpreter still owns a valid registration and
    gets an update rather than a conflict.
    """
    command, args = _launch_command_and_args(entry)
    if command is None:
        return False

    # A module name is meaningful only in the interpreter's module-launch
    # slot.  Looking for the bare token anywhere in the flattened command
    # let foreign wrappers such as ``node wrapper.js relinkra.mcp_cli``
    # masquerade as Relinkra and be overwritten.
    module_positions = [index for index, token in enumerate(args) if token == "-m"]
    if _is_python_interpreter(command) and len(module_positions) == 1:
        index = module_positions[0]
        if index == 0 and index + 1 < len(args) and args[index + 1] == SERVER_MODULE:
            return True

    # Console-script ownership belongs to the executable token only.  A
    # script name appearing in an arbitrary argument is not a launch target.
    base = _basename(command).lower()
    return base in (CONSOLE_SCRIPT.lower(), (CONSOLE_SCRIPT + ".exe").lower())


def is_managed_entry(entry: Any) -> bool:
    """Whether an entry is Relinkra-managed rather than a mixed launch.

    ``launches_relinkra`` remains the tolerant launch-shape predicate used
    by callers that only need to know what an entry starts. Ownership paths
    must additionally reject a launch carrying a direct CBM marker.
    """
    if not launches_relinkra(entry):
        return False
    # Lazy import avoids the backend-detection module's import of this
    # module's token flattener during module initialization.
    from .backend_detection import BACKEND_CBM, entry_matches_backend

    return not entry_matches_backend(entry, BACKEND_CBM)


# ---------------------------------------------------------------------------
# Entry builders — one per verified host format
# ---------------------------------------------------------------------------


def _string_command_entry(launch: LaunchContract) -> Dict[str, Any]:
    """``{command: str, args: [str]}`` — Claude Code and Windsurf.

    Verified against a real local entry in both hosts' configs. ``env``
    is emitted only when the launch actually needs one, so a packaged
    install writes the minimal entry those configs already contain.
    """
    entry: Dict[str, Any] = {
        "command": launch.command,
        "args": list(launch.args),
    }
    if launch.env:
        entry["env"] = dict(launch.env)
    return entry


def _list_command_entry(launch: LaunchContract) -> Dict[str, Any]:
    """OpenCode's shape: ``type``/``command`` as one list/``environment``.

    Verified against a real local ``mcp`` entry, which stores the program
    as element 0 of ``command`` rather than in a separate field.
    """
    entry: Dict[str, Any] = {
        "type": "local",
        "command": [launch.command, *launch.args],
        "enabled": True,
    }
    if launch.env:
        entry["environment"] = dict(launch.env)
    return entry


def _toml_command_entry(launch: LaunchContract) -> Dict[str, Any]:
    """Codex's ``[mcp_servers.<name>]`` table: ``command`` plus ``args``."""
    entry: Dict[str, Any] = {
        "command": launch.command,
        "args": list(launch.args),
    }
    if launch.env:
        entry["env"] = dict(launch.env)
    return entry


# ---------------------------------------------------------------------------
# Claude Code project keys and dynamic containers
# ---------------------------------------------------------------------------


def claude_project_key(workspace_root) -> str:
    """The ``projects[]`` key Claude Code uses for a workspace.

    Empirically verified against Claude Code 2.1.220: the absolute path
    with forward slashes, an UPPERCASE drive letter on Windows, and no
    trailing slash (``C:\\Users\\dev\\relinkra`` becomes
    ``C:/Users/dev/relinkra``; POSIX paths keep their form). Pure —
    no filesystem access, so the key can be computed for any root.
    """
    text = str(workspace_root).replace("\\", "/")
    text = text.rstrip("/")
    if len(text) >= 2 and text[1] == ":" and text[0].isalpha():
        text = text[0].upper() + text[1:]
    return text


def _claude_container(workspace_root) -> Optional[Tuple[str, ...]]:
    """LOCAL scope: ``projects[<project-key>].mcpServers`` in ~/.claude.json.

    ``None`` when no workspace root is known, which falls the connector
    back to its static container — the same file's top-level
    ``mcpServers`` (USER scope). Apply/check/plan always run inside a
    repository, so the fallback is reachable only from read-only
    commands run outside one.
    """
    if workspace_root is None:
        return None
    return ("projects", claude_project_key(workspace_root), "mcpServers")


def container_path_for(spec: "ConnectorSpec", workspace_root) -> Tuple[str, ...]:
    """The container a connector targets, static or workspace-resolved."""
    if spec.container_resolver is not None:
        resolved = spec.container_resolver(workspace_root)
        if resolved:
            return tuple(resolved)
    return spec.container_path


def container_label(container_path: Sequence[str]) -> str:
    """A portable label for a container path.

    A workspace-resolved container carries the project key, which is
    derived from an absolute path and therefore machine-local. It is
    redacted here — once, at the single place labels are made — so plan
    and warning text can never leak it into portable output.
    """
    from .handoff import contains_absolute_path

    return ".".join(
        "<project>" if contains_absolute_path(segment) else segment
        for segment in container_path
    )


# ---------------------------------------------------------------------------
# Connector specs
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConnectorSpec:
    """Everything Relinkra knows about one host, declared in one place."""

    connector_id: str
    display_name: str
    host_type: str
    aliases: Tuple[str, ...] = ()
    support_status: str = SUPPORT_EXPERIMENTAL
    executables: Tuple[str, ...] = ()
    locations: Tuple[LocationSpec, ...] = ()
    container_path: Tuple[str, ...] = ()
    #: Optional hook resolving the container from the workspace root.
    #: Called with the root (or None outside a repository); a None
    #: result falls back to the static ``container_path``.
    container_resolver: Optional[Callable[[Optional[Any]], Optional[Tuple[str, ...]]]] = None
    #: Top-level server containers the host INHERITS alongside the
    #: targeted one (Claude Code's top-level ``mcpServers``, inherited by
    #: projects that do not override it). Empty for hosts whose container
    #: is itself top-level or that have no inheritance — the direct-CBM
    #: gate scans exactly what is declared here, never a hardcoded key.
    inherited_container_paths: Tuple[Tuple[str, ...], ...] = ()
    config_format: str = FORMAT_JSON
    entry_builder: Optional[Callable[[LaunchContract], Dict[str, Any]]] = None
    #: True only when the shape was read out of a real configuration file.
    format_verified: bool = False
    format_evidence: str = ""
    #: Whether unknown members are known-safe to add. Gates the explicit
    #: ownership marker; false everywhere until a host is shown to keep
    #: unknown keys across a rewrite.
    marker_allowed: bool = False
    #: Whether this phase may WRITE. Separate from format_verified on
    #: purpose: parsing a format and being trusted to mutate someone's
    #: live configuration are different claims, opened per connector.
    apply_available: bool = False
    apply_unavailable_reason: str = ""
    real_host_launch_proven: bool = False
    restart_instruction: str = ""
    security_notes: Tuple[str, ...] = ()
    #: Location ids that belong to a PREVIOUS name for this product. Kept
    #: discoverable rather than dropped: a rename does not move anyone's
    #: existing config file, and a connector that stops looking at the old
    #: location reports a configured host as not installed.
    legacy_location_ids: Tuple[str, ...] = ()
    #: How this connector's naming changed, in one sentence, when it did.
    naming_migration: str = ""

    @property
    def all_names(self) -> Tuple[str, ...]:
        return (self.connector_id, *self.aliases)


def _claude_locations() -> Tuple[LocationSpec, ...]:
    """Claude Code's MCP configuration locations, in preference order.

    Empirically verified against Claude Code 2.1.220 and the official
    docs: LOCAL scope lives in ``~/.claude.json`` under
    ``projects[<project-key>].mcpServers`` — that is the active and only
    apply target. ``~/.claude/settings.json`` is NOT honored for
    mcpServers by Claude Code 2.1+ (verified: an entry there is
    invisible to ``claude mcp list``), and ``.mcp.json`` project scope
    is approval-gated; both stay discoverable and nothing more.
    """
    return (
        LocationSpec(
            location_id="claude_user_config",
            scope=SCOPE_USER,
            config_format=FORMAT_JSON,
            display_hint="~/.claude.json",
            build=lambda env: env.home_path(".claude.json"),
        ),
        LocationSpec(
            location_id="claude_workspace_mcp",
            scope=SCOPE_WORKSPACE,
            config_format=FORMAT_JSON,
            display_hint="<workspace>/.mcp.json",
            build=lambda env: env.workspace_path(".mcp.json"),
            discovery_only=True,
            # Approval-gated but honored: a direct CBM registration here
            # is a live bypass, so apply and routing surveys scan it.
            mcp_authoritative=True,
        ),
        LocationSpec(
            location_id="claude_user_settings",
            scope=SCOPE_USER,
            config_format=FORMAT_JSON,
            display_hint="~/.claude/settings.json",
            build=lambda env: env.home_path(".claude", "settings.json"),
            discovery_only=True,
        ),
        LocationSpec(
            location_id="claude_workspace_settings_local",
            scope=SCOPE_WORKSPACE,
            config_format=FORMAT_JSON,
            display_hint="<workspace>/.claude/settings.local.json",
            build=lambda env: env.workspace_path(".claude", "settings.local.json"),
            discovery_only=True,
        ),
    )


def _opencode_locations() -> Tuple[LocationSpec, ...]:
    """OpenCode's MCP configuration locations, in preference order.

    Verified against the real local ``~/.config/opencode/opencode.json``:
    the USER-scope file is the active config and the only apply target.
    Live discovery against upstream (packages/opencode/src/config/config.ts,
    ConfigPaths) proved OpenCode loads BOTH ``opencode.json`` AND
    ``opencode.jsonc`` from the same directory and deep-merges them, jsonc
    applied AFTER json so jsonc wins on conflicts — so every ``.jsonc``
    sibling is declared here, discoverable and scanned for direct CBM, but
    deliberately never the apply target (``discovery_only``): only the
    ``.json`` user file is ever mutated. The workspace ``opencode.json`` /
    ``opencode.jsonc`` pair is honored by the host as project config, so
    both stay discoverable and CBM-scanned under the same rule.
    """
    return (
        LocationSpec(
            location_id="opencode_user_config",
            scope=SCOPE_USER,
            config_format=FORMAT_JSON,
            display_hint="~/.config/opencode/opencode.json",
            build=lambda env: env.config_home("opencode", "opencode.json"),
        ),
        LocationSpec(
            location_id="opencode_user_config_jsonc",
            scope=SCOPE_USER,
            config_format=FORMAT_JSON,
            display_hint="~/.config/opencode/opencode.jsonc",
            build=lambda env: env.config_home("opencode", "opencode.jsonc"),
            discovery_only=True,
            mcp_authoritative=True,
        ),
        LocationSpec(
            location_id="opencode_user_appdata",
            scope=SCOPE_USER,
            config_format=FORMAT_JSON,
            display_hint="%APPDATA%/opencode/opencode.json",
            build=lambda env: env.app_data("opencode", "opencode.json"),
            # OpenCode 1.18.11 uses ~/.config/opencode as the user config
            # path on this host. Keep the Windows candidate discoverable and
            # authoritative for CBM scanning, but never make it writable.
            discovery_only=True,
            mcp_authoritative=True,
        ),
        LocationSpec(
            location_id="opencode_workspace",
            scope=SCOPE_WORKSPACE,
            config_format=FORMAT_JSON,
            display_hint="<workspace>/opencode.json",
            build=lambda env: env.workspace_path("opencode.json"),
            discovery_only=True,
            mcp_authoritative=True,
        ),
        LocationSpec(
            location_id="opencode_workspace_jsonc",
            scope=SCOPE_WORKSPACE,
            config_format=FORMAT_JSON,
            display_hint="<workspace>/opencode.jsonc",
            build=lambda env: env.workspace_path("opencode.jsonc"),
            discovery_only=True,
            mcp_authoritative=True,
        ),
    )


def _codex_locations() -> Tuple[LocationSpec, ...]:
    return (
        LocationSpec(
            location_id="codex_user_config",
            scope=SCOPE_USER,
            config_format=FORMAT_TOML,
            display_hint="~/.codex/config.toml",
            build=lambda env: (
                env.env_dir("CODEX_HOME", "config.toml")
                or env.home_path(".codex", "config.toml")
            ),
        ),
    )


def _devin_desktop_locations() -> Tuple[LocationSpec, ...]:
    """Where the local desktop agent keeps its MCP configuration.

    Declaration order IS precedence, and it follows the current
    product's own contract rather than a guess: ``devin mcp add --help``
    (devin 3000.3.27, Devin Desktop 3.6.27) documents three scopes —
    workspace-local ``.devin/mcp_config.local.json`` (the default,
    overriding project), workspace-project ``.devin/mcp_config.json``
    and user ``~/.config/devin/mcp_config.json``. The Windows app
    profile ``%APPDATA%\\Devin\\mcp_config.json`` is not in the CLI
    text but is the file the installed product actually holds live MCP
    servers in on this machine, so it outranks the CLI-documented user
    path on observed liveness. Both user scopes are authoritative so
    the shadow scan reports divergence instead of guessing a merge
    rule.

    The legacy Windsurf/Codeium files come LAST: they are still read
    as evidence — the current product WATCHES and imports them one-way
    into its MCP registry (TrustedOnNonce, proven in the shipped
    bundles) — but they are never authoritative and never the active
    target of a plan. See :data:`DEVIN_DESKTOP_NAMING`.
    """
    return (
        LocationSpec(
            location_id="devin_workspace_local_mcp",
            scope=SCOPE_WORKSPACE,
            config_format=FORMAT_JSON,
            display_hint="<workspace>/.devin/mcp_config.local.json",
            build=lambda env: env.workspace_path(
                ".devin", "mcp_config.local.json"
            ),
            mcp_authoritative=True,
        ),
        LocationSpec(
            location_id="devin_workspace_project_mcp",
            scope=SCOPE_WORKSPACE,
            config_format=FORMAT_JSON,
            display_hint="<workspace>/.devin/mcp_config.json",
            build=lambda env: env.workspace_path(".devin", "mcp_config.json"),
            mcp_authoritative=True,
        ),
        LocationSpec(
            location_id="devin_user_appdata_mcp",
            scope=SCOPE_USER,
            config_format=FORMAT_JSON,
            display_hint="%APPDATA%/Devin/mcp_config.json",
            build=lambda env: env.app_data("Devin", "mcp_config.json"),
            mcp_authoritative=True,
        ),
        LocationSpec(
            location_id="devin_user_config_mcp",
            scope=SCOPE_USER,
            config_format=FORMAT_JSON,
            display_hint="~/.config/devin/mcp_config.json",
            build=lambda env: env.config_home("devin", "mcp_config.json"),
            mcp_authoritative=True,
        ),
        LocationSpec(
            location_id="windsurf_user_mcp",
            scope=SCOPE_USER,
            config_format=FORMAT_JSON,
            display_hint="~/.codeium/windsurf/mcp_config.json",
            build=lambda env: env.home_path(
                ".codeium", "windsurf", "mcp_config.json"
            ),
        ),
        LocationSpec(
            location_id="windsurf_next_mcp",
            scope=SCOPE_USER,
            config_format=FORMAT_JSON,
            display_hint="~/.codeium/windsurf-next/mcp_config.json",
            build=lambda env: env.home_path(
                ".codeium", "windsurf-next", "mcp_config.json"
            ),
        ),
    )


#: The legacy location ids for the desktop connector. Named once so
#: discovery, the naming report and the tests all mean the same set.
DEVIN_DESKTOP_LEGACY_LOCATIONS: Tuple[str, ...] = (
    "windsurf_user_mcp",
    "windsurf_next_mcp",
)

DEVIN_DESKTOP_NAMING = (
    "Windsurf (Codeium) is now Devin Desktop. The connector id is "
    "'devin-desktop'; 'windsurf' and 'codeium' remain aliases, and the "
    "~/.codeium locations stay discoverable because a rename does not move "
    "anyone's existing configuration — and because the current product "
    "still watches and imports them one-way into its MCP registry. The "
    "current-product locations are declared from the 'devin mcp add' "
    "scope documentation and the observed %APPDATA%/Devin app profile."
)


GENERIC = ConnectorSpec(
    connector_id="generic",
    display_name="Generic MCP host",
    host_type="generic",
    aliases=("mcp", "stdio"),
    support_status=SUPPORT_SUPPORTED,
    format_verified=True,
    format_evidence="Relinkra's own stdio MCP entry point (relinkra.mcp_cli).",
    apply_available=False,
    apply_unavailable_reason=(
        "the generic connector describes a launch contract; it owns no "
        "configuration file to mutate."
    ),
    restart_instruction=(
        "Add the emitted server entry to your host's MCP configuration and "
        "restart the host."
    ),
    security_notes=(
        "Command and arguments are structured values; no shell is invoked.",
        "Environment values are machine-local and are printed only with "
        "--reveal-paths.",
    ),
)

CLAUDE = ConnectorSpec(
    connector_id="claude",
    display_name="Claude Code",
    host_type="cli_agent",
    aliases=("claude-code", "claudecode"),
    support_status=SUPPORT_EXPERIMENTAL,
    executables=("claude",),
    locations=_claude_locations(),
    # USER scope in the same file; the resolver retargets to LOCAL scope
    # (projects[<project-key>].mcpServers) whenever a workspace is known.
    container_path=("mcpServers",),
    container_resolver=_claude_container,
    # Claude Code inherits the top-level ~/.claude.json mcpServers into
    # projects that do not override it, so the CBM gate scans both.
    inherited_container_paths=(("mcpServers",),),
    config_format=FORMAT_JSON,
    entry_builder=_string_command_entry,
    format_verified=True,
    format_evidence=(
        "LOCAL scope 'projects[<project-key>].mcpServers' in ~/.claude.json "
        "with {command, args} entries, read from a real local Claude Code "
        "2.1.220 state file. Empirically verified: Claude Code 2.1+ does "
        "NOT honor mcpServers from ~/.claude/settings.json."
    ),
    # R4C.1B opened the write path for Claude Code first; R4C.1C
    # extended the same engine and gates to OpenCode. The apply engine
    # still refuses unsafe targets, conflicts and direct CBM exposure,
    # and a written config is reported as host-unverified.
    apply_available=True,
    apply_unavailable_reason="",
    restart_instruction="Restart Claude Code, then run '/mcp' to confirm.",
    security_notes=(
        "Unrelated MCP servers, sibling projects and unknown state-file "
        "members are preserved untouched.",
        "An entry of the same name that does not launch Relinkra is treated "
        "as a conflict and never overwritten.",
        "Claude Code 2.1+ ignores mcpServers in ~/.claude/settings.json "
        "(verified against 2.1.220); the file stays discoverable as a "
        "legacy location and is never the apply target.",
        "USER scope (top-level ~/.claude.json mcpServers) is deliberately "
        "not the target: the launch contract pins --workspace-root to one "
        "workspace, and a user-scope entry would load into every project.",
        "PROJECT scope (<workspace>/.mcp.json) remains available but is "
        "approval-gated; it is not the apply target in this phase.",
    ),
)

OPENCODE = ConnectorSpec(
    connector_id="opencode",
    display_name="OpenCode",
    host_type="cli_agent",
    aliases=("open-code",),
    support_status=SUPPORT_EXPERIMENTAL,
    executables=("opencode",),
    locations=_opencode_locations(),
    container_path=("mcp",),
    config_format=FORMAT_JSON,
    entry_builder=_list_command_entry,
    format_verified=True,
    format_evidence=(
        "'mcp' object with {type: local, command: [...]} entries, read from "
        "the real local ~/.config/opencode/opencode.json: a regular 94 KB "
        "JSON file whose 'mcp' container holds a local entry "
        "('engram': {type: local, command: ['engram', 'mcp', ...]}) and a "
        "remote entry ('context7': {type: remote, url}), beside '$schema', "
        "'agent', 'default_agent', 'permission' and 'share' top-level keys. "
        "Verified against upstream (packages/opencode/src/config/config.ts, "
        "ConfigPaths): OpenCode loads opencode.json AND opencode.jsonc from "
        "the same directory and deep-merges them, jsonc applied after json "
        "so jsonc wins on conflicts."
    ),
    # R4C.1C opens the write path for OpenCode, on the same engine and
    # the same gates as Claude Code (R4C.1B): unsafe targets, conflicts
    # and direct CBM exposure are refused, and a written config is
    # reported as host-unverified.
    apply_available=True,
    apply_unavailable_reason="",
    restart_instruction="Restart OpenCode so it re-reads its configuration.",
    security_notes=(
        "Unrelated MCP entries in the same file — local ones like the "
        "'engram' launch and remote (URL) ones like 'context7' — are "
        "preserved untouched, as are unknown top-level and nested fields "
        "('$schema', agents, permissions).",
        "An entry of the same name that does not launch Relinkra is treated "
        "as a conflict and never overwritten.",
        "The apply target is the USER-scope 'mcp' container "
        "(~/.config/opencode/opencode.json). The entry pins "
        "--workspace-root/--registry to one workspace, so in other "
        "workspaces it points at this workspace's registry — the same "
        "documented tradeoff class as the global 'engram' entry already "
        "present there.",
        "OpenCode deep-merges opencode.json AND opencode.jsonc (jsonc "
        "wins on conflicts, verified against upstream ConfigPaths). Both "
        "are discovered and scanned for direct CBM; only the '.json' user "
        "file is ever mutated — the '.jsonc' siblings are never written.",
        "An entry named 'relinkra' in ANY merged-in scope (a '.jsonc' "
        "sibling, the %APPDATA% user config or the workspace pair) shadows "
        "the managed registration: apply refuses and check reports the "
        "conflict, whatever that entry launches. Relinkra never removes or "
        "overwrites another scope's entry to resolve the ambiguity.",
        "A workspace-scope opencode.json / opencode.jsonc remains "
        "discoverable and is scanned for direct CBM, but neither is the "
        "apply target.",
        "The '.jsonc' files are read with the strict JSON parser: a file "
        "using JSONC comments or trailing commas is treated as an "
        "unreadable authoritative scope and fails closed, never parsed "
        "leniently.",
        "The program is written as element 0 of 'command'; no shell string is "
        "ever produced.",
    ),
)

CODEX = ConnectorSpec(
    connector_id="codex",
    display_name="Codex CLI",
    host_type="cli_agent",
    aliases=("openai-codex",),
    support_status=SUPPORT_EXPERIMENTAL,
    executables=("codex",),
    locations=_codex_locations(),
    container_path=("mcp_servers",),
    config_format=FORMAT_TOML,
    entry_builder=_toml_command_entry,
    format_verified=True,
    format_evidence=(
        "'[mcp_servers.<name>]' tables with command/args/env/cwd/url, read "
        "from a real local Codex configuration and from the schema the "
        "official 'codex mcp add' (codex-cli 0.146.0) writes. Global user "
        "scope at ~/.codex/config.toml, overridable with CODEX_HOME."
    ),
    apply_available=True,
    apply_unavailable_reason="",
    restart_instruction="Restart the Codex CLI so it re-reads config.toml.",
    security_notes=(
        "Writes use a scoped textual TOML editor: only the byte extent of "
        "the '[mcp_servers.relinkra]' table is replaced; every other table, "
        "comment, quoting style, line ending and the BOM are preserved "
        "byte-for-byte. The official 'codex mcp add' was rejected because "
        "it drops comments adjacent to the mcp_servers region and "
        "normalizes CRLF to LF globally.",
        "Dotted-key or inline-table representations of the managed member "
        "are refused, never rewritten.",
        "Reading and writing require tomllib (Python 3.11+); older "
        "interpreters report the registration state as unknown and refuse "
        "to write, rather than guessing.",
    ),
)

DEVIN_DESKTOP = ConnectorSpec(
    connector_id="devin-desktop",
    display_name="Devin Desktop",
    host_type="editor",
    # The old names stay first-class. Someone with Windsurf installed and
    # a year of muscle memory types 'windsurf', and being told that is not
    # a connector would be a rename breaking a working command.
    aliases=("windsurf", "codeium", "windsurf-next"),
    support_status=SUPPORT_EXPERIMENTAL,
    executables=("devin", "windsurf"),
    locations=_devin_desktop_locations(),
    legacy_location_ids=DEVIN_DESKTOP_LEGACY_LOCATIONS,
    naming_migration=DEVIN_DESKTOP_NAMING,
    container_path=("mcpServers",),
    config_format=FORMAT_JSON,
    entry_builder=_string_command_entry,
    # Verified against the current product on this machine, not inherited
    # from the rename: the evidence names the CLI scope documentation AND
    # the files the installed product actually holds, because "format
    # verified" for a renamed product is the easiest place to quietly
    # inherit a claim that was never re-checked.
    format_verified=True,
    format_evidence=(
        "'mcpServers' object with {command, args} entries. Current-product "
        "evidence, proven locally on Devin Desktop 3.6.27 (product.json "
        "1.126.0 stable, CLI devin 3000.3.27): 'devin mcp add --help' "
        "documents workspace-local .devin/mcp_config.local.json (default, "
        "overrides project), workspace-project .devin/mcp_config.json and "
        "user ~/.config/devin/mcp_config.json; the product's own config "
        "base is the lLr/f$ pair in the shipped bundles "
        "(out/vs/sessions/sessions.desktop.main.js and "
        "out/vs/workbench/api/node/extensionHostProcess.js): Windows -> "
        "<home>/AppData/Roaming/devin, POSIX -> <home>/.config/devin, so "
        "the CLI user scope IS the app profile on Windows. The running "
        "product holds its live mcpServers in "
        "%APPDATA%/Devin/mcp_config.json. The legacy "
        "~/.codeium/windsurf/mcp_config.json is a watched one-way IMPORT "
        "source (adapter with discoverySource 'windsurf', getFilePath -> "
        "<home>/.codeium/<windsurf|windsurf-insiders|windsurf-next>/"
        "mcp_config.json, watchFile -> adaptFile into the MCP registry, "
        "trustBehavior TrustedOnNonce, order 400); no write-to-legacy path "
        "exists in the workbench bundles. The byte-identity observed on "
        "this machine is the 2026-06-03 migration artifact "
        "(.devin-migration-complete marker; CLI migrations/"
        "mcp_to_dedicated_file.rs), not an ongoing mirror."
    ),
    # R4C.1E Gate B opens the write path. Gate B1 machine evidence proved
    # the mirror semantics (PROVEN_MULTI_SOURCE): the authoritative
    # user-scope write target on Windows is the product's own
    # %APPDATA%/Devin/mcp_config.json (= the CLI user scope), and the
    # legacy paths are evidence-only import sources, never write targets.
    # The same engine and the same gates as Claude Code (R4C.1B),
    # OpenCode (R4C.1C) and Codex (R4C.1D) apply: unsafe targets,
    # conflicts and direct CBM exposure in authoritative scopes are
    # refused, and a written config is reported as host-unverified.
    apply_available=True,
    apply_unavailable_reason="",
    restart_instruction=(
        "Reload the MCP configuration from the Cascade/MCP panel."
    ),
    security_notes=(
        "Unrelated MCP servers in mcp_config.json are preserved untouched.",
        "Legacy ~/.codeium locations are watched one-way import sources "
        "(TrustedOnNonce, proven in the shipped workbench bundles): they "
        "are read as evidence, never migrated, deleted or written, and "
        "are never the plan target.",
        "A direct codebase-memory (CBM) registration in a legacy file IS "
        "imported into the live host registry by the current product, so "
        "check and apply surface it loudly as a finding; per the phase "
        "contract it does not block apply to the current-product target "
        "(only authoritative-scope CBM blocks), and Relinkra never "
        "removes it.",
        "Workspace scopes (.devin/mcp_config.local.json overriding "
        ".devin/mcp_config.json) and both user scopes are authoritative: "
        "an entry shadowing the managed name in any of them is reported "
        "as a conflict, never merged away.",
    ),
)

DEVIN_CLOUD = ConnectorSpec(
    connector_id="devin-cloud",
    display_name="Devin (hosted)",
    host_type="hosted_agent",
    aliases=(),
    support_status=SUPPORT_UNSUPPORTED,
    format_verified=False,
    format_evidence="",
    apply_available=False,
    apply_unavailable_reason=(
        "hosted Devin is a remote agent with no local configuration file. It "
        "is listed so the roadmap is visible, and it is deliberately a "
        "SEPARATE connector from devin-desktop: the two share a brand and "
        "nothing else."
    ),
    naming_migration=(
        "Hosted Devin is 'devin-cloud' and is unsupported. It is not an alias "
        "of devin-desktop, and configuring one says nothing about the other."
    ),
    security_notes=(),
)

#: Registration order is presentation order. Append to extend; the CLI
#: never names a connector, so nothing else changes.
CONNECTORS: Tuple[ConnectorSpec, ...] = (
    GENERIC,
    CLAUDE,
    OPENCODE,
    CODEX,
    DEVIN_DESKTOP,
    DEVIN_CLOUD,
)

#: Names that used to identify one product and now identify two. Resolved
#: to NOTHING on purpose: guessing which Devin someone meant would either
#: point a desktop user at an unsupported hosted connector or silently
#: reinterpret an existing script. The error names both and lets the human
#: decide, which costs one retry and prevents a wrong answer.
AMBIGUOUS_NAMES: Dict[str, Tuple[str, ...]] = {
    "devin": ("devin-desktop", "devin-cloud"),
}


class AmbiguousConnectorError(UnknownConnectorError):
    """Raised when a name maps to more than one connector."""


def resolve_connector(name: str) -> ConnectorSpec:
    """Look a connector up by id or alias, case-insensitively.

    The error names every accepted value, because a typo here is the
    single most likely way a user meets this function.
    """
    key = (name or "").strip().lower()
    candidates = AMBIGUOUS_NAMES.get(key)
    if candidates:
        raise AmbiguousConnectorError(
            f"{name!r} is ambiguous since Windsurf became Devin Desktop; "
            "name one of: " + ", ".join(candidates)
        )
    for spec in CONNECTORS:
        if key in tuple(item.lower() for item in spec.all_names):
            return spec
    known = ", ".join(sorted(spec.connector_id for spec in CONNECTORS))
    raise UnknownConnectorError(f"unknown connector {name!r}; known: {known}")


def connector_ids() -> List[str]:
    return [spec.connector_id for spec in CONNECTORS]


# ---------------------------------------------------------------------------
# TOML reading (Codex)
# ---------------------------------------------------------------------------


def _load_toml(text: str) -> Optional[Dict[str, Any]]:
    """Parse TOML when the interpreter can. ``None`` when it cannot.

    ``tomllib`` landed in 3.11 and Relinkra supports 3.9, so on older
    interpreters the answer is "unknown", never a hand-rolled parse. A
    regex over TOML would appear to work and then quietly misread a
    multi-line array — an incorrect registration state is worse than an
    absent one.
    """
    try:
        import tomllib
    except ImportError:
        return None
    # A UTF-8 BOM is legal in files Windows tools write and is not legal
    # TOML; stripping it here matches the JSON reader's tolerance.
    if text.startswith("\ufeff"):
        text = text[1:]
    try:
        return tomllib.loads(text)
    except (ValueError, RecursionError) as exc:
        raise MalformedConfigError(f"configuration is not valid TOML: {exc}") from exc


# ---------------------------------------------------------------------------
# Inspection
# ---------------------------------------------------------------------------


@dataclass
class InspectionResult:
    """Discovery plus the parsed container, shared by inspect/plan/check.

    One read of the config, three commands. Reading it once per command
    would let ``inspect`` and ``plan`` disagree about the same file.
    """

    spec: ConnectorSpec
    locations: Tuple[ConfigLocation, ...] = ()
    location: Optional[ConfigLocation] = None
    executable: Optional[str] = None
    discovery_status: str = DISCOVERY_UNVERIFIED
    registration_state: str = REGISTRATION_UNKNOWN
    document: Optional[Dict[str, Any]] = None
    raw_text: Optional[str] = None
    existing_entry: Optional[Any] = None
    #: The container that was actually read: the spec's static path, or
    #: the workspace-resolved one when the connector declares a resolver.
    #: Carried here so plan/check/apply read the SAME container inspect
    #: did and can never disagree about where the registration lives.
    container_path: Tuple[str, ...] = ()
    warnings: List[ConnectorWarning] = field(default_factory=list)

    def warn(self, code: str, message: str) -> None:
        self.warnings.append(ConnectorWarning(code, message))


def _read_container(document: Mapping[str, Any], path: Sequence[str]) -> Any:
    node: Any = document
    for key in path:
        if not isinstance(node, Mapping):
            return None
        node = node.get(key)
        if node is None:
            return None
    return node


def inspect_connector(
    spec: ConnectorSpec, env: DiscoveryEnvironment
) -> InspectionResult:
    """Read-only discovery for one connector. Never writes, never raises.

    Every failure mode below becomes a REPORTED state rather than an
    exception, because a user with one broken host config still needs
    ``inspect`` to tell them about the other three.
    """
    result = InspectionResult(spec=spec)

    if not spec.locations:
        # Generic and roadmap connectors own no config file.
        result.discovery_status = (
            DISCOVERY_DISCOVERED
            if spec.support_status == SUPPORT_SUPPORTED
            else DISCOVERY_UNVERIFIED
        )
        result.registration_state = REGISTRATION_UNKNOWN
        return result

    result.locations = probe(spec.locations, env)
    result.executable = find_executable(env, spec.executables)
    result.location = active_location(result.locations)
    # Resolved up front: plan, check and apply all read this same value,
    # so a workspace-scoped container is targeted identically whether
    # the config parses, is missing, or has yet to be created.
    result.container_path = container_path_for(spec, env.workspace_root)

    if result.location is None:
        result.discovery_status = (
            DISCOVERY_CONFIG_MISSING
            if result.executable
            else DISCOVERY_NOT_INSTALLED
        )
        result.registration_state = REGISTRATION_ABSENT
        return result

    if not result.location.readable:
        result.discovery_status = DISCOVERY_CONFIG_UNSUPPORTED
        result.warn(
            "config_unreadable",
            "the host configuration exists but could not be read; check its "
            "permissions.",
        )
        return result

    try:
        text = read_bounded_text(result.location.path)
    except ConfigTooLargeError as exc:
        result.discovery_status = DISCOVERY_CONFIG_UNSUPPORTED
        result.warn("config_too_large", str(exc))
        return result
    except (SafeWriteError, OSError, UnicodeDecodeError) as exc:
        result.discovery_status = DISCOVERY_CONFIG_UNSUPPORTED
        result.warn("config_unreadable", f"could not read configuration: {exc}")
        return result

    result.raw_text = text

    try:
        if spec.config_format == FORMAT_TOML:
            document = _load_toml(text)
            if document is None:
                result.discovery_status = DISCOVERY_DISCOVERED
                result.registration_state = REGISTRATION_UNKNOWN
                result.warn(
                    "toml_parser_unavailable",
                    "reading TOML needs Python 3.11 or newer; the "
                    "registration state cannot be determined on this "
                    "interpreter.",
                )
                return result
        else:
            document = parse_json_document(text)
    except MalformedConfigError as exc:
        result.discovery_status = DISCOVERY_CONFIG_MALFORMED
        result.warn("config_malformed", str(exc))
        return result
    except UnsupportedShapeError as exc:
        result.discovery_status = DISCOVERY_CONFIG_UNSUPPORTED
        result.warn("config_unsupported", str(exc))
        return result

    result.document = document
    result.discovery_status = DISCOVERY_DISCOVERED

    container = _read_container(document, result.container_path)
    if container is None:
        result.registration_state = REGISTRATION_ABSENT
        return result
    if not isinstance(container, Mapping):
        result.discovery_status = DISCOVERY_CONFIG_UNSUPPORTED
        result.registration_state = REGISTRATION_UNKNOWN
        result.warn(
            "config_unsupported",
            f"'{container_label(result.container_path)}' is not an object in "
            "this configuration.",
        )
        return result

    entry = container.get(MANAGED_SERVER_NAME)
    if entry is None:
        result.registration_state = REGISTRATION_ABSENT
        return result

    result.existing_entry = entry
    is_managed = ownership_test(is_managed_entry, marker_allowed=spec.marker_allowed)
    if not is_managed(entry):
        result.registration_state = REGISTRATION_CONFLICT
        result.warn(
            "registration_conflict",
            f"an entry named '{MANAGED_SERVER_NAME}' exists but does not "
            "launch Relinkra; it will never be overwritten.",
        )
        return result

    result.registration_state = REGISTRATION_ALREADY_CONNECTED
    return result


def build_report(
    spec: ConnectorSpec,
    inspection: InspectionResult,
    launch: Optional[LaunchContract] = None,
    plan: Optional[ConnectorPlan] = None,
) -> ConnectorReport:
    """Render an inspection as the portable report both commands print.

    ``plan`` is optional but callers should supply it: without it,
    ``registration_planned`` can only ever be false, and a capability
    that is structurally incapable of being true tells the reader
    nothing.
    """
    registration_detected = inspection.registration_state in (
        REGISTRATION_ALREADY_CONNECTED,
        REGISTRATION_NEEDS_UPDATE,
    )
    capabilities = CapabilityMatrix(
        # Structural, not a name check. Keying off the literal "generic"
        # would silently flip this capability to false the day that
        # connector is renamed, with nothing failing to say so.
        implementation_exists=(
            bool(spec.locations)
            or spec.entry_builder is not None
            or spec.format_verified
        ),
        configuration_format_verified=spec.format_verified,
        registration_detected=registration_detected,
        registration_planned=bool(plan is not None and plan.status == PLAN_READY),
        configuration_validated=inspection.document is not None,
        mcp_process_contract_validated=bool(launch and launch.resolved),
        real_host_launch_proven=spec.real_host_launch_proven,
    )
    return ConnectorReport(
        connector_id=spec.connector_id,
        display_name=spec.display_name,
        host_type=spec.host_type,
        aliases=spec.aliases,
        support_status=spec.support_status,
        discovery_status=inspection.discovery_status,
        registration_state=inspection.registration_state,
        transport=TRANSPORT_STDIO,
        executable_found=bool(inspection.executable),
        locations=list(inspection.locations),
        active_location_id=(
            inspection.location.location_id if inspection.location else ""
        ),
        env_keys=list(launch.env_keys) if launch else [],
        warnings=list(inspection.warnings),
        capabilities=capabilities,
        restart_instruction=spec.restart_instruction,
        security_notes=list(spec.security_notes),
    )


# ---------------------------------------------------------------------------
# Planning
# ---------------------------------------------------------------------------


def _target_ref(spec: ConnectorSpec, location: Optional[ConfigLocation]) -> str:
    """Semantic target id. Stable across machines, never a path."""
    suffix = location.location_id if location else "unresolved"
    return f"{spec.connector_id}:{suffix}"


def _preferred_target(
    spec: ConnectorSpec, inspection: InspectionResult
) -> Optional[ConfigLocation]:
    """Where a write WOULD go: the active config, else the first
    declared writable candidate. Declaration order is the preference.

    A legacy location of a renamed host is never the target, even when
    it is the active config the inspection read: the plan points at the
    first declared current-product candidate instead — a create path
    when nothing current exists yet, the same contract a host with no
    configuration at all gets.
    """
    legacy_ids = spec.legacy_location_ids
    if (
        inspection.location is not None
        and inspection.location.location_id not in legacy_ids
    ):
        return inspection.location
    for location in inspection.locations:
        if location.location_id not in legacy_ids:
            return location
    return None


def _describe_entry(entry: Mapping[str, Any]) -> str:
    """Summarise a planned entry without printing any of its values.

    Arity and key names only. That is enough for a reviewer to see that
    the plan is the shape they expect, and it carries no interpreter
    path, no workspace root and no environment value.
    """
    tokens = entry_tokens(entry)
    env_keys = sorted(entry.get("env") or entry.get("environment") or {})
    parts = [f"{len(tokens)} command token(s)"]
    if env_keys:
        parts.append("env keys: " + ", ".join(env_keys))
    else:
        parts.append("no environment")
    return "; ".join(parts)


def build_plan(
    spec: ConnectorSpec,
    inspection: InspectionResult,
    launch: LaunchContract,
) -> ConnectorPlan:
    """Produce a deterministic mutation plan. Touches no file.

    The plan is built from the config as it was READ; a precondition on
    every mutating step names the digest the executor must still see, so
    an edit made between planning and applying aborts the write instead
    of silently discarding the user's change.
    """
    plan = ConnectorPlan(
        connector_id=spec.connector_id,
        apply_available=spec.apply_available,
        restart_instruction=spec.restart_instruction,
        registration_state=inspection.registration_state,
    )
    plan.warnings.extend(inspection.warnings)
    for message in launch.warnings:
        plan.warnings.append(ConnectorWarning("launch_contract", message))

    if not spec.locations or spec.entry_builder is None:
        plan.status = PLAN_UNAVAILABLE
        plan.unavailable_reason = (
            spec.apply_unavailable_reason
            or "this connector owns no host configuration."
        )
        return plan

    if not spec.format_verified:
        plan.status = PLAN_UNAVAILABLE
        plan.unavailable_reason = (
            "this host's configuration format has not been verified; "
            "Relinkra will not invent a schema."
        )
        return plan

    if not launch.resolved:
        plan.status = PLAN_UNAVAILABLE
        plan.unavailable_reason = (
            "the MCP launch contract could not be resolved on this machine."
        )
        return plan

    location = _preferred_target(spec, inspection)
    plan.target_ref = _target_ref(spec, location)
    if location is None:
        plan.status = PLAN_UNAVAILABLE
        plan.unavailable_reason = (
            "no configuration location applies to this platform."
        )
        return plan

    if inspection.discovery_status in (
        DISCOVERY_CONFIG_MALFORMED,
        DISCOVERY_CONFIG_UNSUPPORTED,
    ):
        plan.status = PLAN_UNAVAILABLE
        plan.unavailable_reason = (
            "the existing configuration could not be parsed, so no safe "
            "merge can be planned."
        )
        return plan

    if inspection.raw_text is not None and inspection.document is None:
        # The file was read but not parsed (TOML on an interpreter
        # without tomllib). The registration state is UNKNOWN, and a
        # plan built on an unknown state would be a guess.
        plan.status = PLAN_UNAVAILABLE
        plan.unavailable_reason = next(
            (warning.message for warning in inspection.warnings),
            "the existing configuration could not be parsed on this "
            "interpreter.",
        )
        return plan

    if adapter_for(spec.config_format) is None:
        plan.status = PLAN_UNAVAILABLE
        plan.unavailable_reason = (
            spec.apply_unavailable_reason
            or "this host's configuration format is not writable in this "
            "phase."
        )
        return plan

    desired = spec.entry_builder(launch)
    # The document the decision merges into must be the TARGET's content.
    # When the preferred target is not the inspected location — a
    # legacy-only install whose plan aims at a current-product create
    # path — the inspected document describes another file, so the plan
    # starts from empty exactly as an absent config does.
    document = (
        inspection.document
        if inspection.document is not None and location is inspection.location
        else {}
    )
    is_managed = ownership_test(is_managed_entry, marker_allowed=spec.marker_allowed)
    container_path = inspection.container_path or spec.container_path

    try:
        decision = decide_member(
            document,
            container_path,
            MANAGED_SERVER_NAME,
            desired,
            is_managed=is_managed,
        )
    except MergeError as exc:
        plan.status = PLAN_UNAVAILABLE
        plan.unavailable_reason = str(exc)
        return plan

    container = container_label(container_path)
    file_exists = bool(location.exists)
    digest_precondition = (
        "target file content is unchanged since inspection"
        if file_exists
        else "target file does not exist"
    )

    if decision.action == ACTION_CONFLICT:
        plan.status = PLAN_BLOCKED
        plan.registration_state = REGISTRATION_CONFLICT
        plan.conflicts.append(
            f"{container}.{MANAGED_SERVER_NAME} is owned by another server"
        )
        plan.warnings.append(
            ConnectorWarning("registration_conflict", decision.reason)
        )
        return plan

    if decision.action == ACTION_NO_OP:
        plan.status = PLAN_READY
        plan.registration_state = REGISTRATION_ALREADY_CONNECTED
        plan.operations.append(
            PlanOperation(
                op=OP_NO_OP,
                target_ref=plan.target_ref,
                detail=(
                    f"{container}.{MANAGED_SERVER_NAME} is already correct; "
                    "nothing to change."
                ),
                preconditions=(digest_precondition,),
                postconditions=("configuration is byte-identical",),
                rollback="not applicable; no write occurs",
            )
        )
        return plan

    operations: List[PlanOperation] = []
    if file_exists:
        operations.append(
            PlanOperation(
                op=OP_BACKUP_FILE,
                target_ref=plan.target_ref,
                detail="copy the existing configuration aside before writing",
                preconditions=(digest_precondition, "target is a regular file"),
                postconditions=("a collision-safe backup copy exists",),
                rollback="restore the target from the backup copy",
            )
        )
    else:
        operations.append(
            PlanOperation(
                op=OP_CREATE_FILE,
                target_ref=plan.target_ref,
                detail="create the configuration file with owner-only permissions",
                preconditions=("target file does not exist",),
                postconditions=("a new configuration file exists",),
                rollback="delete the created file",
            )
        )

    if decision.action == ACTION_ADD:
        plan.registration_state = REGISTRATION_ABSENT
        operations.append(
            PlanOperation(
                op=OP_ADD_OBJECT_MEMBER,
                target_ref=plan.target_ref,
                detail=(
                    f"add {container}.{MANAGED_SERVER_NAME} "
                    f"({_describe_entry(desired)})"
                ),
                preconditions=(
                    f"{container}.{MANAGED_SERVER_NAME} does not exist",
                    "all unrelated members are preserved",
                ),
                postconditions=(
                    f"{container}.{MANAGED_SERVER_NAME} launches Relinkra",
                    "every pre-existing member is unchanged",
                ),
                rollback="restore the target from the backup copy",
            )
        )
    elif decision.action == ACTION_UPDATE:
        plan.registration_state = REGISTRATION_NEEDS_UPDATE
        operations.append(
            PlanOperation(
                op=OP_REPLACE_MANAGED_MEMBER,
                target_ref=plan.target_ref,
                detail=(
                    f"refresh the stale Relinkra entry at "
                    f"{container}.{MANAGED_SERVER_NAME} "
                    f"({_describe_entry(decision.member or desired)})"
                ),
                preconditions=(
                    f"{container}.{MANAGED_SERVER_NAME} is Relinkra-managed",
                    digest_precondition,
                ),
                postconditions=(
                    "fields Relinkra does not manage are preserved",
                    "every unrelated member is unchanged",
                ),
                rollback="restore the target from the backup copy",
            )
        )
    else:
        # Unreachable with today's four actions. Kept so that adding a
        # fifth cannot silently produce a plan that backs the file up and
        # then never mutates it.
        plan.status = PLAN_UNAVAILABLE
        plan.unavailable_reason = f"unsupported merge action: {decision.action}"
        return plan

    operations.append(
        PlanOperation(
            op=OP_VALIDATE_JSON,
            target_ref=plan.target_ref,
            detail="re-parse the written file before accepting the change",
            preconditions=("the write completed",),
            postconditions=(
                f"the written configuration parses as {spec.config_format.upper()}",
            ),
            rollback="restore the target from the backup copy",
        )
    )
    operations.append(
        PlanOperation(
            op=OP_REQUEST_RESTART,
            target_ref=plan.target_ref,
            detail=spec.restart_instruction,
            preconditions=("the configuration was written and validated",),
            postconditions=("the host has re-read its configuration",),
            rollback="not applicable; no file is touched",
        )
    )

    plan.operations = operations
    plan.status = PLAN_READY
    if not spec.apply_available:
        plan.unavailable_reason = spec.apply_unavailable_reason
    return plan


# ---------------------------------------------------------------------------
# Checking an existing registration
# ---------------------------------------------------------------------------


@dataclass
class CheckResult:
    """Validation of an EXISTING registration. Read-only by construction."""

    connector_id: str
    registration_state: str = REGISTRATION_UNKNOWN
    valid: bool = False
    findings: List[str] = field(default_factory=list)
    warnings: List[ConnectorWarning] = field(default_factory=list)
    matches_workspace: Optional[bool] = None
    target_ref: str = ""

    def to_dict(self) -> dict:
        return {
            "connector_id": self.connector_id,
            "registration_state": self.registration_state,
            "valid": self.valid,
            "findings": list(self.findings),
            "warnings": [w.to_dict() for w in self.warnings],
            "matches_workspace": self.matches_workspace,
            "target_ref": self.target_ref,
        }


def check_registration(
    spec: ConnectorSpec,
    inspection: InspectionResult,
    launch: LaunchContract,
    *,
    shadow_hints: Tuple[str, ...] = (),
    authoritative_scope_finding: str = "",
    legacy_scope_findings: Tuple[str, ...] = (),
) -> CheckResult:
    """Validate the registration that is already there, changing nothing.

    ``matches_workspace`` compares the recorded ``--workspace-root``
    against this workspace. A registration pointing at a DIFFERENT repo
    is valid MCP configuration and still wrong for the user standing
    here, so it is reported as its own fact rather than folded into
    ``valid``.

    ``shadow_hints`` names authoritative scopes — other than the
    inspected target — holding an entry under the managed server name.
    The host merges those scopes beside the target, so such an entry
    SHADOWS the target registration at runtime: the state is reported
    as a conflict even when the inspected file itself is clean, because
    which entry the host runs is the host's merge rule, not Relinkra's.

    ``legacy_scope_findings`` names facts about the connector's
    LEGACY/evidence-only locations (a direct CBM entry the host still
    imports, an unreadable legacy file). They are surfaced as warnings,
    never as findings: the ``valid``/exit semantics describe the
    CURRENT-product registration, and a legacy-scope fact must not flip
    them — but it must never pass silently either.
    """
    result = CheckResult(
        connector_id=spec.connector_id,
        registration_state=inspection.registration_state,
        target_ref=_target_ref(spec, inspection.location),
    )
    result.warnings.extend(inspection.warnings)
    for message in legacy_scope_findings:
        result.warnings.append(ConnectorWarning("legacy_scope", message))

    if authoritative_scope_finding:
        result.registration_state = REGISTRATION_UNKNOWN
        result.findings.append(authoritative_scope_finding)
        return result

    if shadow_hints:
        joined = ", ".join(shadow_hints)
        result.registration_state = REGISTRATION_CONFLICT
        result.findings.append(
            f"an entry named '{MANAGED_SERVER_NAME}' in {joined} shadows the "
            "managed registration: the host merges that scope beside this "
            "configuration, so which entry runs is the host's merge rule, "
            "not Relinkra's."
        )
        return result
    if inspection.registration_state == REGISTRATION_CONFLICT:
        result.findings.append(
            f"an entry named '{MANAGED_SERVER_NAME}' exists but does not "
            "launch Relinkra."
        )
        return result
    if inspection.registration_state == REGISTRATION_UNKNOWN:
        # Distinct from "absent". The config could not be read or parsed
        # — on an interpreter without tomllib, for instance — so nothing
        # is known either way. Claiming absence here would contradict the
        # state field printed directly above it.
        result.findings.append(
            "the registration state could not be determined; see the "
            "warnings below."
        )
        return result
    if inspection.existing_entry is None:
        result.findings.append("no Relinkra registration found for this host.")
        return result

    if (
        inspection.location is not None
        and inspection.location.location_id in spec.legacy_location_ids
    ):
        # A registration at a LEGACY location of a renamed host is not a
        # current-product registration, however equivalent its content:
        # the plan contract refuses to treat that path as the target, so
        # check must refuse to call it valid. ``registration_state`` stays
        # truthful about what the inspected file contains; the finding is
        # what flips ``valid`` and forces a human decision.
        result.findings.append(
            "the registration was found only at the legacy "
            f"'{inspection.location.display_hint}' location, which belongs "
            f"to the retired product naming; it is read as evidence but is "
            f"not a current {spec.display_name} registration."
        )

    entry = inspection.existing_entry
    tokens = entry_tokens(entry)
    if not tokens:
        result.findings.append("the registration has no command to run.")
        return result

    desired_root: Optional[str] = None
    for index, token in enumerate(launch.args):
        if token == "--workspace-root" and index + 1 < len(launch.args):
            desired_root = launch.args[index + 1]
            break
    recorded_root: Optional[str] = None
    for index, token in enumerate(tokens):
        if token == "--workspace-root" and index + 1 < len(tokens):
            recorded_root = tokens[index + 1]
            break

    if desired_root and recorded_root:
        result.matches_workspace = _same_path(recorded_root, desired_root)
        if not result.matches_workspace:
            result.findings.append(
                "the registration points at a different workspace than this one."
            )
    elif desired_root and not recorded_root:
        result.matches_workspace = False
        result.findings.append(
            "the registration does not pin a workspace root, so the server "
            "will bind to whichever directory the host starts it in."
        )

    if launch.env and not (entry.get("env") or entry.get("environment")):
        result.findings.append(
            "this workspace runs Relinkra from a source checkout, but the "
            "registration passes no environment; the server may fail to "
            "import."
        )

    # Staleness is decided by the SAME engine ``build_plan`` uses.
    # Answering this question a second way here is exactly how ``check``
    # ends up calling a registration valid that ``plan``, looking at the
    # same file, reports as needing an update.
    if (
        spec.entry_builder is not None
        and inspection.document is not None
        and launch.resolved
    ):
        try:
            decision = decide_member(
                inspection.document,
                inspection.container_path or spec.container_path,
                MANAGED_SERVER_NAME,
                spec.entry_builder(launch),
                is_managed=ownership_test(
                    is_managed_entry, marker_allowed=spec.marker_allowed
                ),
            )
        except MergeError:
            decision = None
        if decision is not None and decision.action == ACTION_UPDATE:
            result.registration_state = REGISTRATION_NEEDS_UPDATE
            result.findings.append(
                "the registration is out of date; run "
                "'relinkra connect plan' to see what would change."
            )

    result.valid = not result.findings
    return result


def _same_path(left: str, right: str) -> bool:
    """Compare two recorded workspace roots.

    ``Path`` comparison rather than string equality so a trailing
    separator or a different separator style is not read as a different
    workspace. Case folding follows the platform, which is what
    ``PurePath`` equality already does.
    """
    try:
        return PurePath(left) == PurePath(right) or Path(left) == Path(right)
    except (TypeError, ValueError):
        return left == right
