"""R4C.1A — CBM private-backend certification tests.

Pins the historical AND certified (0.9.0) CLI contracts, the pin policy,
the doctor trust ladder, deep health probing, and honest degradation —
plus real-binary proofs gated on a resolvable CBM executable.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from relinkra import cbm_support
from relinkra import context_cli
from relinkra.app_service import RelinkraServices, ServiceConfig
from relinkra.backend_policy import (
    CBM_DIRECTLY_EXPOSED,
    ROUTE_BYPASSED,
    RouteInputs,
    classify_cbm_ownership,
    classify_context_route,
)
from relinkra.cbm_adapter import (
    CBMAdapterError,
    CBMCLIAdapter,
    MAX_CHILD_OUTPUT_BYTES,
    _normalize_workspace_root,
    parse_cli_json,
    strip_project_slug,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
SLUG = "C-Desarrollos-relinkra-relinkra"
PID = "rlk_" + "a" * 32
WID = "ws_" + "b" * 32


def _completed(rc=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=["cbm"], returncode=rc, stdout=stdout, stderr=stderr)


def _search_payload(*nodes, total=None):
    return json.dumps(
        {"total": total if total is not None else len(nodes), "results": list(nodes), "has_more": False}
    )


def _node(qn_suffix, file_path, name=None, label="Function", start=10, end=20):
    return {
        "name": name or qn_suffix.rsplit(".", 1)[-1],
        "qualified_name": f"{SLUG}.{qn_suffix}",
        "label": label,
        "file_path": file_path,
        "start_line": start,
        "end_line": end,
    }


def _adapter(**overrides):
    defaults = dict(
        cbm_bin="cbm.exe",
        cache_dir="cache",
        cbm_project_name=SLUG,
        workspace_root="C:/Desarrollos/relinkra",
    )
    defaults.update(overrides)
    return CBMCLIAdapter(**defaults)


class TestWorkspaceRootIdentity(unittest.TestCase):
    """R5C: foreign-absolute workspace roots keep their identity verbatim.

    Passing a foreign-syntax absolute path through host-native
    ``os.path.abspath()`` prepends the cwd and FABRICATES a host-local
    path that never existed (on POSIX: ``abspath("C:/w")`` →
    ``"<cwd>/C:/w"``). The workspace root is a portable identity used for
    string-prefix relativization and safe.directory binding — never a
    host-local IO path.
    """

    def test_windows_drive_root_is_verbatim_on_any_host(self):
        self.assertEqual(
            _normalize_workspace_root("C:\\Desarrollos\\relinkra"),
            "C:/Desarrollos/relinkra",
        )

    def test_posix_root_is_verbatim_on_any_host(self):
        self.assertEqual(
            _normalize_workspace_root("/home/u/repo"), "/home/u/repo"
        )

    def test_unc_root_is_verbatim_on_any_host(self):
        self.assertEqual(
            _normalize_workspace_root("\\\\server\\share\\repo"),
            "//server/share/repo",
        )

    def test_relative_root_resolves_against_cwd(self):
        resolved = _normalize_workspace_root("rel/ws")
        self.assertTrue(resolved.endswith("/rel/ws"))
        self.assertNotIn("\\", resolved)

    def test_constructor_preserves_foreign_root_identity(self):
        adapter = _adapter(workspace_root="C:\\Desarrollos\\relinkra")
        self.assertEqual(adapter.workspace_root, "C:/Desarrollos/relinkra")


class TestHistoricalContract(unittest.TestCase):
    """The pinned historical contract the adapter was built against."""

    def test_logs_before_json_are_tolerated(self):
        payload = parse_cli_json(
            'level=info msg=mem.init budget_mb=1\n{"results": [], "total": 0}\n'
        )
        self.assertEqual(payload, {"results": [], "total": 0})

    def test_malformed_json_raises(self):
        with self.assertRaises(CBMAdapterError):
            parse_cli_json("level=info only logs\n{not json")

    def test_json_with_trailing_junk_is_rejected(self):
        with self.assertRaises(CBMAdapterError):
            parse_cli_json('{"results": []} injected')

    def test_slug_stripping(self):
        self.assertEqual(
            strip_project_slug(f"{SLUG}.relinkra.cbm_adapter.CBMCLIAdapter", SLUG),
            "relinkra.cbm_adapter.CBMCLIAdapter",
        )
        self.assertEqual(strip_project_slug("other.qn", SLUG), "other.qn")
        self.assertEqual(strip_project_slug(SLUG, SLUG), "")

    def test_child_environment_is_minimal_but_git_safe_directory_bound(self):
        adapter = _adapter(workspace_root="C:/Desarrollos/relinkra")
        env = adapter._child_environment()
        self.assertEqual(env["GIT_CONFIG_COUNT"], "1")
        self.assertEqual(env["GIT_CONFIG_KEY_0"], "safe.directory")
        self.assertEqual(env["GIT_CONFIG_VALUE_0"], "C:/Desarrollos/relinkra")
        self.assertNotIn("USERPROFILE", env)
        self.assertNotIn("ENGRAM_HTTP_TOKEN", env)

    def test_search_symbols_normalizes_candidates(self):
        node = _node("relinkra.x.func", "relinkra/x.py")
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=_completed(stdout=_search_payload(node)),
        ) as run:
            candidates = _adapter().search_symbols(query="func")
        argv = run.call_args[0][0]
        self.assertEqual(argv[:3], ["cbm.exe", "cli", "search_graph"])
        self.assertIn("--project", argv)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(
            candidates[0]["relative_qualified_name"], "relinkra.x.func"
        )
        self.assertEqual(candidates[0]["cbm_project_name"], SLUG)

    def test_timeout_is_normalized(self):
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="cbm", timeout=1),
        ):
            with self.assertRaises(CBMAdapterError) as ctx:
                _adapter().search_symbols(query="x")
        self.assertIn("timed out", str(ctx.exception))

    def test_error_output_is_sanitized(self):
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=_completed(rc=1, stderr="boom C:\\secret\\path"),
        ):
            with self.assertRaises(CBMAdapterError):
                _adapter().search_symbols(query="x")

    def test_child_environment_excludes_credentials(self):
        with mock.patch(
            "relinkra.cbm_adapter.os.environ",
            {"PATH": "path", "SystemRoot": "root", "CBM_TOKEN": "secret"},
        ), mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=_completed(stdout='{"results": [], "total": 0}'),
        ) as run:
            self.assertEqual(_adapter().search_symbols(query="x"), [])
        child_env = run.call_args.kwargs["env"]
        self.assertNotIn("CBM_TOKEN", child_env)
        self.assertEqual(child_env["CBM_CACHE_DIR"], "cache")
        self.assertIs(run.call_args.kwargs["stdin"], subprocess.DEVNULL)

    def test_oversized_child_output_is_rejected(self):
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=_completed(stdout="x" * (MAX_CHILD_OUTPUT_BYTES + 1)),
        ):
            with self.assertRaisesRegex(CBMAdapterError, "output limit"):
                _adapter().search_symbols(query="x")

    def test_exit_zero_structured_errors_are_not_lookup_misses(self):
        error = '{"error": "backend offline"}'
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=_completed(stdout=error),
        ):
            with self.assertRaises(CBMAdapterError):
                _adapter().search_symbols(query="x")
            with self.assertRaises(CBMAdapterError):
                _adapter().get_snippet(f"{SLUG}.relinkra.x.Nope")
            with self.assertRaises(CBMAdapterError):
                _adapter().list_projects()


class TestCertifiedContract090(unittest.TestCase):
    """Contract shapes reproduced against the certified 0.9.0 binary."""

    def test_search_payload_carries_total_and_has_more(self):
        node = _node("relinkra.x.func", "relinkra/x.py")
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=_completed(stdout=_search_payload(node, total=41)),
        ):
            candidates = _adapter().search_symbols(query="func", limit=5)
        self.assertEqual(len(candidates), 1)

    def test_missing_symbol_search_is_empty_not_error(self):
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=_completed(stdout='{"total": 0, "results": [], "has_more": false}'),
        ):
            self.assertEqual(_adapter().search_symbols(query="NoSuch"), [])

    def test_missing_project_search_raises_honestly(self):
        stderr = '{"error":"project not found or not indexed"}'
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=_completed(rc=1, stderr=stderr),
        ):
            with self.assertRaises(CBMAdapterError):
                _adapter().search_symbols(query="x")

    def test_missing_symbol_snippet_returns_none(self):
        # 0.9.0: exit 1 + "symbol not found" at the START of stderr — a
        # lookup miss, not an outage.
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=_completed(rc=1, stderr="symbol not found. Use search_graph first."),
        ):
            self.assertIsNone(_adapter().get_snippet(f"{SLUG}.relinkra.x.Nope"))

    def test_wrapped_outage_with_the_phrase_still_raises(self):
        # An outage whose stderr merely CONTAINS the phrase (not at the
        # start of the failure detail) is outage-class, never a silent
        # miss.
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=_completed(
                rc=1, stderr="fatal: symbol not found table missing, index corrupted"
            ),
        ):
            with self.assertRaises(CBMAdapterError):
                _adapter().get_snippet(f"{SLUG}.relinkra.x.Nope")

    def test_other_snippet_failures_raise(self):
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=_completed(rc=1, stderr="project not found or not indexed"),
        ):
            with self.assertRaises(CBMAdapterError):
                _adapter().get_snippet(f"{SLUG}.relinkra.x.Nope")

    def test_snippet_absolute_windows_path_is_relativized(self):
        payload = json.dumps(
            _node(
                "relinkra.backend_policy.classify_context_route",
                "C:/Desarrollos/relinkra/relinkra/backend_policy.py",
            )
        )
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=_completed(stdout=payload),
        ):
            candidate = _adapter().get_snippet(
                f"{SLUG}.relinkra.backend_policy.classify_context_route"
            )
        self.assertEqual(candidate["file_path"], "relinkra/backend_policy.py")
        self.assertNotIn("Desarrollos", candidate["file_path"])

    def test_snippet_absolute_posix_path_is_relativized(self):
        # The constructor absolutizes workspace_root with host semantics
        # (on Windows "/home/u/repo" would gain a drive letter), so set
        # the normalized attribute directly to exercise POSIX keys.
        adapter = _adapter(workspace_root=None)
        adapter.workspace_root = "/home/u/repo"
        payload = json.dumps(_node("src.x.func", "/home/u/repo/src/x.py"))
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=_completed(stdout=payload),
        ):
            candidate = adapter.get_snippet(f"{SLUG}.src.x.func")
        self.assertEqual(candidate["file_path"], "src/x.py")

    def test_probe_version(self):
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=_completed(stdout="codebase-memory-mcp 0.9.0\n"),
        ):
            self.assertEqual(_adapter().probe_version(), "codebase-memory-mcp 0.9.0")

    def test_probe_version_missing_binary(self):
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run", side_effect=FileNotFoundError
        ):
            with self.assertRaises(CBMAdapterError):
                _adapter().probe_version()

    def test_list_projects_and_index_status(self):
        projects = {"projects": [{"name": SLUG, "nodes": 1}]}
        status = {"project": SLUG, "status": "ready", "git": {"head_sha": "abc"}}
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            side_effect=[
                _completed(stdout=json.dumps(projects)),
                _completed(stdout=json.dumps(status)),
            ],
        ):
            adapter = _adapter()
            self.assertEqual(adapter.list_projects()[0]["name"], SLUG)
            self.assertEqual(adapter.index_status()["status"], "ready")


class TestPinPolicy(unittest.TestCase):
    def test_classify_version(self):
        self.assertEqual(cbm_support.classify_version("0.9.0"), cbm_support.VERSION_CERTIFIED)
        for variant in ("0.9.0-rc.1", "0.9.0-beta.2", "0.9.0+dirty", "0.9.1-rc.1"):
            with self.subTest(variant=variant):
                self.assertNotEqual(
                    cbm_support.classify_version(variant),
                    cbm_support.VERSION_CERTIFIED,
                )
        self.assertNotEqual(
            cbm_support.classify_version("0.9.0foo"),
            cbm_support.VERSION_CERTIFIED,
        )
        self.assertEqual(
            cbm_support.classify_version("codebase-memory-mcp 0.9.7"),
            cbm_support.VERSION_SUPPORTED,
        )
        self.assertEqual(cbm_support.classify_version("0.8.1"), cbm_support.VERSION_UNSUPPORTED)
        self.assertEqual(cbm_support.classify_version("0.10.0"), cbm_support.VERSION_UNSUPPORTED)
        self.assertEqual(cbm_support.classify_version("garbage"), cbm_support.VERSION_UNKNOWN)
        self.assertEqual(cbm_support.classify_version(None), cbm_support.VERSION_UNKNOWN)

    def test_parse_version_prefers_the_named_triple(self):
        self.assertEqual(
            cbm_support.parse_version("go1.22.3 toolchain; codebase-memory-mcp 0.9.0"),
            (0, 9, 0),
        )
        # Unnamed fallback: the LAST dotted triple, so a prefixed
        # toolchain version cannot shadow the tool's own.
        self.assertEqual(cbm_support.parse_version("built with go1.22.3, v0.9.0"), (0, 9, 0))

    def test_certified_provenance_recorded(self):
        entry = cbm_support.CERTIFIED_CBM_BINARIES["windows-amd64"]
        self.assertEqual(entry["version"], cbm_support.CERTIFIED_CBM_VERSION)
        self.assertEqual(len(entry["sha256"]), 64)

    def test_resolve_cbm_binary_env_wins(self):
        self.assertEqual(
            cbm_support.resolve_cbm_binary(
                "root", environ={"RELINKRA_CBM_BIN": "x/cbm.exe"}
            ),
            "x/cbm.exe",
        )

    def test_resolve_cbm_binary_managed_location(self):
        with tempfile.TemporaryDirectory() as tmp:
            managed = Path(tmp) / ".codebase-memory" / "bin"
            managed.mkdir(parents=True)
            exe = managed / "codebase-memory-mcp.exe"
            exe.write_text("bin", encoding="utf-8")
            found = cbm_support.resolve_cbm_binary(tmp, environ={})
            self.assertEqual(found, str(exe))

    def test_resolve_cbm_binary_none(self):
        with mock.patch("shutil.which", return_value=None):
            self.assertIsNone(cbm_support.resolve_cbm_binary(None, environ={}))

    def test_cache_path_must_stay_inside_managed_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                cbm_support.absolutize_against_root(tmp, "..\\outside")
            with self.assertRaises(ValueError):
                cbm_support.absolutize_against_root(tmp, "C:\\outside")

    def test_trust_gated_adapter_rechecks_replaced_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "cbm.exe"
            binary.write_bytes(b"trusted")
            expected = hashlib.sha256(b"trusted").hexdigest()
            adapter = _adapter(cbm_bin=str(binary), expected_sha256=expected)
            binary.write_bytes(b"replaced")
            with mock.patch("relinkra.cbm_adapter.subprocess.run") as run:
                with self.assertRaisesRegex(CBMAdapterError, "hash changed"):
                    adapter.search_symbols(query="x")
            run.assert_not_called()


# ---------------------------------------------------------------------------
# Doctor trust ladder
# ---------------------------------------------------------------------------


class _FakeAdapter:
    """Duck-typed CBMCLIAdapter stand-in for the ladder."""

    version = "codebase-memory-mcp 0.9.0"
    projects = None
    status = None
    search_error = None
    version_error = None

    def __init__(self, **kwargs):
        pass

    def probe_version(self):
        if self.version_error:
            raise CBMAdapterError(self.version_error)
        return self.version

    def list_projects(self):
        return list(self.projects or [])

    def index_status(self, project=None):
        return dict(self.status or {})

    def search_symbols(self, **kwargs):
        if self.search_error:
            raise CBMAdapterError(self.search_error)
        return []


def _make_workspace(tmp, *, with_cbm_record=True):
    """A minimal initialized workspace: config.json + registry."""
    root = Path(tmp)
    (root / ".git").mkdir()
    from relinkra.product_cli import WorkspaceConfig

    WorkspaceConfig(project_id=PID, workspace_id=WID, initialized_at="t").save(root)
    registry_dir = root / ".relinkra"
    registry_dir.mkdir(exist_ok=True)
    cbm = None
    if with_cbm_record:
        cbm = {
            "project_name": SLUG,
            "cache_dir": ".codebase-memory/cache",
            "db_path": f".codebase-memory/cache/{SLUG}.db",
            "binary": {"version": "0.9.0", "sha256": "0" * 64},
        }
    registry = {
        "schema_version": 1,
        "projects": {
            PID: {
                "project_id": PID,
                "display_name": "x",
                "repository_identity": {
                    "kind": "remote",
                    "value": "remote://git/github.com/x/y",
                    "trust": "strong",
                },
                "created_at": "t",
            }
        },
        "workspaces": {
            WID: {
                "workspace_id": WID,
                "project_id": PID,
                "absolute_path": str(root),
                "canonical_path": str(root).lower(),
                "os": "windows",
                "registered_at": "t",
                "last_seen_at": "t",
                "cbm": cbm,
            }
        },
    }
    (registry_dir / "registry.json").write_text(
        json.dumps(registry), encoding="utf-8"
    )
    return root


def _ladder(root, fake, *, binary="cbm.exe", platform_tag="windows-amd64"):
    from relinkra import product_cli
    from relinkra.product_cli import WorkspaceConfig, cbm_trust_checks

    config = WorkspaceConfig.load(root)
    with mock.patch.object(
        product_cli.cbm_support, "resolve_cbm_binary", return_value=binary
    ), mock.patch(
        "relinkra.cbm_support.CBMCLIAdapter", fake
    ), mock.patch.object(
        product_cli.cbm_support, "platform_tag", return_value=platform_tag
    ), mock.patch(
        "relinkra.cbm_support.git_head_sha", return_value="h" * 40
    ):
        return {c.name: c for c in cbm_trust_checks(root, config)}


class TestDoctorTrustLadder(unittest.TestCase):
    def setUp(self):
        from relinkra import product_cli

        self._certified = dict(cbm_support.CERTIFIED_CBM_BINARIES)
        self.addCleanup(
            setattr,
            product_cli.cbm_support,
            "CERTIFIED_CBM_BINARIES",
            self._certified,
        )

    def _fake_binary(self, root):
        exe = root / ".codebase-memory" / "bin" / "codebase-memory-mcp.exe"
        exe.parent.mkdir(parents=True, exist_ok=True)
        exe.write_bytes(b"fake-cbm")
        sha = hashlib.sha256(b"fake-cbm").hexdigest()
        from relinkra import product_cli

        product_cli.cbm_support.CERTIFIED_CBM_BINARIES = {
            "windows-amd64": {"version": "0.9.0", "sha256": sha}
        }
        return str(exe)

    def _make_index(self, root):
        cache = root / ".codebase-memory" / "cache"
        cache.mkdir(parents=True, exist_ok=True)
        (cache / f"{SLUG}.db").write_text("db", encoding="utf-8")

    def test_happy_path_all_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _make_workspace(tmp)
            binary = self._fake_binary(root)
            self._make_index(root)

            class Fake(_FakeAdapter):
                projects = [{"name": SLUG}]
                status = {
                    "root_path": str(root).replace("\\", "/"),
                    "git": {"head_sha": "h" * 40},
                }

            checks = _ladder(root, Fake, binary=binary)
            for name in ("CBM binary", "CBM version", "CBM provenance",
                         "CBM index", "CBM graph", "CBM query"):
                self.assertEqual(checks[name].status, "PASS", f"{name}: {checks[name].detail}")

    def test_binary_missing_is_warn_never_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _make_workspace(tmp)
            checks = _ladder(root, _FakeAdapter, binary=None)
            self.assertEqual(list(checks), ["CBM binary"])
            self.assertEqual(checks["CBM binary"].status, "WARN")

    def test_uncertified_version_warns(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _make_workspace(tmp)
            binary = self._fake_binary(root)

            class Fake(_FakeAdapter):
                version = "codebase-memory-mcp 0.9.9"

            checks = _ladder(root, Fake, binary=binary)
            self.assertEqual(checks["CBM version"].status, "WARN")
            self.assertIn("not the certified", checks["CBM version"].detail)

    def test_unsupported_version_warns(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _make_workspace(tmp)
            binary = self._fake_binary(root)

            class Fake(_FakeAdapter):
                version = "codebase-memory-mcp 0.8.1"

            checks = _ladder(root, Fake, binary=binary)
            self.assertEqual(checks["CBM version"].status, "WARN")

    def test_provenance_mismatch_warns_and_refuses_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _make_workspace(tmp)
            exe = root / "cbm.exe"
            exe.write_bytes(b"not-the-certified-binary")

            class Fake(_FakeAdapter):
                constructed = 0

                def __init__(self, **kwargs):
                    Fake.constructed += 1

            checks = _ladder(root, Fake, binary=str(exe))
            self.assertEqual(checks["CBM provenance"].status, "WARN")
            # The ladder stops BEFORE executing an unverified binary.
            self.assertNotIn("CBM version", checks)
            self.assertEqual(Fake.constructed, 0)

    def test_unreachable_backend_reports_unknown_never_missing(self):
        # A backend that cannot answer must NOT be diagnosed as "index
        # missing" — re-indexing a healthy graph is the wrong remedy.
        with tempfile.TemporaryDirectory() as tmp:
            root = _make_workspace(tmp)
            binary = self._fake_binary(root)
            self._make_index(root)

            class Fake(_FakeAdapter):
                def list_projects(self):
                    raise CBMAdapterError("cbm list_projects timed out")

            checks = _ladder(root, Fake, binary=binary)
            self.assertEqual(checks["CBM index"].status, "WARN")
            self.assertIn("unknown", checks["CBM index"].detail)
            self.assertNotIn("re-index", checks["CBM index"].action.lower())

    def test_missing_or_malformed_graph_metadata_warns_without_query(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _make_workspace(tmp)
            binary = self._fake_binary(root)
            self._make_index(root)

            for status in (
                {"git": {"head_sha": "h" * 40}},
                {"root_path": str(root).replace("\\", "/"), "git": "not-a-dict"},
                {"root_path": str(root).replace("\\", "/"), "git": {}},
            ):
                with self.subTest(status=status):
                    class Fake(_FakeAdapter):
                        projects = [{"name": SLUG}]
                        search_calls = 0

                        def index_status(self, project=None):
                            return status

                        def search_symbols(self, **kwargs):
                            type(self).search_calls += 1
                            return []

                    checks = _ladder(root, Fake, binary=binary)
                    self.assertEqual(checks["CBM graph"].status, "WARN")
                    self.assertNotIn("CBM query", checks)
                    self.assertEqual(Fake.search_calls, 0)

    def test_missing_cache_stops_before_adapter_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _make_workspace(tmp)
            binary = self._fake_binary(root)
            registry_path = root / ".relinkra" / "registry.json"
            registry = json.loads(registry_path.read_text(encoding="utf-8"))
            registry["workspaces"][WID]["cbm"]["cache_dir"] = ""
            registry_path.write_text(json.dumps(registry), encoding="utf-8")

            class Fake(_FakeAdapter):
                constructed = 0

                def __init__(self, **kwargs):
                    type(self).constructed += 1

            checks = _ladder(root, Fake, binary=binary)
            self.assertEqual(checks["CBM cache"].status, "WARN")
            self.assertNotIn("CBM index", checks)
            self.assertEqual(Fake.constructed, 0)

    def test_project_slug_cannot_escape_the_managed_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _make_workspace(tmp)
            binary = self._fake_binary(root)
            registry_path = root / ".relinkra" / "registry.json"
            registry = json.loads(registry_path.read_text(encoding="utf-8"))
            registry["workspaces"][WID]["cbm"]["project_name"] = "../outside"
            registry_path.write_text(json.dumps(registry), encoding="utf-8")

            class Fake(_FakeAdapter):
                constructed = 0

                def __init__(self, **kwargs):
                    type(self).constructed += 1

            checks = _ladder(root, Fake, binary=binary)
            self.assertEqual(checks["CBM index"].status, "WARN")
            self.assertNotIn("CBM query", checks)
            self.assertEqual(Fake.constructed, 1)

    def test_index_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _make_workspace(tmp)
            binary = self._fake_binary(root)
            checks = _ladder(root, _FakeAdapter, binary=binary)
            self.assertEqual(checks["CBM index"].status, "WARN")
            self.assertNotIn("CBM query", checks)

    def test_stale_index_warns(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _make_workspace(tmp)
            binary = self._fake_binary(root)
            self._make_index(root)

            class Fake(_FakeAdapter):
                projects = [{"name": SLUG}]
                status = {
                    "root_path": str(root).replace("\\", "/"),
                    "git": {"head_sha": "0" * 40},
                }

            checks = _ladder(root, Fake, binary=binary)
            self.assertEqual(checks["CBM graph"].status, "WARN")
            self.assertIn("stale", checks["CBM graph"].detail)

    def test_wrong_workspace_graph_warns(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _make_workspace(tmp)
            binary = self._fake_binary(root)
            self._make_index(root)

            class Fake(_FakeAdapter):
                projects = [{"name": SLUG}]
                status = {"root_path": "D:/elsewhere/repo", "git": {}}

            checks = _ladder(root, Fake, binary=binary)
            self.assertEqual(checks["CBM graph"].status, "WARN")
            self.assertIn("different workspace", checks["CBM graph"].detail)

    def test_configured_but_not_callable_is_not_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _make_workspace(tmp)
            binary = self._fake_binary(root)
            self._make_index(root)

            class Fake(_FakeAdapter):
                projects = [{"name": SLUG}]
                status = {
                    "root_path": str(root).replace("\\", "/"),
                    "git": {"head_sha": "h" * 40},
                }
                search_error = "cbm search_graph failed: boom"

            checks = _ladder(root, Fake, binary=binary)
            self.assertEqual(checks["CBM query"].status, "WARN")
            self.assertIn("not callable", checks["CBM query"].detail)

    def test_no_configuration_no_ladder(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _make_workspace(tmp, with_cbm_record=False)
            checks = _ladder(root, _FakeAdapter, binary=None)
            self.assertEqual(checks, {})


class TestDoctorSafety(unittest.TestCase):
    """Doctor never produces a false PASS and never writes outside the
    workspace state dir."""

    def test_doctor_writes_nothing_and_touches_no_agent_dirs(self):
        from relinkra.product_cli import cmd_doctor

        with tempfile.TemporaryDirectory() as tmp:
            root = _make_workspace(tmp, with_cbm_record=False)
            snapshot = lambda: {  # noqa: E731
                str(p.relative_to(root)): p.read_bytes()
                for p in root.rglob("*")
                if p.is_file() and not p.name.endswith(".lock")
            }
            before = snapshot()

            class _Args:
                path = str(root)
                json = True

            import io
            from contextlib import redirect_stdout

            with mock.patch(
                "relinkra.cbm_support.resolve_cbm_binary", return_value=None
            ), mock.patch.object(
                sys, "argv", ["relinkra", "doctor"]
            ), redirect_stdout(io.StringIO()):
                cmd_doctor(_Args())
            self.assertEqual(before, snapshot())
            self.assertFalse((root / ".windsurf").exists())

    def test_direct_cbm_exposure_is_detected_as_bypass(self):
        inputs = RouteInputs(
            hosts_inspected=1,
            relinkra_registered=False,
            direct_cbm_registered=True,
        )
        self.assertEqual(classify_context_route(inputs), ROUTE_BYPASSED)
        self.assertEqual(classify_cbm_ownership(inputs), CBM_DIRECTLY_EXPOSED)


# ---------------------------------------------------------------------------
# Deep health + service-level integration (fake adapter)
# ---------------------------------------------------------------------------


class _ServiceFakeAdapter:
    """search_symbols/get_snippet over a canned candidate."""

    fail = False

    def __init__(self, **kwargs):
        self.calls = 0

    def search_symbols(self, **kwargs):
        self.calls += 1
        if self.fail:
            raise CBMAdapterError("cbm executable not found: cbm.exe")
        return [
            {
                "name": "classify_context_route",
                "qualified_name": f"{SLUG}.relinkra.backend_policy.classify_context_route",
                "relative_qualified_name": "relinkra.backend_policy.classify_context_route",
                "label": "Function",
                "file_path": "relinkra/backend_policy.py",
                "start_line": 507,
                "end_line": 534,
                "cbm_project_name": SLUG,
            }
        ]

    def get_snippet(self, qualified_name, **kwargs):
        if self.fail:
            raise CBMAdapterError("cbm executable not found: cbm.exe")
        return None


class _IdentityServiceFakeAdapter(_ServiceFakeAdapter):
    """Fake production identity inputs for deep-health cache coverage."""

    def __init__(self, binary, cache_dir):
        super().__init__()
        self.cbm_bin = str(binary)
        self.cache_dir = str(cache_dir)
        self.cbm_project_name = SLUG
        self.expected_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
        self.verify_calls = 0

    def _verify_binary(self):
        self.verify_calls += 1
        actual = hashlib.sha256(Path(self.cbm_bin).read_bytes()).hexdigest()
        if actual != self.expected_sha256:
            raise CBMAdapterError("cbm executable hash changed")


def _services_with(adapter):
    # A registry path that never exists: these tests assert CBM behavior,
    # not registry resolution, and must not pick up the developer's real
    # workspace registry from the current directory.
    registry_path = str(
        Path(tempfile.gettempdir()) / "rlk-cbm-test-no-registry" / "registry.json"
    )
    return RelinkraServices(
        config=ServiceConfig(
            workspace_root=str(REPO_ROOT), registry_path=registry_path
        ),
        cbm_adapter=adapter,
    )


class TestConfiguredCBMTrust(unittest.TestCase):
    def _config(self, root, binary):
        return ServiceConfig(
            workspace_root=str(root),
            registry_path=str(root / "missing-registry.json"),
            cbm_bin=str(binary),
        )

    def test_untrusted_binary_is_not_attached_or_executed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "cbm.exe"
            binary.write_bytes(b"untrusted-cbm")
            certified_sha256 = hashlib.sha256(b"certified-cbm").hexdigest()

            with mock.patch.object(
                cbm_support, "platform_tag", return_value="windows-amd64"
            ), mock.patch.object(
                cbm_support,
                "CERTIFIED_CBM_BINARIES",
                {"windows-amd64": {"sha256": certified_sha256}},
            ), mock.patch("relinkra.app_service.CBMCLIAdapter") as adapter_type:
                services = RelinkraServices(config=self._config(root, binary))

            self.assertIsNone(services.cbm_adapter)
            self.assertIn("hash does not match", services._cbm_config_error)
            adapter_type.assert_not_called()

    def test_prerelease_version_is_rejected_after_hash_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "cbm.exe"
            contents = b"certified-cbm"
            binary.write_bytes(contents)
            certified_sha256 = hashlib.sha256(contents).hexdigest()

            for raw_version in (
                "codebase-memory-mcp 0.9.0-rc.1",
                "not-a-cbm-version",
            ):
                with self.subTest(raw_version=raw_version):
                    with mock.patch.object(
                        cbm_support, "platform_tag", return_value="windows-amd64"
                    ), mock.patch.object(
                        cbm_support,
                        "CERTIFIED_CBM_BINARIES",
                        {"windows-amd64": {"sha256": certified_sha256}},
                    ), mock.patch(
                        "relinkra.app_service.CBMCLIAdapter"
                    ) as adapter_type:
                        adapter = adapter_type.return_value
                        adapter.probe_version.return_value = raw_version
                        config = self._config(root, binary)
                        config.cbm_cache_dir = ".codebase-memory/cache"
                        config.cbm_project_name = SLUG
                        services = RelinkraServices(
                            config=config
                        )

                    self.assertIsNone(services.cbm_adapter)
                    expected_detail = (
                        "inside the supported range but is not the certified"
                        if "-rc." in raw_version
                        else "version could not be determined"
                    )
                    self.assertIn(expected_detail, services._cbm_config_error)
                    adapter_type.assert_called_once_with(
                        cbm_bin=str(binary),
                        # absolutize_against_root canonicalizes through
                        # realpath as a containment property; under an
                        # aliased TEMP (8.3 short path, /var symlink) the
                        # raw join and the canonical path differ.
                        cache_dir=os.path.realpath(
                            str(root / ".codebase-memory" / "cache")
                        ),
                        cbm_project_name=SLUG,
                        workspace_root=str(root),
                        timeout=10.0,
                        expected_sha256=certified_sha256,
                    )
                    adapter.probe_version.assert_called_once_with()

    def test_production_service_rejects_missing_cache_before_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "cbm.exe"
            contents = b"certified-cbm"
            binary.write_bytes(contents)
            certified_sha256 = hashlib.sha256(contents).hexdigest()

            with mock.patch.object(
                cbm_support, "platform_tag", return_value="windows-amd64"
            ), mock.patch.object(
                cbm_support,
                "CERTIFIED_CBM_BINARIES",
                {"windows-amd64": {"sha256": certified_sha256}},
            ), mock.patch("relinkra.app_service.CBMCLIAdapter") as adapter_type:
                adapter = adapter_type.return_value
                adapter.probe_version.return_value = "codebase-memory-mcp 0.9.0"
                services = RelinkraServices(config=self._config(root, binary))

            self.assertIsNone(services.cbm_adapter)
            self.assertIn("cache_dir", services._cbm_config_error)
            adapter_type.assert_not_called()

    def test_context_cli_configured_adapter_uses_shared_trust_gate(self):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(
            cbm_support,
            "certify_configured_adapter",
            side_effect=CBMAdapterError("graph trust failed"),
        ) as certify, mock.patch("sys.stdout", out), mock.patch("sys.stderr", err):
            code = context_cli.main(
                [
                    "--project-id", PID,
                    "--cbm-bin", "cbm.exe",
                    "--workspace-root", str(REPO_ROOT),
                ],
                store=object(),
            )

        self.assertEqual(code, 1)
        self.assertIn("graph trust failed", err.getvalue())
        certify.assert_called_once()


class TestDeepHealth(unittest.TestCase):
    def _identity_adapter(self, root):
        binary = root / "cbm.exe"
        cache_dir = root / "cache"
        binary.write_bytes(b"certified-cbm")
        cache_dir.mkdir()
        (cache_dir / f"{SLUG}.db").write_bytes(b"initial-index")
        return _IdentityServiceFakeAdapter(binary, cache_dir), binary, cache_dir

    def test_shallow_health_is_config_only(self):
        services = _services_with(_ServiceFakeAdapter())
        cbm = services.health()["components"]["cbm"]
        # Configuration alone is not a callable-backend proof and must not
        # advertise code resolution as available.
        self.assertFalse(cbm["available"])
        self.assertFalse(cbm["checked"])
        self.assertIn("configured", cbm["detail"])

    def test_deep_health_runs_real_query(self):
        adapter = _ServiceFakeAdapter()
        services = _services_with(adapter)
        cbm = services.health(deep=True)["components"]["cbm"]
        self.assertTrue(cbm["available"])
        self.assertTrue(cbm["checked"])
        self.assertGreaterEqual(adapter.calls, 1)

    def test_deep_health_failure_is_honest(self):
        class Broken(_ServiceFakeAdapter):
            fail = True

        services = _services_with(Broken())
        health = services.health(deep=True)
        self.assertFalse(health["components"]["cbm"]["available"])
        self.assertTrue(health["components"]["cbm"]["checked"])
        self.assertIn("cbm", health["degraded"])
        self.assertFalse(health["capabilities"]["code_resolution"])

    def test_deep_probe_is_ttl_capped_per_instance(self):
        adapter = _ServiceFakeAdapter()
        services = _services_with(adapter)
        services.health(deep=True)
        services.health(deep=True)
        # One of the calls is the cached verdict: agent-triggered deep
        # probes cannot spawn unbounded subprocesses.
        self.assertEqual(adapter.calls, 1)

    def test_deep_probe_reuses_cached_pass_when_identity_is_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            adapter, _, _ = self._identity_adapter(Path(tmp))
            services = _services_with(adapter)

            self.assertTrue(services.health(deep=True)["components"]["cbm"]["available"])
            self.assertTrue(services.health(deep=True)["components"]["cbm"]["available"])

            self.assertEqual(adapter.calls, 1)
            self.assertGreaterEqual(adapter.verify_calls, 2)

    def test_binary_change_bypasses_cached_pass_and_reports_outage(self):
        with tempfile.TemporaryDirectory() as tmp:
            adapter, binary, _ = self._identity_adapter(Path(tmp))
            services = _services_with(adapter)
            self.assertTrue(services.health(deep=True)["components"]["cbm"]["available"])

            binary.write_bytes(b"replacement-cbm")
            adapter.fail = True
            health = services.health(deep=True)

            self.assertFalse(health["components"]["cbm"]["available"])
            self.assertEqual(adapter.calls, 2)

    def test_database_change_bypasses_cached_pass_and_reports_outage(self):
        with tempfile.TemporaryDirectory() as tmp:
            adapter, _, cache_dir = self._identity_adapter(Path(tmp))
            services = _services_with(adapter)
            self.assertTrue(services.health(deep=True)["components"]["cbm"]["available"])

            (cache_dir / f"{SLUG}.db").write_bytes(b"updated-index-metadata")
            adapter.fail = True
            health = services.health(deep=True)

            self.assertFalse(health["components"]["cbm"]["available"])
            self.assertEqual(adapter.calls, 2)

    def test_health_never_claims_callable_without_query(self):
        # configured-only probe must stay out of the "verified" set
        services = _services_with(_ServiceFakeAdapter())
        health = services.health()
        self.assertIn("code_resolution", health["capabilities_unchecked"])


class TestServiceIntegration(unittest.TestCase):
    def test_code_resolve_real_behavior(self):
        services = _services_with(_ServiceFakeAdapter())
        result = services.code_resolve(
            project_id=PID, symbol="classify_context_route"
        )
        self.assertEqual(result["resolution_state"], "resolved")
        ref = result["code_references"][0]["data"]["reference"]
        self.assertEqual(ref["file_path"], "relinkra/backend_policy.py")
        self.assertEqual(
            ref["qualified_name"], "relinkra.backend_policy.classify_context_route"
        )
        self.assertNotIn(SLUG, json.dumps(ref["qualified_name"]))

    def test_context_get_receives_cbm_evidence(self):
        services = _services_with(_ServiceFakeAdapter())
        result = services.context_get(
            project_id=PID, symbol="classify_context_route", include_git=False
        )
        facts = result["packet"]["code_facts"]
        self.assertTrue(facts, "context_get carried no CBM-derived code facts")
        payload = json.dumps(result)
        self.assertNotIn("C:/Desarrollos", payload)
        self.assertNotIn("C:\\Desarrollos", payload)

    def test_cbm_failure_degrades_and_recovers(self):
        adapter = _ServiceFakeAdapter()
        services = _services_with(adapter)
        adapter.fail = True
        degraded = services.code_resolve(project_id=PID, symbol="classify_context_route")
        codes = [w["code"] for w in degraded["warnings"]]
        self.assertIn("cbm_unavailable", codes)
        adapter.fail = False
        recovered = services.code_resolve(
            project_id=PID, symbol="classify_context_route"
        )
        self.assertEqual(recovered["resolution_state"], "resolved")


class TestMCPHealthDeep(unittest.TestCase):
    def test_relinkra_health_accepts_deep(self):
        from relinkra.mcp_server import MCPServer

        server = MCPServer(_services_with(_ServiceFakeAdapter()))
        response = server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "relinkra_health", "arguments": {"deep": True}},
            }
        )
        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertTrue(payload["components"]["cbm"]["checked"])
        self.assertTrue(payload["components"]["cbm"]["available"])


# ---------------------------------------------------------------------------
# Real certified binary (gated)
# ---------------------------------------------------------------------------


def _real_cbm_bin():
    candidate = REPO_ROOT / ".codebase-memory" / "bin" / "codebase-memory-mcp.exe"
    if candidate.is_file():
        return str(candidate)
    return os.environ.get("RELINKRA_CBM_BIN")


@unittest.skipUnless(_real_cbm_bin(), "no real CBM binary resolvable")
class TestRealCertifiedBinary(unittest.TestCase):
    """Run only where the certified binary is present (cert machines)."""

    def setUp(self):
        self.adapter = CBMCLIAdapter(
            cbm_bin=_real_cbm_bin(),
            cache_dir=str(REPO_ROOT / ".codebase-memory" / "cache"),
            cbm_project_name=SLUG,
            workspace_root=str(REPO_ROOT),
        )
        try:
            names = [p.get("name") for p in self.adapter.list_projects()]
        except CBMAdapterError:
            names = []
        if SLUG not in names:
            self.skipTest(
                f"recorded project {SLUG} not indexed on this machine"
            )

    def test_real_version_is_certified(self):
        version = self.adapter.probe_version()
        self.assertEqual(
            cbm_support.classify_version(version), cbm_support.VERSION_CERTIFIED
        )

    def test_real_query_capability_probe(self):
        candidates = self.adapter.search_symbols(query="CBMCLIAdapter", limit=3)
        self.assertTrue(candidates, "real CBM query returned no candidates")
        for candidate in candidates:
            self.assertFalse(os.path.isabs(candidate["file_path"]))

    def test_real_index_lists_recorded_project(self):
        names = [p.get("name") for p in self.adapter.list_projects()]
        self.assertIn(SLUG, names)

    def test_real_index_status_matches_workspace(self):
        status = self.adapter.index_status()
        self.assertEqual(status.get("status"), "ready")
        root = str(status.get("root_path") or "").replace("\\", "/").rstrip("/")
        self.assertEqual(root.lower(), str(REPO_ROOT).replace("\\", "/").lower())


if __name__ == "__main__":
    unittest.main()
