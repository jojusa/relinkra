"""R6J tests — disclose and block legacy direct-CBM bypasses.

THE DEFECT. ``connect all`` reported Devin Desktop as
``already_valid``/``no-op`` with exit 0 while a legacy Windsurf config
held a direct CBM registration that the code itself says the current
product still imports into its live MCP registry. The onboarding result
was misleading and the agent could bypass Relinkra's context route.

THE CONTRACT. A structurally identified direct CBM registration is a
live bypass unless it is Relinkra's own managed route. It is disclosed
by ``inspect`` (structured fields + a human headline), classified as a
real problem by ``check`` (finding, invalid, actionable next step, never
"Config valid"), included in ``connect all``'s pre-action classification
(``legacy_bypass``/refused, never a no-op), and it REFUSES the apply:
Relinkra cannot reconcile a foreign import file (legacy files are never
write targets), so it fails closed instead of writing a registration
that leaves the bypass live. Removal is an explicit user action; after
it, apply/check are green and a second run is an idempotent no-op.

Everything here runs against sandboxed fixture homes. No real host
configuration is read or written.
"""

from __future__ import annotations

import json
import unittest
from unittest import mock

from relinkra import connector_apply
from relinkra.connector import iter_strings
from relinkra.connector_apply import direct_cbm_state
from relinkra.connectors import DEVIN_DESKTOP
from relinkra.handoff import contains_absolute_path
from relinkra.product_cli import (
    EXIT_ACTION_REQUIRED,
    EXIT_OK,
)
from test_connect_apply_devin_desktop import (  # noqa: E402
    ConnectApplyDevinDesktopCase,
    _CBM_ENTRY,
)
from test_r6e import ConnectAllCase  # noqa: E402

_UNRELATED_ENTRY = {"command": "npx", "args": ["-y", "@upstash/context7-mcp"]}
_LEGACY_UNRELATED = {"command": "old-tool", "args": ["serve"]}


class R6jDevinCase(ConnectApplyDevinDesktopCase):
    """Single-host Devin fixture with helpers for the R6J matrix."""

    def legacy_direct_cbm(self, legacy_name="helper"):
        return self.legacy_config(
            {"mcpServers": {legacy_name: dict(_CBM_ENTRY)}}
        )

    def state(self):
        return direct_cbm_state(DEVIN_DESKTOP, self.env())

    def assert_portable(self, payload):
        for value in iter_strings(payload):
            self.assertFalse(contains_absolute_path(value), value)


class R6jInspectDisclosureTests(R6jDevinCase):
    """Section 6 — inspect must expose direct-CBM state explicitly."""

    def test_inspect_discloses_the_legacy_bypass_structured_and_human(self):
        self.current_config(
            {"mcpServers": {"relinkra": self.managed_entry()}}
        )
        self.legacy_direct_cbm()
        code, payload, _ = self.run_json("inspect", "devin-desktop")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertIn("direct_cbm", payload)
        direct = payload["direct_cbm"]
        self.assertTrue(direct["detected"])
        self.assertEqual(direct["relation"], "legacy_import_source")
        self.assertEqual(len(direct["entries"]), 1)
        self.assertEqual(
            direct["entries"][0]["location"],
            "~/.codeium/windsurf/mcp_config.json",
        )
        self.assertEqual(direct["entries"][0]["relation"], "legacy_import_source")
        self.assertTrue(direct["entries"][0]["markers"])
        self.assertFalse(direct["unreadable"])
        self.assert_portable(payload)

        code, out, _ = self.run_cli("inspect", "devin-desktop")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("Legacy direct CBM bypass detected", out)
        self.assertIn("~/.codeium/windsurf/mcp_config.json", out)

    def test_inspect_of_a_clean_host_says_so(self):
        self.current_config({"mcpServers": {"relinkra": self.managed_entry()}})
        code, payload, _ = self.run_json("inspect", "devin-desktop")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertFalse(payload["direct_cbm"]["detected"])
        self.assertEqual(payload["direct_cbm"]["relation"], "none")
        code, out, _ = self.run_cli("inspect", "devin-desktop")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("No direct CBM registration found", out)

    def test_inspect_discloses_an_unreadable_legacy_scope(self):
        self.legacy_config("{ broken")
        code, payload, _ = self.run_json("inspect", "devin-desktop")
        self.assertEqual(code, EXIT_OK, payload)
        direct = payload["direct_cbm"]
        self.assertEqual(direct["relation"], "unreadable")
        self.assertFalse(direct["detected"])
        self.assertEqual(len(direct["unreadable"]), 1)
        self.assertEqual(
            direct["unreadable"][0]["location"],
            "~/.codeium/windsurf/mcp_config.json",
        )
        code, out, _ = self.run_cli("inspect", "devin-desktop")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("Direct CBM check inconclusive", out)

    def test_detection_is_structural_never_a_name_substring(self):
        # A name containing "cbm" that launches something else is NOT a
        # bypass; an unrelated name that launches CBM IS one.
        self.current_config(
            {
                "mcpServers": {
                    "cbm-notes": {"command": "node", "args": ["notes.js"]},
                    "codebase-memory-notes": {
                        "command": "node",
                        "args": ["notes.js"],
                    },
                }
            }
        )
        self.assertFalse(self.state().detected)
        self.legacy_config(
            {
                "mcpServers": {
                    "friendly-name": {
                        "command": "python",
                        "args": ["-m", "codebase_memory_mcp"],
                    }
                }
            }
        )
        state = self.state()
        self.assertTrue(state.detected)
        self.assertEqual(
            state.entries[0].markers, ("module:codebase_memory_mcp",)
        )

    def test_a_relinkra_registration_that_carries_a_cbm_token_is_a_bypass(self):
        # Mixed launch: tolerant Relinkra ownership must NOT launder a
        # direct CBM route into a managed registration.
        self.current_config(
            {
                "mcpServers": {
                    "relinkra": {
                        "command": "python",
                        "args": ["-m", "relinkra.mcp_cli", "codebase-memory-mcp"],
                    }
                }
            }
        )
        self.assertTrue(self.state().detected)

    def test_inspect_carries_no_absolute_path_in_the_new_section(self):
        self.current_config({"mcpServers": {"relinkra": self.managed_entry()}})
        self.legacy_direct_cbm()
        _, payload, _ = self.run_json("inspect", "devin-desktop", "--reveal-paths")
        # Even with revealed locations elsewhere in the payload, the
        # direct-CBM section itself stays portable.
        direct = payload["direct_cbm"]
        self.assert_portable(direct)


class R6jCheckClassificationTests(R6jDevinCase):
    """Section 7 — check must classify the bypass as a real problem."""

    def test_valid_registration_beside_a_legacy_bypass_is_not_valid(self):
        self.current_config(
            {"mcpServers": {"relinkra": self.managed_entry()}}
        )
        self.legacy_direct_cbm()
        code, payload, _ = self.run_json("check", "devin-desktop")
        self.assertEqual(code, EXIT_ACTION_REQUIRED, payload)
        self.assertFalse(payload["valid"])
        self.assertTrue(
            any("direct codebase-memory" in f for f in payload["findings"]),
            payload["findings"],
        )
        self.assertEqual(
            payload["direct_cbm"]["relation"], "legacy_import_source"
        )
        self.assert_portable(payload)

    def test_compact_check_leads_with_the_bypass_and_its_action(self):
        self.current_config(
            {"mcpServers": {"relinkra": self.managed_entry()}}
        )
        self.legacy_direct_cbm()
        code, out, _ = self.run_cli("check", "devin-desktop")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("Legacy direct CBM bypass detected", out)
        self.assertNotIn("✓ Config valid", out)
        # The next action prioritizes the removal over cosmetic restarts.
        self.assertIn("Remove the direct codebase-memory registration", out)
        self.assertNotIn("Next: start/restart Devin Desktop", out)

    def test_verbose_check_explains_the_bypass(self):
        self.current_config(
            {"mcpServers": {"relinkra": self.managed_entry()}}
        )
        self.legacy_direct_cbm()
        code, out, _ = self.run_cli("check", "devin-desktop", "--verbose")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("direct codebase-memory (CBM) exposure", out)
        self.assertIn("legacy", out)

    def test_unreadable_legacy_scope_is_not_healthy(self):
        self.current_config(
            {"mcpServers": {"relinkra": self.managed_entry()}}
        )
        self.legacy_config("{ broken")
        code, payload, _ = self.run_json("check", "devin-desktop")
        self.assertEqual(code, EXIT_ACTION_REQUIRED, payload)
        self.assertFalse(payload["valid"])
        self.assertEqual(payload["direct_cbm"]["relation"], "unreadable")
        self.assertTrue(
            any(
                "could not be read" in finding.lower()
                for finding in payload["findings"]
            ),
            payload["findings"],
        )

    def test_check_stays_valid_when_no_branch_is_exposed(self):
        self.current_config(
            {"mcpServers": {"relinkra": self.managed_entry()}}
        )
        code, payload, _ = self.run_json("check", "devin-desktop")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(payload["valid"])
        self.assertFalse(payload["direct_cbm"]["detected"])
        self.assertEqual(payload["direct_cbm"]["relation"], "none")

    def test_unrelated_mcp_entries_do_not_trip_the_check(self):
        self.current_config(
            {
                "mcpServers": {
                    "relinkra": self.managed_entry(),
                    "context7": dict(_UNRELATED_ENTRY),
                }
            }
        )
        code, payload, _ = self.run_json("check", "devin-desktop")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(payload["valid"])
        self.assertFalse(payload["direct_cbm"]["detected"])

    def test_recorded_host_evidence_does_not_heal_a_bypass(self):
        # "Healthy only after bypass gone": recorded real-host evidence
        # describes the host side; the live config-side bypass keeps
        # check invalid regardless of what the host has been observed
        # doing.
        self.current_config(
            {"mcpServers": {"relinkra": self.managed_entry()}}
        )
        self.legacy_direct_cbm()
        self.record_devin_proof()
        code, payload, _ = self.run_json("check", "devin-desktop")
        self.assertEqual(code, EXIT_ACTION_REQUIRED, payload)
        self.assertFalse(payload["valid"])
        self.assertEqual(
            payload["direct_cbm"]["relation"], "legacy_import_source"
        )


class R6jApplyRefusalTests(R6jDevinCase):
    """Sections 9/10/11 — fail closed, no misleading success, no mutation."""

    def test_apply_refuses_while_the_legacy_bypass_lives(self):
        self.current_config({"mcpServers": {}})
        legacy = self.legacy_direct_cbm()
        legacy_before = legacy.read_bytes()
        before = self.snapshot(self.home)
        code, payload, _ = self.run_json("apply", "devin-desktop")
        self.assertEqual(code, EXIT_ACTION_REQUIRED, payload)
        self.assertIn("direct codebase-memory", payload["refusal_reason"])
        self.assertEqual(
            payload["direct_cbm"]["relation"], "legacy_import_source"
        )
        self.assertFalse(payload["write_attempted"])
        self.assertFalse(payload["backup_created"])
        self.assertFalse(
            (self.repo / ".devin" / "mcp_config.local.json").exists()
        )
        self.assertEqual(self.snapshot(self.home), before)
        self.assertEqual(legacy.read_bytes(), legacy_before)
        self.assert_portable(payload)

    def test_front_door_refuses_before_asking_for_consent(self):
        self.current_config({"mcpServers": {}})
        self.legacy_direct_cbm()
        before = self.snapshot(self.home)
        with mock.patch("builtins.input") as confirm:
            code, payload, _ = self.run_json("devin-desktop")
        self.assertEqual(code, EXIT_ACTION_REQUIRED, payload)
        self.assertTrue(payload["safety_refusal"])
        self.assertIn("direct codebase-memory", payload["refusal_reason"])
        self.assertEqual(
            payload["direct_cbm"]["relation"], "legacy_import_source"
        )
        # A refusal cannot be consented into a write, so no prompt fires
        # and nothing is touched: there is no path from here to a live
        # bypass plus a written registration.
        confirm.assert_not_called()
        self.assertEqual(self.snapshot(self.home), before)

    def test_noninteractive_run_mutates_nothing(self):
        self.current_config({"mcpServers": {}})
        self.legacy_direct_cbm()
        before = self.snapshot(self.home)

        def closed_stdin(*_args, **_kwargs):
            raise EOFError("no interactive user")

        with mock.patch("builtins.input", side_effect=closed_stdin):
            code, payload, _ = self.run_json("devin-desktop")
        self.assertEqual(code, EXIT_ACTION_REQUIRED, payload)
        self.assertFalse(payload.get("write_attempted", False))
        self.assertEqual(self.snapshot(self.home), before)

    def test_valid_registration_beside_bypass_is_never_a_no_op(self):
        self.current_config(
            {"mcpServers": {"relinkra": self.managed_entry()}}
        )
        self.legacy_direct_cbm()
        with mock.patch("builtins.input") as confirm:
            code, payload, _ = self.run_json("devin-desktop")
        self.assertEqual(code, EXIT_ACTION_REQUIRED, payload)
        self.assertTrue(payload["safety_refusal"])
        self.assertNotIn("no_op", payload)
        confirm.assert_not_called()

    def test_terminal_validation_refuses_when_a_bypass_appears_mid_write(self):
        # H: the write path must not report success when direct CBM is
        # seen at the terminal gate. The bypass appears after the
        # preflight scan, simulating a concurrent edit.
        real = connector_apply.direct_cbm_state
        calls = {"n": 0}

        def bypass_appears_after_the_first_scan(spec, env, *, inspection=None):
            calls["n"] += 1
            result = real(spec, env, inspection=inspection)
            if calls["n"] == 1:
                self.legacy_direct_cbm()
            return result

        with mock.patch.object(
            connector_apply,
            "direct_cbm_state",
            side_effect=bypass_appears_after_the_first_scan,
        ):
            code, payload, _ = self.run_json("apply", "devin-desktop")
        self.assertEqual(code, EXIT_ACTION_REQUIRED, payload)
        self.assertGreaterEqual(calls["n"], 2)
        self.assertFalse(payload["write_succeeded"])
        self.assertFalse(payload["write_attempted"])
        self.assertIn("legacy scope", payload["refusal_reason"])
        self.assertFalse(
            (self.repo / ".devin" / "mcp_config.local.json").exists()
        )


class R6jReconciliationTests(R6jDevinCase):
    """Section 15 — user reconciliation, green after, idempotent."""

    def test_user_removes_the_bypass_then_apply_and_check_are_green(self):
        legacy = self.legacy_config(
            {
                "mcpServers": {
                    "helper": dict(_CBM_ENTRY),
                    "legacy-unrelated": dict(_LEGACY_UNRELATED),
                }
            }
        )
        # Before: refused, nothing written.
        code, refused, _ = self.run_json("apply", "devin-desktop")
        self.assertEqual(code, EXIT_ACTION_REQUIRED, refused)
        self.assertFalse(refused["write_attempted"])
        # The explicit user action: remove ONLY the direct CBM entry.
        legacy.write_text(
            json.dumps({"mcpServers": {"legacy-unrelated": dict(_LEGACY_UNRELATED)}}),
            encoding="utf-8",
        )
        legacy_cleaned = legacy.read_bytes()
        # With consent, the normal front door applies the registration.
        with mock.patch("builtins.input", return_value="y") as confirm:
            code, applied, _ = self.run_json("devin-desktop")
        self.assertEqual(code, EXIT_OK, applied)
        self.assertTrue(applied["write_succeeded"])
        self.assertEqual(confirm.call_count, 1)
        self.assertEqual(legacy.read_bytes(), legacy_cleaned)
        # Check: healthy only after the bypass is gone.
        code, check, _ = self.run_json("check", "devin-desktop")
        self.assertEqual(code, EXIT_OK, check)
        self.assertTrue(check["valid"], check["findings"])
        self.assertFalse(check["direct_cbm"]["detected"])
        self.assertEqual(check["direct_cbm"]["relation"], "none")
        # Second run: idempotent no-op, no prompt.
        with mock.patch("builtins.input") as confirm:
            code, second, _ = self.run_json("devin-desktop")
        self.assertEqual(code, EXIT_OK, second)
        self.assertTrue(second["no_op"])
        confirm.assert_not_called()

    def test_declined_consent_writes_nothing_when_the_host_is_clean(self):
        self.current_config({"mcpServers": {}})
        before = self.snapshot(self.home)
        with mock.patch("builtins.input", return_value="n") as confirm:
            code, payload, _ = self.run_json("devin-desktop")
        self.assertEqual(code, EXIT_ACTION_REQUIRED, payload)
        self.assertEqual(payload["confirmation"], "declined")
        self.assertEqual(confirm.call_count, 1)
        self.assertEqual(self.snapshot(self.home), before)

    def test_rollback_preserves_unrelated_entries(self):
        path = self.current_config(
            {"mcpServers": {"context7": dict(_UNRELATED_ENTRY)}}
        )
        with mock.patch("builtins.input", return_value="y"):
            code, applied, _ = self.run_json("devin-desktop")
        self.assertEqual(code, EXIT_OK, applied)
        self.assertTrue(applied["write_succeeded"])
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertIn("relinkra", document["mcpServers"])
        code, rolled, _ = self.run_json("rollback", "devin-desktop")
        self.assertEqual(code, EXIT_OK, rolled)
        self.assertTrue(rolled["rollback_succeeded"])
        restored = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(restored["mcpServers"], {"context7": dict(_UNRELATED_ENTRY)})


class R6jConnectAllTests(ConnectAllCase):
    """Sections 8/21 — aggregate honesty with a legacy bypass in the fleet."""

    def legacy_direct_cbm(self):
        return self.write_home(
            ".codeium",
            "windsurf",
            "mcp_config.json",
            content={"mcpServers": {"helper": dict(_CBM_ENTRY)}},
        )

    def test_healthy_fleet_plus_devin_bypass_is_not_aggregate_success(self):
        self.register_all_hosts()
        self.legacy_direct_cbm()
        before = self.snapshot()
        with mock.patch("builtins.input") as confirm:
            code, payload, _ = self.run_json("all")
        self.assertEqual(code, EXIT_ACTION_REQUIRED, payload)
        devin = self.host_row(payload, "devin-desktop")
        self.assertEqual(devin["classification"], "legacy_bypass")
        self.assertEqual(devin["action"], "refused")
        self.assertEqual(devin["config"], "valid")
        self.assertEqual(devin["direct_cbm"]["relation"], "legacy_import_source")
        self.assertTrue(devin["direct_cbm"]["detected"])
        self.assertIn("direct codebase-memory", devin["detail"])
        for other in ("codex", "opencode", "claude", "zcode"):
            row = self.host_row(payload, other)
            self.assertEqual(row["action"], "no-op", other)
            self.assertEqual(row["classification"], "already_valid", other)
            self.assertFalse(row["direct_cbm"]["detected"], other)
        confirm.assert_not_called()
        self.assertEqual(payload["written"], [])
        self.assertEqual(self.snapshot(), before)

    def test_after_reconciliation_the_fleet_is_green_and_idempotent(self):
        self.register_all_hosts()
        legacy = self.legacy_direct_cbm()
        with mock.patch("builtins.input") as confirm:
            code, payload, _ = self.run_json("all")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertEqual(self.host_row(payload, "devin-desktop")["action"], "refused")
        confirm.assert_not_called()
        # Explicit user action: the direct entry is removed by hand.
        legacy.write_text(
            json.dumps({"mcpServers": {}}), encoding="utf-8"
        )
        with mock.patch("builtins.input") as confirm:
            code, payload, _ = self.run_json("all")
        self.assertEqual(code, EXIT_OK, payload)
        for row in payload["hosts"]:
            self.assertEqual(row["action"], "no-op", row)
            self.assertEqual(row["classification"], "already_valid", row)
            self.assertFalse(row["direct_cbm"]["detected"], row)
        confirm.assert_not_called()

    def test_devin_with_only_a_legacy_bypass_is_not_connected(self):
        self.register_all_hosts()
        (self.repo / ".devin" / "mcp_config.local.json").unlink()
        self.legacy_direct_cbm()
        with mock.patch("builtins.input") as confirm:
            code, payload, _ = self.run_json("all")
        self.assertEqual(code, EXIT_ACTION_REQUIRED, payload)
        devin = self.host_row(payload, "devin-desktop")
        self.assertEqual(devin["action"], "refused")
        self.assertEqual(devin["classification"], "legacy_bypass")
        self.assertEqual(devin["config"], "absent")
        confirm.assert_not_called()

    def test_refusal_preserves_unrelated_mcp_entries_everywhere(self):
        self.register_all_hosts()
        legacy = self.write_home(
            ".codeium",
            "windsurf",
            "mcp_config.json",
            content={
                "mcpServers": {
                    "helper": dict(_CBM_ENTRY),
                    "legacy-unrelated": dict(_LEGACY_UNRELATED),
                }
            },
        )
        devin_path = self.repo / ".devin" / "mcp_config.local.json"
        document = json.loads(devin_path.read_text(encoding="utf-8"))
        document["mcpServers"]["context7"] = dict(_UNRELATED_ENTRY)
        devin_path.write_text(json.dumps(document, indent=2), encoding="utf-8")
        before = self.snapshot()
        with mock.patch("builtins.input") as confirm:
            code, payload, _ = self.run_json("all")
        self.assertEqual(code, EXIT_ACTION_REQUIRED, payload)
        confirm.assert_not_called()
        self.assertEqual(self.snapshot(), before)
        legacy_doc = json.loads(legacy.read_text(encoding="utf-8"))
        self.assertIn("legacy-unrelated", legacy_doc["mcpServers"])
        devin_doc = json.loads(devin_path.read_text(encoding="utf-8"))
        self.assertIn("context7", devin_doc["mcpServers"])

    def test_every_payload_keeps_its_existing_json_contract(self):
        self.register_all_hosts()
        self.legacy_direct_cbm()
        _, inspect_payload, _ = self.run_json("inspect", "devin-desktop")
        for key in (
            "connector_id",
            "registration_state",
            "discovery_status",
            "workspace_matches",
            "warnings",
        ):
            self.assertIn(key, inspect_payload)
        _, check_payload, _ = self.run_json("check", "devin-desktop")
        for key in (
            "connector_id",
            "registration_state",
            "valid",
            "findings",
            "warnings",
            "matches_workspace",
            "target_ref",
        ):
            self.assertIn(key, check_payload)
        _, all_payload, _ = self.run_json("all")
        for key in ("targets", "hosts", "written"):
            self.assertIn(key, all_payload)
        for row in all_payload["hosts"]:
            for key in (
                "connector_id",
                "display_name",
                "classification",
                "config",
                "workspace",
                "runtime",
                "action",
                "detail",
                "warnings",
            ):
                self.assertIn(key, row)


class R6jStructuralUnitTests(R6jDevinCase):
    """Scanner-level proofs that detection is structural, not textual."""

    def test_the_assessment_never_flags_relinkras_own_registration(self):
        self.current_config(
            {"mcpServers": {"relinkra": self.managed_entry()}}
        )
        state = self.state()
        self.assertFalse(state.detected)
        self.assertFalse(state.needs_attention)
        self.assertEqual(state.relation, "none")

    def test_each_detected_entry_names_a_declared_marker(self):
        self.current_config({"mcpServers": {}})
        self.legacy_config(
            {
                "mcpServers": {
                    "alias-one": {
                        "command": "python",
                        "args": ["-m", "codebase_memory_mcp"],
                    },
                    "alias-two": {"command": "cbm", "args": ["serve"]},
                }
            }
        )
        state = self.state()
        self.assertTrue(state.detected)
        self.assertEqual(len(state.entries), 2)
        self.assertEqual(
            sorted(entry.ref for entry in state.entries),
            ["windsurf_user_mcp#1", "windsurf_user_mcp#2"],
        )
        for entry in state.entries:
            self.assertTrue(entry.markers)
        self.assertEqual(state.relation, "legacy_import_source")

    def test_both_legacy_scopes_are_disclosed(self):
        self.current_config({"mcpServers": {}})
        self.legacy_config({"mcpServers": {"one": dict(_CBM_ENTRY)}})
        self.legacy_next_config({"mcpServers": {"two": dict(_CBM_ENTRY)}})
        state = self.state()
        self.assertTrue(state.detected)
        self.assertEqual(len(state.entries), 2)
        self.assertEqual(
            {entry.location for entry in state.entries},
            {
                "~/.codeium/windsurf/mcp_config.json",
                "~/.codeium/windsurf-next/mcp_config.json",
            },
        )


class R6jHumanOutputTests(R6jDevinCase):
    """The human surfaces stay understandable and path-free."""

    def test_all_human_outputs_stay_portable(self):
        self.current_config(
            {"mcpServers": {"relinkra": self.managed_entry()}}
        )
        self.legacy_direct_cbm()
        for argv in (
            ("inspect", "devin-desktop"),
            ("check", "devin-desktop"),
            ("check", "devin-desktop", "--verbose"),
            ("devin-desktop",),
        ):
            with self.subTest(argv=argv):
                code, out, _ = self.run_cli(*argv)
                self.assertIn(code, (EXIT_OK, EXIT_ACTION_REQUIRED))
                self.assertFalse(contains_absolute_path(out), out)


if __name__ == "__main__":
    unittest.main()
