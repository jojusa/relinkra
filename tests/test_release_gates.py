"""Tests for tools/release_gates.py — the release gate model (R5B)."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools import release_gates
from tools.release_gates import (
    CBM_CERTIFICATION,
    CI,
    DOCUMENTATION,
    HOST_CERTIFICATION,
    INSTALLED_CLI_MCP,
    LEGAL,
    LINUX,
    MACOS,
    PACKAGING,
    SECURITY,
    TECHNICAL_CORE,
    WINDOWS,
    GateStatus,
)


def full_positive_evidence():
    """Every gate green, with CBM/HOST shaped per realistic evidence:
    windows-only CBM certification and historical host certification."""
    return {
        "regression": {
            "passed": True,
            "tests": 1972,
            "failures": 0,
            "errors": 0,
            "resource_warnings": 0,
            "where": "ci",
        },
        "packaging": {"wheel_ok": True, "sdist_ok": True, "details": []},
        "installed": {
            "cli": True,
            "mcp": True,
            "details": [
                "wheel exact-artifact CLI/MCP E2E retained",
                "sdist exact-artifact CLI/MCP E2E retained",
            ],
        },
        "platforms": {"windows": "pass", "linux": "pass", "macos": "pass"},
        "cbm": {
            "certified_platforms": ["windows-amd64"],
            "notes": [
                "Linux/macOS CBM not certified "
                "(honest degradation verified)"
            ],
        },
        "hosts": {
            "certified_hosts": ["claude", "opencode"],
            "regenerated_in_ci": False,
        },
        "docs": {
            "release_doc": True,
            "readme_sections": True,
            "installation_doc": True,
        },
        "legal": {"license_present": True, "notice_complete": True},
        "security": {
            "workflows_minimal_permissions": True,
            "no_untrusted_triggers": True,
            "actions_pinned": True,
        },
        "ci": {"workflows_present": True, "remote_runs_passed": True},
    }


class FullPositiveTests(unittest.TestCase):
    def setUp(self):
        self.report = release_gates.evaluate_gates(full_positive_evidence())
        self.statuses = {gate.name: gate.status for gate in self.report.gates}

    def test_gate_order_and_count(self):
        self.assertEqual(
            [gate.name for gate in self.report.gates],
            list(release_gates.GATE_ORDER),
        )

    def test_all_pass_except_realistic_partial_debt(self):
        for name, status in self.statuses.items():
            if name in (CBM_CERTIFICATION, HOST_CERTIFICATION):
                self.assertIs(status, GateStatus.PARTIAL, name)
            else:
                self.assertIs(status, GateStatus.PASS, name)

    def test_cbm_partial_carries_the_honest_note(self):
        gate = self.report._by_name(CBM_CERTIFICATION)
        self.assertTrue(
            any("not certified" in note for note in gate.notes), gate.notes
        )

    def test_safeties_with_realistic_debt(self):
        self.assertTrue(self.report.safe_to_merge)
        self.assertTrue(self.report.safe_to_tag_rc)
        self.assertTrue(self.report.safe_for_public_release)

    def test_overall_is_partial_when_any_gate_is_partial(self):
        self.assertIs(self.report.overall, GateStatus.PARTIAL)

    def test_pending_external_certification_fields_keep_partial_status(self):
        pending = self.report.pending_public_release_external_certifications
        self.assertEqual(
            {item["gate"] for item in pending},
            {CBM_CERTIFICATION, HOST_CERTIFICATION},
        )
        self.assertTrue(all(item["status"] == "PARTIAL" for item in pending))
        self.assertEqual(
            self.report.public_release_external_certification_status,
            "PENDING",
        )

    def test_installed_gate_pass_is_not_pending_external_debt(self):
        gate = self.report._by_name(INSTALLED_CLI_MCP)
        self.assertIs(gate.status, GateStatus.PASS)
        self.assertNotIn(
            INSTALLED_CLI_MCP,
            {item["gate"] for item in
             self.report.pending_public_release_external_certifications},
        )


class AntiFalseGreenTests(unittest.TestCase):
    def test_missing_evidence_never_yields_pass(self):
        report = release_gates.evaluate_gates({})
        for gate in report.gates:
            self.assertIn(
                gate.status,
                (GateStatus.PARTIAL, GateStatus.BLOCKED),
                f"{gate.name} reported {gate.status} with no evidence",
            )
        self.assertFalse(report.safe_to_merge)
        self.assertFalse(report.safe_to_tag_rc)
        self.assertFalse(report.safe_for_public_release)

    def test_cbm_gate_never_passes_with_empty_certified_platforms(self):
        report = release_gates.evaluate_gates(
            {"cbm": {"certified_platforms": [], "notes": ["anything"]}}
        )
        self.assertIsNot(
            report._by_name(CBM_CERTIFICATION).status, GateStatus.PASS
        )


class BlockedGateTests(unittest.TestCase):
    def test_failed_regression_blocks_everything(self):
        evidence = full_positive_evidence()
        evidence["regression"] = {
            "passed": False,
            "tests": 1972,
            "failures": 3,
            "errors": 0,
            "resource_warnings": 0,
            "where": "local",
        }
        report = release_gates.evaluate_gates(evidence)
        self.assertIs(
            report._by_name(TECHNICAL_CORE).status, GateStatus.BLOCKED
        )
        self.assertFalse(report.safe_to_merge)
        self.assertFalse(report.safe_to_tag_rc)
        self.assertFalse(report.safe_for_public_release)
        self.assertTrue(
            any("TECHNICAL_CORE" in item for item in report.blockers),
            report.blockers,
        )

    def test_packaging_failure_blocks_public_release(self):
        evidence = full_positive_evidence()
        evidence["packaging"] = {
            "wheel_ok": False,
            "sdist_ok": True,
            "details": ["wheel missing required metadata"],
        }
        report = release_gates.evaluate_gates(evidence)
        self.assertIs(report._by_name(PACKAGING).status, GateStatus.BLOCKED)
        self.assertFalse(report.safe_to_merge)
        self.assertFalse(report.safe_for_public_release)

    def test_security_failure_blocks_public_release(self):
        evidence = full_positive_evidence()
        evidence["security"]["actions_pinned"] = False
        report = release_gates.evaluate_gates(evidence)
        self.assertIs(report._by_name(SECURITY).status, GateStatus.BLOCKED)
        self.assertFalse(report.safe_to_merge)
        self.assertFalse(report.safe_for_public_release)

    def test_windows_failure_blocks_public_release(self):
        evidence = full_positive_evidence()
        evidence["platforms"]["windows"] = "fail"
        report = release_gates.evaluate_gates(evidence)
        self.assertIs(report._by_name(WINDOWS).status, GateStatus.BLOCKED)
        self.assertFalse(report.safe_for_public_release)

    def test_installed_cli_failure_blocks_release_safeties(self):
        evidence = full_positive_evidence()
        evidence["installed"]["cli"] = False
        report = release_gates.evaluate_gates(evidence)
        gate = report._by_name(INSTALLED_CLI_MCP)
        self.assertIs(gate.status, GateStatus.BLOCKED)
        self.assertTrue(any("installed cli" in item for item in gate.blockers))
        self.assertFalse(report.safe_to_merge)
        self.assertFalse(report.safe_to_tag_rc)
        self.assertFalse(report.safe_for_public_release)

    def test_installed_mcp_failure_blocks_release_safeties(self):
        evidence = full_positive_evidence()
        evidence["installed"]["mcp"] = False
        report = release_gates.evaluate_gates(evidence)
        gate = report._by_name(INSTALLED_CLI_MCP)
        self.assertIs(gate.status, GateStatus.BLOCKED)
        self.assertTrue(any("installed mcp" in item for item in gate.blockers))
        self.assertFalse(report.safe_to_merge)
        self.assertFalse(report.safe_to_tag_rc)
        self.assertFalse(report.safe_for_public_release)

    def test_missing_installed_evidence_is_partial_and_not_public_safe(self):
        evidence = full_positive_evidence()
        del evidence["installed"]
        report = release_gates.evaluate_gates(evidence)
        self.assertIs(
            report._by_name(INSTALLED_CLI_MCP).status, GateStatus.PARTIAL
        )
        self.assertTrue(report.safe_to_merge)
        self.assertTrue(report.safe_to_tag_rc)
        self.assertFalse(report.safe_for_public_release)

    def test_indeterminate_installed_evidence_is_not_pass_or_public_safe(self):
        evidence = full_positive_evidence()
        evidence["installed"]["mcp"] = None
        report = release_gates.evaluate_gates(evidence)
        gate = report._by_name(INSTALLED_CLI_MCP)
        self.assertIs(gate.status, GateStatus.PARTIAL)
        self.assertFalse(report.safe_for_public_release)


class LegalGateTests(unittest.TestCase):
    def test_legal_blocked_allows_rc_but_vetoes_public(self):
        evidence = full_positive_evidence()
        evidence["legal"] = {"license_present": False, "notice_complete": None}
        report = release_gates.evaluate_gates(evidence)
        self.assertIs(report._by_name(LEGAL).status, GateStatus.BLOCKED)
        self.assertTrue(report.safe_to_merge)
        self.assertTrue(report.safe_to_tag_rc)
        self.assertFalse(report.safe_for_public_release)
        self.assertTrue(
            any("LICENSE" in item for item in report.blockers),
            report.blockers,
        )


class CiGateTests(unittest.TestCase):
    def test_remote_runs_pending_keeps_ci_partial_and_blocks_rc(self):
        evidence = full_positive_evidence()
        evidence["ci"] = {"workflows_present": True, "remote_runs_passed": None}
        report = release_gates.evaluate_gates(evidence)
        self.assertIs(report._by_name(CI).status, GateStatus.PARTIAL)
        self.assertFalse(report.safe_to_tag_rc)
        self.assertTrue(report.safe_to_merge)

    def test_failed_remote_runs_block_ci_and_merge(self):
        evidence = full_positive_evidence()
        evidence["ci"] = {"workflows_present": True, "remote_runs_passed": False}
        report = release_gates.evaluate_gates(evidence)
        gate = report._by_name(CI)
        self.assertIs(gate.status, GateStatus.BLOCKED)
        self.assertTrue(
            any("remote CI" in blocker and "failed" in blocker
                for blocker in gate.blockers),
            gate.blockers,
        )
        self.assertFalse(report.safe_to_merge)


class PublicExternalPolicyTests(unittest.TestCase):
    def test_linux_macos_ci_partial_is_visible_but_public_non_blocking(self):
        evidence = full_positive_evidence()
        evidence["platforms"] = {
            "windows": "pass",
            "linux": "pending",
            "macos": "partial",
        }
        evidence["ci"] = {
            "workflows_present": True,
            "remote_runs_passed": None,
        }
        report = release_gates.evaluate_gates(evidence)

        for name in (LINUX, MACOS, CI):
            self.assertIs(
                report._by_name(name).status, GateStatus.PARTIAL, name
            )
        self.assertTrue(report.safe_for_public_release)
        self.assertTrue(report.safe_to_merge)
        self.assertFalse(report.safe_to_tag_rc)
        self.assertEqual(
            {item["gate"] for item in
             report.pending_public_release_external_certifications},
            {LINUX, MACOS, CI, CBM_CERTIFICATION, HOST_CERTIFICATION},
        )
        self.assertNotIn(
            INSTALLED_CLI_MCP,
            {item["gate"] for item in
             report.pending_public_release_external_certifications},
        )

    def test_blocked_external_result_still_blocks_public_release(self):
        cases = {
            LINUX: lambda evidence: evidence["platforms"].update(
                {"linux": "fail"}
            ),
            MACOS: lambda evidence: evidence["platforms"].update(
                {"macos": "BLOCKED"}
            ),
            CI: lambda evidence: evidence.update(
                {"ci": {"workflows_present": True,
                         "remote_runs_passed": False}}
            ),
        }
        for name, make_blocked in cases.items():
            with self.subTest(name=name):
                evidence = full_positive_evidence()
                make_blocked(evidence)
                report = release_gates.evaluate_gates(evidence)
                self.assertIs(
                    report._by_name(name).status, GateStatus.BLOCKED
                )
                self.assertEqual(
                    report.public_release_external_certification_status,
                    "BLOCKED",
                )
                self.assertFalse(report.safe_for_public_release)


class TechnicalCoreGateTests(unittest.TestCase):
    def test_zero_tests_block_a_reported_green_regression(self):
        evidence = full_positive_evidence()
        evidence["regression"] = {
            "passed": True,
            "tests": 0,
            "failures": 0,
            "errors": 0,
            "resource_warnings": 0,
            "where": "ci",
        }
        report = release_gates.evaluate_gates(evidence)
        gate = report._by_name(TECHNICAL_CORE)
        self.assertIs(gate.status, GateStatus.BLOCKED)
        self.assertTrue(
            any("zero" in blocker or "tests <= 0" in blocker
                for blocker in gate.blockers),
            gate.blockers,
        )
        self.assertFalse(report.safe_to_merge)


class CbmGateTests(unittest.TestCase):
    def test_non_windows_certified_claim_without_evidence_blocks(self):
        evidence = full_positive_evidence()
        evidence["cbm"] = {
            "certified_platforms": ["windows-amd64"],
            "notes": ["Linux/macOS CBM not certified"],
            "claims": [
                {"platform": "linux-amd64", "certified": True, "evidence": ""}
            ],
        }
        report = release_gates.evaluate_gates(evidence)
        self.assertIs(
            report._by_name(CBM_CERTIFICATION).status, GateStatus.BLOCKED
        )
        self.assertFalse(report.safe_for_public_release)


class SerializationTests(unittest.TestCase):
    def test_to_dict_round_trips_through_json(self):
        report = release_gates.evaluate_gates(full_positive_evidence())
        payload = json.dumps(report.to_dict())
        decoded = json.loads(payload)
        self.assertEqual(
            set(decoded),
            {
                "gates",
                "overall",
                "safe_to_merge",
                "safe_to_tag_rc",
                "safe_for_public_release",
                "blockers",
                "public_release_external_certification_status",
                "pending_public_release_external_certifications",
            },
        )
        self.assertEqual(len(decoded["gates"]), len(release_gates.GATE_ORDER))
        for gate in decoded["gates"]:
            self.assertEqual(
                set(gate), {"name", "status", "evidence", "blockers", "notes"}
            )
        self.assertEqual(
            decoded["public_release_external_certification_status"],
            "PENDING",
        )
        self.assertTrue(
            all(
                item["status"] == "PARTIAL"
                for item in decoded[
                    "pending_public_release_external_certifications"
                ]
            )
        )

    def test_from_evidence_json_matches_direct_evaluation(self):
        evidence = full_positive_evidence()
        direct = release_gates.evaluate_gates(evidence).to_dict()
        via_json = release_gates.ReleaseReport.from_evidence_json(
            json.dumps(evidence)
        ).to_dict()
        self.assertEqual(direct, via_json)


class ComposedRunEvidenceTests(unittest.TestCase):
    """R5C: composed run-scoped evidence flowing through the gate model.

    The composed regression mapping carries the AGGREGATE execution count
    (sum across matrix cells) with per-cell canonical counts under
    ``cells``; the gate reads only the aggregate, so these tests pin the
    contract that the aggregate shape keeps TECHNICAL_CORE honest.
    """

    def _composed_evidence(self):
        evidence = full_positive_evidence()
        evidence["regression"] = {
            "passed": True,
            "tests": 6183,  # aggregate: 2061 executions x 3 cells
            "failures": 0,
            "errors": 0,
            "resource_warnings": 0,
            "where": "CI full-regression matrix",
            "cells": {
                platform: {
                    "tests": 2061,
                    "failures": 0,
                    "errors": 0,
                    "resource_warnings": 0,
                    "where": f"ci full-regression {platform}-latest",
                }
                for platform in ("linux", "macos", "windows")
            },
        }
        evidence["meta"] = {"sha": "d818b8c20d38557ab6624a9a3e4fe66a11532261",
                            "run_id": "31760708465",
                            "source": "github-actions"}
        return evidence

    def test_remote_runs_passed_true_allows_ci_pass(self):
        report = release_gates.evaluate_gates(self._composed_evidence())
        self.assertIs(report._by_name(CI).status, GateStatus.PASS)
        self.assertIs(
            report._by_name(TECHNICAL_CORE).status, GateStatus.PASS
        )

    def test_remote_runs_passed_false_blocks_ci(self):
        evidence = self._composed_evidence()
        evidence["ci"] = {"workflows_present": True,
                          "remote_runs_passed": False}
        report = release_gates.evaluate_gates(evidence)
        self.assertIs(report._by_name(CI).status, GateStatus.BLOCKED)
        self.assertFalse(report.safe_to_merge)

    def test_remote_runs_passed_absent_keeps_ci_partial(self):
        evidence = self._composed_evidence()
        evidence["ci"] = {"workflows_present": True}
        report = release_gates.evaluate_gates(evidence)
        self.assertIs(report._by_name(CI).status, GateStatus.PARTIAL)
        self.assertTrue(report.safe_to_merge)
        self.assertFalse(report.safe_to_tag_rc)

    def test_full_composed_evidence_with_legal_blocked(self):
        evidence = self._composed_evidence()
        evidence["legal"] = {"license_present": False,
                             "notice_complete": None}
        report = release_gates.evaluate_gates(evidence)
        self.assertIs(report._by_name(LEGAL).status, GateStatus.BLOCKED)
        self.assertFalse(report.safe_for_public_release)
        self.assertTrue(report.safe_to_tag_rc)
        self.assertTrue(report.safe_to_merge)


if __name__ == "__main__":
    unittest.main()
