"""Tests for R4C.0 structural backend detection and routing assessment.

Two things are under test. First, that a registration is classified by
what it LAUNCHES and never by what it is called — the false-friendly-name
cases below are the ones that matter, because a name check would pass
every other test in this file while being completely wrong. Second, that
the assessment built from those detections reaches the routing verdicts
the policy layer defines, end to end, from fixture configs on a fake
filesystem.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from relinkra.backend_detection import (
    BACKEND_MARKERS,
    NAMING_CURRENT,
    NAMING_LEGACY,
    NAMING_NOT_APPLICABLE,
    NAMING_UNVERIFIED,
    HostRouting,
    assess_routing,
    assess_workspace,
    build_trust_ladder,
    classify_entry,
    detect_registrations,
    host_routing,
    survey_hosts,
)
from relinkra.backend_policy import (
    BACKEND_CBM,
    BACKEND_ENGRAM,
    BACKEND_RELINKRA,
    BACKEND_UNKNOWN,
    CBM_DIRECTLY_EXPOSED,
    CBM_EXPLICITLY_ALLOWED_ADVANCED,
    CBM_RELINKRA_PRIVATE,
    CBM_UNAVAILABLE,
    DETECTION_CONFLICTING,
    DETECTION_DETECTED,
    DETECTION_LIKELY,
    DETECTION_UNKNOWN,
    DUPLICATE_DETECTED,
    ENGRAM_DIRECT_UNCLASSIFIED,
    ENGRAM_SHARED_SEPARATED,
    ROUTE_BYPASSED,
    ROUTE_MANAGED,
    ROUTE_MIXED,
    ROUTE_UNVERIFIED,
    STAGE_CONFIGURATION_PRESENT,
    STAGE_HANDOFF_ROUND_TRIP,
    STAGE_HANDSHAKE_VERIFIED,
    STAGE_PROTOCOL_COMPATIBLE,
    STAGE_REGISTRATION_DETECTED,
    STAGE_REQUIRED_TOOLS_CALLABLE,
    STAGE_TOOLS_VISIBLE,
    STAGE_UNVERIFIED,
    TRUST_DEGRADED,
    TRUST_HIGH,
    TRUST_UNRELIABLE,
    TRUST_UNVERIFIED,
)
from relinkra.connectors import (
    CLAUDE,
    CONNECTORS,
    DEVIN_CLOUD,
    DEVIN_DESKTOP,
    DEVIN_DESKTOP_LEGACY_LOCATIONS,
    AmbiguousConnectorError,
    claude_project_key,
    inspect_connector,
    resolve_connector,
)
from relinkra.connector import SUPPORT_UNSUPPORTED, UnknownConnectorError
from relinkra.host_discovery import (
    SYSTEM_LINUX,
    SYSTEM_WINDOWS,
    DiscoveryEnvironment,
)

RELINKRA_ENTRY = {
    "command": "/usr/bin/python3",
    "args": ["-m", "relinkra.mcp_cli", "--workspace-root", "/w"],
}
CBM_ENTRY = {"command": "/opt/bin/codebase-memory-mcp", "args": []}
CBM_ENTRY_WINDOWS = {
    "command": "C:\\Users\\dev\\Programs\\codebase-memory-mcp.exe",
    "args": [],
}
ENGRAM_ENTRY = {"command": "/usr/local/bin/engram", "args": ["mcp", "--tools=agent"]}
GENTLEMAN_ENGRAM_ENTRY = {
    "command": "/home/dev/.gentleman/bin/engram",
    "args": ["mcp"],
}
UNRELATED_ENTRY = {"command": "npx", "args": ["-y", "context7-mcp@2.2.5"]}


class ClassifyEntryTests(unittest.TestCase):
    def test_relinkra_module_is_detected(self):
        result = classify_entry("relinkra", RELINKRA_ENTRY)
        self.assertEqual(result.backend, BACKEND_RELINKRA)
        self.assertEqual(result.confidence, DETECTION_DETECTED)
        self.assertIn("module:relinkra.mcp_cli", result.markers)

    def test_cbm_binary_is_detected(self):
        result = classify_entry("code-search", CBM_ENTRY)
        self.assertEqual(result.backend, BACKEND_CBM)
        self.assertEqual(result.confidence, DETECTION_DETECTED)

    def test_cbm_windows_executable_is_detected(self):
        result = classify_entry("cbm", CBM_ENTRY_WINDOWS)
        self.assertEqual(result.backend, BACKEND_CBM)
        self.assertEqual(result.confidence, DETECTION_DETECTED)
        self.assertIn("executable:codebase-memory-mcp", result.markers)

    def test_engram_binary_is_detected(self):
        result = classify_entry("engram", ENGRAM_ENTRY)
        self.assertEqual(result.backend, BACKEND_ENGRAM)
        self.assertEqual(result.confidence, DETECTION_DETECTED)

    def test_npx_package_token_is_detected_without_its_version(self):
        entry = {"command": "npx", "args": ["-y", "codebase-memory-mcp@1.4.0"]}
        result = classify_entry("indexer", entry)
        self.assertEqual(result.backend, BACKEND_CBM)
        self.assertIn("package:codebase-memory-mcp", result.markers)

    def test_opencode_list_command_shape_is_understood(self):
        entry = {"type": "local", "command": ["engram", "mcp"], "enabled": True}
        self.assertEqual(classify_entry("engram", entry).backend, BACKEND_ENGRAM)

    def test_unrelated_server_is_unknown_and_preserved(self):
        result = classify_entry("context7", UNRELATED_ENTRY)
        self.assertEqual(result.backend, BACKEND_UNKNOWN)
        self.assertEqual(result.confidence, DETECTION_UNKNOWN)
        self.assertEqual(result.markers, ())


class FalseFriendlyNameTests(unittest.TestCase):
    """The name is evidence. The launch target is the answer."""

    def test_an_entry_named_relinkra_that_launches_cbm_is_not_relinkra(self):
        result = classify_entry("relinkra", CBM_ENTRY)
        self.assertEqual(result.backend, BACKEND_CBM)
        self.assertEqual(result.confidence, DETECTION_CONFLICTING)
        self.assertIn(BACKEND_RELINKRA, result.name_suggests)

    def test_a_conflicting_detection_never_drives_a_conclusion(self):
        self.assertFalse(classify_entry("relinkra", CBM_ENTRY).trustworthy)

    def test_an_entry_named_cbm_that_launches_something_else_is_conflicting(self):
        result = classify_entry("cbm", UNRELATED_ENTRY)
        self.assertEqual(result.backend, BACKEND_UNKNOWN)
        self.assertEqual(result.confidence, DETECTION_CONFLICTING)

    def test_a_name_alone_is_only_likely_when_there_is_nothing_to_launch(self):
        # A remote entry has no local command to inspect, so the name is
        # the only evidence there is — and it is labelled as such.
        result = classify_entry("engram", {"type": "remote", "url": "https://x/mcp"})
        self.assertEqual(result.backend, BACKEND_ENGRAM)
        self.assertEqual(result.confidence, DETECTION_LIKELY)
        self.assertFalse(result.trustworthy)

    def test_an_entry_carrying_two_backends_is_conflicting(self):
        entry = {
            "command": "python",
            "args": ["-m", "relinkra.mcp_cli", "--shim", "codebase-memory-mcp"],
        }
        result = classify_entry("hybrid", entry)
        self.assertEqual(result.confidence, DETECTION_CONFLICTING)
        self.assertEqual(result.backend, BACKEND_UNKNOWN)

    def test_wrapper_and_node_module_tokens_are_not_relinkra(self):
        for entry in (
            {"command": "node", "args": ["-m", "relinkra.mcp_cli"]},
            {
                "command": "python",
                "args": ["wrapper.py", "-m", "relinkra.mcp_cli"],
            },
            {"command": "sh", "args": ["-c", "python -m relinkra.mcp_cli"]},
        ):
            with self.subTest(entry=entry):
                result = classify_entry("relinkra", entry)
                self.assertEqual(result.backend, BACKEND_UNKNOWN)
                self.assertEqual(result.confidence, DETECTION_CONFLICTING)

    def test_a_name_that_merely_contains_a_hint_is_not_a_match(self):
        # "engramophone" is not Engram. Hints match whole tokens only.
        result = classify_entry("engramophone", UNRELATED_ENTRY)
        self.assertEqual(result.confidence, DETECTION_UNKNOWN)


class PrivacyTests(unittest.TestCase):
    def test_a_configured_server_name_never_reaches_the_payload(self):
        result = classify_entry("acme-internal-prod-secrets", UNRELATED_ENTRY)
        self.assertNotIn("acme", json.dumps(result.to_dict()))

    def test_a_launch_path_never_reaches_the_payload(self):
        result = classify_entry("cbm", CBM_ENTRY_WINDOWS)
        payload = json.dumps(result.to_dict())
        self.assertNotIn("C:\\Users", payload)
        self.assertNotIn("/opt/bin", payload)

    def test_refs_identify_entries_without_naming_them(self):
        document = {
            "mcpServers": {
                "private-alpha": CBM_ENTRY,
                "private-beta": UNRELATED_ENTRY,
            }
        }
        detections = _detect(document)
        refs = [item.ref for item in detections]
        self.assertEqual(sorted(refs), ["cbm#1", "unknown#1"])


class GentlemanMarkerTests(unittest.TestCase):
    def test_a_gentleman_path_segment_marks_the_registration(self):
        self.assertTrue(classify_entry("engram", GENTLEMAN_ENGRAM_ENTRY).gentleman_marked)

    def test_a_gentle_ai_token_marks_the_registration(self):
        entry = {"command": "/opt/gentle-ai/bin/engram", "args": ["mcp"]}
        self.assertTrue(classify_entry("engram", entry).gentleman_marked)

    def test_a_plugin_scoped_server_name_does_not_mark_the_registration(self):
        # A plugin-scoped name says SOME plugin manages the entry, not
        # which system does. Accepting it would turn an unclassified
        # direct Engram server into a healthy 'shared_separated' PASS on
        # the strength of a user-authored string.
        self.assertFalse(
            classify_entry("plugin:engram:engram", ENGRAM_ENTRY).gentleman_marked
        )

    def test_a_gentleman_named_entry_launching_something_else_is_not_marked(self):
        self.assertFalse(
            classify_entry("gentleman-engram", ENGRAM_ENTRY).gentleman_marked
        )

    def test_a_plain_engram_registration_is_not_marked(self):
        # Absent a marker the honest answer is "unclassified", and
        # inventing one here would turn a warning into a false PASS.
        self.assertFalse(classify_entry("engram", ENGRAM_ENTRY).gentleman_marked)


def _detect(document, spec=CLAUDE):
    """Classify a hand-built configuration document without touching disk."""
    from relinkra.connectors import InspectionResult

    inspection = InspectionResult(spec=spec, document=document)
    return detect_registrations(inspection)


class DetectRegistrationsTests(unittest.TestCase):
    def test_every_entry_in_the_container_is_classified(self):
        document = {
            "mcpServers": {
                "relinkra": RELINKRA_ENTRY,
                "codebase-memory-mcp": CBM_ENTRY,
                "context7": UNRELATED_ENTRY,
            }
        }
        backends = sorted(item.backend for item in _detect(document))
        self.assertEqual(backends, [BACKEND_CBM, BACKEND_RELINKRA, BACKEND_UNKNOWN])

    def test_an_unreadable_document_yields_no_detections(self):
        self.assertEqual(_detect(None), ())

    def test_a_missing_container_yields_no_detections(self):
        self.assertEqual(_detect({"other": {}}), ())

    def test_a_non_object_container_yields_no_detections(self):
        self.assertEqual(_detect({"mcpServers": ["nope"]}), ())

    def test_detection_order_is_deterministic(self):
        document = {"mcpServers": {"z": CBM_ENTRY, "a": ENGRAM_ENTRY, "m": RELINKRA_ENTRY}}
        first = [item.to_dict() for item in _detect(document)]
        second = [item.to_dict() for item in _detect(document)]
        self.assertEqual(first, second)

    def test_declared_inherited_containers_are_generic_and_scoped(self):
        spec = replace(
            CLAUDE,
            connector_id="synthetic",
            container_path=("target",),
            inherited_container_paths=(("inherited",),),
        )
        document = {
            "target": {"relinkra": RELINKRA_ENTRY},
            "inherited": {"cbm": CBM_ENTRY},
            "mcpServers": {"engram": ENGRAM_ENTRY},
        }

        backends = sorted(item.backend for item in _detect(document, spec))

        self.assertEqual(backends, [BACKEND_CBM, BACKEND_RELINKRA])


# ---------------------------------------------------------------------------
# Routing assessment
# ---------------------------------------------------------------------------


def _host(*detection_sources, connector_id="claude", readable=True, naming=NAMING_NOT_APPLICABLE):
    document = {"mcpServers": dict(detection_sources)}
    detections = _detect(document) if readable else ()
    return HostRouting(
        connector_id=connector_id,
        discovery_status="discovered" if readable else "config_missing",
        config_readable=readable,
        detections=detections,
        naming=naming,
    )


class RoutingAssessmentTests(unittest.TestCase):
    def test_healthy_managed_route(self):
        assessment = assess_routing(
            [_host(("relinkra", RELINKRA_ENTRY))],
            launch_resolved=True,
            relinkra_verified=True,
            cbm_backend_available=True,
            engram_backend_available=True,
        )
        self.assertEqual(assessment.context_route, ROUTE_MANAGED)
        self.assertEqual(assessment.cbm_ownership, CBM_RELINKRA_PRIVATE)
        self.assertEqual(assessment.metrics_trust, TRUST_HIGH)
        self.assertFalse(assessment.bypass_detected)

    def test_relinkra_plus_direct_cbm_is_mixed_and_unreliable(self):
        assessment = assess_routing(
            [_host(("relinkra", RELINKRA_ENTRY), ("codebase-memory-mcp", CBM_ENTRY))],
            launch_resolved=True,
            relinkra_verified=True,
            cbm_backend_available=True,
        )
        self.assertEqual(assessment.context_route, ROUTE_MIXED)
        self.assertEqual(assessment.cbm_ownership, CBM_DIRECTLY_EXPOSED)
        self.assertEqual(assessment.metrics_trust, TRUST_UNRELIABLE)
        self.assertEqual(assessment.duplicate_risk, DUPLICATE_DETECTED)
        self.assertTrue(assessment.bypass_detected)

    def test_the_mixed_remediation_never_asks_to_delete_anything(self):
        assessment = assess_routing(
            [_host(("relinkra", RELINKRA_ENTRY), ("cbm", CBM_ENTRY))],
            relinkra_verified=True,
        )
        text = " ".join(assessment.remediation).lower()
        self.assertIn("nothing was changed", text)

    def test_direct_cbm_without_relinkra_is_bypassed(self):
        assessment = assess_routing([_host(("cbm", CBM_ENTRY))], launch_resolved=True)
        self.assertEqual(assessment.context_route, ROUTE_BYPASSED)
        self.assertEqual(assessment.metrics_trust, TRUST_UNRELIABLE)

    def test_explicit_advanced_cbm_downgrades_trust_instead_of_destroying_it(self):
        assessment = assess_routing(
            [_host(("relinkra", RELINKRA_ENTRY), ("cbm", CBM_ENTRY))],
            launch_resolved=True,
            relinkra_verified=True,
            advanced_cbm_allowed=True,
            cbm_backend_available=True,
        )
        self.assertEqual(assessment.cbm_ownership, CBM_EXPLICITLY_ALLOWED_ADVANCED)
        self.assertEqual(assessment.metrics_trust, TRUST_DEGRADED)
        self.assertEqual(assessment.context_route, ROUTE_MIXED)

    def test_relinkra_plus_gentleman_engram_is_valid_shared_separation(self):
        assessment = assess_routing(
            [_host(("relinkra", RELINKRA_ENTRY), ("engram", GENTLEMAN_ENGRAM_ENTRY))],
            launch_resolved=True,
            relinkra_verified=True,
            cbm_backend_available=True,
            engram_backend_available=True,
        )
        self.assertEqual(assessment.engram_ownership, ENGRAM_SHARED_SEPARATED)
        # Sharing Engram with Gentleman does not cost the managed route.
        self.assertEqual(assessment.context_route, ROUTE_MANAGED)

    def test_unclassified_direct_engram_warns_without_failing_the_route(self):
        assessment = assess_routing(
            [_host(("relinkra", RELINKRA_ENTRY), ("engram", ENGRAM_ENTRY))],
            launch_resolved=True,
            relinkra_verified=True,
            cbm_backend_available=True,
            engram_backend_available=True,
        )
        self.assertEqual(assessment.engram_ownership, ENGRAM_DIRECT_UNCLASSIFIED)
        self.assertEqual(assessment.context_route, ROUTE_MANAGED)
        self.assertTrue(
            any("gentleman" in item.lower() for item in assessment.remediation)
        )

    def test_no_readable_config_is_unverified(self):
        assessment = assess_routing([_host(readable=False)])
        self.assertEqual(assessment.context_route, ROUTE_UNVERIFIED)
        self.assertEqual(assessment.metrics_trust, TRUST_UNVERIFIED)

    def test_a_conflicting_registration_makes_the_route_unverified(self):
        assessment = assess_routing(
            [_host(("relinkra", CBM_ENTRY))], launch_resolved=True
        )
        self.assertEqual(assessment.context_route, ROUTE_UNVERIFIED)
        self.assertTrue(any("disagrees" in note for note in assessment.notes))

    def test_unknown_servers_are_counted_and_reported_as_preserved(self):
        assessment = assess_routing([_host(("context7", UNRELATED_ENTRY))])
        self.assertTrue(
            any("preserved untouched" in note for note in assessment.notes)
        )

    def test_route_remediation_addresses_the_route_not_something_else(self):
        assessment = assess_routing(
            [_host(("relinkra", RELINKRA_ENTRY), ("cbm", CBM_ENTRY), ("engram", ENGRAM_ENTRY))],
            relinkra_verified=True,
        )
        self.assertIn("CBM", assessment.route_remediation)

    def test_payload_is_deterministic(self):
        hosts = [_host(("relinkra", RELINKRA_ENTRY), ("cbm", CBM_ENTRY))]
        self.assertEqual(
            assess_routing(hosts).to_dict(), assess_routing(hosts).to_dict()
        )


class TrustLadderConstructionTests(unittest.TestCase):
    def _ladder(self, **kw):
        base = dict(
            launch_resolved=True,
            relinkra_registered=True,
            route=ROUTE_MANAGED,
            metrics_trust=TRUST_HIGH,
            bypass_detected=False,
            handoffs_available=True,
            tools_declared=9,
            real_host_launch_proven=False,
        )
        base.update(kw)
        return build_trust_ladder([_host(("relinkra", RELINKRA_ENTRY))], **base)

    def test_config_present_does_not_prove_a_handshake(self):
        stages = self._ladder().by_stage()
        self.assertTrue(stages[STAGE_CONFIGURATION_PRESENT].proven)
        self.assertEqual(stages[STAGE_HANDSHAKE_VERIFIED].state, STAGE_UNVERIFIED)
        self.assertEqual(stages[STAGE_PROTOCOL_COMPATIBLE].state, STAGE_UNVERIFIED)

    def test_tools_visible_does_not_prove_the_tools_are_callable(self):
        stages = self._ladder().by_stage()
        self.assertTrue(stages[STAGE_TOOLS_VISIBLE].proven)
        self.assertEqual(
            stages[STAGE_REQUIRED_TOOLS_CALLABLE].state, STAGE_UNVERIFIED
        )

    def test_handoff_round_trip_is_unverified_when_the_backend_is_up(self):
        stages = self._ladder(handoffs_available=True).by_stage()
        self.assertEqual(stages[STAGE_HANDOFF_ROUND_TRIP].state, STAGE_UNVERIFIED)

    def test_handoff_round_trip_is_not_proven_when_the_backend_is_down(self):
        stages = self._ladder(handoffs_available=False).by_stage()
        self.assertFalse(stages[STAGE_HANDOFF_ROUND_TRIP].proven)
        self.assertNotEqual(stages[STAGE_HANDOFF_ROUND_TRIP].state, STAGE_UNVERIFIED)

    def test_an_unregistered_relinkra_fails_its_own_rung(self):
        stages = self._ladder(relinkra_registered=False).by_stage()
        self.assertFalse(stages[STAGE_REGISTRATION_DETECTED].proven)

    def test_no_ladder_is_ever_fully_proven_in_this_phase(self):
        # Real host launch cannot be established without a real host, so
        # a fully-green ladder would itself be the bug.
        self.assertFalse(self._ladder().all_proven)

    def test_every_stage_is_declared_once(self):
        stages = [stage.stage for stage in self._ladder().stages]
        self.assertEqual(len(stages), len(set(stages)))

    def test_every_stage_explains_itself(self):
        for stage in self._ladder().stages:
            self.assertTrue(stage.evidence.strip(), stage.stage)


# ---------------------------------------------------------------------------
# Devin Desktop naming migration
# ---------------------------------------------------------------------------


class DevinNamingTests(unittest.TestCase):
    def test_devin_desktop_is_the_primary_local_connector(self):
        self.assertEqual(DEVIN_DESKTOP.connector_id, "devin-desktop")

    def test_windsurf_and_codeium_resolve_to_devin_desktop(self):
        for alias in ("windsurf", "codeium", "windsurf-next", "WINDSURF"):
            self.assertEqual(resolve_connector(alias).connector_id, "devin-desktop")

    def test_devin_cloud_is_a_separate_unsupported_connector(self):
        self.assertEqual(DEVIN_CLOUD.connector_id, "devin-cloud")
        self.assertEqual(DEVIN_CLOUD.support_status, SUPPORT_UNSUPPORTED)
        self.assertEqual(DEVIN_CLOUD.locations, ())
        self.assertNotIn("windsurf", DEVIN_CLOUD.aliases)

    def test_bare_devin_is_ambiguous_rather_than_silently_resolved(self):
        with self.assertRaises(AmbiguousConnectorError) as caught:
            resolve_connector("devin")
        message = str(caught.exception)
        self.assertIn("devin-desktop", message)
        self.assertIn("devin-cloud", message)

    def test_an_ambiguous_name_is_still_an_unknown_connector_error(self):
        # Callers written against R4B catch UnknownConnectorError; the
        # new, more specific error must not slip past them.
        with self.assertRaises(UnknownConnectorError):
            resolve_connector("devin")

    def test_legacy_windsurf_locations_are_still_discovered(self):
        ids = [spec.location_id for spec in DEVIN_DESKTOP.locations]
        self.assertIn("windsurf_user_mcp", ids)
        self.assertIn("windsurf_next_mcp", ids)
        self.assertEqual(DEVIN_DESKTOP.legacy_location_ids, DEVIN_DESKTOP_LEGACY_LOCATIONS)

    def test_the_current_devin_desktop_format_evidence_is_the_observed_config(self):
        # R4C.1E Gate A verified the current product's format against the
        # installed product itself; the evidence must cite that, not the
        # legacy file the rename inherited.
        evidence = DEVIN_DESKTOP.format_evidence
        self.assertIn("mcpServers", evidence)
        self.assertIn("devin mcp add", evidence)
        self.assertIn("%APPDATA%/Devin/mcp_config.json", evidence)
        self.assertNotIn("NOT been verified", evidence)

    def test_the_migration_is_documented_on_both_connectors(self):
        self.assertTrue(DEVIN_DESKTOP.naming_migration.strip())
        self.assertTrue(DEVIN_CLOUD.naming_migration.strip())

    def test_the_connector_list_carries_both_and_no_windsurf_id(self):
        ids = [spec.connector_id for spec in CONNECTORS]
        self.assertIn("devin-desktop", ids)
        self.assertIn("devin-cloud", ids)
        self.assertNotIn("windsurf", ids)

    def test_aliases_do_not_collide_across_connectors(self):
        seen = set()
        for spec in CONNECTORS:
            for name in spec.all_names:
                self.assertNotIn(name.lower(), seen, name)
                seen.add(name.lower())


# ---------------------------------------------------------------------------
# End-to-end survey against a fixture filesystem
# ---------------------------------------------------------------------------


class SurveyTests(unittest.TestCase):
    """Real discovery, real parsing, fixture home. Nothing real is read."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="relinkra-routing-")
        self.addCleanup(self._temp.cleanup)
        self.home = Path(self._temp.name) / "home"
        self.home.mkdir()
        self.repo = Path(self._temp.name) / "repo"
        self.repo.mkdir()

    def env(self):
        return DiscoveryEnvironment(
            system=SYSTEM_WINDOWS if os.name == "nt" else SYSTEM_LINUX,
            home=self.home,
            env={},
            workspace_root=self.repo,
            which=lambda name: None,
        )

    def write(self, *parts, content):
        path = self.home.joinpath(*parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(content, indent=2), encoding="utf-8")
        return path

    def claude_config(self, servers):
        """Write the Claude state file (~/.claude.json) in its real shape."""
        return self.write(
            ".claude.json",
            content={
                "projects": {
                    claude_project_key(self.repo): {"mcpServers": servers}
                }
            },
        )

    def test_a_managed_machine_assesses_as_managed(self):
        self.claude_config({"relinkra": RELINKRA_ENTRY})
        assessment = assess_workspace(
            self.env(),
            health={
                "components": {"cbm": {"available": True}, "engram": {"available": True}},
                "capabilities": {"handoffs": True},
            },
            launch_resolved=True,
        )
        # Registration alone is not enough: the route stays unverified
        # until something beyond a config file has been observed.
        self.assertEqual(assessment.context_route, ROUTE_UNVERIFIED)
        self.assertEqual(assessment.cbm_ownership, CBM_RELINKRA_PRIVATE)

    def test_a_mixed_machine_is_detected_across_two_hosts(self):
        self.claude_config({"relinkra": RELINKRA_ENTRY})
        self.write(
            ".codeium",
            "windsurf",
            "mcp_config.json",
            content={"mcpServers": {"codebase-memory-mcp": CBM_ENTRY}},
        )
        assessment = assess_workspace(self.env(), launch_resolved=True)
        self.assertEqual(assessment.context_route, ROUTE_MIXED)
        self.assertTrue(assessment.bypass_detected)

    def test_current_devin_scope_does_not_hide_legacy_direct_cbm(self):
        self.write(
            ".config",
            "devin",
            "mcp_config.json",
            content={"mcpServers": {"engram": ENGRAM_ENTRY}},
        )
        self.write(
            ".codeium",
            "windsurf",
            "mcp_config.json",
            content={"mcpServers": {"memory-helper": CBM_ENTRY}},
        )
        assessment = assess_workspace(self.env(), launch_resolved=True)
        devin = next(
            host for host in assessment.hosts if host["connector_id"] == "devin-desktop"
        )
        self.assertTrue(
            any(item["backend"] == BACKEND_CBM for item in devin["detections"])
        )
        self.assertTrue(assessment.bypass_detected)

    def test_a_legacy_windsurf_location_is_reported_as_legacy(self):
        self.write(
            ".codeium",
            "windsurf",
            "mcp_config.json",
            content={"mcpServers": {"engram": ENGRAM_ENTRY}},
        )
        hosts = {host.connector_id: host for host in survey_hosts(self.env())}
        self.assertEqual(hosts["devin-desktop"].naming, NAMING_LEGACY)

    def test_a_host_with_no_config_reports_unverified_naming(self):
        hosts = {host.connector_id: host for host in survey_hosts(self.env())}
        self.assertEqual(hosts["devin-desktop"].naming, NAMING_UNVERIFIED)

    def test_a_connector_without_legacy_locations_is_not_applicable(self):
        self.claude_config({})
        hosts = {host.connector_id: host for host in survey_hosts(self.env())}
        self.assertEqual(hosts["claude"].naming, NAMING_NOT_APPLICABLE)

    def test_the_survey_skips_connectors_that_own_no_configuration(self):
        ids = {host.connector_id for host in survey_hosts(self.env())}
        self.assertNotIn("generic", ids)
        self.assertNotIn("devin-cloud", ids)

    def test_a_malformed_config_does_not_hide_the_other_hosts(self):
        (self.home / ".claude.json").write_text("{ broken", encoding="utf-8")
        self.write(
            ".codeium",
            "windsurf",
            "mcp_config.json",
            content={"mcpServers": {"relinkra": RELINKRA_ENTRY}},
        )
        assessment = assess_workspace(self.env(), launch_resolved=True)
        detected = [
            item
            for host in assessment.hosts
            for item in host["detections"]
            if item["backend"] == BACKEND_RELINKRA
        ]
        self.assertTrue(detected)

    def test_the_survey_writes_nothing(self):
        self.claude_config({"relinkra": RELINKRA_ENTRY})
        before = {
            p: p.read_bytes() for p in sorted(self.home.rglob("*")) if p.is_file()
        }
        assess_workspace(self.env())
        after = {
            p: p.read_bytes() for p in sorted(self.home.rglob("*")) if p.is_file()
        }
        self.assertEqual(before, after)

    def test_no_assessment_payload_carries_a_machine_local_path(self):
        from relinkra.handoff import contains_absolute_path
        from relinkra.connector import iter_strings

        self.claude_config({"cbm": CBM_ENTRY, "relinkra": RELINKRA_ENTRY})
        payload = assess_workspace(self.env()).to_dict()
        for value in iter_strings(payload):
            self.assertFalse(contains_absolute_path(value), value)


class MarkerTableTests(unittest.TestCase):
    def test_every_backend_declares_its_evidence(self):
        for markers in BACKEND_MARKERS:
            self.assertTrue(markers.evidence.strip(), markers.backend)

    def test_no_marker_is_claimed_by_two_backends(self):
        for field in ("module_tokens", "executables", "packages"):
            seen = set()
            for markers in BACKEND_MARKERS:
                values = getattr(markers, field)
                self.assertFalse(values & seen, f"{field}: {values & seen}")
                seen |= values


if __name__ == "__main__":
    unittest.main()
