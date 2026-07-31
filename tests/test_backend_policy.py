"""Tests for the R4C.0 backend ownership, routing and trust policy.

Pure-domain tests: every scenario is a ``RouteInputs`` literal, so the
rules are asserted without a machine that happens to have a particular
agent installed. What is being protected here is not code paths but
MEANING — that "managed" cannot be reached from a config file alone, that
"none" is never returned for something nobody looked at, and that the
ownership matrix never lets two systems own the same record.
"""

from __future__ import annotations

import unittest

from relinkra.backend_policy import (
    AGENT_INSTRUCTIONS,
    BACKEND_KINDS,
    BACKEND_UNKNOWN,
    DETECTION_CONFIDENCES,
    STAGE_STATES,
    TRUST_STAGES,
    AUTHORITY_GENTLEMAN,
    AUTHORITY_RELINKRA,
    CBM_DIRECTLY_EXPOSED,
    CBM_EXPLICITLY_ALLOWED_ADVANCED,
    CBM_OWNERSHIP_STATES,
    CBM_RELINKRA_PRIVATE,
    CBM_UNAVAILABLE,
    CBM_UNKNOWN,
    CONTEXT_ROUTE_STATES,
    DUPLICATE_DETECTED,
    DUPLICATE_KINDS,
    DUPLICATE_NONE,
    DUPLICATE_POSSIBLE,
    DUPLICATE_RISK_STATES,
    DUPLICATE_UNVERIFIED,
    DUP_BACKEND_QUERY,
    DUP_CONTEXT_RETRIEVAL,
    DUP_PERSISTED_MEMORY,
    DUP_TOKEN_ATTRIBUTION,
    ENGRAM_DIRECT_UNCLASSIFIED,
    ENGRAM_GENTLEMAN_MANAGED,
    ENGRAM_OWNERSHIP_STATES,
    ENGRAM_RELINKRA_MANAGED,
    ENGRAM_SHARED_SEPARATED,
    ENGRAM_UNAVAILABLE,
    ENGRAM_UNKNOWN,
    INSTRUCTION_VERSION,
    MANAGED_MODE_REQUIREMENTS,
    METRICS_TRUST_STATES,
    OBSERVABILITY_LEVELS,
    OWNERSHIP_MATRIX,
    POLICY_VERSION,
    RECOMMENDED_TOPOLOGY,
    RECORD_FULL,
    RECORD_NONE,
    RECORD_REFERENCE,
    ROUTE_BYPASSED,
    ROUTE_DEGRADED,
    ROUTE_MANAGED,
    ROUTE_MIXED,
    ROUTE_UNVERIFIED,
    STAGE_NOT_PROVEN,
    STAGE_PROVEN,
    STAGE_UNVERIFIED,
    TRUST_DEGRADED,
    TRUST_HIGH,
    TRUST_UNRELIABLE,
    TRUST_UNVERIFIED,
    DuplicateRiskFinding,
    RouteInputs,
    RoutingAssessment,
    TrustLadder,
    TrustStage,
    agent_instruction_document,
    agent_instruction_text,
    aggregate_duplicate_risk,
    authority_for,
    classify_cbm_ownership,
    classify_context_route,
    classify_engram_ownership,
    classify_metrics_trust,
    duplicate_full_ownership,
    duplicate_risk_findings,
)


def managed_inputs(**overrides) -> RouteInputs:
    """The one situation that is allowed to classify as ``managed``.

    Written as the baseline every other scenario mutates, so a test that
    expects a degradation must state exactly which fact caused it.
    """
    base = dict(
        hosts_inspected=1,
        relinkra_registered=True,
        relinkra_verified=True,
        direct_cbm_registered=False,
        advanced_cbm_allowed=False,
        cbm_backend_available=True,
        engram_registered=False,
        engram_gentleman_marked=False,
        engram_backend_available=True,
        relinkra_health_degraded=False,
        conflicting_detection=False,
    )
    base.update(overrides)
    return RouteInputs(**base)


class ContextRouteTests(unittest.TestCase):
    def test_healthy_managed_route(self):
        self.assertEqual(classify_context_route(managed_inputs()), ROUTE_MANAGED)

    def test_relinkra_plus_direct_cbm_is_mixed(self):
        route = classify_context_route(managed_inputs(direct_cbm_registered=True))
        self.assertEqual(route, ROUTE_MIXED)

    def test_direct_cbm_without_relinkra_is_bypassed(self):
        route = classify_context_route(
            managed_inputs(
                relinkra_registered=False,
                relinkra_verified=False,
                direct_cbm_registered=True,
            )
        )
        self.assertEqual(route, ROUTE_BYPASSED)

    def test_explicit_advanced_cbm_is_still_mixed(self):
        # The opt-in changes how much the numbers may be trusted, never
        # whether two paths exist. Calling a deliberate mixture "managed"
        # would make the route field a preference rather than a fact.
        route = classify_context_route(
            managed_inputs(direct_cbm_registered=True, advanced_cbm_allowed=True)
        )
        self.assertEqual(route, ROUTE_MIXED)

    def test_configured_but_unverified_is_never_managed(self):
        route = classify_context_route(managed_inputs(relinkra_verified=False))
        self.assertEqual(route, ROUTE_UNVERIFIED)

    def test_degraded_relinkra_owns_the_route_but_degrades_it(self):
        route = classify_context_route(managed_inputs(relinkra_health_degraded=True))
        self.assertEqual(route, ROUTE_DEGRADED)

    def test_no_hosts_inspected_is_unverified(self):
        self.assertEqual(
            classify_context_route(managed_inputs(hosts_inspected=0)),
            ROUTE_UNVERIFIED,
        )

    def test_conflicting_evidence_beats_every_other_reading(self):
        route = classify_context_route(managed_inputs(conflicting_detection=True))
        self.assertEqual(route, ROUTE_UNVERIFIED)

    def test_empty_machine_is_unverified_not_bypassed(self):
        # Nothing registered anywhere: no route has been bypassed because
        # no route exists yet.
        route = classify_context_route(
            RouteInputs(hosts_inspected=1, relinkra_registered=False)
        )
        self.assertEqual(route, ROUTE_UNVERIFIED)

    def test_every_route_value_is_a_declared_state(self):
        for inputs in (
            managed_inputs(),
            managed_inputs(direct_cbm_registered=True),
            managed_inputs(relinkra_registered=False, direct_cbm_registered=True),
            managed_inputs(relinkra_health_degraded=True),
            managed_inputs(hosts_inspected=0),
        ):
            self.assertIn(classify_context_route(inputs), CONTEXT_ROUTE_STATES)


class CbmOwnershipTests(unittest.TestCase):
    def test_private_when_only_relinkra_reaches_it(self):
        self.assertEqual(
            classify_cbm_ownership(managed_inputs()), CBM_RELINKRA_PRIVATE
        )

    def test_directly_exposed_when_registered_beside_relinkra(self):
        self.assertEqual(
            classify_cbm_ownership(managed_inputs(direct_cbm_registered=True)),
            CBM_DIRECTLY_EXPOSED,
        )

    def test_explicit_advanced_state_is_distinct_from_accidental_exposure(self):
        self.assertEqual(
            classify_cbm_ownership(
                managed_inputs(direct_cbm_registered=True, advanced_cbm_allowed=True)
            ),
            CBM_EXPLICITLY_ALLOWED_ADVANCED,
        )

    def test_unavailable_when_no_backend_anywhere(self):
        self.assertEqual(
            classify_cbm_ownership(managed_inputs(cbm_backend_available=False)),
            CBM_UNAVAILABLE,
        )

    def test_conflicting_detection_yields_unknown_not_a_guess(self):
        self.assertEqual(
            classify_cbm_ownership(managed_inputs(conflicting_detection=True)),
            CBM_UNKNOWN,
        )

    def test_private_is_never_claimed_when_relinkra_is_registered_nowhere(self):
        # "relinkra_private" renders as a PASS. Claiming it while the
        # route is unverified would put a green ownership line beside a
        # warning that says Relinkra is not in the route at all.
        inputs = managed_inputs(relinkra_registered=False, relinkra_verified=False)
        self.assertEqual(classify_cbm_ownership(inputs), CBM_UNKNOWN)
        self.assertEqual(classify_context_route(inputs), ROUTE_UNVERIFIED)

    def test_an_absent_backend_stays_unavailable_without_relinkra(self):
        # "nothing to own" is a definite answer and survives the rule
        # above; only the positive CLAIM needs Relinkra present.
        inputs = managed_inputs(
            relinkra_registered=False, relinkra_verified=False,
            cbm_backend_available=False,
        )
        self.assertEqual(classify_cbm_ownership(inputs), CBM_UNAVAILABLE)

    def test_direct_exposure_is_reported_even_without_relinkra(self):
        inputs = managed_inputs(
            relinkra_registered=False, relinkra_verified=False,
            direct_cbm_registered=True,
        )
        self.assertEqual(classify_cbm_ownership(inputs), CBM_DIRECTLY_EXPOSED)

    def test_every_value_is_a_declared_state(self):
        for inputs in (
            managed_inputs(),
            managed_inputs(direct_cbm_registered=True),
            managed_inputs(cbm_backend_available=False),
            managed_inputs(conflicting_detection=True),
        ):
            self.assertIn(classify_cbm_ownership(inputs), CBM_OWNERSHIP_STATES)


class EngramOwnershipTests(unittest.TestCase):
    def test_gentleman_marked_registration_is_shared_separated(self):
        # The headline coexistence case: Gentleman has Engram, Relinkra
        # has Engram, and that is a HEALTHY arrangement, not a conflict.
        state = classify_engram_ownership(
            managed_inputs(engram_registered=True, engram_gentleman_marked=True)
        )
        self.assertEqual(state, ENGRAM_SHARED_SEPARATED)

    def test_gentleman_only_when_relinkra_cannot_reach_the_backend(self):
        state = classify_engram_ownership(
            managed_inputs(
                engram_registered=True,
                engram_gentleman_marked=True,
                engram_backend_available=False,
            )
        )
        self.assertEqual(state, ENGRAM_GENTLEMAN_MANAGED)

    def test_unmarked_direct_registration_is_unclassified_not_an_error(self):
        state = classify_engram_ownership(managed_inputs(engram_registered=True))
        self.assertEqual(state, ENGRAM_DIRECT_UNCLASSIFIED)

    def test_relinkra_managed_when_nothing_is_registered_directly(self):
        self.assertEqual(
            classify_engram_ownership(managed_inputs()), ENGRAM_RELINKRA_MANAGED
        )

    def test_managed_is_never_claimed_when_relinkra_is_registered_nowhere(self):
        inputs = managed_inputs(relinkra_registered=False, relinkra_verified=False)
        self.assertEqual(classify_engram_ownership(inputs), ENGRAM_UNKNOWN)
        self.assertEqual(classify_context_route(inputs), ROUTE_UNVERIFIED)

    def test_unavailable_when_there_is_no_backend_at_all(self):
        state = classify_engram_ownership(
            managed_inputs(engram_backend_available=False)
        )
        self.assertEqual(state, ENGRAM_UNAVAILABLE)

    def test_every_value_is_a_declared_state(self):
        for inputs in (
            managed_inputs(),
            managed_inputs(engram_registered=True),
            managed_inputs(engram_registered=True, engram_gentleman_marked=True),
            managed_inputs(engram_backend_available=False),
        ):
            self.assertIn(classify_engram_ownership(inputs), ENGRAM_OWNERSHIP_STATES)


class MetricsTrustTests(unittest.TestCase):
    def test_managed_route_earns_high_trust(self):
        self.assertEqual(classify_metrics_trust(ROUTE_MANAGED), TRUST_HIGH)

    def test_accidental_mixture_is_unreliable(self):
        self.assertEqual(classify_metrics_trust(ROUTE_MIXED), TRUST_UNRELIABLE)

    def test_deliberate_mixture_is_degraded_not_unreliable(self):
        # A known, documented gap is worth less than a complete picture
        # and more than an unexplained one.
        self.assertEqual(
            classify_metrics_trust(ROUTE_MIXED, advanced_cbm_allowed=True),
            TRUST_DEGRADED,
        )

    def test_bypassed_route_is_unreliable(self):
        self.assertEqual(classify_metrics_trust(ROUTE_BYPASSED), TRUST_UNRELIABLE)

    def test_degraded_route_is_degraded(self):
        self.assertEqual(classify_metrics_trust(ROUTE_DEGRADED), TRUST_DEGRADED)

    def test_unverified_route_never_produces_a_trust_claim(self):
        self.assertEqual(classify_metrics_trust(ROUTE_UNVERIFIED), TRUST_UNVERIFIED)

    def test_every_value_is_a_declared_state(self):
        for route in CONTEXT_ROUTE_STATES:
            self.assertIn(classify_metrics_trust(route), METRICS_TRUST_STATES)


class DuplicateRiskTests(unittest.TestCase):
    def _risks(self, inputs):
        return {f.kind: f.risk for f in duplicate_risk_findings(inputs)}

    def test_mixed_route_detects_retrieval_and_attribution_duplication(self):
        risks = self._risks(managed_inputs(direct_cbm_registered=True))
        self.assertEqual(risks[DUP_CONTEXT_RETRIEVAL], DUPLICATE_DETECTED)
        self.assertEqual(risks[DUP_BACKEND_QUERY], DUPLICATE_DETECTED)
        self.assertEqual(risks[DUP_TOKEN_ATTRIBUTION], DUPLICATE_DETECTED)

    def test_managed_route_reports_no_duplication(self):
        risks = self._risks(managed_inputs())
        self.assertEqual(risks[DUP_CONTEXT_RETRIEVAL], DUPLICATE_NONE)
        self.assertEqual(risks[DUP_TOKEN_ATTRIBUTION], DUPLICATE_NONE)

    def test_shared_engram_is_possible_not_detected(self):
        # Relinkra reads only its own envelope, so the records stay
        # separated. What remains possible is a shared EVENT written by
        # both sides, which no configuration file can rule out.
        risks = self._risks(
            managed_inputs(engram_registered=True, engram_gentleman_marked=True)
        )
        self.assertEqual(risks[DUP_PERSISTED_MEMORY], DUPLICATE_POSSIBLE)

    def test_unclassified_engram_is_unverified_not_none(self):
        risks = self._risks(managed_inputs(engram_registered=True))
        self.assertEqual(risks[DUP_PERSISTED_MEMORY], DUPLICATE_UNVERIFIED)

    def test_unverified_relinkra_cannot_claim_single_sourced_attribution(self):
        risks = self._risks(managed_inputs(relinkra_verified=False))
        self.assertEqual(risks[DUP_TOKEN_ATTRIBUTION], DUPLICATE_UNVERIFIED)

    def test_every_declared_kind_is_classified(self):
        kinds = {f.kind for f in duplicate_risk_findings(managed_inputs())}
        self.assertEqual(kinds, set(DUPLICATE_KINDS))

    def test_every_finding_declares_a_real_observability_level(self):
        for inputs in (managed_inputs(), managed_inputs(direct_cbm_registered=True)):
            for finding in duplicate_risk_findings(inputs):
                self.assertIn(finding.observability, OBSERVABILITY_LEVELS)
                self.assertIn(finding.risk, DUPLICATE_RISK_STATES)
                self.assertTrue(finding.detail)

    def test_aggregate_is_worst_wins(self):
        findings = (
            DuplicateRiskFinding("a", DUPLICATE_NONE, "in_process"),
            DuplicateRiskFinding("b", DUPLICATE_POSSIBLE, "in_process"),
            DuplicateRiskFinding("c", DUPLICATE_DETECTED, "in_process"),
        )
        self.assertEqual(aggregate_duplicate_risk(findings), DUPLICATE_DETECTED)

    def test_aggregate_prefers_possible_over_unverified(self):
        findings = (
            DuplicateRiskFinding("a", DUPLICATE_UNVERIFIED, "outside_process"),
            DuplicateRiskFinding("b", DUPLICATE_POSSIBLE, "in_process"),
        )
        self.assertEqual(aggregate_duplicate_risk(findings), DUPLICATE_POSSIBLE)

    def test_no_findings_is_unverified_never_none(self):
        self.assertEqual(aggregate_duplicate_risk(()), DUPLICATE_UNVERIFIED)


class OwnershipMatrixTests(unittest.TestCase):
    def test_no_domain_is_fully_owned_by_both_systems(self):
        self.assertEqual(duplicate_full_ownership(), ())

    def test_every_domain_has_exactly_one_full_owner(self):
        for rule in OWNERSHIP_MATRIX:
            full = [
                side
                for side in (rule.relinkra_stores, rule.gentleman_stores)
                if side == RECORD_FULL
            ]
            self.assertEqual(len(full), 1, rule.domain)

    def test_the_authority_is_the_side_holding_the_full_record(self):
        for rule in OWNERSHIP_MATRIX:
            holder = (
                AUTHORITY_RELINKRA
                if rule.relinkra_stores == RECORD_FULL
                else AUTHORITY_GENTLEMAN
            )
            self.assertEqual(rule.authority, holder, rule.domain)

    def test_gentleman_keeps_its_sdd_workflow_and_receipts(self):
        self.assertEqual(authority_for("sdd_workflow_state"), AUTHORITY_GENTLEMAN)
        self.assertEqual(
            authority_for("gentleman_reviews_and_receipts"), AUTHORITY_GENTLEMAN
        )
        self.assertEqual(
            authority_for("gentleman_workflow_checkpoints"), AUTHORITY_GENTLEMAN
        )

    def test_relinkra_keeps_the_agent_neutral_half(self):
        for domain in (
            "cross_agent_handoffs",
            "agent_neutral_project_memory",
            "context_packets_and_selection_metadata",
            "portable_memory_code_linkage",
            "git_linked_task_results",
            "relinkra_verification_summaries",
        ):
            self.assertEqual(authority_for(domain), AUTHORITY_RELINKRA, domain)

    def test_relinkra_never_stores_a_full_copy_of_a_gentleman_domain(self):
        for rule in OWNERSHIP_MATRIX:
            if rule.authority == AUTHORITY_GENTLEMAN:
                self.assertIn(
                    rule.relinkra_stores, (RECORD_NONE, RECORD_REFERENCE), rule.domain
                )

    def test_domains_are_unique(self):
        domains = [rule.domain for rule in OWNERSHIP_MATRIX]
        self.assertEqual(len(domains), len(set(domains)))

    def test_unknown_domain_has_no_authority(self):
        self.assertIsNone(authority_for("not_a_domain"))


class TrustLadderTests(unittest.TestCase):
    def test_unverified_stage_is_never_proven(self):
        stage = TrustStage("x", None, "nobody looked")
        self.assertEqual(stage.state, STAGE_UNVERIFIED)
        self.assertFalse(stage.proven)

    def test_states_map_to_the_declared_vocabulary(self):
        self.assertEqual(TrustStage("x", True).state, STAGE_PROVEN)
        self.assertEqual(TrustStage("x", False).state, STAGE_NOT_PROVEN)

    def test_a_ladder_with_one_unverified_stage_is_not_all_proven(self):
        ladder = TrustLadder((TrustStage("a", True), TrustStage("b", None)))
        self.assertFalse(ladder.all_proven)
        self.assertEqual([s.stage for s in ladder.unproven()], ["b"])

    def test_an_empty_ladder_proves_nothing(self):
        self.assertFalse(TrustLadder().all_proven)

    def test_rendering_never_calls_an_unverified_stage_proven(self):
        payload = TrustLadder((TrustStage("a", None),)).to_dict()
        self.assertEqual(payload["stages"][0]["state"], STAGE_UNVERIFIED)
        self.assertFalse(payload["all_proven"])


class AgentContractTests(unittest.TestCase):
    def test_document_declares_it_is_not_written_to_a_host(self):
        document = agent_instruction_document()
        self.assertEqual(document["instruction_version"], INSTRUCTION_VERSION)
        self.assertFalse(document["written_to_host"])

    def test_every_required_instruction_is_present(self):
        ids = {item.instruction_id for item in AGENT_INSTRUCTIONS}
        self.assertLessEqual(
            {
                "context_via_relinkra",
                "memory_via_relinkra",
                "no_direct_cbm",
                "engram_only_for_gentleman",
                "no_double_memory_read",
                "report_degraded_health",
            },
            ids,
        )

    def test_every_instruction_carries_a_rationale(self):
        for item in AGENT_INSTRUCTIONS:
            self.assertTrue(item.text.strip(), item.instruction_id)
            self.assertTrue(item.rationale.strip(), item.instruction_id)

    def test_instruction_ids_are_unique(self):
        ids = [item.instruction_id for item in AGENT_INSTRUCTIONS]
        self.assertEqual(len(ids), len(set(ids)))

    def test_text_rendering_lists_every_instruction(self):
        lines = agent_instruction_text().splitlines()
        self.assertEqual(len(lines), len(AGENT_INSTRUCTIONS))

    def test_document_is_deterministic(self):
        self.assertEqual(agent_instruction_document(), agent_instruction_document())

    def test_recommended_topology_routes_every_backend_through_relinkra(self):
        for line in RECOMMENDED_TOPOLOGY[:3]:
            self.assertTrue(line.startswith("agent -> Relinkra MCP ->"), line)
        self.assertTrue(any("Gentleman -> Engram" in line for line in RECOMMENDED_TOPOLOGY))

    def test_managed_mode_keeps_gentleman_available(self):
        joined = " ".join(MANAGED_MODE_REQUIREMENTS).lower()
        self.assertIn("gentleman tools and workflows remain available", joined)


class DeclaredVocabularyTests(unittest.TestCase):
    """Every emitted value must belong to a declared set.

    The point of closing these enums was to stop loose strings spreading;
    a set nothing checks would not have stopped anything. These are the
    checks.
    """

    def test_backend_kinds_cover_every_detection_backend(self):
        from relinkra.backend_detection import BACKEND_MARKERS

        for markers in BACKEND_MARKERS:
            self.assertIn(markers.backend, BACKEND_KINDS)
        self.assertIn(BACKEND_UNKNOWN, BACKEND_KINDS)

    def test_detection_confidences_cover_every_emitted_confidence(self):
        from relinkra.backend_detection import classify_entry

        entries = (
            ("relinkra", {"command": "py", "args": ["-m", "relinkra.mcp_cli"]}),
            ("relinkra", {"command": "/opt/codebase-memory-mcp"}),
            ("engram", {"type": "remote", "url": "https://x"}),
            ("context7", {"command": "npx", "args": ["-y", "context7-mcp"]}),
        )
        for name, entry in entries:
            self.assertIn(
                classify_entry(name, entry).confidence, DETECTION_CONFIDENCES, name
            )

    def test_stage_states_cover_every_ladder_state(self):
        for value in (True, False, None):
            self.assertIn(TrustStage("s", value).state, STAGE_STATES)

    def test_trust_stages_names_the_full_ladder_the_detector_builds(self):
        from relinkra.backend_detection import build_trust_ladder

        ladder = build_trust_ladder(
            (),
            launch_resolved=False,
            relinkra_registered=False,
            route=ROUTE_UNVERIFIED,
            metrics_trust=TRUST_UNVERIFIED,
            bypass_detected=False,
            handoffs_available=None,
            tools_declared=0,
            real_host_launch_proven=False,
        )
        self.assertEqual(
            tuple(stage.stage for stage in ladder.stages), TRUST_STAGES
        )

    def test_observability_levels_cover_every_duplicate_finding(self):
        for inputs in (
            managed_inputs(),
            managed_inputs(direct_cbm_registered=True),
            managed_inputs(engram_registered=True),
        ):
            for finding in duplicate_risk_findings(inputs):
                self.assertIn(finding.observability, OBSERVABILITY_LEVELS)


class AssessmentShapeTests(unittest.TestCase):
    def test_defaults_are_the_unverified_states(self):
        assessment = RoutingAssessment()
        self.assertEqual(assessment.context_route, ROUTE_UNVERIFIED)
        self.assertEqual(assessment.metrics_trust, TRUST_UNVERIFIED)
        self.assertEqual(assessment.duplicate_risk, DUPLICATE_UNVERIFIED)
        self.assertFalse(assessment.bypass_detected)

    def test_bypass_is_derived_from_cbm_ownership(self):
        for state, expected in (
            (CBM_RELINKRA_PRIVATE, False),
            (CBM_UNAVAILABLE, False),
            (CBM_DIRECTLY_EXPOSED, True),
            (CBM_EXPLICITLY_ALLOWED_ADVANCED, True),
        ):
            self.assertEqual(
                RoutingAssessment(cbm_ownership=state).bypass_detected, expected, state
            )

    def test_payload_carries_the_policy_version(self):
        self.assertEqual(RoutingAssessment().to_dict()["policy_version"], POLICY_VERSION)

    def test_payload_is_deterministic(self):
        assessment = RoutingAssessment(
            duplicate_findings=duplicate_risk_findings(managed_inputs())
        )
        self.assertEqual(assessment.to_dict(), assessment.to_dict())


if __name__ == "__main__":
    unittest.main()
