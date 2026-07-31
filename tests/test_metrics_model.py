"""Tests for the R4C.0 ecosystem metrics vocabulary (typed, uncollected).

Nothing here measures anything, which is exactly what is being asserted.
The failure mode this guards against is a telemetry layer that ships with
plausible zeros: a metric nobody instrumented reporting ``0`` reads as
"this did not happen" and gets quoted as evidence. Every sample this
module can produce today carries ``None`` and says why.
"""

from __future__ import annotations

import json
import unittest

from relinkra.backend_policy import (
    ROUTE_MANAGED,
    ROUTE_MIXED,
    TRUST_HIGH,
    TRUST_UNRELIABLE,
    TRUST_UNVERIFIED,
)
from relinkra.metrics_model import (
    METRICS_VERSION,
    METRIC_DEFINITIONS,
    METRIC_DEFINITIONS_BY_NAME,
    METRIC_SOURCES,
    OBSERVABILITY_DERIVED,
    OBSERVABILITY_LEVELS,
    OBSERVABILITY_OBSERVED,
    OBSERVABILITY_UNAVAILABLE,
    OBSERVABILITY_UNVERIFIED,
    SOURCE_BUDGET,
    SOURCE_CBM,
    SOURCE_DEDUPLICATION,
    SOURCE_DIRECT_AGENT_EXPLORATION,
    SOURCE_ENGRAM,
    SOURCE_GIT,
    SOURCE_HANDOFF,
    SOURCE_REGISTRY,
    SOURCE_RELEVANCE,
    SOURCE_UNKNOWN_EXTERNAL,
    UNITS,
    UNIT_COUNT,
    UNIT_TOKENS,
    EcosystemMetricsRecord,
    MetricSample,
    empty_record,
)

#: Everything section 8 of the R4C.0 brief requires be measurable later.
REQUIRED_METRICS = (
    "total_task_tokens",
    "context_tokens_delivered",
    "tokens_removed_by_budget",
    "tool_calls",
    "files_explored",
    "cbm_queries",
    "engram_queries",
    "git_queries",
    "duplicate_retrievals_avoided",
    "duplicate_retrievals_detected",
    "handoff_reuse",
    "time_to_first_useful_action",
    "total_task_duration",
    "rework",
    "tests_quality_result",
    "attribution_trust",
)


class VocabularyTests(unittest.TestCase):
    def test_every_required_source_is_declared(self):
        self.assertEqual(
            set(METRIC_SOURCES),
            {
                SOURCE_REGISTRY,
                SOURCE_ENGRAM,
                SOURCE_CBM,
                SOURCE_GIT,
                SOURCE_RELEVANCE,
                SOURCE_BUDGET,
                SOURCE_HANDOFF,
                SOURCE_DEDUPLICATION,
                SOURCE_DIRECT_AGENT_EXPLORATION,
                SOURCE_UNKNOWN_EXTERNAL,
            },
        )

    def test_direct_agent_exploration_is_a_first_class_source(self):
        # Work the agent does on its own is not a rounding error. If it
        # is not attributable somewhere, it silently inflates Relinkra's
        # apparent contribution.
        self.assertIn(SOURCE_DIRECT_AGENT_EXPLORATION, METRIC_SOURCES)

    def test_sources_are_unique(self):
        self.assertEqual(len(METRIC_SOURCES), len(set(METRIC_SOURCES)))

    def test_observability_levels_separate_cannot_from_have_not(self):
        self.assertIn(OBSERVABILITY_UNAVAILABLE, OBSERVABILITY_LEVELS)
        self.assertIn(OBSERVABILITY_UNVERIFIED, OBSERVABILITY_LEVELS)
        self.assertNotEqual(OBSERVABILITY_UNAVAILABLE, OBSERVABILITY_UNVERIFIED)


class DefinitionTests(unittest.TestCase):
    def test_every_required_metric_is_defined(self):
        self.assertEqual(set(METRIC_DEFINITIONS_BY_NAME), set(REQUIRED_METRICS))

    def test_metric_names_are_unique(self):
        names = [definition.metric for definition in METRIC_DEFINITIONS]
        self.assertEqual(len(names), len(set(names)))

    def test_every_definition_names_at_least_one_source(self):
        for definition in METRIC_DEFINITIONS:
            self.assertTrue(definition.sources, definition.metric)
            for source in definition.sources:
                self.assertIn(source, METRIC_SOURCES, definition.metric)

    def test_every_definition_uses_a_declared_unit(self):
        for definition in METRIC_DEFINITIONS:
            self.assertIn(definition.unit, UNITS, definition.metric)

    def test_metrics_that_happen_inside_the_agent_are_not_instrumentable(self):
        for name in (
            "total_task_tokens",
            "tool_calls",
            "files_explored",
            "time_to_first_useful_action",
            "total_task_duration",
        ):
            self.assertFalse(
                METRIC_DEFINITIONS_BY_NAME[name].instrumentable, name
            )

    def test_metrics_relinkra_serves_itself_are_instrumentable(self):
        for name in (
            "context_tokens_delivered",
            "tokens_removed_by_budget",
            "cbm_queries",
            "engram_queries",
            "git_queries",
            "handoff_reuse",
        ):
            self.assertTrue(METRIC_DEFINITIONS_BY_NAME[name].instrumentable, name)

    def test_backend_query_counts_are_scoped_to_the_relinkra_route(self):
        # The note matters as much as the number: a direct registration
        # is invisible here, and a reader must not assume otherwise.
        note = METRIC_DEFINITIONS_BY_NAME["cbm_queries"].note.lower()
        self.assertIn("through relinkra", note)

    def test_units_are_the_ones_the_metric_actually_has(self):
        self.assertEqual(METRIC_DEFINITIONS_BY_NAME["cbm_queries"].unit, UNIT_COUNT)
        self.assertEqual(
            METRIC_DEFINITIONS_BY_NAME["context_tokens_delivered"].unit, UNIT_TOKENS
        )


class SampleTests(unittest.TestCase):
    def test_an_unmeasured_sample_is_none_and_never_zero(self):
        sample = MetricSample.unmeasured(METRIC_DEFINITIONS_BY_NAME["cbm_queries"])
        self.assertIsNone(sample.value)
        self.assertFalse(sample.measured)

    def test_an_uninstrumentable_metric_is_unavailable_not_unverified(self):
        sample = MetricSample.unmeasured(METRIC_DEFINITIONS_BY_NAME["files_explored"])
        self.assertEqual(sample.observability, OBSERVABILITY_UNAVAILABLE)

    def test_an_instrumentable_metric_is_unverified_not_unavailable(self):
        sample = MetricSample.unmeasured(METRIC_DEFINITIONS_BY_NAME["git_queries"])
        self.assertEqual(sample.observability, OBSERVABILITY_UNVERIFIED)

    def test_a_value_without_observation_is_still_not_measured(self):
        sample = MetricSample(
            "x", 12.0, UNIT_COUNT, SOURCE_CBM, OBSERVABILITY_UNVERIFIED, TRUST_HIGH
        )
        self.assertFalse(sample.measured)

    def test_an_observed_value_is_measured(self):
        sample = MetricSample(
            "x", 12.0, UNIT_COUNT, SOURCE_CBM, OBSERVABILITY_OBSERVED, TRUST_HIGH
        )
        self.assertTrue(sample.measured)

    def test_a_derived_value_is_measured(self):
        sample = MetricSample(
            "x", 1.0, UNIT_COUNT, SOURCE_BUDGET, OBSERVABILITY_DERIVED, TRUST_HIGH
        )
        self.assertTrue(sample.measured)

    def test_an_unmeasured_sample_explains_itself(self):
        for definition in METRIC_DEFINITIONS:
            sample = MetricSample.unmeasured(definition)
            if definition.note:
                self.assertTrue(sample.detail, definition.metric)


class EmptyRecordTests(unittest.TestCase):
    def test_the_empty_record_measures_nothing(self):
        record = empty_record(trust=TRUST_UNVERIFIED)
        self.assertEqual(record.measured_count, 0)
        self.assertEqual(len(record.samples), len(METRIC_DEFINITIONS))
        for sample in record.samples:
            self.assertIsNone(sample.value)

    def test_the_empty_record_still_lists_every_metric(self):
        record = empty_record()
        self.assertEqual(set(record.by_metric()), set(REQUIRED_METRICS))

    def test_trust_is_carried_onto_every_sample(self):
        record = empty_record(trust=TRUST_UNRELIABLE)
        self.assertEqual(record.trust, TRUST_UNRELIABLE)
        for sample in record.samples:
            self.assertEqual(sample.trust, TRUST_UNRELIABLE)

    def test_an_undeclared_trust_state_is_refused(self):
        with self.assertRaises(ValueError):
            empty_record(trust="pretty-good")

    def test_the_record_carries_the_route_it_was_collected_under(self):
        record = empty_record(context_route=ROUTE_MIXED, trust=TRUST_UNRELIABLE)
        self.assertEqual(record.context_route, ROUTE_MIXED)

    def test_the_payload_never_reports_a_fabricated_number(self):
        payload = empty_record(context_route=ROUTE_MANAGED, trust=TRUST_HIGH).to_dict()
        self.assertEqual(payload["measured_count"], 0)
        for sample in payload["samples"]:
            self.assertIsNone(sample["value"])
            self.assertFalse(sample["measured"])

    def test_the_payload_is_deterministic(self):
        record = empty_record(project_id="rlk_x", task_id="t1")
        self.assertEqual(record.to_dict(), record.to_dict())

    def test_the_payload_is_json_serialisable(self):
        json.dumps(empty_record().to_dict())

    def test_the_payload_carries_the_metrics_version(self):
        self.assertEqual(empty_record().to_dict()["metrics_version"], METRICS_VERSION)

    def test_sources_used_are_reported(self):
        record = empty_record()
        self.assertTrue(set(record.sources_used()) <= set(METRIC_SOURCES))

    def test_a_record_defaults_to_unverified_trust(self):
        self.assertEqual(EcosystemMetricsRecord().trust, TRUST_UNVERIFIED)


if __name__ == "__main__":
    unittest.main()
