"""Tests for Relinkra's side of a shared memory backend (R4C.0).

The constraint under test is NON-INTERFERENCE. Engram holds records from
more than one system, Gentleman was there first, and Relinkra must be
able to read, write and diagnose its own memory without reinterpreting,
rewriting, copying or even parsing anybody else's.

Every "Gentleman record" below is a fixture written directly into the
store, never through Relinkra. That is the point: the tests assert what
happens to records Relinkra did not create, which is the only situation
where interference could occur.
"""

from __future__ import annotations

import json
import unittest

from relinkra.engram_adapter import InMemoryStore
from relinkra.memory import ENVELOPE_VERSION, MemoryService
from relinkra.memory_ownership import (
    MAX_EXTERNAL_ID_CHARS,
    MAX_SUMMARY_CHARS,
    OP_READ,
    OP_WRITE,
    OWNER_EXTERNAL,
    OWNER_RELINKRA,
    REFERENCE_KIND_DOMAIN,
    REFERENCE_VERSION,
    SOURCE_GENTLEMAN,
    ExternalReference,
    ExternalReferenceError,
    ObservingStore,
    OperationLedger,
    build_external_reference,
    classify_record,
    is_relinkra_owned,
    partition_records,
    read_external_reference,
    save_external_reference,
)

PID = "rlk_" + "a" * 32
REPO = {
    "kind": "remote",
    "value": "remote://git/github.com/org/repo",
    "trust": "strong",
}

#: What a Gentleman-style record plausibly looks like in a shared store.
#: Deliberately NOT rlkmem1 and deliberately JSON, because the dangerous
#: case is a record that parses cleanly and still is not ours.
GENTLEMAN_RECORDS = (
    json.dumps(
        {
            "v": "gentleman-sdd/v1",
            "phase": "apply",
            "change": "add-routing-policy",
            "receipt": "lineage-7f3a",
        }
    ),
    json.dumps(
        {
            "kind": "review_receipt",
            "lineage": "lineage-7f3a",
            "result": "allow",
            "target_tree": "8c1d2e4f6a7b8c9d0e1f2a3b4c5d6e7f80912a3b",
            "findings": [
                {
                    "severity": "warning",
                    "lens": "review-readability",
                    "file": "relinkra/backend_detection.py",
                    "text": "naming: marker table would read better as a mapping",
                },
                {
                    "severity": "suggestion",
                    "lens": "review-reliability",
                    "file": "tests/test_backend_policy.py",
                    "text": "consider asserting the aggregate ordering directly",
                },
            ],
            "evidence": "1199 tests OK, skipped=9",
        }
    ),
    "SDD phase note: apply completed, 12 tasks closed.",
)


def make_service(store=None):
    store = store or InMemoryStore()
    tick = {"n": 0}
    ids = {"n": 0}

    def clock():
        tick["n"] += 1
        return f"2026-01-01T00:00:{tick['n']:02d}+00:00"

    def id_gen():
        ids["n"] += 1
        return f"mem_{ids['n']:016x}"

    return MemoryService(store, clock=clock, id_generator=id_gen), store


def seed_gentleman(store):
    """Write Gentleman-style records straight into the store."""
    for index, content in enumerate(GENTLEMAN_RECORDS):
        store.save_record(
            title=f"gentleman record {index}",
            content=content,
            storage_type="manual",
            project=PID,
            scope="project",
            topic_key=f"gentleman/v1/{index}",
        )


def store_snapshot(store):
    return [
        (record.title, record.content, record.storage_type)
        for record in store.search_records(query="", project=PID, limit=500)
    ]


class RecordOwnershipTests(unittest.TestCase):
    def test_the_relinkra_envelope_is_recognised(self):
        content = json.dumps({"v": ENVELOPE_VERSION, "memory_id": "mem_1"})
        ownership = classify_record(content)
        self.assertEqual(ownership.owner, OWNER_RELINKRA)
        self.assertTrue(ownership.relinkra_native)
        self.assertEqual(ownership.envelope_version, ENVELOPE_VERSION)

    def test_a_foreign_envelope_version_is_never_relinkra_owned(self):
        ownership = classify_record(json.dumps({"v": "gentleman-sdd/v1"}))
        self.assertEqual(ownership.owner, OWNER_EXTERNAL)
        self.assertEqual(ownership.envelope_version, "gentleman-sdd/v1")

    def test_a_record_with_no_version_is_external(self):
        self.assertFalse(is_relinkra_owned(json.dumps({"kind": "review_receipt"})))

    def test_plain_text_is_external_not_a_crash(self):
        ownership = classify_record("just a note someone wrote")
        self.assertEqual(ownership.owner, OWNER_EXTERNAL)

    def test_a_json_array_is_external(self):
        self.assertFalse(is_relinkra_owned("[1, 2, 3]"))

    def test_none_is_external(self):
        self.assertFalse(is_relinkra_owned(None))

    def test_a_mapping_is_accepted_without_re_serialising(self):
        self.assertTrue(is_relinkra_owned({"v": ENVELOPE_VERSION}))

    def test_every_gentleman_fixture_is_classified_external(self):
        for content in GENTLEMAN_RECORDS:
            self.assertFalse(is_relinkra_owned(content), content[:40])

    def test_ownership_never_guesses_from_shape(self):
        # A record carrying every Relinkra field EXCEPT the envelope
        # version is still not ours. Shape-matching here is precisely how
        # a tool starts serving somebody else's data as its own.
        lookalike = json.dumps(
            {
                "memory_id": "mem_x",
                "project_id": PID,
                "memory_type": "decision",
                "title": "T",
                "timestamp": "2026-01-01T00:00:00+00:00",
                "scope": "project_shared",
                "repository_identity": REPO,
            }
        )
        self.assertFalse(is_relinkra_owned(lookalike))

    def test_partition_separates_without_dropping_anything(self):
        _, store = make_service()
        seed_gentleman(store)
        records = store.search_records(query="", project=PID, limit=500)
        owned, external = partition_records(records)
        self.assertEqual(owned, [])
        self.assertEqual(len(external), len(GENTLEMAN_RECORDS))


class GentlemanNonInterferenceTests(unittest.TestCase):
    """Relinkra shares the store. It does not touch what is not its own."""

    def setUp(self):
        self.service, self.store = make_service()
        seed_gentleman(self.store)
        self.before = store_snapshot(self.store)

    def test_gentleman_records_survive_a_relinkra_save_unchanged(self):
        self.service.save(
            project_id=PID,
            memory_type="decision",
            title="Route context through Relinkra",
            body="CBM stays private.",
            repository_identity=REPO,
        )
        after = store_snapshot(self.store)
        for record in self.before:
            self.assertIn(record, after)

    def test_gentleman_records_survive_a_relinkra_query_unchanged(self):
        self.service.query(project_id=PID, scope="project_shared", limit=25)
        self.assertEqual(store_snapshot(self.store), self.before)

    def test_gentleman_records_are_not_selected_as_relinkra_memories(self):
        self.service.save(
            project_id=PID,
            memory_type="decision",
            title="Ours",
            body="Ours",
            repository_identity=REPO,
        )
        result = self.service.query(project_id=PID, scope="project_shared", limit=50)
        titles = [memory.title for memory in result.memories]
        self.assertEqual(titles, ["Ours"])
        for title in titles:
            self.assertNotIn("gentleman", title.lower())

    def test_relinkra_records_stay_readable_beside_gentleman_records(self):
        for index in range(3):
            self.service.save(
                project_id=PID,
                memory_type="decision",
                title=f"Decision {index}",
                body=f"body {index}",
                repository_identity=REPO,
            )
        result = self.service.query(project_id=PID, scope="project_shared", limit=50)
        self.assertEqual(len(result.memories), 3)

    def test_a_foreign_record_the_store_returns_is_skipped_not_parsed(self):
        # Force the store to hand the foreign records back by searching
        # for text they contain. They still reach the envelope parser,
        # and the parser still refuses every one of them.
        result = self.service.query(
            project_id=PID, scope="project_shared", text="gentleman", limit=50
        )
        self.assertEqual(result.memories, [])
        self.assertGreater(result.skipped_malformed, 0)

    def test_a_default_query_returns_no_foreign_records_at_all(self):
        result = self.service.query(project_id=PID, scope="project_shared", limit=50)
        self.assertEqual(result.memories, [])

    def test_relinkra_never_supersedes_a_foreign_record(self):
        # Supersession works over topic keys, and a foreign record has no
        # Relinkra topic key at all — so it can never be selected as the
        # prior version of anything Relinkra writes.
        _, _, superseded = self.service.save(
            project_id=PID,
            memory_type="verification",
            title="review_receipt lineage-7f3a",
            body="ok",
            repository_identity=REPO,
        )
        self.assertEqual(superseded, [])
        after = store_snapshot(self.store)
        for record in self.before:
            self.assertIn(record, after)


class ExternalReferenceTests(unittest.TestCase):
    def setUp(self):
        self.service, self.store = make_service()

    def test_a_review_receipt_may_be_referenced(self):
        reference = build_external_reference(
            source_system=SOURCE_GENTLEMAN,
            external_id="lineage-7f3a",
            kind="review_receipt",
            summary="allow",
        )
        self.assertEqual(reference.source_system, SOURCE_GENTLEMAN)
        self.assertEqual(reference.external_id, "lineage-7f3a")

    def test_sdd_workflow_state_may_not_be_referenced_at_all(self):
        # The matrix gives Relinkra NO record for that domain, and "just
        # a pointer" is still a record.
        with self.assertRaises(ExternalReferenceError) as caught:
            build_external_reference(
                source_system=SOURCE_GENTLEMAN,
                external_id="change-1",
                kind="sdd_phase",
            )
        self.assertIn("belongs entirely to its authority", str(caught.exception))

    def test_workflow_checkpoints_may_not_be_referenced(self):
        with self.assertRaises(ExternalReferenceError):
            build_external_reference(
                source_system=SOURCE_GENTLEMAN,
                external_id="ckpt-1",
                kind="workflow_checkpoint",
            )

    def test_an_oversized_summary_is_refused_as_a_copy(self):
        with self.assertRaises(ExternalReferenceError) as caught:
            build_external_reference(
                source_system=SOURCE_GENTLEMAN,
                external_id="lineage-7f3a",
                kind="review_receipt",
                summary="x" * (MAX_SUMMARY_CHARS + 1),
            )
        self.assertIn("not a copy", str(caught.exception))

    def test_an_oversized_external_id_is_refused(self):
        with self.assertRaises(ExternalReferenceError):
            build_external_reference(
                source_system=SOURCE_GENTLEMAN,
                external_id="x" * (MAX_EXTERNAL_ID_CHARS + 1),
                kind="review_receipt",
            )

    def test_an_empty_external_id_is_refused(self):
        with self.assertRaises(ExternalReferenceError):
            build_external_reference(
                source_system=SOURCE_GENTLEMAN, external_id="  ", kind="review_receipt"
            )

    def test_an_unknown_source_system_is_refused(self):
        with self.assertRaises(ExternalReferenceError):
            build_external_reference(
                source_system="mystery", external_id="x", kind="review_receipt"
            )

    def test_an_unknown_kind_is_refused(self):
        with self.assertRaises(ExternalReferenceError):
            build_external_reference(
                source_system=SOURCE_GENTLEMAN, external_id="x", kind="invented"
            )

    def test_every_declared_kind_maps_to_a_matrix_domain(self):
        from relinkra.backend_policy import OWNERSHIP_MATRIX

        domains = {rule.domain for rule in OWNERSHIP_MATRIX}
        for kind, domain in REFERENCE_KIND_DOMAIN.items():
            self.assertIn(domain, domains, kind)

    def test_a_saved_reference_goes_through_the_memory_service(self):
        reference = build_external_reference(
            source_system=SOURCE_GENTLEMAN,
            external_id="lineage-7f3a",
            kind="review_receipt",
            summary="allow, 0 blockers",
        )
        memory, deduplicated, _ = save_external_reference(
            self.service,
            project_id=PID,
            repository_identity=REPO,
            reference=reference,
        )
        self.assertFalse(deduplicated)
        # It is Relinkra memory: full envelope, Relinkra topic key.
        self.assertTrue(memory.topic_key.startswith("relinkra/v1/"))
        self.assertTrue(is_relinkra_owned(memory.envelope_json()))

    def test_a_referenced_review_stores_no_duplicate_full_payload(self):
        full_receipt = json.loads(GENTLEMAN_RECORDS[1])
        reference = build_external_reference(
            source_system=SOURCE_GENTLEMAN,
            external_id=full_receipt["lineage"],
            kind="review_receipt",
            summary=f"result={full_receipt['result']}",
        )
        memory, _, _ = save_external_reference(
            self.service,
            project_id=PID,
            repository_identity=REPO,
            reference=reference,
        )
        stored = memory.envelope_json()
        # The pointer is there; the payload is not.
        self.assertIn("lineage-7f3a", stored)
        self.assertNotIn("findings", stored)
        self.assertNotIn("review-readability", stored)
        self.assertNotIn("target_tree", stored)
        # A reference is bounded by construction; the record it points at
        # is not. That difference is the whole guarantee.
        self.assertLess(len(memory.body), len(GENTLEMAN_RECORDS[1]))
        self.assertLessEqual(len(reference.summary), MAX_SUMMARY_CHARS)

    def test_a_reference_round_trips_through_its_body(self):
        reference = build_external_reference(
            source_system=SOURCE_GENTLEMAN,
            external_id="lineage-7f3a",
            kind="review_receipt",
            summary="allow",
        )
        parsed = read_external_reference(reference.to_body())
        self.assertEqual(parsed, reference)

    def test_ordinary_prose_is_not_mistaken_for_a_reference(self):
        self.assertIsNone(read_external_reference("we decided to use stdio"))
        self.assertIsNone(read_external_reference(json.dumps({"ref": "other/v9"})))

    def test_a_reference_with_an_unknown_kind_is_not_parsed_back(self):
        body = json.dumps({"ref": REFERENCE_VERSION, "kind": "invented"})
        self.assertIsNone(read_external_reference(body))

    def test_the_body_is_deterministic(self):
        reference = ExternalReference(SOURCE_GENTLEMAN, "id", "review_receipt", "s")
        self.assertEqual(reference.to_body(), reference.to_body())

    def test_referencing_a_review_leaves_gentleman_records_untouched(self):
        seed_gentleman(self.store)
        before = store_snapshot(self.store)
        save_external_reference(
            self.service,
            project_id=PID,
            repository_identity=REPO,
            reference=build_external_reference(
                source_system=SOURCE_GENTLEMAN,
                external_id="lineage-7f3a",
                kind="review_receipt",
                summary="allow",
            ),
        )
        for record in before:
            self.assertIn(record, store_snapshot(self.store))


class OperationLedgerTests(unittest.TestCase):
    def test_an_empty_ledger_reports_no_duplicates(self):
        self.assertEqual(OperationLedger().duplicates(), ())

    def test_repeated_identical_reads_are_counted(self):
        ledger = OperationLedger()
        ledger.record(OP_READ, "q|p|t|200")
        ledger.record(OP_READ, "q|p|t|200")
        ledger.record(OP_READ, "other")
        duplicates = ledger.duplicates()
        self.assertEqual(len(duplicates), 1)
        self.assertEqual(duplicates[0].count, 2)
        self.assertEqual(ledger.duplicate_reads_avoidable, 1)

    def test_reads_and_writes_are_counted_separately(self):
        ledger = OperationLedger()
        ledger.record(OP_READ, "same")
        ledger.record(OP_WRITE, "same")
        self.assertEqual(ledger.duplicates(), ())
        self.assertEqual(ledger.read_calls, 1)
        self.assertEqual(ledger.write_calls, 1)

    def test_reset_clears_the_operation(self):
        ledger = OperationLedger()
        ledger.record(OP_READ, "a")
        ledger.reset()
        self.assertEqual(ledger.read_calls, 0)

    def test_the_payload_is_deterministic(self):
        ledger = OperationLedger()
        for key in ("b", "a", "b"):
            ledger.record(OP_READ, key)
        self.assertEqual(ledger.to_dict(), ledger.to_dict())


class ObservingStoreTests(unittest.TestCase):
    def setUp(self):
        self.inner = InMemoryStore()
        self.observed = ObservingStore(self.inner)
        self.service, _ = make_service(self.observed)

    def test_observation_does_not_change_what_the_service_returns(self):
        plain_service, plain_store = make_service()
        for service in (self.service, plain_service):
            service.save(
                project_id=PID,
                memory_type="decision",
                title="T",
                body="B",
                repository_identity=REPO,
            )
        observed = self.service.query(project_id=PID, scope="project_shared", limit=10)
        plain = plain_service.query(project_id=PID, scope="project_shared", limit=10)
        self.assertEqual(
            [m.title for m in observed.memories], [m.title for m in plain.memories]
        )

    def test_a_save_records_exactly_one_write(self):
        self.service.save(
            project_id=PID,
            memory_type="decision",
            title="T",
            body="B",
            repository_identity=REPO,
        )
        self.assertEqual(self.observed.ledger.write_calls, 1)

    def test_a_single_save_performs_more_than_one_read(self):
        # Dedup and topic supersession each consult the store, and the
        # ledger exists precisely to make that visible rather than
        # leaving it as folklore about a hot path.
        self.service.save(
            project_id=PID,
            memory_type="decision",
            title="T",
            body="B",
            repository_identity=REPO,
        )
        self.assertGreater(self.observed.ledger.read_calls, 1)

    def test_identical_repeated_reads_are_reported_as_duplicates(self):
        self.observed.ledger.reset()
        for _ in range(3):
            self.service.query(project_id=PID, scope="project_shared", limit=10)
        duplicates = self.observed.ledger.duplicates()
        self.assertTrue(duplicates)
        self.assertEqual(duplicates[0].operation, OP_READ)
        self.assertEqual(self.observed.ledger.duplicate_reads_avoidable, 2)

    def test_writes_of_different_content_are_not_duplicates(self):
        for index in range(2):
            self.service.save(
                project_id=PID,
                memory_type="decision",
                title=f"T{index}",
                body="B",
                repository_identity=REPO,
            )
        write_duplicates = [
            item for item in self.observed.ledger.duplicates() if item.operation == OP_WRITE
        ]
        self.assertEqual(write_duplicates, [])

    def test_the_ledger_never_holds_raw_record_content(self):
        self.service.save(
            project_id=PID,
            memory_type="decision",
            title="a very distinctive title",
            body="a very distinctive body",
            repository_identity=REPO,
        )
        payload = json.dumps(self.observed.ledger.to_dict())
        self.assertNotIn("distinctive body", payload)

    def test_unwrapped_attributes_pass_through(self):
        self.assertIs(self.observed.saved_args, self.inner.saved_args)

    def test_the_decorator_is_not_a_cache(self):
        # A read after a save must see the save. Silently collapsing the
        # second call would change MemoryService semantics.
        self.service.save(
            project_id=PID,
            memory_type="decision",
            title="First",
            body="B",
            repository_identity=REPO,
        )
        first = self.service.query(project_id=PID, scope="project_shared", limit=10)
        self.service.save(
            project_id=PID,
            memory_type="discovery",
            title="Second",
            body="B",
            repository_identity=REPO,
        )
        second = self.service.query(project_id=PID, scope="project_shared", limit=10)
        self.assertEqual(len(first.memories), 1)
        self.assertEqual(len(second.memories), 2)


if __name__ == "__main__":
    unittest.main()
