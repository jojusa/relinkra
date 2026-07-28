"""Tests for the non-destructive structured merge engine (R4B).

The engine is the piece that decides whether Relinkra may touch someone
else's configuration, so the cases here are written from the standpoint
of the user whose file it is: what must survive, what must never be
overwritten, and what must be refused outright.
"""

from __future__ import annotations

import json
import unittest

from relinkra.config_merge import (
    ACTION_ADD,
    ACTION_CONFLICT,
    ACTION_NO_OP,
    ACTION_UPDATE,
    DEFAULT_INDENT,
    MalformedConfigError,
    UnsupportedShapeError,
    apply_member,
    decide_member,
    detect_indent,
    has_marker,
    merge_entry,
    ownership_test,
    parse_json_document,
    serialize_json_document,
    stamp_marker,
    validate_json_text,
)
from relinkra.connector import MARKER_KEY, MARKER_VALUE
from relinkra.connectors import launches_relinkra

RELINKRA_ENTRY = {
    "command": "/usr/bin/python3",
    "args": ["-m", "relinkra.mcp_cli", "--workspace-root", "/repo"],
}
OTHER_ENTRY = {"command": "node", "args": ["server.js"]}

_MANAGED = ownership_test(launches_relinkra, marker_allowed=False)


class ParseTests(unittest.TestCase):
    def test_empty_file_is_an_empty_object(self):
        # Several hosts create the file before writing anything into it.
        self.assertEqual(parse_json_document(""), {})
        self.assertEqual(parse_json_document("   \n\t "), {})
        self.assertEqual(parse_json_document(None), {})

    def test_bom_prefixed_document_parses(self):
        self.assertEqual(parse_json_document('\ufeff{"a": 1}'), {"a": 1})

    def test_malformed_json_is_typed(self):
        with self.assertRaises(MalformedConfigError):
            parse_json_document('{"a": ')

    def test_non_object_root_is_typed_separately(self):
        # Parsing succeeded; the SHAPE is wrong. Different user action.
        for text in ("[]", '"text"', "3", "null"):
            with self.subTest(text=text):
                with self.assertRaises(UnsupportedShapeError):
                    parse_json_document(text)

    def test_document_nested_too_deeply_is_malformed_not_a_crash(self):
        # ~40 KB of brackets is far under MAX_CONFIG_BYTES, so the size
        # ceiling does not cover this. json.loads raises RecursionError,
        # which is not a ValueError and would otherwise escape every
        # caller and reach the user as a raw traceback.
        payload = '{"mcpServers":' + "[" * 20000 + "]" * 20000 + "}"
        self.assertLess(len(payload), 1_048_576)
        with self.assertRaises(MalformedConfigError):
            parse_json_document(payload)

    def test_utf8_content_round_trips(self):
        document = parse_json_document('{"name": "café ⚙"}')
        rendered = serialize_json_document(document)
        self.assertIn("café ⚙", rendered)
        self.assertEqual(parse_json_document(rendered), document)

    def test_validate_json_text_rejects_garbage(self):
        validate_json_text('{"ok": true}')
        with self.assertRaises(MalformedConfigError):
            validate_json_text("{oops")


class SerializationTests(unittest.TestCase):
    def test_key_order_is_the_documents_own(self):
        # Sorting would reorder the user's whole file and turn a
        # one-member addition into a whole-file diff in their VCS.
        document = {"zebra": 1, "alpha": 2, "mid": 3}
        rendered = serialize_json_document(document)
        self.assertLess(rendered.index("zebra"), rendered.index("alpha"))

    def test_serialization_is_deterministic(self):
        document = parse_json_document('{"b": 1, "a": {"x": [1, 2]}}')
        self.assertEqual(
            serialize_json_document(document), serialize_json_document(document)
        )

    def test_crlf_is_preserved(self):
        rendered = serialize_json_document({"a": 1, "b": [1, 2]}, newline="\r\n")
        self.assertIn("\r\n", rendered)
        # Every LF must be part of a CRLF: a stray bare LF would mean the
        # rewrite mixed line endings inside the user's file.
        self.assertEqual(rendered.count("\n"), rendered.count("\r\n"))
        self.assertEqual(json.loads(rendered), {"a": 1, "b": [1, 2]})

    def test_trailing_newline_is_optional(self):
        self.assertTrue(serialize_json_document({"a": 1}).endswith("\n"))
        self.assertFalse(
            serialize_json_document({"a": 1}, trailing_newline=False).endswith("\n")
        )

    def test_detect_indent_reads_the_document(self):
        self.assertEqual(detect_indent('{\n    "a": 1\n}'), 4)
        self.assertEqual(detect_indent('{\n  "a": 1\n}'), 2)
        self.assertEqual(detect_indent('{\n\t"a": 1\n}'), "\t")
        self.assertEqual(detect_indent("{}"), DEFAULT_INDENT)
        self.assertEqual(detect_indent(""), DEFAULT_INDENT)

    def test_detected_indent_round_trips(self):
        original = '{\n    "a": 1\n}\n'
        document = parse_json_document(original)
        rendered = serialize_json_document(document, indent=detect_indent(original))
        self.assertEqual(rendered, original)


class OwnershipTests(unittest.TestCase):
    def test_relinkra_module_entry_is_owned(self):
        self.assertTrue(_MANAGED(RELINKRA_ENTRY))

    def test_console_script_entry_is_owned(self):
        for command in ("relinkra-mcp", "/opt/bin/relinkra-mcp", r"C:\bin\relinkra-mcp.exe"):
            with self.subTest(command=command):
                self.assertTrue(_MANAGED({"command": command, "args": []}))

    def test_list_command_entry_is_owned(self):
        # OpenCode stores the program as element 0 of `command`.
        self.assertTrue(
            _MANAGED({"type": "local", "command": ["python", "-m", "relinkra.mcp_cli"]})
        )

    def test_unrelated_entry_is_not_owned(self):
        self.assertFalse(_MANAGED(OTHER_ENTRY))

    def test_non_mapping_entry_is_not_owned(self):
        for entry in ("relinkra", ["relinkra.mcp_cli"], 7, None):
            with self.subTest(entry=entry):
                self.assertFalse(_MANAGED(entry))

    def test_a_name_alone_never_confers_ownership(self):
        # The whole point: the NAME is what a coincidental user entry
        # would share, so ownership is decided by what it launches.
        self.assertFalse(_MANAGED({"command": "relinkra", "args": ["--serve"]}))

    def test_marker_is_ignored_unless_the_host_allows_it(self):
        marked = stamp_marker(OTHER_ENTRY)
        self.assertTrue(has_marker(marked))
        self.assertFalse(_MANAGED(marked))
        permissive = ownership_test(launches_relinkra, marker_allowed=True)
        self.assertTrue(permissive(marked))

    def test_marker_helpers_do_not_mutate_the_input(self):
        original = dict(OTHER_ENTRY)
        stamp_marker(original)
        self.assertNotIn(MARKER_KEY, original)
        self.assertEqual(stamp_marker(original)[MARKER_KEY], MARKER_VALUE)


class DecisionTests(unittest.TestCase):
    def decide(self, document, desired=None):
        return decide_member(
            document,
            ("mcpServers",),
            "relinkra",
            desired or RELINKRA_ENTRY,
            is_managed=_MANAGED,
        )

    def test_absent_container_is_an_add(self):
        decision = self.decide({})
        self.assertEqual(decision.action, ACTION_ADD)
        self.assertEqual(decision.containers_created, ("mcpServers",))

    def test_empty_container_is_an_add(self):
        decision = self.decide({"mcpServers": {}})
        self.assertEqual(decision.action, ACTION_ADD)
        self.assertEqual(decision.containers_created, ())

    def test_correct_existing_entry_is_a_no_op(self):
        decision = self.decide({"mcpServers": {"relinkra": dict(RELINKRA_ENTRY)}})
        self.assertEqual(decision.action, ACTION_NO_OP)
        self.assertFalse(decision.changes_anything)

    def test_stale_managed_entry_is_an_update(self):
        stale = {
            "command": "python",
            "args": ["-m", "relinkra.mcp_cli", "--workspace-root", "/old"],
        }
        decision = self.decide({"mcpServers": {"relinkra": stale}})
        self.assertEqual(decision.action, ACTION_UPDATE)
        self.assertTrue(decision.changes_anything)
        self.assertEqual(decision.member["args"], RELINKRA_ENTRY["args"])

    def test_user_owned_entry_of_the_same_name_is_a_conflict(self):
        decision = self.decide({"mcpServers": {"relinkra": dict(OTHER_ENTRY)}})
        self.assertEqual(decision.action, ACTION_CONFLICT)
        self.assertIsNone(decision.member)
        self.assertIn("not created by Relinkra", decision.reason)

    def test_non_object_entry_of_the_same_name_is_a_conflict(self):
        decision = self.decide({"mcpServers": {"relinkra": "some-string"}})
        self.assertEqual(decision.action, ACTION_CONFLICT)
        self.assertEqual(decision.existing_kind, "str")

    def test_unknown_fields_on_a_managed_entry_survive(self):
        existing = dict(RELINKRA_ENTRY)
        existing["disabled"] = True
        existing["hostSpecificThing"] = {"deep": 1}
        decision = self.decide({"mcpServers": {"relinkra": existing}})
        # Nothing Relinkra manages changed, so this must be a no-op —
        # NOT an update that quietly resets the user's own fields.
        self.assertEqual(decision.action, ACTION_NO_OP)
        self.assertTrue(decision.member["disabled"])
        self.assertEqual(decision.member["hostSpecificThing"], {"deep": 1})

    def test_unknown_fields_survive_an_actual_update(self):
        existing = {
            "command": "python",
            "args": ["-m", "relinkra.mcp_cli"],
            "disabled": True,
        }
        decision = self.decide({"mcpServers": {"relinkra": existing}})
        self.assertEqual(decision.action, ACTION_UPDATE)
        self.assertTrue(decision.member["disabled"])

    def test_non_object_container_is_refused_not_guessed(self):
        for container in ([], "text", 7):
            with self.subTest(container=container):
                with self.assertRaises(UnsupportedShapeError):
                    self.decide({"mcpServers": container})

    def test_nested_container_path(self):
        decision = decide_member(
            {"projects": {"demo": {"mcpServers": {"relinkra": dict(RELINKRA_ENTRY)}}}},
            ("projects", "demo", "mcpServers"),
            "relinkra",
            RELINKRA_ENTRY,
            is_managed=_MANAGED,
        )
        self.assertEqual(decision.action, ACTION_NO_OP)

    def test_nested_container_reports_every_missing_level(self):
        decision = decide_member(
            {},
            ("projects", "demo", "mcpServers"),
            "relinkra",
            RELINKRA_ENTRY,
            is_managed=_MANAGED,
        )
        self.assertEqual(decision.action, ACTION_ADD)
        self.assertEqual(
            decision.containers_created, ("projects", "demo", "mcpServers")
        )

    def test_null_container_is_treated_as_absent(self):
        decision = self.decide({"mcpServers": None})
        self.assertEqual(decision.action, ACTION_ADD)

    def test_desired_member_must_be_an_object(self):
        with self.assertRaises(UnsupportedShapeError):
            decide_member(
                {}, ("mcpServers",), "relinkra", ["not", "an", "object"],
                is_managed=_MANAGED,
            )

    def test_decision_dict_is_serializable(self):
        payload = self.decide({}).to_dict()
        self.assertEqual(json.loads(json.dumps(payload)), payload)


class ApplyTests(unittest.TestCase):
    def test_unrelated_entries_are_preserved(self):
        document = {
            "$schema": "https://example.invalid/schema.json",
            "theme": "dark",
            "mcpServers": {
                "context7": {"command": "npx", "args": ["-y", "ctx"]},
                "engram": {"command": "engram", "args": ["mcp"]},
            },
        }
        result = apply_member(document, ("mcpServers",), "relinkra", RELINKRA_ENTRY)
        self.assertEqual(result["$schema"], document["$schema"])
        self.assertEqual(result["theme"], "dark")
        self.assertEqual(result["mcpServers"]["context7"], document["mcpServers"]["context7"])
        self.assertEqual(result["mcpServers"]["engram"], document["mcpServers"]["engram"])
        self.assertEqual(result["mcpServers"]["relinkra"], RELINKRA_ENTRY)

    def test_input_document_is_never_mutated(self):
        document = {"mcpServers": {"other": dict(OTHER_ENTRY)}}
        snapshot = json.dumps(document, sort_keys=True)
        apply_member(document, ("mcpServers",), "relinkra", RELINKRA_ENTRY)
        self.assertEqual(json.dumps(document, sort_keys=True), snapshot)

    def test_missing_containers_are_created(self):
        result = apply_member({}, ("a", "b", "c"), "relinkra", RELINKRA_ENTRY)
        self.assertEqual(result["a"]["b"]["c"]["relinkra"], RELINKRA_ENTRY)

    def test_apply_refuses_a_non_object_container(self):
        with self.assertRaises(UnsupportedShapeError):
            apply_member({"mcpServers": []}, ("mcpServers",), "relinkra", RELINKRA_ENTRY)

    def test_applied_member_is_deep_copied(self):
        desired = {"command": "python", "args": ["-m", "relinkra.mcp_cli"]}
        result = apply_member({}, ("mcpServers",), "relinkra", desired)
        desired["args"].append("--tampered")
        self.assertEqual(result["mcpServers"]["relinkra"]["args"], ["-m", "relinkra.mcp_cli"])

    def test_apply_then_decide_is_a_no_op(self):
        # The idempotency property the plan engine depends on.
        document = {"mcpServers": {"other": dict(OTHER_ENTRY)}}
        applied = apply_member(document, ("mcpServers",), "relinkra", RELINKRA_ENTRY)
        decision = decide_member(
            applied, ("mcpServers",), "relinkra", RELINKRA_ENTRY, is_managed=_MANAGED
        )
        self.assertEqual(decision.action, ACTION_NO_OP)


class MergeEntryTests(unittest.TestCase):
    def test_desired_fields_win(self):
        merged = merge_entry({"command": "old", "extra": 1}, {"command": "new"})
        self.assertEqual(merged["command"], "new")
        self.assertEqual(merged["extra"], 1)

    def test_non_mapping_existing_is_replaced_wholesale(self):
        self.assertEqual(merge_entry("junk", {"command": "new"}), {"command": "new"})


if __name__ == "__main__":
    unittest.main()
