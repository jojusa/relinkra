"""UTF-8 stdout regression tests for the context CLI.

On Windows a redirected stdout uses the locale codec (cp1252), so the
CLI's text ``print`` crashed with ``UnicodeEncodeError`` as soon as a
packet carried valid Unicode outside cp1252 (a rightwards arrow in real
engram content), exiting 1 with empty stdout. The CLI now writes the
document as UTF-8 bytes through the binary stdout buffer.

The fixture redirects stdout to a cp1252 ``TextIOWrapper`` over a binary
buffer -- the same stream shape Python builds for a redirected stdout on
Windows -- so the defect class stays covered without depending on the
host's console code page.
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
import unittest

from relinkra import context_cli

try:
    from tests.test_context_packet import Env, fixed_clock
except ImportError:  # pragma: no cover - discover vs module invocation
    from test_context_packet import Env, fixed_clock

ARROW = "\u2192"
SPANISH = "caf\u00e9 ni\u00f1o se\u00f1al \u00bfqu\u00e9? \u00e1\u00e9\u00ed\u00f3\u00fa\u00f1"
NON_CP1252 = "\u4e2d\u6587 \u03bb \u2588"
UNICODE_BODY = f"Deploy {ARROW} verify; {SPANISH}; non-cp1252: {NON_CP1252}"


class Cp1252Stdout:
    """Redirect ``sys.stdout`` to a cp1252 text layer over a byte buffer."""

    def __init__(self):
        self.raw = io.BytesIO()
        self._previous = None
        self.stream = None

    def __enter__(self):
        self._previous = sys.stdout
        self.stream = io.TextIOWrapper(
            self.raw, encoding="cp1252", newline="\n"
        )
        sys.stdout = self.stream
        return self

    def __exit__(self, *exc_info):
        sys.stdout = self._previous
        # Detach so garbage collection of the text layer cannot close the
        # bytes buffer before the test reads it.
        try:
            self.stream.detach()
        except (ValueError, OSError):
            pass
        return False

    @property
    def bytes(self) -> bytes:
        return self.raw.getvalue()


class ContextCliStdoutEncodingTests(unittest.TestCase):
    def setUp(self):
        self.env = Env(seed=False)
        self.addCleanup(self.env.cleanup)
        self.env.save(
            memory_type="handoff",
            title="Unicode wiring handoff " + ARROW,
            body=UNICODE_BODY,
        )
        self.env.save(
            memory_type="decision", title="Accents " + SPANISH, body=ARROW
        )

    def argv(self, *extra):
        return [
            "--project-id", self.env.project_id,
            "--registry", self.env.registry_path,
            *extra,
        ]

    def run_cli(self, *extra):
        """Run the CLI under a cp1252 stdout redirect; return (bytes, err)."""
        err = io.StringIO()
        with Cp1252Stdout() as captured:
            with contextlib.redirect_stderr(err):
                code = context_cli.main(
                    self.argv(*extra), store=self.env.store, clock=fixed_clock
                )
        self.assertEqual(code, 0, err.getvalue())
        return captured.bytes, err.getvalue()

    def test_redirected_cp1252_stdout_exit_success(self):
        # A: the exact defect condition must not raise UnicodeEncodeError.
        payload, err = self.run_cli()
        self.assertTrue(payload)

    def test_emitted_bytes_decode_as_utf8(self):
        # B: the wire bytes are UTF-8, not cp1252.
        payload, _ = self.run_cli()
        payload.decode("utf-8")

    def test_emitted_json_parses(self):
        # C: the emitted document stays a valid JSON packet.
        payload, _ = self.run_cli()
        packet = json.loads(payload.decode("utf-8"))
        self.assertEqual(packet["project_id"], self.env.project_id)

    def test_unicode_value_survives_exactly(self):
        # D: no replacement, sanitizing, or escaping of valid content.
        self.assertRaises(UnicodeEncodeError, ARROW.encode, "cp1252")
        self.assertRaises(UnicodeEncodeError, NON_CP1252.encode, "cp1252")
        payload, _ = self.run_cli()
        text = payload.decode("utf-8")
        self.assertEqual(text.encode("utf-8"), payload)
        self.assertNotIn("\ufffd", text)
        packet = json.loads(text)
        handoff = next(
            item for item in packet["handoffs"]
            if item["data"]["title"].startswith("Unicode wiring handoff")
        )
        self.assertEqual(handoff["data"]["body"], UNICODE_BODY)
        decision = next(
            item for item in packet["memories"]
            if item["data"]["title"] == "Accents " + SPANISH
        )
        self.assertEqual(decision["data"]["body"], ARROW)

    def test_pretty_output_still_valid(self):
        # E: --pretty keeps its indentation and trailing newline.
        payload, _ = self.run_cli("--pretty")
        text = payload.decode("utf-8")
        self.assertIn("\n  ", text)
        self.assertTrue(text.endswith("\n"))
        self.assertIn(ARROW, text)
        json.loads(text)

    def test_compact_output_still_valid(self):
        # F: the default compact form stays one line.
        payload, _ = self.run_cli()
        text = payload.decode("utf-8")
        self.assertTrue(text.endswith("\n"))
        self.assertEqual(text.rstrip("\n").count("\n"), 0)
        self.assertIn(ARROW, text)
        json.loads(text)

    def test_stringio_harness_stays_compatible(self):
        # G: text-only streams keep working for in-process callers.
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = context_cli.main(
                self.argv(), store=self.env.store, clock=fixed_clock
            )
        self.assertEqual(code, 0, err.getvalue())
        packet = json.loads(out.getvalue())
        self.assertEqual(packet["project_id"], self.env.project_id)
        self.assertIn(ARROW, out.getvalue())

    def test_markdown_output_stays_compatible(self):
        # G (markdown branch): the text path also runs under the redirect.
        payload, _ = self.run_cli("--format", "markdown")
        text = payload.decode("utf-8")
        self.assertIn("# RELINKRA CONTEXT", text)
        self.assertIn(ARROW, text)

    def test_no_raw_traceback_on_stderr(self):
        # H: success leaves stderr empty -- no partial traceback.
        _, err = self.run_cli()
        self.assertEqual(err, "")
        self.assertNotIn("Traceback", err)
        self.assertNotIn("UnicodeEncodeError", err)

    def test_packet_content_unchanged_vs_text_path(self):
        # I: identical invocation, identical document on both stream shapes.
        payload, _ = self.run_cli()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = context_cli.main(
                self.argv(), store=self.env.store, clock=fixed_clock
            )
        self.assertEqual(code, 0)
        text = payload.decode("utf-8")
        self.assertEqual(text, out.getvalue())
        self.assertEqual(
            json.loads(text), json.loads(out.getvalue())
        )

    def test_ascii_only_packet_no_regression(self):
        # J: ASCII-only packets keep the exact same shape.
        env = Env()  # default ASCII seed
        self.addCleanup(env.cleanup)
        err = io.StringIO()
        with Cp1252Stdout() as captured:
            with contextlib.redirect_stderr(err):
                code = context_cli.main(
                    [
                        "--project-id", env.project_id,
                        "--registry", env.registry_path,
                    ],
                    store=env.store,
                    clock=fixed_clock,
                )
        self.assertEqual(code, 0, err.getvalue())
        packet = json.loads(captured.bytes.decode("utf-8"))
        titles_ = [item["data"]["title"] for item in packet["memories"]]
        self.assertIn("Use JWT for auth", titles_)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
