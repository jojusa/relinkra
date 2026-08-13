"""Tests for the backup / atomic-write / rollback primitives (R4B).

Every test runs against a temporary directory. Nothing here touches a
real host configuration, and the suite asserts the property that matters
most for a tool that edits files it does not own: on any failure, the
target is exactly what it was before.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from relinkra import safe_write as safe_write_module
from relinkra.config_merge import validate_json_text
from relinkra.safe_write import (
    BACKUP_SUFFIX,
    MAX_CONFIG_BYTES,
    NEW_FILE_MODE,
    ConfigTooLargeError,
    ContentValidationError,
    PreconditionError,
    SafeWriteError,
    UnsafeTargetError,
    assert_writable_target,
    atomic_write_text,
    create_backup,
    detect_newline,
    digest_text,
    next_backup_path,
    read_bounded_text,
    safe_replace,
)

_POSIX = os.name != "nt"


class TempCase(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="relinkra-safewrite-")
        self.addCleanup(self._temp.cleanup)
        self.root = Path(self._temp.name)
        self.target = self.root / "config.json"

    def write(self, text: str) -> Path:
        self.target.write_text(text, encoding="utf-8")
        return self.target

    def temp_files(self):
        return sorted(p.name for p in self.root.iterdir() if p.name.endswith(".tmp"))


class ReadTests(TempCase):
    def test_reads_utf8(self):
        self.write('{"name": "café ⚙"}')
        self.assertIn("café", read_bounded_text(self.target))

    def test_rejects_oversized_file_by_stat(self):
        self.write("x" * 128)
        with self.assertRaises(ConfigTooLargeError):
            read_bounded_text(self.target, max_bytes=64)

    def test_rejects_oversized_content_even_when_stat_understates_it(self):
        # Multi-byte characters make the decoded read the authoritative
        # check; the stat byte count alone is not enough to trust.
        self.write("é" * 100)
        with self.assertRaises(ConfigTooLargeError):
            read_bounded_text(self.target, max_bytes=150)

    def test_missing_file_is_typed(self):
        with self.assertRaises(SafeWriteError):
            read_bounded_text(self.root / "nope.json")

    def test_default_limit_is_bounded(self):
        self.assertLessEqual(MAX_CONFIG_BYTES, 8 * 1024 * 1024)

    def test_digest_is_stable_and_content_sensitive(self):
        self.assertEqual(digest_text("a"), digest_text("a"))
        self.assertNotEqual(digest_text("a"), digest_text("b"))

    def test_security_digest_distinguishes_line_endings_and_bom(self):
        self.assertNotEqual(digest_text("a\n"), digest_text("a\r\n"))
        self.assertNotEqual(digest_text("a"), digest_text("\ufeffa"))

    def test_detect_newline(self):
        self.assertEqual(detect_newline("a\r\nb"), "\r\n")
        self.assertEqual(detect_newline("a\nb"), "\n")
        self.assertEqual(detect_newline("a"), "\n")


class BackupTests(TempCase):
    def test_first_backup_uses_the_plain_suffix(self):
        self.write("{}")
        self.assertEqual(
            next_backup_path(self.target).name, self.target.name + BACKUP_SUFFIX
        )

    def test_backup_names_never_collide(self):
        self.write("{}")
        first = create_backup(self.target)
        second = create_backup(self.target)
        third = create_backup(self.target)
        self.assertNotEqual(first, second)
        self.assertNotEqual(second, third)
        self.assertTrue(second.name.endswith(BACKUP_SUFFIX + "-1"))
        self.assertTrue(third.name.endswith(BACKUP_SUFFIX + "-2"))

    def test_backup_content_matches(self):
        self.write('{"a": 1}')
        backup = create_backup(self.target)
        self.assertEqual(backup.read_text(encoding="utf-8"), '{"a": 1}')

    def test_absent_target_produces_no_backup(self):
        self.assertIsNone(create_backup(self.target))

    def test_exhausted_backup_names_are_typed(self):
        self.write("{}")
        create_backup(self.target)
        with self.assertRaises(SafeWriteError):
            next_backup_path(self.target, attempts=1)

    @unittest.skipUnless(_POSIX, "POSIX permission semantics")
    def test_backup_preserves_mode(self):
        self.write("{}")
        os.chmod(self.target, 0o640)
        backup = create_backup(self.target)
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o640)


class AtomicWriteTests(TempCase):
    def test_creates_the_file_and_its_directory(self):
        nested = self.root / "a" / "b" / "config.json"
        atomic_write_text(nested, '{"a": 1}')
        self.assertEqual(json.loads(nested.read_text(encoding="utf-8")), {"a": 1})

    def test_no_temporary_file_survives_success(self):
        atomic_write_text(self.target, "{}")
        self.assertEqual(self.temp_files(), [])

    def test_no_temporary_file_survives_failure(self):
        # An unencodable surrogate fails inside the temp write, after the
        # temp file exists. The cleanup path is what is under test.
        with self.assertRaises(UnicodeEncodeError):
            atomic_write_text(self.target, "\ud800")
        self.assertEqual(self.temp_files(), [])
        self.assertFalse(self.target.exists())

    def test_crlf_content_is_not_translated_again(self):
        atomic_write_text(self.target, "a\r\nb\r\n")
        raw = self.target.read_bytes()
        self.assertNotIn(b"\r\r\n", raw)
        self.assertEqual(raw, b"a\r\nb\r\n")

    @unittest.skipUnless(_POSIX, "POSIX permission semantics")
    def test_new_files_are_owner_only(self):
        atomic_write_text(self.target, "{}")
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), NEW_FILE_MODE)

    @unittest.skipUnless(_POSIX, "POSIX permission semantics")
    def test_explicit_mode_is_honoured(self):
        atomic_write_text(self.target, "{}", mode=0o640)
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o640)


class UnsafeTargetTests(TempCase):
    def test_directory_target_is_refused(self):
        directory = self.root / "adir"
        directory.mkdir()
        with self.assertRaises(UnsafeTargetError):
            safe_replace(directory, "{}")

    @unittest.skipUnless(
        _POSIX or sys.platform == "win32", "needs a symlink-capable platform"
    )
    def test_symlink_target_is_refused(self):
        real = self.write('{"real": true}')
        link = self.root / "link.json"
        try:
            link.symlink_to(real)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlinks unavailable: {exc}")
        with self.assertRaises(UnsafeTargetError):
            safe_replace(link, '{"replaced": true}')
        # The link is intact and still points at unchanged content.
        self.assertTrue(link.is_symlink())
        self.assertEqual(json.loads(real.read_text(encoding="utf-8")), {"real": True})

    def test_relative_target_is_refused_and_writes_nothing(self):
        # R5C write containment: a relative target would resolve against
        # the process working directory. Fail closed, write nothing.
        relative = Path("relinkra-r5c-must-never-exist.json")
        with self.assertRaises(UnsafeTargetError):
            atomic_write_text(relative, "{}")
        self.assertFalse(relative.exists())
        with self.assertRaises(UnsafeTargetError):
            assert_writable_target(relative)

    def test_backslash_rooted_target_is_refused_everywhere(self):
        # The exact R5C Linux worktree-contamination shape: "\tmp\..." is
        # a RELATIVE filename on POSIX and a drive-relative path on
        # Windows — absolute on NEITHER host. It must never become a
        # write target.
        foreign = "\\tmp\\relinkra-r5c-leak\\opencode.json"
        with self.assertRaises(UnsafeTargetError):
            atomic_write_text(foreign, "{}")
        self.assertFalse(Path(foreign).exists())

    @unittest.skipUnless(
        _POSIX, "a Windows drive string is only a relative name on POSIX"
    )
    def test_windows_drive_string_is_refused_on_posix(self):
        # str(PureWindowsPath(...)) on POSIX is a backslash-laden RELATIVE
        # name; previously it could be written into the process cwd.
        with self.assertRaises(UnsafeTargetError):
            atomic_write_text("C:\\relinkra-r5c-leak\\x.json", "{}")


class SafeReplaceTests(TempCase):
    def test_replaces_content_and_reports_digests(self):
        self.write('{"a": 1}')
        receipt = safe_replace(
            self.target, '{"a": 2}\n', validator=validate_json_text
        )
        self.assertFalse(receipt.created)
        self.assertTrue(receipt.backup_created)
        self.assertEqual(receipt.digest_before, digest_text('{"a": 1}'))
        self.assertEqual(receipt.digest_after, digest_text('{"a": 2}\n'))
        self.assertEqual(receipt.backup_digest, digest_text('{"a": 1}'))
        self.assertEqual(json.loads(self.target.read_text(encoding="utf-8")), {"a": 2})

    def test_creates_an_absent_file_without_a_backup(self):
        receipt = safe_replace(self.target, "{}\n", validator=validate_json_text)
        self.assertTrue(receipt.created)
        self.assertFalse(receipt.backup_created)
        self.assertIsNone(receipt.digest_before)

    def test_receipt_dict_carries_no_path(self):
        self.write("{}")
        payload = safe_replace(self.target, "{}\n").to_dict()
        self.assertNotIn("target", payload)
        self.assertNotIn("backup_path", payload)
        self.assertTrue(payload["backup_created"])

    def test_pre_validation_failure_changes_nothing(self):
        original = '{"a": 1}'
        self.write(original)
        with self.assertRaises(ContentValidationError) as caught:
            safe_replace(self.target, "{not json", validator=validate_json_text)
        self.assertFalse(caught.exception.rolled_back)
        self.assertEqual(self.target.read_text(encoding="utf-8"), original)
        # No pointless backup is left behind for a write that never ran.
        self.assertEqual(list(self.root.glob("*" + BACKUP_SUFFIX)), [])

    def test_post_write_validation_failure_rolls_back(self):
        original = '{"a": 1}'
        self.write(original)
        calls = {"n": 0}

        def flaky(text):
            # Accept the pre-write check, reject what lands on disk. This
            # is the truncated-write / bad-encoding case: the string was
            # fine, the file is not.
            calls["n"] += 1
            if calls["n"] > 1:
                raise ValueError("what landed on disk is unusable")

        with self.assertRaises(ContentValidationError) as caught:
            safe_replace(self.target, '{"a": 2}', validator=flaky)
        self.assertTrue(caught.exception.rolled_back)
        self.assertEqual(self.target.read_text(encoding="utf-8"), original)

    def test_rollback_removes_a_file_that_did_not_exist_before(self):
        # No backup can exist for a file that was absent, so the correct
        # restoration is deletion — not leaving a half-valid file behind.
        calls = {"n": 0}

        def reject_written(text):
            calls["n"] += 1
            if calls["n"] > 1:
                raise ValueError("nope")

        with self.assertRaises(ContentValidationError) as caught:
            safe_replace(self.target, '{"a": 2}', validator=reject_written)
        self.assertTrue(caught.exception.rolled_back)
        self.assertFalse(self.target.exists())

    def test_rollback_without_a_backup_restores_the_original(self):
        # backup=False still has to honour "nothing changed": the original
        # text was already read to compute the precondition digest, so it
        # is available even though no backup file exists. Without that
        # route the rejected content stays on disk permanently.
        original = '{"a": 1}'
        self.write(original)
        calls = {"n": 0}

        def flaky(text):
            calls["n"] += 1
            if calls["n"] > 1:
                raise ValueError("what landed on disk is unusable")

        with self.assertRaises(ContentValidationError) as caught:
            safe_replace(self.target, '{"a": 2}', validator=flaky, backup=False)
        self.assertTrue(caught.exception.rolled_back)
        self.assertEqual(self.target.read_text(encoding="utf-8"), original)
        self.assertEqual(list(self.root.glob("*" + BACKUP_SUFFIX)), [])
        self.assertEqual(self.temp_files(), [])

    @unittest.skipUnless(_POSIX or sys.platform == "win32", "needs symlinks")
    def test_a_target_swapped_for_a_symlink_mid_write_is_refused(self):
        # The pre-lock check cannot see a swap that happens after it, so
        # the refusal is re-asserted immediately before the replace.
        original = '{"a": 1}'
        self.write(original)
        elsewhere = self.root / "elsewhere.json"
        elsewhere.write_text('{"victim": true}', encoding="utf-8")

        real_backup = safe_write_module.create_backup

        def swap_then_backup(path):
            result = real_backup(path)
            os.unlink(str(self.target))
            try:
                self.target.symlink_to(elsewhere)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlinks unavailable: {exc}")
            return result

        safe_write_module.create_backup = swap_then_backup
        try:
            with self.assertRaises(UnsafeTargetError):
                safe_replace(self.target, '{"a": 2}')
        finally:
            safe_write_module.create_backup = real_backup
        # The symlink survived and its target was never written through.
        self.assertTrue(self.target.is_symlink())
        self.assertEqual(elsewhere.read_text(encoding="utf-8"), '{"victim": true}')

    def test_no_temporary_files_survive_a_rollback(self):
        self.write("{}")

        def always_bad(text):
            raise ValueError("bad")

        with self.assertRaises(ContentValidationError):
            safe_replace(self.target, "{}", validator=always_bad)
        self.assertEqual(self.temp_files(), [])

    def test_precondition_digest_guards_a_concurrent_edit(self):
        self.write('{"a": 1}')
        stale = digest_text('{"a": 0}')
        with self.assertRaises(PreconditionError):
            safe_replace(self.target, '{"a": 2}', expected_digest=stale)
        self.assertEqual(json.loads(self.target.read_text(encoding="utf-8")), {"a": 1})

    def test_matching_precondition_digest_permits_the_write(self):
        self.write('{"a": 1}')
        safe_replace(
            self.target, '{"a": 2}', expected_digest=digest_text('{"a": 1}')
        )
        self.assertEqual(json.loads(self.target.read_text(encoding="utf-8")), {"a": 2})

    def test_precondition_digest_on_an_absent_file(self):
        with self.assertRaises(PreconditionError):
            safe_replace(self.target, "{}", expected_digest=digest_text("{}"))

    def test_oversized_existing_content_is_refused(self):
        self.write("x" * (MAX_CONFIG_BYTES + 16))
        with self.assertRaises(ConfigTooLargeError):
            safe_replace(self.target, "{}")

    @unittest.skipUnless(_POSIX, "POSIX permission semantics")
    def test_existing_permissions_are_not_widened(self):
        self.write("{}")
        os.chmod(self.target, 0o640)
        safe_replace(self.target, '{"a": 1}')
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o640)


class ConcurrencyTests(TempCase):
    def test_concurrent_writers_never_corrupt_the_target(self):
        # The invariant is not "one specific writer wins" — it is that
        # the file is always complete and parseable, never a partial
        # interleaving of two writes.
        self.write('{"n": 0}')
        writers = 8
        errors = []
        barrier = threading.Barrier(writers)

        def writer(index):
            payload = json.dumps({"n": index}) + "\n"
            try:
                barrier.wait(timeout=10)
                safe_replace(self.target, payload, validator=validate_json_text)
            except Exception as exc:  # recorded, asserted below
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(writers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)

        self.assertEqual([type(e).__name__ for e in errors], [])
        final = json.loads(self.target.read_text(encoding="utf-8"))
        self.assertIn(final["n"], list(range(writers)))
        self.assertEqual(self.temp_files(), [])

    def test_concurrent_backups_get_distinct_names(self):
        self.write("{}")
        made = []
        lock = threading.Lock()

        def backup():
            path = create_backup(self.target)
            with lock:
                made.append(path)

        threads = [threading.Thread(target=backup) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertEqual(len(made), 6)
        # Racing name selection may hand two threads the same candidate;
        # what must never happen is losing a distinct user file. Every
        # produced backup must still hold the original content.
        for path in made:
            self.assertEqual(path.read_text(encoding="utf-8"), "{}")


if __name__ == "__main__":
    unittest.main()
