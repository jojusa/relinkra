"""_GitRunner tests for relinkra.git_intelligence (R2 Git Intelligence, B1).

Covers the read-only guarantee (allowlist enforced pre-spawn), subprocess
hygiene (argv array, no shell, explicit cwd/timeout, UTF-8), and typed
degradation (GitUnavailable / NotGitRepository / GitCommandError with
sanitized messages). subprocess.run is mocked — no git binary needed.
"""

from __future__ import annotations

import subprocess
import unittest
from unittest import mock

import relinkra.git_intelligence as gi
from relinkra.git_intelligence import (
    GIT_TIMEOUT_SECONDS,
    GitCommandError,
    GitError,
    GitUnavailable,
    NotGitRepository,
    _GitRunner,
)


def _completed(returncode=0, stdout="ok", stderr=""):
    return subprocess.CompletedProcess(
        args=["git"], returncode=returncode, stdout=stdout, stderr=stderr
    )


class AllowlistTests(unittest.TestCase):
    def test_read_only_verbs_match_design(self):
        self.assertEqual(
            gi.READ_ONLY_VERBS, frozenset({"status", "log", "diff", "rev-parse", "show"})
        )

    def test_each_allowlisted_verb_spawns(self):
        for verb in sorted(gi.READ_ONLY_VERBS):
            with self.subTest(verb=verb), mock.patch.object(
                gi.subprocess, "run", return_value=_completed(stdout="out")
            ) as run:
                self.assertEqual(_GitRunner().run("/repo", verb, "--flag"), "out")
                run.assert_called_once()

    def test_mutating_verbs_rejected_before_spawn(self):
        for verb in (
            "commit", "push", "pull", "fetch", "merge", "rebase", "reset",
            "checkout", "switch", "branch", "clean", "stash", "tag", "rev-list",
        ):
            with self.subTest(verb=verb), mock.patch.object(
                gi.subprocess, "run"
            ) as run:
                with self.assertRaises(GitCommandError):
                    _GitRunner().run("/repo", verb)
                run.assert_not_called()

    def test_rejected_verb_error_names_verb_and_has_no_returncode(self):
        with self.assertRaises(GitCommandError) as ctx:
            _GitRunner().run("/repo", "commit")
        self.assertEqual(ctx.exception.verb, "commit")
        self.assertIsNone(ctx.exception.returncode)
        self.assertIn("commit", str(ctx.exception))

    def test_no_argv_rejected_before_spawn(self):
        with mock.patch.object(gi.subprocess, "run") as run:
            with self.assertRaises(GitCommandError):
                _GitRunner().run("/repo")
            run.assert_not_called()


class SpawnHygieneTests(unittest.TestCase):
    def test_argv_array_no_shell_explicit_cwd_timeout_utf8(self):
        with mock.patch.object(
            gi.subprocess, "run", return_value=_completed()
        ) as run:
            _GitRunner().run("/some/repo", "status", "--porcelain=v1", "-z")
        args, kwargs = run.call_args
        argv = args[0]
        self.assertIsInstance(argv, list)
        self.assertEqual(argv, ["git", "status", "--porcelain=v1", "-z"])
        self.assertNotIn("shell", kwargs)  # shell defaults to False
        self.assertEqual(kwargs["cwd"], "/some/repo")
        self.assertEqual(kwargs["timeout"], GIT_TIMEOUT_SECONDS)
        self.assertEqual(kwargs["encoding"], "utf-8")
        self.assertEqual(kwargs["errors"], "replace")
        self.assertTrue(kwargs["capture_output"])
        self.assertFalse(kwargs["check"])

    def test_custom_executable_and_timeout(self):
        with mock.patch.object(
            gi.subprocess, "run", return_value=_completed()
        ) as run:
            _GitRunner(executable="/usr/local/bin/git", timeout=2).run(
                "/repo", "status"
            )
        args, kwargs = run.call_args
        self.assertEqual(args[0][0], "/usr/local/bin/git")
        self.assertEqual(kwargs["timeout"], 2)


class TypedDegradationTests(unittest.TestCase):
    def test_file_not_found_maps_to_git_unavailable(self):
        with mock.patch.object(
            gi.subprocess, "run", side_effect=FileNotFoundError("no git")
        ):
            with self.assertRaises(GitUnavailable):
                _GitRunner().run("/repo", "status")

    def test_timeout_maps_to_git_unavailable(self):
        with mock.patch.object(
            gi.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(cmd=["git"], timeout=5),
        ):
            with self.assertRaises(GitUnavailable) as ctx:
                _GitRunner().run("/repo", "log")
        self.assertIn("timed out", str(ctx.exception))

    def test_rev_parse_failure_maps_to_not_git_repository(self):
        with mock.patch.object(
            gi.subprocess,
            "run",
            return_value=_completed(
                returncode=128, stderr="fatal: not a git repository"
            ),
        ):
            with self.assertRaises(NotGitRepository):
                _GitRunner().run("/repo", "rev-parse", "--show-toplevel")

    def test_other_verb_failure_maps_to_git_command_error(self):
        with mock.patch.object(
            gi.subprocess,
            "run",
            return_value=_completed(returncode=1, stderr="boom"),
        ):
            with self.assertRaises(GitCommandError) as ctx:
                _GitRunner().run("/repo", "log")
        self.assertEqual(ctx.exception.verb, "log")
        self.assertEqual(ctx.exception.returncode, 1)

    def test_stderr_secret_is_sanitized_in_error_message(self):
        token = "ghp_" + "a1B2c3" * 6  # matches known-token pattern (>= 20 chars)
        with mock.patch.object(
            gi.subprocess,
            "run",
            return_value=_completed(returncode=1, stderr=f"fatal: {token} leaked"),
        ):
            with self.assertRaises(GitCommandError) as ctx:
                _GitRunner().run("/repo", "show")
        message = str(ctx.exception)
        self.assertNotIn(token, message)
        self.assertIn("[REDACTED]", message)

    def test_non_file_not_found_oserror_maps_to_git_unavailable_sanitized(self):
        token = "ghp_" + "a1B2c3" * 6  # known-token pattern (>= 20 chars)
        with mock.patch.object(
            gi.subprocess,
            "run",
            side_effect=NotADirectoryError(267, f"invalid dir {token}"),
        ):
            with self.assertRaises(GitUnavailable) as ctx:
                _GitRunner().run("/missing", "status")
        message = str(ctx.exception)
        self.assertNotIn(token, message)
        self.assertIn("[REDACTED]", message)

    def test_probe_version_oserror_maps_to_git_unavailable(self):
        with mock.patch.object(
            gi.subprocess,
            "run",
            side_effect=PermissionError(5, "Access is denied"),
        ):
            with self.assertRaises(GitUnavailable):
                _GitRunner().probe_version()

    def test_service_capabilities_on_missing_directory_degrades(self):
        service = gi.GitIntelligenceService()
        with mock.patch.object(
            service._runner, "probe_version", return_value="2.40.0"
        ):
            caps, warnings = service.collect_capabilities(
                "definitely-missing-dir-r2-x9/nope"
            )
        self.assertFalse(caps.git_available)
        self.assertFalse(caps.repository_detected)
        self.assertEqual(len(warnings), 1)
        self.assertEqual(warnings[0].code, gi.WARN_GIT_UNAVAILABLE)

    def test_all_errors_share_git_error_base(self):
        for exc_type in (GitUnavailable, NotGitRepository, GitCommandError, gi.GitParseError):
            self.assertTrue(issubclass(exc_type, GitError))


if __name__ == "__main__":
    unittest.main()
