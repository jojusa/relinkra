"""_GitRunner tests for relinkra.git_intelligence (R2 Git Intelligence, B1).

Covers the read-only guarantee (allowlist enforced pre-spawn), subprocess
hygiene (argv array, no shell, explicit cwd/timeout, UTF-8), and typed
degradation (GitUnavailable / NotGitRepository / GitCommandError with
sanitized messages). subprocess.run is mocked — no git binary needed.
"""

from __future__ import annotations

import os
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
    _sanitize_stderr,
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


class StderrSanitizationTests(unittest.TestCase):
    """Git stderr must not leak absolute paths or credentials, but typed
    error classes must remain intact."""

    def test_windows_repo_path_is_stripped(self):
        text = (
            "fatal: not a git repository (or any of the parent directories): "
            "C:\\Users\\dev\\relinkra\\.git"
        )
        clean = _sanitize_stderr(text, cwd=r"C:\Users\dev\relinkra")
        self.assertNotIn(r"C:\Users\dev\relinkra", clean)
        self.assertNotIn("C:/Users/dev/relinkra", clean)
        self.assertIn("not a git repository", clean)

    def test_posix_repo_path_is_stripped(self):
        text = (
            "fatal: not a git repository (or any of the parent directories): "
            "/home/dev/relinkra/.git"
        )
        clean = _sanitize_stderr(text, cwd="/home/dev/relinkra")
        self.assertNotIn("/home/dev/relinkra", clean)
        self.assertIn("not a git repository", clean)

    def test_home_path_is_masked(self):
        text = "fatal: cannot read /home/dev/.gitconfig: No such file"
        clean = _sanitize_stderr(
            text, cwd="/home/dev/relinkra", home="/home/dev"
        )
        self.assertNotIn("/home/dev/.gitconfig", clean)
        self.assertIn("~/.gitconfig", clean)

    def test_credentials_still_redacted(self):
        token = "ghp_" + "a1B2c3" * 6
        text = f"fatal: {token} in /home/dev/relinkra/.git"
        clean = _sanitize_stderr(text, cwd="/home/dev/relinkra")
        self.assertNotIn(token, clean)
        self.assertIn("[REDACTED]", clean)
        self.assertNotIn("/home/dev/relinkra", clean)

    def test_runner_uses_sanitized_stderr_for_command_error(self):
        with mock.patch.object(
            gi.subprocess,
            "run",
            return_value=_completed(
                returncode=128,
                stderr="fatal: not a git repository: /home/dev/relinkra/.git",
            ),
        ):
            with self.assertRaises(GitCommandError) as ctx:
                _GitRunner().run("/home/dev/relinkra", "log")
        message = str(ctx.exception)
        self.assertNotIn("/home/dev/relinkra", message)
        self.assertIn("not a git repository", message)

    def test_sibling_path_with_same_prefix_is_not_mangled(self):
        """Stripping /repo must not corrupt an unrelated /repo_sibling."""
        text = "fatal: cannot access /repo_sibling/config: Permission denied"
        clean = _sanitize_stderr(text, cwd="/repo")
        self.assertNotIn("/_sibling", clean)
        self.assertIn("/repo_sibling", clean)

    def test_dot_suffixed_sibling_directory_is_not_mangled(self):
        """/repo.bak is a different directory and must survive intact."""
        text = "fatal: cannot access /repo.bak/config: Permission denied"
        clean = _sanitize_stderr(text, cwd="/repo")
        self.assertIn("/repo.bak/config", clean)

    def test_quoted_path_is_stripped(self):
        """Git quotes paths; the closing quote is not a path separator."""
        text = "fatal: cannot change to '/home/dev/relinkra': No such file"
        clean = _sanitize_stderr(text, cwd="/home/dev/relinkra", home="")
        self.assertNotIn("/home/dev/relinkra", clean)
        self.assertIn("No such file", clean)

    def test_path_at_end_of_inner_line_is_stripped(self):
        """Multi-line stderr: a path ending a non-final line still leaks
        unless the match is anchored on path characters, not on $."""
        text = "fatal: repo is /home/dev/relinkra\nhint: check the path"
        clean = _sanitize_stderr(text, cwd="/home/dev/relinkra", home="")
        self.assertNotIn("/home/dev/relinkra", clean)
        self.assertIn("hint: check the path", clean)

    def test_punctuation_terminated_windows_path_is_stripped(self):
        text = "error: unable to read C:\\Users\\dev\\relinkra;"
        clean = _sanitize_stderr(text, cwd="C:\\Users\\dev\\relinkra", home="")
        self.assertNotIn("C:\\Users\\dev\\relinkra", clean)
        self.assertNotIn("C:/Users/dev/relinkra", clean)

    def test_relative_cwd_does_not_mangle_message_punctuation(self):
        """A relative root such as '.' must never be used as a literal
        prefix: it would match sentence periods and shred the message."""
        text = (
            "fatal: detected dubious ownership in repository at '/srv/x'. "
            "To add an exception, run..."
        )
        clean = _sanitize_stderr(text, cwd=".", home="")
        self.assertIn("'/srv/x'.", clean)
        self.assertIn("To add an exception, run...", clean)

    def test_relative_cwd_still_strips_its_resolved_absolute_path(self):
        """'.' resolves to the process cwd, and THAT prefix is stripped."""
        here = os.getcwd()
        text = f"fatal: cannot read {here}/.gitconfig"
        clean = _sanitize_stderr(text, cwd=".", home="")
        self.assertNotIn(here, clean)
        self.assertNotIn(here.replace("\\", "/"), clean)

    def test_filesystem_root_is_not_used_as_a_prefix(self):
        """'/' matches everything; stripping it would destroy the text."""
        text = "fatal: cannot access /etc/gitconfig: Permission denied"
        clean = _sanitize_stderr(text, cwd="/", home="")
        self.assertIn("/etc/gitconfig", clean)

    def test_not_a_git_repository_fallback_omits_cwd(self):
        """Empty stderr must not fall back to interpolating the cwd: the
        message becomes a packet warning that ships in portable output."""
        with mock.patch.object(
            gi.subprocess,
            "run",
            return_value=_completed(returncode=128, stderr=""),
        ):
            with self.assertRaises(NotGitRepository) as ctx:
                _GitRunner().run("/home/dev/secret-project", "rev-parse", "--verify")
        message = str(ctx.exception)
        self.assertNotIn("/home/dev/secret-project", message)
        self.assertIn("not a git repository", message)


class ProbeCacheScopeTests(unittest.TestCase):
    """The repository-probe memo is scoped to one collection pass; the
    shared module-level service must not carry it across calls."""

    def test_reset_probe_cache_forgets_verified_directories(self):
        service = gi.GitIntelligenceService()
        service._repo_verified.add("/some/repo")
        service.reset_probe_cache()
        self.assertEqual(service._repo_verified, set())

    def test_default_service_resets_between_convenience_calls(self):
        gi._default_service = None
        try:
            service = gi._get_default_service()
            service._repo_verified.add("/some/repo")
            self.assertIs(gi._get_default_service(), service)
            self.assertEqual(service._repo_verified, set())
        finally:
            gi._default_service = None

    def test_stale_memo_after_reset_restores_not_repository_warning(self):
        """The memo must not survive a reset: once cleared, a directory
        that stopped being a repository degrades with the correct typed
        warning again instead of a generic command failure."""
        service = gi.GitIntelligenceService()
        service._repo_verified.add("/gone")

        with mock.patch.object(
            service._runner,
            "run",
            side_effect=NotGitRepository("not a git repository"),
        ):
            # Memoized: the probe is skipped, so the failure comes from
            # `status` and is reported as a generic command failure.
            _, stale_warnings = service.collect_working_tree("/gone")
            service.reset_probe_cache()
            _, fresh_warnings = service.collect_working_tree("/gone")

        self.assertEqual(len(fresh_warnings), 1)
        self.assertEqual(fresh_warnings[0].code, gi.WARN_GIT_NOT_REPOSITORY)
        self.assertEqual(len(stale_warnings), 1)

    def test_injected_capabilities_do_not_suppress_the_repo_probe(self):
        """collect_repository_state must not trust a caller-supplied
        GitCapabilities as proof that cwd is a repository."""
        service = gi.GitIntelligenceService()
        # Bare + no HEAD: collect_repository_state runs no git command at
        # all, so nothing can legitimately earn a memo entry.
        caps = gi.GitCapabilities(
            git_available=True,
            git_version="2.40.0",
            repository_detected=True,
            is_bare=True,
            head_available=False,
        )
        with mock.patch.object(
            service._runner, "run", return_value=""
        ) as run:
            service.collect_repository_state("/not/probed", capabilities=caps)
        self.assertEqual(run.call_count, 0)
        self.assertNotIn("/not/probed", service._repo_verified)


if __name__ == "__main__":
    unittest.main()
