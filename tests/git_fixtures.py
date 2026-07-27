"""Shared temp-repo fixtures for git intelligence tests (R2 Git Intelligence).

Deterministic by construction: every commit pins ``-c user.name`` /
``-c user.email`` and the ``GIT_AUTHOR_DATE`` / ``GIT_COMMITTER_DATE``
environment variables, so fixture repos never depend on global config or
wall-clock time. Requires the real ``git`` binary.
"""

from __future__ import annotations

import os
import subprocess
from typing import Dict

GIT_TEST_USER_NAME = "Relinkra Test"
GIT_TEST_USER_EMAIL = "relinkra-test@example.invalid"
FIXED_AUTHOR_DATE = "2024-01-01T00:00:00+00:00"
FIXED_COMMITTER_DATE = "2024-01-01T00:00:00+00:00"


def git(
    repo_path,
    *args,
    check: bool = True,
    author_date: str = FIXED_AUTHOR_DATE,
    committer_date: str = FIXED_COMMITTER_DATE,
):
    """Run git in ``repo_path`` with pinned identity and dates.

    Returns stdout (stripped) on success. With ``check=False`` returns the
    CompletedProcess instead so callers can inspect expected failures
    (e.g. a conflicted merge).
    """
    env = os.environ.copy()
    env["GIT_AUTHOR_DATE"] = author_date
    env["GIT_COMMITTER_DATE"] = committer_date
    result = subprocess.run(
        [
            "git",
            "-C",
            str(repo_path),
            "-c",
            f"user.name={GIT_TEST_USER_NAME}",
            "-c",
            f"user.email={GIT_TEST_USER_EMAIL}",
            *args,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        check=False,
    )
    if not check:
        return result
    if result.returncode != 0:
        raise AssertionError(
            f"git {' '.join(args)} failed: {result.stderr.strip()}"
        )
    return result.stdout.strip()


def make_repo(path) -> str:
    """Create a fresh repository at ``path`` on branch ``main``."""
    os.makedirs(path, exist_ok=True)
    git(path, "init", "-q", "-b", "main")
    return str(path)


def _write_file(repo_path, rel_path: str, content: str) -> None:
    abs_path = os.path.join(str(repo_path), *rel_path.split("/"))
    parent = os.path.dirname(abs_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(abs_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)


def commit_files(
    repo_path,
    files: Dict[str, str],
    message: str,
    *,
    author_date: str = FIXED_AUTHOR_DATE,
    committer_date: str = FIXED_COMMITTER_DATE,
) -> str:
    """Write every ``{rel_path: content}`` entry, commit once, return the SHA."""
    for rel_path, content in files.items():
        _write_file(repo_path, rel_path, content)
        git(repo_path, "add", "--", rel_path)
    git(
        repo_path,
        "commit",
        "-q",
        "-m",
        message,
        author_date=author_date,
        committer_date=committer_date,
    )
    return git(repo_path, "rev-parse", "HEAD")


def commit_file(
    repo_path,
    rel_path: str,
    content: str,
    message: str,
    *,
    author_date: str = FIXED_AUTHOR_DATE,
    committer_date: str = FIXED_COMMITTER_DATE,
) -> str:
    """Write ``rel_path`` with ``content``, commit it, return the commit SHA."""
    return commit_files(
        repo_path,
        {rel_path: content},
        message,
        author_date=author_date,
        committer_date=committer_date,
    )


def _date(day: int) -> str:
    return f"2024-01-{day:02d}T00:00:00+00:00"


def scenario_abcd(repo_path) -> Dict[str, str]:
    """Four-commit co-change scenario: A:alpha; B:alpha+beta; C:beta+gamma; D:alpha.

    Deterministic dates per commit so log order and timestamps are stable.
    alpha.py is touched by A, B and D; beta.py by B and C; gamma.py by C.
    Returns a mapping of commit label to SHA.
    """
    shas: Dict[str, str] = {}
    shas["A"] = commit_files(
        repo_path, {"alpha.py": "alpha A\n"}, "A",
        author_date=_date(1), committer_date=_date(1),
    )
    shas["B"] = commit_files(
        repo_path, {"alpha.py": "alpha B\n", "beta.py": "beta B\n"}, "B",
        author_date=_date(2), committer_date=_date(2),
    )
    shas["C"] = commit_files(
        repo_path, {"beta.py": "beta C\n", "gamma.py": "gamma C\n"}, "C",
        author_date=_date(3), committer_date=_date(3),
    )
    shas["D"] = commit_files(
        repo_path, {"alpha.py": "alpha D\n"}, "D",
        author_date=_date(4), committer_date=_date(4),
    )
    return shas


def rename_fixture(repo_path) -> Dict[str, str]:
    """Commit ``alpha.py`` then rename it to ``delta.py`` (pre/post-rename SHAs)."""
    before = commit_file(
        repo_path, "alpha.py", "alpha before rename\n", "add alpha",
        author_date=_date(1), committer_date=_date(1),
    )
    git(repo_path, "mv", "alpha.py", "delta.py")
    git(
        repo_path, "commit", "-q", "-m", "rename alpha to delta",
        author_date=_date(2), committer_date=_date(2),
    )
    return {"before": before, "after": git(repo_path, "rev-parse", "HEAD")}


def bare_fixture(source_path, bare_path) -> str:
    """Clone ``source_path`` into a bare repository at ``bare_path``."""
    git(source_path, "clone", "-q", "--bare", str(source_path), str(bare_path))
    return str(bare_path)


def unicode_fixture(repo_path) -> str:
    """Commit a file under ``a b/ñ.txt`` (space + non-ASCII path)."""
    return commit_file(
        repo_path, "a b/ñ.txt", "unicode path\n", "add unicode path"
    )


def conflict_fixture(repo_path) -> Dict[str, str]:
    """Diverging edits to ``alpha.py`` on main/side, merged into a UU conflict.

    Leaves the repo mid-merge with ``alpha.py`` in a both-modified (UU)
    state. Returns base/main/side commit SHAs.
    """
    base = commit_file(
        repo_path, "alpha.py", "base\n", "base",
        author_date=_date(1), committer_date=_date(1),
    )
    git(repo_path, "branch", "side")
    main = commit_file(
        repo_path, "alpha.py", "main change\n", "main change",
        author_date=_date(2), committer_date=_date(2),
    )
    git(repo_path, "checkout", "-q", "side")
    side = commit_file(
        repo_path, "alpha.py", "side change\n", "side change",
        author_date=_date(3), committer_date=_date(3),
    )
    git(repo_path, "checkout", "-q", "main")
    result = git(repo_path, "merge", "--no-commit", "--no-ff", "side", check=False)
    if result.returncode == 0:
        raise AssertionError("conflict_fixture: merge unexpectedly succeeded")
    if "UU alpha.py" not in git(repo_path, "status", "--porcelain"):
        raise AssertionError("conflict_fixture: alpha.py is not in UU state")
    return {"base": base, "main": main, "side": side}
