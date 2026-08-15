# Contributing to Relinkra

Thanks for your interest. This document covers the minimum you need to get
a change from a clone to a pull request.

## Setup

```powershell
# Windows (PowerShell)
git clone https://github.com/jojusa/relinkra.git
cd relinkra
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
pip install -e .
```

```bash
# Linux / macOS
git clone https://github.com/jojusa/relinkra.git
cd relinkra
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
pip install -e .
```

The editable install (`pip install -e .`) makes source edits take effect
immediately.

## Running the tests

```bash
# Core suite (full suite minus the two venv E2E files)
python -W error::ResourceWarning tools/run_core_tests.py

# Full suite
python -W error::ResourceWarning -m unittest discover -s tests -q
```

No real agent hosts, no Gentle/gentle-ai authority, and no credentials are
needed. The E2E suites skip safely without network access.

## Building and checking artifacts

```bash
python -m pip install build setuptools
python -m build
```

Then inspect the artifacts (adjust the version in the filenames to the
current `relinkra --version`). PowerShell does not expand `dist/*`, so
pass explicit paths:

```powershell
# PowerShell
python tools/artifact_checks.py dist/relinkra-0.1.0rc1-py3-none-any.whl dist/relinkra-0.1.0rc1.tar.gz
```

```bash
# bash
python tools/artifact_checks.py dist/*
```

## Release checks (maintainer-facing)

```bash
python tools/release_check.py --json
python tools/release_check.py --run-packaging --require merge
```

See [docs/release.md](docs/release.md) for the gate semantics.

## Workflow

1. Fork the repository and create a branch off `master`.
2. Make your change; keep it focused and include tests.
3. Run the core suite before pushing.
4. Open a pull request against `master`.

There is no complex branching policy beyond that.

## A note on test fixtures

Some tests contain Windows-style path fixtures (for example
`C:\Desarrollos\relinkra`) and privacy assertions proving those paths are
never leaked into output. They are synthetic data pinned by
load-bearing privacy tests — do not "clean them up".
