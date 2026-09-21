"""M7 — install/PATH and source-tree resolution diagnostics.

Two real operational failure classes motivate this suite:

A. INSTALL / PATH. A distribution installs successfully while its script
   directory is absent from ``PATH``: the package imports, and the
   ``relinkra`` command does not resolve.
B. SOURCE-TREE SHADOWING. The repository checkout wins the import race
   against an installed distribution, so a verification the operator
   believes is testing the installed artifact is really testing source.

M7B adds a third, sharper variant the independent review found reachable:
an editable installation whose PEP 610 metadata names checkout A, while
the import actually resolved to a different checkout B, with ``PYTHONPATH``
contributing B. Editable metadata proves the CONFIGURED target; it never
proves what imported, so that state must not be reported as a healthy
editable installation.

Every test here is deterministic and hermetic. The classification matrix
injects its facts, so it never depends on the developer machine's real
``PATH``, its real site-packages, or an installed Relinkra. The probing
tests build real temporary directories — including one with a space and
one with non-ASCII characters — so the filesystem-facing code is exercised
without touching anything outside the temp tree.

Nothing in this suite mutates PATH, PYTHONPATH, the environment, or an
installed package, and nothing reads a developer-machine path.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Optional
from unittest import mock

from relinkra import install_resolution as ir
from relinkra import product_cli
from relinkra.handoff import contains_absolute_path
from relinkra.product_cli import (
    EXIT_ACTION_REQUIRED,
    PASS,
    WARN,
    check_install_resolution,
)

try:
    from tests import git_fixtures as gf
except ImportError:  # pragma: no cover - discover vs module invocation
    import git_fixtures as gf

#: Synthetic interpreter layout. Never the developer's real one, and
#: deliberately free of any home-directory prefix that the CI hygiene
#: audit would flag as a leaked machine path.
LIB_DIR = "C:/py/Lib/site-packages"
SCRIPTS_DIR = "C:/py/Scripts"
USER_SCRIPTS_DIR = "C:/Users/user/AppData/Roaming/Python/Python314/Scripts"
OTHER_SCRIPTS_DIR = "D:/other/tools/Scripts"
CHECKOUT = "C:/work/relinkra"
INSTALLED_ROOT = LIB_DIR + "/relinkra"

#: The M7B state: the editable install configures one checkout while the
#: import resolves to a sibling that shares only a name prefix.
CHECKOUT_A = "C:/work/relinkra-editable"
CHECKOUT_B = "C:/work/relinkra-shadow"

#: A module file inside the package, which is what an import reports.
CHECKOUT_FILE = CHECKOUT + "/relinkra/__init__.py"
INSTALLED_FILE = INSTALLED_ROOT + "/__init__.py"
FOREIGN_FILE = CHECKOUT_B + "/relinkra/__init__.py"

#: Distinguishes "no target supplied" from an explicit ``None``, so a
#: test can build the malformed-in-the-wild record that says editable
#: without naming any target.
_UNSET_TARGET = object()


def installed_metadata(
    lib_dir: str = LIB_DIR,
    version: str = "0.1.4",
    editable: bool = False,
    editable_target: Any = _UNSET_TARGET,
) -> ir.LibMetadata:
    """Metadata as the library-directory probe would report it.

    A real PEP 610 editable record names the checkout it configures, so
    an editable record built here carries ``CHECKOUT`` as its target by
    default. Tests override the target to build a mismatch, or pass
    ``None`` for the record that is not promoted at all.
    """
    if not editable:
        target: Optional[str] = None
    elif editable_target is _UNSET_TARGET:
        target = CHECKOUT
    else:
        target = editable_target
    return ir.LibMetadata(
        lib_dir=lib_dir,
        kind=ir.SHAPE_DIST_INFO,
        editable=editable,
        editable_target=target,
        version=version,
        metadata_dir=f"{lib_dir}/relinkra-{version}.dist-info",
    )


def evidence(
    *,
    imported_file: str = CHECKOUT_FILE,
    lib_dirs=(LIB_DIR,),
    scripts_dir=SCRIPTS_DIR,
    user_scripts_dir=USER_SCRIPTS_DIR,
    environ=None,
    which=None,
    cwd="C:/tmp",
    lib_metadata=(),
    expected_script_present=False,
    checkout_evidence=True,
    distribution_lookup=None,
) -> ir.InstallEvidence:
    """Gathered facts with every environmental input injected."""
    return ir.gather_install_evidence(
        imported_file=imported_file,
        lib_dirs=list(lib_dirs),
        scripts_dir=scripts_dir,
        user_scripts_dir=user_scripts_dir,
        environ={} if environ is None else environ,
        which=(lambda name: None) if which is None else which,
        cwd=cwd,
        lib_metadata=list(lib_metadata),
        expected_script_present=expected_script_present,
        checkout_evidence=checkout_evidence,
        distribution_lookup=(
            (lambda name: None) if distribution_lookup is None
            else distribution_lookup
        ),
    )


def classify(**kwargs) -> ir.InstallResolution:
    return ir.classify_install(evidence(**kwargs))


def resolved_at(directory: str, name: str = "relinkra"):
    """A ``which`` stub that resolves a console script into ``directory``."""
    return lambda candidate: f"{directory}/{name}.exe"


def mismatch_resolution() -> ir.InstallResolution:
    """The reviewer's compound state, injected and deterministic.

    Editable metadata names checkout A, the import resolved to checkout B,
    and PYTHONPATH contributes B.
    """
    return classify(
        imported_file=FOREIGN_FILE,
        lib_metadata=(
            installed_metadata(editable=True, editable_target=CHECKOUT_A),
        ),
        expected_script_present=True,
        which=resolved_at(SCRIPTS_DIR),
        environ={"PYTHONPATH": CHECKOUT_B, "PATH": SCRIPTS_DIR},
    )


# ---------------------------------------------------------------------------
# Classification matrix (cases A-J)
# ---------------------------------------------------------------------------


class ExecutionModeTests(unittest.TestCase):
    """Which code is this interpreter actually running?"""

    def test_a_installed_distribution_is_classified_as_installed(self):
        resolution = classify(
            imported_file=INSTALLED_FILE,
            lib_metadata=(installed_metadata(),),
            expected_script_present=True,
            which=resolved_at(SCRIPTS_DIR),
            environ={"PATH": SCRIPTS_DIR},
        )
        self.assertEqual(resolution.running_from, ir.RUNNING_INSTALLED)
        self.assertEqual(resolution.conditions, ())
        self.assertEqual(
            resolution.installed_distribution_version, "0.1.4"
        )
        self.assertTrue(resolution.scripts_dir_on_path)

    def test_b_source_checkout_with_nothing_installed_is_not_a_complaint(self):
        """A developer running from a checkout is a legitimate state."""
        resolution = classify(
            lib_metadata=(),
            expected_script_present=False,
        )
        self.assertEqual(resolution.running_from, ir.RUNNING_SOURCE)
        self.assertFalse(resolution.installed_for_interpreter)
        self.assertEqual(resolution.conditions, ())
        self.assertTrue(resolution.checkout_evidence)

    def test_c_source_checkout_shadowing_an_install_is_flagged(self):
        resolution = classify(
            lib_metadata=(installed_metadata(),),
            expected_script_present=True,
            which=resolved_at(SCRIPTS_DIR),
            environ={"PYTHONPATH": CHECKOUT, "PATH": SCRIPTS_DIR},
        )
        self.assertEqual(resolution.running_from, ir.RUNNING_SOURCE)
        self.assertTrue(resolution.shadowed)
        self.assertIn(ir.CONDITION_SHADOWED, resolution.conditions)

    def test_d_pythonpath_presence_is_reported_as_boolean_only(self):
        resolution = classify(
            lib_metadata=(installed_metadata(),),
            environ={"PYTHONPATH": CHECKOUT + os.pathsep + "C:/other"},
        )
        payload = resolution.to_dict()
        self.assertTrue(payload["pythonpath"]["set"])
        self.assertTrue(payload["pythonpath"]["contributes_imported_package"])
        # The value itself must not travel in the portable projection.
        self.assertNotIn(CHECKOUT, json.dumps(payload))

    def test_d2_pythonpath_that_does_not_contribute_is_still_reported(self):
        resolution = classify(
            environ={"PYTHONPATH": "D:/unrelated"},
        )
        self.assertTrue(resolution.pythonpath_set)
        self.assertFalse(resolution.pythonpath_contributes_imported)

    def test_d3_working_directory_is_recorded_as_shadow_evidence(self):
        resolution = classify(
            lib_metadata=(installed_metadata(),),
            cwd=CHECKOUT,
        )
        self.assertTrue(resolution.working_directory_is_package_root)

    def test_i_editable_install_is_its_own_mode(self):
        resolution = classify(
            lib_metadata=(installed_metadata(editable=True),),
            expected_script_present=True,
            which=resolved_at(SCRIPTS_DIR),
            environ={"PATH": SCRIPTS_DIR},
        )
        self.assertEqual(resolution.running_from, ir.RUNNING_EDITABLE)
        self.assertTrue(resolution.editable_evidence)
        # An editable install's metadata describes this very checkout, so
        # imports are correct and nothing is shadowed.
        self.assertEqual(resolution.conditions, ())

    def test_j_ambiguous_when_library_directories_cannot_be_established(self):
        resolution = classify(lib_dirs=())
        self.assertEqual(resolution.running_from, ir.RUNNING_AMBIGUOUS)
        self.assertEqual(resolution.primary_condition, ir.CONDITION_AMBIGUOUS)

    def test_execution_modes_are_mutually_exclusive(self):
        observed = {
            classify(
                imported_file=INSTALLED_FILE,
                lib_metadata=(installed_metadata(),),
            ).running_from,
            classify(lib_metadata=()).running_from,
            classify(
                lib_metadata=(installed_metadata(editable=True),)
            ).running_from,
            classify(lib_dirs=()).running_from,
        }
        self.assertEqual(
            observed,
            {
                ir.RUNNING_INSTALLED,
                ir.RUNNING_SOURCE,
                ir.RUNNING_EDITABLE,
                ir.RUNNING_AMBIGUOUS,
            },
        )


# ---------------------------------------------------------------------------
# Editable target vs import origin (M7B cases A-C)
# ---------------------------------------------------------------------------


class _FakeDistribution:
    """The ``importlib.metadata`` record, reduced to what gather reads."""

    def __init__(
        self,
        direct_url: Optional[str],
        path: str = LIB_DIR,
    ):
        self.version = "0.1.4"
        self.files = ["relinkra-0.1.4.dist-info/METADATA"]
        self._path = path + "/relinkra-0.1.4.dist-info"
        self._direct_url = direct_url

    def read_text(self, name):
        if name == "direct_url.json" and self._direct_url is not None:
            return self._direct_url
        raise FileNotFoundError(name)

    def locate_file(self, path):
        return Path(LIB_DIR)


def _editable_document(target: str, editable: bool = True) -> str:
    return json.dumps(
        {"url": target, "dir_info": {"editable": editable}}
    )


class EditableTargetTests(unittest.TestCase):
    """PEP 610 names the configured target; the import origin is separate.

    An editable claim is healthy only while the imported package root sits
    inside the checkout that metadata names. When it does not, the state
    is a source checkout carrying an explicit mismatch condition — never a
    healthy editable installation, because that would invent provenance.
    """

    def test_a_editable_target_matching_the_imported_root_is_unchanged(self):
        resolution = classify(
            lib_metadata=(installed_metadata(editable=True),),
            expected_script_present=True,
            which=resolved_at(SCRIPTS_DIR),
            environ={"PATH": SCRIPTS_DIR},
        )
        self.assertEqual(resolution.running_from, ir.RUNNING_EDITABLE)
        self.assertEqual(resolution.conditions, ())
        self.assertTrue(resolution.editable_evidence)

    def test_a2_the_package_root_equal_to_the_target_is_inside_it(self):
        # The module-file convention makes the root two levels up, so the
        # equality branch is exercised with evidence built directly: a
        # package root that IS the checkout still belongs to it.
        resolution = ir.classify_install(
            ir.InstallEvidence(
                imported_root=CHECKOUT,
                interpreter="C:/py/python.exe",
                interpreter_version="3.14.6",
                lib_dirs=(LIB_DIR,),
                lib_metadata=(
                    installed_metadata(editable=True, editable_target=CHECKOUT),
                ),
                cwd="C:/tmp",
            )
        )
        self.assertEqual(resolution.running_from, ir.RUNNING_EDITABLE)
        self.assertEqual(resolution.conditions, ())

    def test_b_pythonpath_shadow_of_an_editable_target_is_not_healthy(self):
        """The reviewer's compound state, injected and deterministic."""
        resolution = classify(
            imported_file=FOREIGN_FILE,
            lib_metadata=(
                installed_metadata(editable=True, editable_target=CHECKOUT_A),
            ),
            expected_script_present=True,
            which=resolved_at(SCRIPTS_DIR),
            environ={"PYTHONPATH": CHECKOUT_B, "PATH": SCRIPTS_DIR},
        )
        self.assertEqual(resolution.running_from, ir.RUNNING_SOURCE)
        self.assertNotEqual(resolution.running_from, ir.RUNNING_EDITABLE)
        self.assertEqual(
            resolution.conditions, (ir.CONDITION_EDITABLE_MISMATCH,)
        )
        self.assertEqual(
            resolution.primary_condition, ir.CONDITION_EDITABLE_MISMATCH
        )
        self.assertTrue(resolution.pythonpath_contributes_imported)
        # The metadata still declares an editable install for this
        # interpreter; what it must not do is describe the imported code.
        self.assertTrue(resolution.editable_evidence)

    def test_c_mismatch_without_pythonpath_contribution_is_still_not_editable(self):
        resolution = classify(
            imported_file=FOREIGN_FILE,
            lib_metadata=(
                installed_metadata(editable=True, editable_target=CHECKOUT_A),
            ),
            expected_script_present=True,
            which=resolved_at(SCRIPTS_DIR),
            environ={"PYTHONPATH": "D:/unrelated", "PATH": SCRIPTS_DIR},
        )
        self.assertEqual(resolution.running_from, ir.RUNNING_SOURCE)
        self.assertIn(ir.CONDITION_EDITABLE_MISMATCH, resolution.conditions)
        self.assertTrue(resolution.pythonpath_set)
        self.assertFalse(resolution.pythonpath_contributes_imported)

    def test_c2_a_mismatch_with_no_pythonpath_at_all_is_still_reported(self):
        resolution = classify(
            imported_file=FOREIGN_FILE,
            lib_metadata=(
                installed_metadata(editable=True, editable_target=CHECKOUT_A),
            ),
            expected_script_present=True,
            which=resolved_at(SCRIPTS_DIR),
            environ={"PATH": SCRIPTS_DIR},
        )
        self.assertEqual(resolution.running_from, ir.RUNNING_SOURCE)
        self.assertIn(ir.CONDITION_EDITABLE_MISMATCH, resolution.conditions)
        self.assertFalse(resolution.pythonpath_set)

    def test_the_importlib_record_alone_can_establish_the_mismatch(self):
        """No probe hit: the distribution record is evidence too."""
        document = _FakeDistribution(
            _editable_document(Path(CHECKOUT_A).as_uri())
        )
        resolution = classify(
            imported_file=FOREIGN_FILE,
            lib_metadata=(),
            distribution_lookup=lambda name: document,
            expected_script_present=True,
            which=resolved_at(SCRIPTS_DIR),
            environ={"PYTHONPATH": CHECKOUT_B, "PATH": SCRIPTS_DIR},
        )
        self.assertEqual(resolution.running_from, ir.RUNNING_SOURCE)
        self.assertEqual(
            resolution.conditions, (ir.CONDITION_EDITABLE_MISMATCH,)
        )

    def test_the_importlib_record_with_a_matching_target_is_editable(self):
        document = _FakeDistribution(
            _editable_document(Path(CHECKOUT).as_uri())
        )
        resolution = classify(
            lib_metadata=(),
            distribution_lookup=lambda name: document,
            expected_script_present=True,
            which=resolved_at(SCRIPTS_DIR),
            environ={"PATH": SCRIPTS_DIR},
        )
        self.assertEqual(resolution.running_from, ir.RUNNING_EDITABLE)
        self.assertEqual(resolution.conditions, ())

    def test_one_matching_target_among_several_is_enough(self):
        resolution = classify(
            lib_metadata=(
                installed_metadata(
                    editable=True, editable_target=CHECKOUT_A
                ),
                installed_metadata(
                    lib_dir="D:/py/user/Lib/site-packages",
                    editable=True,
                    editable_target=CHECKOUT,
                ),
            ),
            expected_script_present=True,
            which=resolved_at(SCRIPTS_DIR),
            environ={"PATH": SCRIPTS_DIR},
        )
        self.assertEqual(resolution.running_from, ir.RUNNING_EDITABLE)
        self.assertEqual(resolution.conditions, ())

    def test_a_sibling_checkout_sharing_a_name_prefix_is_not_inside(self):
        # relinkra-shadow must never be read as a child of relinkra.
        self.assertFalse(ir._within(CHECKOUT_B + "/relinkra", CHECKOUT))
        self.assertFalse(ir._within("C:/work/relinkra2", CHECKOUT))

    def test_the_shadow_condition_is_not_double_reported_on_a_mismatch(self):
        # A mismatch is its own condition; folding it into
        # source_shadows_installed would name two causes for one state.
        resolution = classify(
            imported_file=FOREIGN_FILE,
            lib_metadata=(
                installed_metadata(editable=True, editable_target=CHECKOUT_A),
            ),
            environ={"PYTHONPATH": CHECKOUT_B},
        )
        self.assertNotIn(ir.CONDITION_SHADOWED, resolution.conditions)

    def test_a_targetless_editable_record_is_not_promoted(self):
        # PEP 610 requires the url; without it there is nothing to compare,
        # so the record is not authority and the state stays a checkout.
        resolution = classify(
            lib_metadata=(
                installed_metadata(editable=True, editable_target=None),
            ),
            environ={"PYTHONPATH": CHECKOUT_B},
            imported_file=FOREIGN_FILE,
        )
        self.assertEqual(resolution.running_from, ir.RUNNING_SOURCE)
        self.assertFalse(resolution.editable_evidence)
        self.assertNotIn(ir.CONDITION_EDITABLE_MISMATCH, resolution.conditions)
        self.assertIn(ir.CONDITION_SHADOWED, resolution.conditions)

    def test_editable_target_count_is_bounded(self):
        flood = tuple(
            installed_metadata(
                lib_dir=f"C:/lib{index}",
                editable=True,
                editable_target=f"C:/work/target{index}",
            )
            for index in range(ir.MAX_EDITABLE_TARGETS + 6)
        )
        resolution = classify(lib_metadata=flood)
        # Bounded work, and none of the flooded targets contains the
        # imported root, so the honest answer is still a mismatch.
        self.assertEqual(resolution.running_from, ir.RUNNING_SOURCE)
        self.assertIn(ir.CONDITION_EDITABLE_MISMATCH, resolution.conditions)


class DirectUrlParsingTests(unittest.TestCase):
    """PEP 610 parsing: fail-honest, and target-aware (cases D-H)."""

    def test_a_file_url_yields_its_local_target(self):
        self.assertEqual(
            ir._local_target_from_url("file:///C:/work/relinkra"),
            "C:/work/relinkra",
        )
        self.assertEqual(
            ir._local_target_from_url("file:///home/user/relinkra"),
            "/home/user/relinkra",
        )

    def test_e_percent_escapes_are_decoded(self):
        self.assertEqual(
            ir._local_target_from_url("file:///C:/work/my%20project"),
            "C:/work/my project",
        )

    def test_f_percent_encoded_unicode_is_decoded(self):
        self.assertEqual(
            ir._local_target_from_url(
                "file:///home/user/%D0%94%D0%BE%D0%BA%D1%83%D0%BC%D0%B5%D0%BD%D1%82%D1%8B"
            ),
            "/home/user/Документы",
        )

    def test_a_bare_local_path_is_accepted_when_it_is_absolute(self):
        self.assertEqual(
            ir._local_target_from_url("C:/work/relinkra"),
            "C:/work/relinkra",
        )
        self.assertEqual(
            ir._local_target_from_url("\\\\server\\share\\relinkra"),
            "\\\\server\\share\\relinkra",
        )
        self.assertEqual(
            ir._local_target_from_url("/home/user/relinkra"),
            "/home/user/relinkra",
        )

    def test_remote_and_relative_targets_are_not_authority(self):
        for url in (
            "https://example.invalid/relinkra",
            "git+https://example.invalid/relinkra.git",
            "file:relative/relinkra",
            "relative/relinkra",
            "",
            None,
            7,
        ):
            self.assertIsNone(ir._local_target_from_url(url), url)

    def test_d_editable_without_a_usable_target_is_not_promoted(self):
        for document in (
            json.dumps({"dir_info": {"editable": True}}),
            json.dumps({"url": "https://x.invalid/y", "dir_info": {"editable": True}}),
            json.dumps({"url": "file:rel", "dir_info": {"editable": True}}),
            "not json at all",
            json.dumps(["not", "a", "document"]),
            json.dumps({"url": "file:///C:/x", "dir_info": {"editable": False}}),
            json.dumps({"url": "file:///C:/x"}),
        ):
            self.assertEqual(ir._parse_direct_url(document), (False, None), document)

    def test_a_valid_document_yields_its_target(self):
        self.assertEqual(
            ir._parse_direct_url(
                json.dumps(
                    {
                        "url": "file:///C:/work/relinkra",
                        "dir_info": {"editable": True},
                    }
                )
            ),
            (True, "C:/work/relinkra"),
        )

    def test_a_local_host_and_a_network_share_are_read_literally(self):
        self.assertEqual(
            ir._local_target_from_url("file://localhost/C:/work/relinkra"),
            "C:/work/relinkra",
        )
        self.assertEqual(
            ir._local_target_from_url("file://server/share/relinkra"),
            "//server/share/relinkra",
        )

    def test_target_dedupe_folds_duplicates_and_is_bounded(self):
        values = [
            "C:/work/relinkra",
            "C:/work/relinkra",
            "C:/work/relinkra/",
        ] + [
            f"C:/work/target{index}"
            for index in range(ir.MAX_EDITABLE_TARGETS + 6)
        ]
        bounded = ir._unique_paths(values, ir.MAX_EDITABLE_TARGETS)
        self.assertEqual(len(bounded), ir.MAX_EDITABLE_TARGETS)
        self.assertEqual(len(ir._unique_paths([], 4)), 0)
        self.assertEqual(ir._unique_paths([None, ""], 4), ())

    def test_g_windows_case_only_differences_are_equal_on_windows(self):
        if os.name != "nt":
            self.skipTest("Windows path semantics only")
        self.assertTrue(
            ir._within("C:/Work/Relinkra/relinkra", "c:/work/relinkra")
        )

    def test_h_case_is_distinct_on_posix(self):
        if os.name == "nt":
            self.skipTest("POSIX path semantics only")
        self.assertFalse(
            ir._within("C:/Work/Relinkra/relinkra", "c:/work/relinkra")
        )


class EditableMetadataProbeTests(unittest.TestCase):
    """The filesystem-facing half of the editable claim, on a temp tree."""

    @staticmethod
    def _write_direct_url(lib_dir: Path, document: str) -> None:
        dist_info = lib_dir / "relinkra-0.1.4.dist-info"
        dist_info.mkdir(parents=True, exist_ok=True)
        (dist_info / "direct_url.json").write_text(document, encoding="utf-8")

    def _probe(self, lib_dir: Path) -> ir.LibMetadata:
        found = ir._probe_lib_metadata([str(lib_dir)])
        self.assertEqual(len(found), 1)
        return found[0]

    def test_e_a_target_path_with_spaces_round_trips(self):
        with tempfile.TemporaryDirectory() as tmp:
            lib = Path(tmp) / "site-packages"
            project = Path(tmp) / "my project"
            (project / "relinkra").mkdir(parents=True)
            self._write_direct_url(
                lib,
                json.dumps(
                    {
                        "url": project.as_uri(),
                        "dir_info": {"editable": True},
                    }
                ),
            )
            metadata = self._probe(lib)
            self.assertTrue(metadata.editable)
            self.assertTrue(
                ir._within(str(project / "relinkra"), metadata.editable_target)
            )

    def test_f_a_unicode_target_path_round_trips(self):
        with tempfile.TemporaryDirectory() as tmp:
            lib = Path(tmp) / "site-packages"
            project = Path(tmp) / "Документы" / "проект"
            (project / "relinkra").mkdir(parents=True)
            self._write_direct_url(
                lib,
                json.dumps(
                    {
                        "url": project.as_uri(),
                        "dir_info": {"editable": True},
                    }
                ),
            )
            metadata = self._probe(lib)
            self.assertTrue(metadata.editable)
            self.assertTrue(
                ir._within(str(project / "relinkra"), metadata.editable_target)
            )

    def test_d_a_malformed_document_is_not_editable_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            lib = Path(tmp) / "site-packages"
            self._write_direct_url(lib, "{ not json")
            metadata = self._probe(lib)
            self.assertFalse(metadata.editable)
            self.assertIsNone(metadata.editable_target)

    def test_a_targetless_document_is_not_editable_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            lib = Path(tmp) / "site-packages"
            self._write_direct_url(
                lib, json.dumps({"dir_info": {"editable": True}})
            )
            metadata = self._probe(lib)
            self.assertFalse(metadata.editable)
            self.assertIsNone(metadata.editable_target)

    def test_an_oversized_direct_url_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            lib = Path(tmp) / "site-packages"
            self._write_direct_url(
                lib,
                json.dumps(
                    {
                        "url": "file:///C:/work/relinkra",
                        "dir_info": {"editable": True},
                        "padding": "x" * (ir.MAX_DIRECT_URL_BYTES + 1024),
                    }
                ),
            )
            metadata = self._probe(lib)
            self.assertFalse(metadata.editable)


# ---------------------------------------------------------------------------
# Console-script resolution (cases E-H, K-L)
# ---------------------------------------------------------------------------


class ConsoleScriptTests(unittest.TestCase):
    """Can the ``relinkra`` command actually be reached?"""

    def test_e_resolved_into_this_interpreters_script_dir_is_clean(self):
        resolution = classify(
            imported_file=INSTALLED_FILE,
            lib_metadata=(installed_metadata(),),
            expected_script_present=True,
            which=resolved_at(SCRIPTS_DIR),
            environ={"PATH": SCRIPTS_DIR},
        )
        self.assertEqual(resolution.cli_status, ir.CLI_RESOLVED)
        self.assertEqual(resolution.conditions, ())

    def test_f_present_but_no_path_entry_reaches_it(self):
        """Failure class A, exactly as observed in the field."""
        resolution = classify(
            imported_file=INSTALLED_FILE,
            lib_metadata=(installed_metadata(),),
            expected_script_present=True,
            which=None,
            environ={"PATH": "C:/Windows"},
        )
        self.assertEqual(resolution.cli_status, ir.CLI_PRESENT_NOT_ON_PATH)
        self.assertIn(ir.CONDITION_CLI_NOT_ON_PATH, resolution.conditions)
        self.assertEqual(
            resolution.primary_condition, ir.CONDITION_CLI_NOT_ON_PATH
        )

    def test_f2_scripts_dir_off_path_is_reported_even_when_resolved(self):
        """The user-scheme script dir is this interpreter's, too."""
        resolution = classify(
            imported_file=INSTALLED_FILE,
            lib_metadata=(installed_metadata(),),
            expected_script_present=True,
            which=resolved_at(USER_SCRIPTS_DIR),
            environ={"PATH": USER_SCRIPTS_DIR},
        )
        self.assertEqual(resolution.cli_status, ir.CLI_RESOLVED)
        self.assertEqual(resolution.conditions, ())
        self.assertFalse(resolution.scripts_dir_on_path)
        self.assertEqual(resolution.scripts_dir_name, "Scripts")

    def test_g_a_path_cli_outside_this_interpreters_dirs_is_suspect(self):
        resolution = classify(
            imported_file=INSTALLED_FILE,
            lib_metadata=(installed_metadata(),),
            expected_script_present=True,
            which=resolved_at(OTHER_SCRIPTS_DIR),
            environ={"PATH": OTHER_SCRIPTS_DIR},
        )
        self.assertEqual(resolution.cli_status, ir.CLI_RESOLVED_ELSEWHERE)
        self.assertIn(ir.CONDITION_CLI_ELSEWHERE, resolution.conditions)

    def test_h_no_console_script_at_all(self):
        resolution = classify(
            imported_file=INSTALLED_FILE,
            lib_metadata=(installed_metadata(),),
            expected_script_present=False,
            which=None,
            environ={"PATH": "C:/Windows"},
        )
        self.assertEqual(resolution.cli_status, ir.CLI_ABSENT)
        self.assertIn(ir.CONDITION_CLI_MISSING, resolution.conditions)

    def test_h2_a_cli_with_no_install_is_still_compared_to_this_interpreter(self):
        resolution = classify(
            lib_metadata=(),
            which=resolved_at(OTHER_SCRIPTS_DIR),
            environ={"PATH": OTHER_SCRIPTS_DIR},
        )
        self.assertIn(ir.CONDITION_CLI_ELSEWHERE, resolution.conditions)

    def test_k_windows_launcher_name_is_found_in_the_script_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            scripts = Path(tmp) / "Scripts"
            scripts.mkdir()
            (scripts / "relinkra.exe").write_bytes(b"MZ")
            self.assertTrue(ir._expected_script_present(str(scripts)))

    def test_l_posix_extensionless_launcher_is_found_in_bin(self):
        with tempfile.TemporaryDirectory() as tmp:
            bin_dir = Path(tmp) / "bin"
            bin_dir.mkdir()
            launcher = bin_dir / "relinkra"
            launcher.write_text("#!/usr/bin/env python\n", encoding="utf-8")
            self.assertTrue(ir._expected_script_present(str(bin_dir)))

    def test_l2_an_unrelated_directory_reports_no_launcher(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(ir._expected_script_present(tmp))
            self.assertFalse(ir._expected_script_present(None))

    def test_unknown_when_the_interpreter_reports_no_script_directory(self):
        resolution = classify(
            scripts_dir=None,
            user_scripts_dir=None,
            which=None,
        )
        self.assertEqual(resolution.cli_status, ir.CLI_UNKNOWN)


class ExplicitNoScriptDirectoryTests(unittest.TestCase):
    """An interpreter that discloses no script directory claims nothing."""

    def test_classification_with_no_script_directory_is_unknown(self):
        # A location outside the library dirs with no library dirs known
        # is ambiguous, so the script directory is reported as unknown
        # rather than as absent — nothing was proven missing.
        resolution = ir.classify_install(
            ir.InstallEvidence(
                imported_root=CHECKOUT,
                interpreter="C:/py/python.exe",
                interpreter_version="3.14.6",
                lib_dirs=(LIB_DIR,),
                scripts_dir=None,
                user_scripts_dir=None,
                cwd="C:/tmp",
                expected_script_present=False,
                checkout_evidence=True,
            )
        )
        self.assertEqual(resolution.cli_status, ir.CLI_UNKNOWN)
        self.assertNotIn(ir.CONDITION_CLI_MISSING, resolution.conditions)


# ---------------------------------------------------------------------------
# Filesystem probing (cases M-N and boundedness)
# ---------------------------------------------------------------------------


class ProbingTests(unittest.TestCase):
    """The filesystem-facing half: bounded, and honest about failure."""

    def test_m_paths_containing_spaces_are_handled(self):
        with tempfile.TemporaryDirectory() as tmp:
            spaced = Path(tmp) / "Program Files" / "Python 3.14" / "Scripts"
            spaced.mkdir(parents=True)
            (spaced / "relinkra.exe").write_bytes(b"MZ")
            self.assertTrue(ir._expected_script_present(str(spaced)))

    def test_n_unicode_paths_are_handled(self):
        with tempfile.TemporaryDirectory() as tmp:
            unicode_dir = Path(tmp) / "Документы" / "Pythøn" / "bin"
            unicode_dir.mkdir(parents=True)
            (unicode_dir / "relinkra").write_text("", encoding="utf-8")
            self.assertTrue(ir._expected_script_present(str(unicode_dir)))

    def test_library_probe_finds_metadata_and_reads_its_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            dist_info = Path(tmp) / "relinkra-0.9.9.dist-info"
            dist_info.mkdir()
            (dist_info / "METADATA").write_text(
                "Metadata-Version: 2.1\nName: relinkra\nVersion: 0.9.9\n"
                "\nA very long body that must never be parsed.\n",
                encoding="utf-8",
            )
            found = ir._probe_lib_metadata([tmp])
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0].kind, ir.SHAPE_DIST_INFO)
            self.assertEqual(found[0].version, "0.9.9")
            self.assertFalse(found[0].editable)

    def test_library_probe_detects_editable_from_pep610_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            dist_info = Path(tmp) / "relinkra-0.1.4.dist-info"
            dist_info.mkdir()
            (dist_info / "METADATA").write_text(
                "Name: relinkra\nVersion: 0.1.4\n\n", encoding="utf-8"
            )
            (dist_info / "direct_url.json").write_text(
                json.dumps(
                    {
                        "url": "file:///work/relinkra",
                        "dir_info": {"editable": True},
                    }
                ),
                encoding="utf-8",
            )
            found = ir._probe_lib_metadata([tmp])
            self.assertEqual(len(found), 1)
            self.assertTrue(found[0].editable)

    def test_editable_evidence_is_absent_when_metadata_does_not_say_so(self):
        with tempfile.TemporaryDirectory() as tmp:
            dist_info = Path(tmp) / "relinkra-0.1.4.dist-info"
            dist_info.mkdir()
            (dist_info / "direct_url.json").write_text(
                json.dumps({"url": "file:///work/relinkra"}),
                encoding="utf-8",
            )
            found = ir._probe_lib_metadata([tmp])
            self.assertEqual(len(found), 1)
            self.assertFalse(found[0].editable)

    def test_a_non_editable_egg_info_is_not_promoted_to_editable(self):
        with tempfile.TemporaryDirectory() as tmp:
            egg_info = Path(tmp) / "relinkra.egg-info"
            egg_info.mkdir()
            (egg_info / "direct_url.json").write_text(
                json.dumps({"dir_info": {"editable": True}}),
                encoding="utf-8",
            )
            found = ir._probe_lib_metadata([tmp])
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0].kind, ir.SHAPE_EGG_INFO)
            self.assertFalse(found[0].editable)

    def test_checkout_evidence_needs_a_project_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(ir._checkout_evidence(tmp))
            (Path(tmp) / "pyproject.toml").write_text("", encoding="utf-8")
            self.assertTrue(ir._checkout_evidence(tmp))
            self.assertFalse(ir._checkout_evidence(None))

    def test_unreadable_metadata_directory_is_not_evidence(self):
        missing = "C:/definitely/not/here"
        self.assertEqual(ir._probe_lib_metadata([missing]), ())

    def test_version_reader_stops_at_the_header_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            dist_info = Path(tmp) / "relinkra-1.2.3.dist-info"
            dist_info.mkdir()
            (dist_info / "METADATA").write_text(
                "Metadata-Version: 2.1\nName: relinkra\n"
                "\nVersion: 9.9.9\n",
                encoding="utf-8",
            )
            self.assertIsNone(
                ir.read_metadata_version(str(dist_info), ir.SHAPE_DIST_INFO)
            )

    def test_version_reader_returns_none_on_garbage_input(self):
        self.assertIsNone(ir.read_metadata_version(None, ir.SHAPE_DIST_INFO))
        self.assertIsNone(ir.read_metadata_version("C:/nope", "unknown"))

    def test_oversized_metadata_is_refused_rather_than_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            dist_info = Path(tmp) / "relinkra-0.1.4.dist-info"
            dist_info.mkdir()
            (dist_info / "METADATA").write_text(
                "Name: relinkra\nVersion: 0.1.4\n"
                + ("x" * (ir.MAX_METADATA_BYTES + 1024)),
                encoding="utf-8",
            )
            self.assertIsNone(
                ir.read_metadata_version(str(dist_info), ir.SHAPE_DIST_INFO)
            )


# ---------------------------------------------------------------------------
# Privacy and bounded output (case O)
# ---------------------------------------------------------------------------


class PortableOutputTests(unittest.TestCase):
    """The portable projection may not carry a machine-local path."""

    def _assert_path_free(self, payload):
        def walk(value):
            if isinstance(value, str):
                self.assertFalse(
                    contains_absolute_path(value),
                    f"absolute path leaked: {value!r}",
                )
            elif isinstance(value, dict):
                for item in value.values():
                    walk(item)
            elif isinstance(value, (list, tuple)):
                for item in value:
                    walk(item)

        walk(payload)

    def test_to_dict_is_path_free_in_every_mode(self):
        modes = (
            classify(imported_file=INSTALLED_FILE,
                     lib_metadata=(installed_metadata(),)),
            classify(lib_metadata=(installed_metadata(),)),
            classify(lib_metadata=(installed_metadata(editable=True),)),
            classify(lib_dirs=()),
        )
        for resolution in modes:
            self._assert_path_free(resolution.to_dict())

    def test_to_dict_never_carries_the_imported_root_or_interpreter(self):
        resolution = classify(
            lib_metadata=(installed_metadata(),),
            which=resolved_at(SCRIPTS_DIR),
            environ={"PYTHONPATH": CHECKOUT, "PATH": SCRIPTS_DIR},
        )
        rendered = json.dumps(resolution.to_dict())
        self.assertNotIn(CHECKOUT, rendered)
        self.assertNotIn(LIB_DIR, rendered)
        self.assertNotIn(SCRIPTS_DIR, rendered)

    def test_local_paths_is_the_only_projection_with_real_paths(self):
        resolution = classify(
            lib_metadata=(installed_metadata(),),
            which=resolved_at(SCRIPTS_DIR),
            environ={"PYTHONPATH": CHECKOUT},
        )
        local = resolution.local_paths()
        # Reported in the native form, which is the form the operator can
        # actually paste into a shell on this machine.
        self.assertEqual(local["package_origin"], str(Path(CHECKOUT)))
        self.assertEqual(
            local["expected_scripts_dir"], str(Path(SCRIPTS_DIR))
        )
        # PYTHONPATH entries are echoed verbatim, not normalized: the
        # operator has to find that exact string in their environment.
        self.assertEqual(local["pythonpath"], [CHECKOUT])

    def test_local_paths_bounds_the_pythonpath_it_reports(self):
        long_entry = "C:/" + ("p" * (ir.MAX_LOCAL_PATH_CHARS * 3))
        entries = os.pathsep.join(
            [f"C:/entry{index}" for index in range(ir.MAX_LOCAL_PATHS + 6)]
            + [long_entry]
        )
        resolution = classify(environ={"PYTHONPATH": entries})
        local = resolution.local_paths()
        self.assertLessEqual(len(local["pythonpath"]), ir.MAX_LOCAL_PATHS)
        for entry in local["pythonpath"]:
            self.assertLessEqual(len(entry), ir.MAX_LOCAL_PATH_CHARS)

    def test_pythonpath_scan_is_bounded(self):
        flood = os.pathsep.join(
            f"C:/p{index}" for index in range(ir.MAX_PYTHONPATH_ENTRIES + 50)
        )
        self.assertEqual(
            len(ir._pythonpath_entries(flood)), ir.MAX_PYTHONPATH_ENTRIES
        )

    def test_path_scan_is_bounded(self):
        flood = os.pathsep.join(
            f"C:/b{index}" for index in range(ir.MAX_PATH_ENTRIES + 50)
        )
        self.assertFalse(ir._path_contains(flood, "C:/elsewhere"))

    def test_library_probe_is_bounded_per_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            for index in range(ir.MAX_METADATA_PER_DIR + 4):
                (Path(tmp) / f"relinkra-0.{index}.dist-info").mkdir()
            found = ir._probe_lib_metadata([tmp])
            self.assertLessEqual(len(found), ir.MAX_METADATA_PER_DIR)


# ---------------------------------------------------------------------------
# Doctor integration
# ---------------------------------------------------------------------------


class InstallCheckRenderingTests(unittest.TestCase):
    """The doctor check: severity, actionability, and honest wording."""

    def test_a_healthy_install_passes(self):
        check = check_install_resolution(
            classify(
                imported_file=INSTALLED_FILE,
                lib_metadata=(installed_metadata(),),
                expected_script_present=True,
                which=resolved_at(SCRIPTS_DIR),
                environ={"PATH": SCRIPTS_DIR},
            )
        )
        self.assertEqual(check.name, "Install resolution")
        self.assertEqual(check.status, PASS)
        self.assertIn("installed distribution 0.1.4", check.detail)

    def test_a_source_checkout_with_no_install_passes_without_noise(self):
        check = check_install_resolution(classify(lib_metadata=()))
        self.assertEqual(check.status, PASS)
        self.assertIn("source checkout", check.detail)
        self.assertEqual(check.action, "")

    def test_every_warning_is_actionable(self):
        warned = [
            classify(
                imported_file=INSTALLED_FILE,
                lib_metadata=(installed_metadata(),),
                expected_script_present=True,
                which=None,
                environ={"PATH": "C:/Windows"},
            ),
            classify(
                imported_file=INSTALLED_FILE,
                lib_metadata=(installed_metadata(),),
                which=resolved_at(OTHER_SCRIPTS_DIR),
                environ={"PATH": OTHER_SCRIPTS_DIR},
            ),
            classify(
                imported_file=INSTALLED_FILE,
                lib_metadata=(installed_metadata(),),
            ),
            classify(lib_metadata=(installed_metadata(),)),
            classify(lib_dirs=()),
        ]
        for resolution in warned:
            check = check_install_resolution(resolution)
            self.assertEqual(check.status, WARN)
            self.assertTrue(check.action, check.detail)
            self.assertTrue(check.detail)

    def test_the_check_never_fails(self):
        """A WARN never changes the exit code, and that is deliberate."""
        for kwargs in (
            {"imported_file": INSTALLED_FILE},
            {"lib_metadata": (installed_metadata(),)},
            {"lib_dirs": ()},
            {},
        ):
            check = check_install_resolution(classify(**kwargs))
            self.assertIn(check.status, (PASS, WARN))

    def test_shadow_warning_names_the_gap_without_claiming_an_index(self):
        # A properly installed, PATH-reachable CLI that still loses the
        # import race: the classic "I installed it, yet it runs old code".
        check = check_install_resolution(
            classify(
                lib_metadata=(installed_metadata(),),
                expected_script_present=True,
                which=resolved_at(SCRIPTS_DIR),
                environ={"PYTHONPATH": CHECKOUT, "PATH": SCRIPTS_DIR},
            )
        )
        self.assertEqual(check.status, WARN)
        self.assertEqual(
            check.detail.count("resolved to the checkout"), 1
        )
        self.assertIn("PYTHONPATH", check.action)
        lowered = check.detail.lower()
        self.assertNotIn("pypi", lowered)
        self.assertNotIn("site-packages", lowered)

    def test_pythonpath_action_does_not_mention_it_when_it_is_not_set(self):
        check = check_install_resolution(
            classify(lib_metadata=(installed_metadata(),), cwd=CHECKOUT)
        )
        self.assertEqual(check.status, WARN)
        self.assertNotIn("PYTHONPATH points", check.action)

    def test_detail_is_path_free(self):
        for kwargs in (
            {"lib_metadata": (installed_metadata(),)},
            {"lib_metadata": (installed_metadata(),), "lib_dirs": ()},
            {"imported_file": INSTALLED_FILE},
        ):
            check = check_install_resolution(classify(**kwargs))
            self.assertFalse(contains_absolute_path(check.detail))
            self.assertFalse(contains_absolute_path(check.action))

    def test_an_editable_target_mismatch_warns_and_is_path_free(self):
        check = check_install_resolution(mismatch_resolution())
        self.assertEqual(check.status, WARN)
        self.assertIn("editable target", check.detail)
        self.assertIn("PYTHONPATH", check.action)
        self.assertFalse(contains_absolute_path(check.detail))
        self.assertFalse(contains_absolute_path(check.action))
        lowered = check.detail.lower()
        self.assertNotIn("pypi", lowered)
        self.assertNotIn("site-packages", lowered)

    def test_a_mismatch_without_pythonpath_offers_a_different_action(self):
        check = check_install_resolution(
            classify(
                imported_file=FOREIGN_FILE,
                lib_metadata=(
                    installed_metadata(
                        editable=True, editable_target=CHECKOUT_A
                    ),
                ),
                expected_script_present=True,
                which=resolved_at(SCRIPTS_DIR),
                environ={"PATH": SCRIPTS_DIR},
            )
        )
        self.assertEqual(check.status, WARN)
        self.assertNotIn("PYTHONPATH points", check.action)
        self.assertIn("editable", check.action)

    def test_a_targetless_editable_record_reads_as_a_shadow_not_a_mismatch(self):
        check = check_install_resolution(
            classify(
                imported_file=FOREIGN_FILE,
                lib_metadata=(
                    installed_metadata(editable=True, editable_target=None),
                ),
                expected_script_present=True,
                which=resolved_at(SCRIPTS_DIR),
                environ={"PYTHONPATH": CHECKOUT_B, "PATH": SCRIPTS_DIR},
            )
        )
        self.assertEqual(check.status, WARN)
        self.assertIn("resolved to the checkout", check.detail)
        self.assertNotIn("editable target", check.detail)


class DoctorAndVersionIntegrationTests(unittest.TestCase):
    """The real CLI wiring, driven through ``main(argv)``."""

    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = product_cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_doctor_reports_the_install_section_and_a_clean_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Outside a repository on purpose: doctor must still disclose
            # which code is running, and the payload audit must still hold.
            code, out, _ = self._run(["doctor", "--json", "--path", tmp])
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        payload = json.loads(out)
        self.assertIn("install", payload)
        names = [check["name"] for check in payload["checks"]]
        self.assertIn("Install resolution", names)
        portable = [
            check
            for check in payload["checks"]
            if check["name"] == "Portable output"
        ]
        self.assertEqual(len(portable), 1)
        self.assertEqual(portable[0]["status"], PASS)
        self.assertIn(
            payload["install"]["running_from"],
            (
                ir.RUNNING_INSTALLED,
                ir.RUNNING_SOURCE,
                ir.RUNNING_EDITABLE,
                ir.RUNNING_AMBIGUOUS,
            ),
        )
        self.assertIn("interpreter", payload["install"])

    def test_doctor_default_view_names_the_install_row(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, out, _ = self._run(["doctor", "--path", tmp])
        self.assertIn("Install resolution", out)

    def test_version_default_payload_is_unchanged_and_path_free(self):
        code, out, _ = self._run(["version", "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(
            set(payload),
            {
                "relinkra_version",
                "contract_version",
                "python_version",
                "min_python_version",
                "install_mode",
                "installed_metadata_version",
                "metadata_version_consistent",
                "build_provenance",
            },
        )
        self.assertNotIn("local_paths", payload)
        self.assertNotIn(str(Path.cwd()), out)

    def test_version_paths_is_an_explicit_opt_in(self):
        code, out, _ = self._run(["version", "--paths", "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertIn("local_paths", payload)
        local = payload["local_paths"]
        for key in (
            "interpreter",
            "package_origin",
            "distribution_metadata",
            "expected_scripts_dir",
            "resolved_console_script",
            "pythonpath",
        ):
            self.assertIn(key, local)
        self.assertEqual(local["package_origin"], str(Path(ir.__file__).resolve().parent.parent))

    def test_version_paths_text_renders_the_same_facts(self):
        code, out, _ = self._run(["version", "--paths"])
        self.assertEqual(code, 0)
        self.assertIn("local resolution", out)
        self.assertIn("interpreter:", out)
        self.assertIn("expected_scripts_dir:", out)

    def test_version_without_paths_stays_path_free(self):
        _, out, _ = self._run(["version"])
        self.assertNotIn(str(Path.cwd()), out)
        self.assertNotIn("local resolution", out)

    def test_doctor_install_status_follows_the_injected_resolution(self):
        """Doctor renders whatever the resolver establishes, verbatim."""
        shadowed = classify(
            lib_metadata=(installed_metadata(),),
            expected_script_present=True,
            which=resolved_at(SCRIPTS_DIR),
            environ={"PYTHONPATH": CHECKOUT, "PATH": SCRIPTS_DIR},
        )
        with mock.patch.object(
            product_cli.install_resolution,
            "resolve_install",
            return_value=shadowed,
        ):
            with tempfile.TemporaryDirectory() as tmp:
                _, out, _ = self._run(["doctor", "--json", "--path", tmp])
        payload = json.loads(out)
        row = [
            check
            for check in payload["checks"]
            if check["name"] == "Install resolution"
        ][0]
        self.assertEqual(row["status"], WARN)
        self.assertTrue(row["action"])
        self.assertEqual(
            payload["install"]["conditions"],
            [ir.CONDITION_SHADOWED],
        )

    def test_i_doctor_renders_a_mismatch_and_keeps_the_payload_portable(self):
        with mock.patch.object(
            product_cli.install_resolution,
            "resolve_install",
            return_value=mismatch_resolution(),
        ):
            with tempfile.TemporaryDirectory() as tmp:
                _, out, _ = self._run(["doctor", "--json", "--path", tmp])
        payload = json.loads(out)
        row = [
            check
            for check in payload["checks"]
            if check["name"] == "Install resolution"
        ][0]
        self.assertEqual(row["status"], WARN)
        self.assertTrue(row["action"])
        self.assertEqual(
            payload["install"]["conditions"],
            [ir.CONDITION_EDITABLE_MISMATCH],
        )
        # The mismatch classification must not smuggle a local path into
        # the payload: the self-audit row still has to pass.
        portable = [
            check
            for check in payload["checks"]
            if check["name"] == "Portable output"
        ][0]
        self.assertEqual(portable["status"], PASS)

    def test_j_version_paths_stays_an_explicit_opt_in(self):
        _, default_out, _ = self._run(["version"])
        self.assertNotIn("local resolution", default_out)
        _, paths_out, _ = self._run(["version", "--paths"])
        self.assertIn("package_origin:", paths_out)
        _, json_out, _ = self._run(["version", "--json"])
        self.assertNotIn("local_paths", json.loads(json_out))

    def test_m_a_mismatch_warning_never_moves_the_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            plain_code, plain_out, _ = self._run(
                ["doctor", "--json", "--path", tmp]
            )
            with mock.patch.object(
                product_cli.install_resolution,
                "resolve_install",
                return_value=mismatch_resolution(),
            ):
                code, out, _ = self._run(
                    ["doctor", "--json", "--path", tmp]
                )
        # The WARN is real, and it is still not a FAIL: same exit code and
        # same FAIL count as the very same machine without the mismatch.
        self.assertEqual(code, plain_code)
        mismatch_payload = json.loads(out)
        plain_payload = json.loads(plain_out)
        self.assertEqual(
            mismatch_payload["summary"]["fail"],
            plain_payload["summary"]["fail"],
        )
        row = [
            check
            for check in mismatch_payload["checks"]
            if check["name"] == "Install resolution"
        ][0]
        self.assertEqual(row["status"], WARN)

    def test_n_an_install_warning_never_outranks_onboarding(self):
        """The install row is appended last, so onboarding keeps Next.

        The compact "Next:" line takes the first warning in check order,
        and cmd_doctor appends the install check after every workspace
        row. A mismatch must never displace "Run 'relinkra init'.".
        """
        with tempfile.TemporaryDirectory() as tmp:
            repo = gf.make_repo(tmp)
            with mock.patch.object(
                product_cli.install_resolution,
                "resolve_install",
                return_value=mismatch_resolution(),
            ):
                _, out, _ = self._run(["doctor", "--path", repo])
        self.assertIn("Install resolution", out)
        next_lines = [
            line for line in out.splitlines() if line.startswith("Next: ")
        ]
        self.assertEqual(len(next_lines), 1)
        self.assertIn("relinkra init", next_lines[0])


class GathererTests(unittest.TestCase):
    """The live gatherer, exercised through its own seams."""

    def test_the_gathered_root_is_the_package_root(self):
        found = ir.gather_install_evidence(distribution_lookup=lambda n: None)
        expected = str(Path(ir.__file__).resolve().parent.parent)
        self.assertEqual(found.imported_root, expected)

    def test_a_failing_distribution_lookup_is_not_fatal(self):
        def explode(name):
            raise RuntimeError("metadata store is broken")

        found = ir.gather_install_evidence(distribution_lookup=explode)
        self.assertIsNone(found.distribution)
        self.assertIsNone(found.distribution_version)

    def test_a_failing_which_is_not_fatal(self):
        def explode(name):
            raise OSError("PATH is unreadable")

        resolution = ir.resolve_install(which=explode)
        self.assertIn(
            resolution.cli_status,
            (ir.CLI_ABSENT, ir.CLI_PRESENT_NOT_ON_PATH, ir.CLI_UNKNOWN),
        )

    def test_interpreter_identity_is_reported_without_a_path(self):
        payload = ir.resolve_install().to_dict()
        self.assertEqual(payload["interpreter"]["version"], (
            ".".join(str(part) for part in sys.version_info[:3])
        ))
        self.assertIsNotNone(payload["interpreter"]["name"])
        self.assertNotIn(os.sep, payload["interpreter"]["name"] or "")


if __name__ == "__main__":
    unittest.main()
