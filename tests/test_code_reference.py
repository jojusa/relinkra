"""Offline deterministic tests for the R1D CodeReference model."""

from __future__ import annotations

import unittest

from relinkra.code_reference import (
    CODE_REF_ID_RE,
    CodeReference,
    CodeRefValidationError,
    compute_code_reference_id,
    derive_language,
    normalize_repo_path,
)

PID = "rlk_" + "a" * 32
WID_A = "ws_" + "1" * 32
WID_B = "ws_" + "2" * 32

# Real R1A fixture slugs: same repo, two different workspace paths, so
# two different path-derived CBM project names.
SLUG_A = "C-Desarrollos-relinkra-.relinkra-r1a-fixture-a"
SLUG_B = "C-Desarrollos-relinkra-.relinkra-r1a-fixture-b"

REPO = {
    "kind": "remote",
    "value": "remote://git/github.com/org/repo",
    "trust": "strong",
}


def make_ref(**over):
    defaults = dict(
        project_id=PID,
        reference_kind="symbol",
        file_path="src/calculator.py",
        symbol_name="add",
        qualified_name="src.calculator.add",
        symbol_kind="Function",
    )
    defaults.update(over)
    return CodeReference(**defaults)


class TestPathNormalization(unittest.TestCase):
    def test_backslashes_become_posix(self):
        self.assertEqual(normalize_repo_path(r"src\pkg\mod.py"), "src/pkg/mod.py")

    def test_dot_and_empty_segments_collapse(self):
        self.assertEqual(normalize_repo_path("./src//pkg/./mod.py"), "src/pkg/mod.py")

    def test_rejects_absolute_paths(self):
        for bad in (
            "/home/user/repo/src/x.py",
            r"C:\Desarrollos\relinkra\src\x.py",
            "C:/Desarrollos/relinkra/src/x.py",
            r"\\server\share\src\x.py",
            r"\relative\to\drive-root",
        ):
            with self.assertRaises(CodeRefValidationError, msg=bad):
                normalize_repo_path(bad)

    def test_rejects_traversal(self):
        for bad in ("../x.py", "src/../x.py", r"src\..\x.py", ".."):
            with self.assertRaises(CodeRefValidationError, msg=bad):
                normalize_repo_path(bad)

    def test_rejects_control_chars_and_empty(self):
        for bad in ("", "   ", "src/a\nb.py", "src/a\tb.py", "src/a\x00b.py"):
            with self.assertRaises(CodeRefValidationError, msg=repr(bad)):
                normalize_repo_path(bad)

    def test_rejects_url_like_and_scp_like(self):
        for bad in (
            "https://user:hunter2@github.com/org/repo",
            "git@github.com:org/repo",
        ):
            with self.assertRaises(CodeRefValidationError, msg=bad):
                normalize_repo_path(bad)

    def test_npm_scoped_dir_is_legal(self):
        self.assertEqual(
            normalize_repo_path("node_modules/@types/node/index.d.ts"),
            "node_modules/@types/node/index.d.ts",
        )


class TestModelValidation(unittest.TestCase):
    def test_file_ref_needs_no_symbol(self):
        ref = CodeReference(
            project_id=PID, reference_kind="file", file_path="src/calculator.py"
        )
        self.assertEqual(ref.reference_kind, "file")
        self.assertIsNone(ref.symbol_name)

    def test_symbol_ref_requires_symbol_identity(self):
        with self.assertRaises(CodeRefValidationError):
            CodeReference(
                project_id=PID,
                reference_kind="symbol",
                file_path="src/calculator.py",
            )

    def test_rejects_bad_project_and_workspace_ids(self):
        with self.assertRaises(CodeRefValidationError):
            make_ref(project_id=r"C:\Desarrollos\relinkra")
        with self.assertRaises(CodeRefValidationError):
            make_ref(workspace_id="not-a-ws-id")
        self.assertEqual(make_ref(workspace_id=WID_A).workspace_id, WID_A)

    def test_rejects_qualified_name_with_cbm_slug(self):
        with self.assertRaises(CodeRefValidationError):
            make_ref(
                qualified_name=f"{SLUG_A}.src.calculator.add",
                cbm_project_name=SLUG_A,
            )

    def test_rejects_path_shaped_qualified_name(self):
        for bad in ("src/calculator.add", r"src\calculator.add"):
            with self.assertRaises(CodeRefValidationError, msg=bad):
                make_ref(qualified_name=bad)

    def test_language_derived_from_extension(self):
        self.assertEqual(make_ref().language, "python")
        self.assertEqual(
            make_ref(file_path="web/app.tsx", qualified_name="web.app.App").language,
            "typescript",
        )
        self.assertIsNone(make_ref(file_path="data/blob.xyz").language)
        self.assertIsNone(derive_language("Makefile"))
        self.assertEqual(derive_language("a.min.JS"), "javascript")

    def test_language_validation(self):
        with self.assertRaises(CodeRefValidationError):
            make_ref(language="not a language!")

    def test_line_metadata_validation(self):
        with self.assertRaises(CodeRefValidationError):
            make_ref(start_line=0)
        with self.assertRaises(CodeRefValidationError):
            make_ref(start_line=10, end_line=3)
        with self.assertRaises(CodeRefValidationError):
            make_ref(start_line="soon")
        ref = make_ref(start_line=1, end_line=2)
        self.assertEqual((ref.start_line, ref.end_line), (1, 2))

    def test_commit_sha_is_metadata(self):
        self.assertEqual(make_ref(commit_sha="ABCDEF1").commit_sha, "abcdef1")
        with self.assertRaises(CodeRefValidationError):
            make_ref(commit_sha="not hex!")

    def test_cbm_project_name_is_slug_not_path(self):
        for bad in (r"C:\cache\proj", "/cache/proj", "proj with space"):
            with self.assertRaises(CodeRefValidationError, msg=bad):
                make_ref(cbm_project_name=bad)

    def test_repository_identity_validated_and_credential_free(self):
        ref = make_ref(repository_identity=REPO)
        self.assertEqual(ref.repository_identity["value"], REPO["value"])
        with self.assertRaises(CodeRefValidationError):
            make_ref(
                repository_identity={
                    "kind": "remote",
                    "value": "remote://git/user@github.com/org/repo",
                    "trust": "strong",
                }
            )

    def test_secrets_redacted_from_symbol_fields(self):
        secret = "sk-" + "z" * 30
        ref = make_ref(symbol_name=secret, qualified_name=None)
        self.assertNotIn(secret, ref.symbol_name)
        self.assertIn("[REDACTED]", ref.symbol_name)

    def test_serialization_roundtrip(self):
        ref = make_ref(
            workspace_id=WID_A,
            start_line=1,
            end_line=2,
            cbm_project_name=SLUG_A,
            commit_sha="6d0f9cc4",
            repository_identity=REPO,
        )
        data = ref.to_dict()
        self.assertEqual(data["code_reference_id"], ref.code_reference_id)
        restored = CodeReference.from_dict(data)
        self.assertEqual(restored.to_dict(), data)

    def test_from_dict_rejects_garbage(self):
        with self.assertRaises(CodeRefValidationError):
            CodeReference.from_dict("not a mapping")
        with self.assertRaises(CodeRefValidationError):
            CodeReference.from_dict({"project_id": PID})
        with self.assertRaises(CodeRefValidationError):
            CodeReference.from_dict(
                {
                    "project_id": PID,
                    "reference_kind": "symbol",
                    "file_path": "/abs/path.py",
                    "symbol_name": "x",
                }
            )


class TestCodeReferenceId(unittest.TestCase):
    def test_format_and_determinism(self):
        ref = make_ref()
        self.assertTrue(CODE_REF_ID_RE.match(ref.code_reference_id))
        self.assertEqual(ref.code_reference_id, make_ref().code_reference_id)
        self.assertEqual(
            ref.code_reference_id,
            compute_code_reference_id(
                PID, "symbol", "src/calculator.py", "src.calculator.add"
            ),
        )

    def test_metadata_never_enters_identity(self):
        base = make_ref()
        for over in (
            {"workspace_id": WID_A},
            {"workspace_id": WID_B},
            {"cbm_project_name": SLUG_A},
            {"cbm_project_name": SLUG_B},
            {"start_line": 1, "end_line": 2},
            {"start_line": 99, "end_line": 100},
            {"commit_sha": "6d0f9cc4"},
            {"symbol_kind": "Method"},
            {"language": "python"},
        ):
            self.assertEqual(
                make_ref(**over).code_reference_id,
                base.code_reference_id,
                msg=str(over),
            )

    def test_semantic_fields_change_identity(self):
        base = make_ref().code_reference_id
        self.assertNotEqual(
            make_ref(file_path="src/other.py").code_reference_id, base
        )
        self.assertNotEqual(
            make_ref(qualified_name="src.calculator.sub").code_reference_id, base
        )
        self.assertNotEqual(
            make_ref(reference_kind="file", symbol_name=None,
                     qualified_name=None).code_reference_id,
            base,
        )
        self.assertNotEqual(
            make_ref(project_id="rlk_" + "b" * 32).code_reference_id, base
        )

    def test_symbol_name_only_ref_uses_empty_qn(self):
        ref = make_ref(qualified_name=None)
        self.assertEqual(
            ref.code_reference_id,
            compute_code_reference_id(PID, "symbol", "src/calculator.py", ""),
        )

    def test_cross_workspace_portability_fixture_ab(self):
        """R1A fixtures A/B: same repo at two paths -> same ref id.

        Same project_id (same remote), same repo-relative file/symbol,
        but different workspace ids and different path-derived CBM
        project slugs. Identity must converge.
        """
        ref_a = make_ref(
            workspace_id=WID_A, cbm_project_name=SLUG_A, start_line=1, end_line=2
        )
        ref_b = make_ref(
            workspace_id=WID_B,
            cbm_project_name=SLUG_B,
            start_line=5,
            end_line=6,
            commit_sha="6d0f9cc4",
        )
        self.assertNotEqual(ref_a.cbm_project_name, ref_b.cbm_project_name)
        self.assertEqual(ref_a.code_reference_id, ref_b.code_reference_id)

    def test_backslash_and_posix_paths_share_identity(self):
        self.assertEqual(
            make_ref(file_path=r"src\calculator.py").code_reference_id,
            make_ref(file_path="src/calculator.py").code_reference_id,
        )


if __name__ == "__main__":
    unittest.main()
