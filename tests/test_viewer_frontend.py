"""VIS-2 frontend asset contract tests.

Hermetic: the packaged viewer assets are read as text through
``importlib.resources``. No browser, no socket, no JavaScript runtime —
every assertion pins the static shell structure, the URL surface the UI
talks to, and the safety invariants (no HTML injection primitives, no
external URLs).
"""

from __future__ import annotations

import importlib.resources
import unittest

#: The SVG namespace is an XML identifier, never fetched. It is the ONE
#: legitimate ``http://`` string in the viewer assets and is removed
#: before the external-URL audit so ``createElementNS`` stays usable.
_SVG_NAMESPACE = "http://www.w3.org/2000/svg"

GRAPH_IDS = (
    "panel-graph",
    "graph-search-form",
    "graph-query",
    "graph-advisory",
    "graph-results-status",
    "graph-results",
    "graph-coverage",
    "graph-svg",
    "graph-cap",
    "graph-detail",
    "graph-copy",
    "graph-expand",
    "graph-copy-value",
    "graph-search-button",
)


def _asset(name: str) -> str:
    return (
        importlib.resources.files("relinkra")
        .joinpath("viewer", name)
        .read_text(encoding="utf-8")
    )


class ShellSkeletonTests(unittest.TestCase):
    """The Graph panel ships the exact skeleton the renderer drives."""

    @classmethod
    def setUpClass(cls):
        cls.html = _asset("index.html")

    def test_graph_skeleton_ids_are_exact(self):
        for element_id in GRAPH_IDS:
            with self.subTest(element_id=element_id):
                self.assertIn(f'id="{element_id}"', self.html)

    def test_graph_skeleton_structure(self):
        for fragment in (
            '<form id="graph-search-form" class="graph-search" autocomplete="off">',
            '<div class="graph-kind" role="group" aria-label="Search kind">',
            '<button type="button" class="kind" data-kind="symbol" '
            'aria-pressed="true">Symbol</button>',
            '<button type="button" class="kind" data-kind="file" '
            'aria-pressed="false">File</button>',
            '<div class="graph-layout">',
            '<ul id="graph-results" class="results"></ul>',
            '<svg id="graph-svg" viewBox="0 0 960 560" role="img" '
            'aria-label="Bounded relationship graph"></svg>',
            '<dl id="graph-detail" class="facts detail-facts"></dl>',
            '<p id="graph-advisory" class="advisory" hidden></p>',
            '<p id="graph-cap" class="advisory" hidden></p>',
            'class="visually-hidden"',
            'maxlength="200"',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.html)

    def test_kind_toggle_semantics_ship_in_the_shell(self):
        self.assertLess(
            self.html.index('data-kind="symbol"'),
            self.html.index('data-kind="file"'),
        )
        self.assertIn('data-kind="symbol" aria-pressed="true"', self.html)
        self.assertIn('data-kind="file" aria-pressed="false"', self.html)

    def test_existing_shell_surfaces_are_untouched(self):
        self.assertIn("No ContextPacket metrics recorded yet", self.html)
        for tab in ("graph", "metrics", "status"):
            with self.subTest(tab=tab):
                self.assertIn(f'data-tab="{tab}"', self.html)
        self.assertIn('id="status-action"', self.html)
        self.assertIn('id="fact-project-id"', self.html)
        self.assertNotIn("Graph explorer will load here", self.html)

    def test_effective_identity_surfaces_ship_in_the_status_panel(self):
        for element_id, label in (
            ("fact-project-id", "Effective project"),
            ("fact-registered-project-id", "Registered project"),
            ("fact-live-project-id", "Detected Git project"),
            ("fact-identity-state", "Identity state"),
            ("fact-identity-action", "Recommended action"),
        ):
            with self.subTest(element_id=element_id):
                self.assertIn(label, self.html)
                self.assertIn(f'id="{element_id}"', self.html)


class AppScriptTests(unittest.TestCase):
    """The renderer talks only to the bounded viewer routes."""

    @classmethod
    def setUpClass(cls):
        cls.js = _asset("app.js")

    def test_graph_routes_are_referenced(self):
        self.assertIn("/api/graph/search", self.js)
        self.assertIn("/api/graph/node", self.js)

    def test_search_form_has_a_submit_listener(self):
        self.assertIn('getElementById("graph-search-form")', self.js)
        self.assertIn('addEventListener("submit"', self.js)

    def test_pinned_copy_strings_are_present(self):
        self.assertIn("No matches in the indexed graph.", self.js)
        self.assertIn(
            "Graph is stale. Results may reflect an older revision.", self.js
        )

    def test_svg_is_built_with_the_namespace_api(self):
        self.assertIn("createElementNS", self.js)

    def test_identity_fields_are_rendered_from_the_status_payload(self):
        for field in (
            "registered_project_id",
            "live_project_id",
            "identity_state",
            "recommended_action",
        ):
            with self.subTest(field=field):
                self.assertIn(field, self.js)
        self.assertIn("Migration available", self.js)
        self.assertIn('setText("fact-registered-project-id"', self.js)
        self.assertIn('setText("fact-live-project-id"', self.js)
        self.assertIn('setText("fact-identity-state"', self.js)
        self.assertIn('setText("fact-identity-action"', self.js)

    def test_no_html_injection_or_eval_primitives(self):
        for name in ("index.html", "app.js", "styles.css"):
            text = _asset(name)
            for forbidden in (
                "innerHTML",
                "insertAdjacentHTML",
                "eval(",
                "Function(",
            ):
                with self.subTest(asset=name, forbidden=forbidden):
                    self.assertNotIn(forbidden, text)


class ExternalUrlTests(unittest.TestCase):
    """No asset may load anything from the network."""

    def test_no_external_urls(self):
        for name in ("index.html", "app.js", "styles.css"):
            text = _asset(name).replace(_SVG_NAMESPACE, "")
            with self.subTest(asset=name):
                self.assertNotIn("http://", text)
                self.assertNotIn("https://", text)


class StylesheetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.css = _asset("styles.css")

    def test_required_graph_selectors_exist(self):
        for selector in (
            ".edge.test",
            ".graph-node.selected",
            ".graph-layout",
            ".graph-column",
            ".visually-hidden",
            ".advisory",
            ".detail-facts",
            ".copy-value",
            ".results",
        ):
            with self.subTest(selector=selector):
                self.assertIn(selector, self.css)


if __name__ == "__main__":
    unittest.main()
