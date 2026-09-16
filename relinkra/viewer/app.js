"use strict";

(function () {
  var tabs = Array.prototype.slice.call(document.querySelectorAll(".tab"));
  var panels = {
    graph: document.getElementById("panel-graph"),
    metrics: document.getElementById("panel-metrics"),
    status: document.getElementById("panel-status")
  };
  var statusLoaded = false;

  function selectTab(name) {
    tabs.forEach(function (tab) {
      var active = tab.getAttribute("data-tab") === name;
      tab.setAttribute("aria-selected", active ? "true" : "false");
      tab.classList.toggle("active", active);
    });
    Object.keys(panels).forEach(function (key) {
      panels[key].hidden = key !== name;
    });
    if (name === "status") {
      loadStatus();
    }
  }

  tabs.forEach(function (tab) {
    tab.addEventListener("click", function () {
      selectTab(tab.getAttribute("data-tab"));
    });
  });

  function setText(id, value) {
    document.getElementById(id).textContent = value;
  }

  function shortSha(value) {
    if (typeof value !== "string" || value === "") {
      return "unavailable";
    }
    return value.slice(0, 12);
  }

  function driftText(value) {
    if (value === true) {
      return "drift detected";
    }
    if (value === false) {
      return "no drift";
    }
    return "unavailable";
  }

  function countText(value) {
    if (typeof value === "number") {
      return String(value);
    }
    return "unavailable";
  }

  function stateText(value) {
    if (typeof value === "string" && value !== "") {
      return value;
    }
    return "unavailable";
  }

  function describeStatus(payload) {
    var cbm = payload.cbm || {};
    var availability = cbm.availability;
    var state = cbm.state;
    if (
      availability === "UNAVAILABLE" ||
      availability === "UNSUPPORTED" ||
      availability === "UNTRUSTED"
    ) {
      return "CBM is unavailable. Run `relinkra cbm setup`.";
    }
    if (state === "MISSING") {
      return "CBM index is missing. Run `relinkra cbm index`.";
    }
    if (state === "STALE") {
      return "Graph is stale. Run `relinkra cbm refresh`; displayed graph data may be outdated.";
    }
    if (state === "READY") {
      return "Graph matches the current revision.";
    }
    return "Index state cannot be determined.";
  }

  function clearFields() {
    setText("fact-project-id", "unavailable");
    setText("fact-workspace-id", "unavailable");
    setText("fact-availability", "unavailable");
    setText("fact-state", "unavailable");
    setText("fact-current-revision", "unavailable");
    setText("fact-indexed-revision", "unavailable");
    setText("fact-committed-drift", "unavailable");
    setText("fact-worktree-drift", "unavailable");
    setText("fact-nodes", "unavailable");
    setText("fact-edges", "unavailable");
  }

  function renderStatus(payload) {
    var cbm = payload.cbm || {};
    var project = payload.project || {};
    var revision = payload.revision || {};
    var workspace = payload.workspace || {};

    setText("fact-project-id", stateText(project.project_id));
    if (workspace.initialized === true) {
      setText("fact-workspace-id", stateText(workspace.workspace_id));
    } else {
      setText("fact-workspace-id", "not initialized");
    }
    setText("fact-availability", stateText(cbm.availability));
    setText("fact-state", stateText(cbm.state));
    setText("fact-current-revision", shortSha(revision.current));
    setText("fact-indexed-revision", shortSha(revision.indexed));
    setText("fact-committed-drift", driftText(cbm.committed_drift));
    setText("fact-worktree-drift", driftText(cbm.worktree_drift));
    setText("fact-nodes", countText(cbm.nodes));
    setText("fact-edges", countText(cbm.edges));
    setText("status-action", describeStatus(payload));
  }

  function loadStatus() {
    if (statusLoaded) {
      return;
    }
    var action = document.getElementById("status-action");
    action.textContent = "Loading status\u2026";
    fetch("/api/status", {
      cache: "no-store",
      headers: { Accept: "application/json" }
    })
      .then(function (response) {
        if (!response.ok) {
          throw new Error("status request failed");
        }
        return response.json();
      })
      .then(function (payload) {
        statusLoaded = true;
        renderStatus(payload);
      })
      .catch(function () {
        clearFields();
        action.textContent = "Could not load status from the local server.";
      });
  }

  selectTab("status");
})();