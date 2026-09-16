"use strict";

(function () {
  var tabs = Array.prototype.slice.call(document.querySelectorAll(".tab"));
  var panels = {
    graph: document.getElementById("panel-graph"),
    metrics: document.getElementById("panel-metrics"),
    status: document.getElementById("panel-status")
  };
  var statusLoaded = false;
  var metricsLoaded = false;

  // -- graph explorer constants (bounds mirror the server contract) ----

  var SVG_NS = "http://www.w3.org/2000/svg";
  var SVG_WIDTH = 960;
  var SVG_HEIGHT = 560;
  var NODE_W = 150;
  var NODE_H = 44;
  var MARGIN = 24;
  var BAND_INBOUND_Y = 56;
  var BAND_FOCAL_Y = 258;
  var BAND_OUTBOUND_Y = 460;
  var SEARCH_LIMIT = 20;
  var DEFAULT_INITIAL_CAP = 50;
  var DEFAULT_EXPANDED_CAP = 100;

  var graph = {
    nodes: {},
    order: [],
    edges: [],
    edgeKeys: {},
    focalKey: null,
    selectedKey: null,
    trimmed: 0,
    trimmedKeys: {},
    trimmedCap: DEFAULT_INITIAL_CAP,
    coverageNotice: ""
  };
  var graphKind = "symbol";
  var copyResetTimer = null;

  // -- tab routing ------------------------------------------------------

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
    if (name === "metrics") {
      loadMetrics();
    }
    if (name === "graph") {
      loadGraphAdvisory();
    }
  }

  tabs.forEach(function (tab) {
    tab.addEventListener("click", function () {
      selectTab(tab.getAttribute("data-tab"));
    });
  });

  // -- DOM helpers ------------------------------------------------------

  function element(tag, className, text) {
    var node = document.createElement(tag);
    if (className) {
      node.className = className;
    }
    if (typeof text === "string") {
      node.textContent = text;
    }
    return node;
  }

  function svgElement(tag, className, text) {
    var node = document.createElementNS(SVG_NS, tag);
    if (className) {
      node.setAttribute("class", className);
    }
    if (typeof text === "string") {
      node.textContent = text;
    }
    return node;
  }

  function clearChildren(target) {
    while (target.firstChild) {
      target.removeChild(target.firstChild);
    }
  }

  // -- kind toggle ------------------------------------------------------

  var kindButtons = Array.prototype.slice.call(document.querySelectorAll(".kind"));

  function setKind(kind) {
    graphKind = kind;
    kindButtons.forEach(function (button) {
      var active = button.getAttribute("data-kind") === kind;
      button.setAttribute("aria-pressed", active ? "true" : "false");
      button.classList.toggle("active", active);
    });
  }

  kindButtons.forEach(function (button) {
    button.addEventListener("click", function () {
      setKind(button.getAttribute("data-kind"));
    });
  });

  // -- bounded requests -------------------------------------------------

  function errorText(payload) {
    var message =
      payload && typeof payload.message === "string" && payload.message !== ""
        ? payload.message
        : "Could not load graph data from the local server.";
    if (
      payload &&
      typeof payload.next_action === "string" &&
      payload.next_action !== ""
    ) {
      return message + " Next: " + payload.next_action;
    }
    return message;
  }

  function requestJson(path, onSuccess, onError) {
    fetch(path, {
      cache: "no-store",
      headers: { Accept: "application/json" }
    })
      .then(function (response) {
        return response.json().then(
          function (payload) {
            return { ok: response.ok, payload: payload };
          },
          function () {
            return { ok: false, payload: null };
          }
        );
      })
      .then(function (result) {
        if (result.ok) {
          onSuccess(result.payload);
          return;
        }
        onError(errorText(result.payload));
      })
      .catch(function () {
        onError(errorText(null));
      });
  }

  function coverageNotice(coverage) {
    if (coverage && typeof coverage.notice === "string") {
      return coverage.notice;
    }
    return "";
  }

  // -- search -----------------------------------------------------------

  function renderResults(payload) {
    var status = document.getElementById("graph-results-status");
    var list = document.getElementById("graph-results");
    clearChildren(list);
    var results =
      payload && Array.isArray(payload.results) ? payload.results : [];
    if (results.length === 0) {
      var coverage = payload ? payload.coverage : null;
      var dropped =
        coverage &&
        typeof coverage.total === "number" &&
        coverage.total > 0;
      status.textContent = dropped
        ? coverage.notice
        : "No matches in the indexed graph.";
      return;
    }
    results.forEach(function (record) {
      var item = element("li");
      var button = element("button");
      button.type = "button";
      button.appendChild(
        element("span", "result-name", record.name || record.key)
      );
      button.appendChild(
        element("span", "result-qn", record.qualified_name || record.key)
      );
      button.appendChild(
        element("span", "result-file", record.file_path || "unknown file")
      );
      if (record.is_test === true) {
        button.appendChild(element("span", "badge", "TEST"));
      }
      button.addEventListener("click", function () {
        loadFocal(record.key);
      });
      item.appendChild(button);
      list.appendChild(item);
    });
    status.textContent = coverageNotice(payload.coverage) || "Results loaded.";
  }

  function runSearch() {
    var query = document.getElementById("graph-query").value.trim();
    var status = document.getElementById("graph-results-status");
    var button = document.getElementById("graph-search-button");
    button.disabled = true;
    status.textContent = "Searching\u2026";
    requestJson(
      "/api/graph/search?q=" +
        encodeURIComponent(query) +
        "&kind=" +
        encodeURIComponent(graphKind) +
        "&limit=" +
        SEARCH_LIMIT,
      function (payload) {
        button.disabled = false;
        renderResults(payload);
      },
      function (message) {
        button.disabled = false;
        clearChildren(document.getElementById("graph-results"));
        status.textContent = message;
      }
    );
  }

  document
    .getElementById("graph-search-form")
    .addEventListener("submit", function (event) {
      event.preventDefault();
      runSearch();
    });

  // -- graph state ------------------------------------------------------

  function emptyNode(key) {
    return {
      key: key,
      name: null,
      qualified_name: key,
      file_path: null,
      label: null,
      start_line: null,
      end_line: null,
      in_degree: null,
      out_degree: null,
      complexity: null,
      lines: null,
      is_test: null,
      is_exported: null,
      is_entry_point: null,
      reference: null,
      roles: { inbound: false, outbound: false, focal: false },
      loaded: false,
      expanded: false
    };
  }

  function reserveNode(key, cap) {
    if (graph.nodes[key]) {
      return graph.nodes[key];
    }
    if (graph.order.length >= cap) {
      // Count each distinct dropped node once: the same key can be
      // offered more than once in one payload, and repeated expansion
      // attempts must not inflate the honest "not shown" count.
      if (!graph.trimmedKeys[key]) {
        graph.trimmedKeys[key] = true;
        graph.trimmed += 1;
      }
      graph.trimmedCap = cap;
      return null;
    }
    var node = emptyNode(key);
    graph.nodes[key] = node;
    graph.order.push(key);
    return node;
  }

  function enrichNode(node, record) {
    if (!node || !record) {
      return;
    }
    if (typeof record.name === "string" && record.name !== "") {
      node.name = record.name;
    }
    if (typeof record.qualified_name === "string" && record.qualified_name !== "") {
      node.qualified_name = record.qualified_name;
    }
    if (typeof record.file_path === "string" && record.file_path !== "") {
      node.file_path = record.file_path;
    }
    if (typeof record.label === "string" && record.label !== "") {
      node.label = record.label;
    }
    ["start_line", "end_line", "in_degree", "out_degree", "complexity", "lines"].forEach(
      function (field) {
        if (typeof record[field] === "number") {
          node[field] = record[field];
        }
      }
    );
    ["is_test", "is_exported", "is_entry_point"].forEach(function (field) {
      if (record[field] === true || record[field] === false) {
        node[field] = record[field];
      }
    });
    if (record.reference) {
      node.reference = record.reference;
    }
  }

  function applyEntry(node, entry, side) {
    if (!node || !entry) {
      return;
    }
    if (node.name === null && typeof entry.name === "string" && entry.name !== "") {
      node.name = entry.name;
    }
    // is_test is true ONLY when the backend said so; absence is unknown.
    if (entry.is_test === true) {
      node.is_test = true;
    }
    node.roles[side] = true;
  }

  function addEdge(from, to) {
    if (!graph.nodes[from] || !graph.nodes[to]) {
      return;
    }
    var id = from + "\u0000" + to;
    if (graph.edgeKeys[id]) {
      return;
    }
    graph.edgeKeys[id] = true;
    graph.edges.push({ from: from, to: to });
  }

  function buildFromFocal(payload) {
    graph.nodes = {};
    graph.order = [];
    graph.edges = [];
    graph.edgeKeys = {};
    graph.trimmed = 0;
    graph.trimmedKeys = {};
    graph.trimmedCap = DEFAULT_INITIAL_CAP;
    var focal = payload && payload.focal ? payload.focal : null;
    graph.focalKey = focal && focal.key ? focal.key : null;
    graph.selectedKey = graph.focalKey;
    graph.coverageNotice = coverageNotice(payload ? payload.coverage : null);
    var caps =
      payload && payload.coverage && payload.coverage.node_caps
        ? payload.coverage.node_caps
        : {};
    var cap = typeof caps.initial === "number" ? caps.initial : DEFAULT_INITIAL_CAP;
    if (!graph.focalKey) {
      return;
    }
    var focalNode = reserveNode(graph.focalKey, cap);
    if (focalNode) {
      enrichNode(focalNode, focal);
      focalNode.roles.focal = true;
      focalNode.loaded = true;
      focalNode.expanded = true;
    }
    (payload.inbound || []).forEach(function (entry) {
      if (!entry || !entry.key) {
        return;
      }
      var node = reserveNode(entry.key, cap);
      if (!node) {
        return;
      }
      applyEntry(node, entry, "inbound");
      addEdge(entry.key, graph.focalKey);
    });
    (payload.outbound || []).forEach(function (entry) {
      if (!entry || !entry.key) {
        return;
      }
      var node = reserveNode(entry.key, cap);
      if (!node) {
        return;
      }
      applyEntry(node, entry, "outbound");
      addEdge(graph.focalKey, entry.key);
    });
  }

  function mergeNeighborhood(key, payload) {
    var target = graph.nodes[key];
    if (!target) {
      return;
    }
    var caps =
      payload && payload.coverage && payload.coverage.node_caps
        ? payload.coverage.node_caps
        : {};
    var cap =
      typeof caps.expanded === "number" ? caps.expanded : DEFAULT_EXPANDED_CAP;
    graph.coverageNotice = coverageNotice(payload ? payload.coverage : null)
      || graph.coverageNotice;
    enrichNode(target, payload ? payload.focal : null);
    target.loaded = true;
    target.expanded = true;
    (payload.inbound || []).forEach(function (entry) {
      if (!entry || !entry.key) {
        return;
      }
      var node = reserveNode(entry.key, cap);
      if (!node) {
        return;
      }
      applyEntry(node, entry, "inbound");
      addEdge(entry.key, key);
    });
    (payload.outbound || []).forEach(function (entry) {
      if (!entry || !entry.key) {
        return;
      }
      var node = reserveNode(entry.key, cap);
      if (!node) {
        return;
      }
      applyEntry(node, entry, "outbound");
      addEdge(key, entry.key);
    });
  }

  // -- rendering --------------------------------------------------------

  function bandX(index, count) {
    if (count <= 1) {
      return (SVG_WIDTH - NODE_W) / 2;
    }
    return (
      MARGIN + (index * (SVG_WIDTH - 2 * MARGIN - NODE_W)) / (count - 1)
    );
  }

  function displayName(node) {
    if (node.name) {
      return node.name;
    }
    var key = node.qualified_name || node.key || "";
    var parts = key.split(".");
    return parts[parts.length - 1] || key;
  }

  function truncateLabel(value) {
    var text = value || "";
    if (text.length <= 20) {
      return text;
    }
    return text.slice(0, 20) + "\u2026";
  }

  function renderGraph() {
    var svg = document.getElementById("graph-svg");
    clearChildren(svg);
    var bandYs = [BAND_INBOUND_Y, BAND_FOCAL_Y, BAND_OUTBOUND_Y];
    var bands = [[], [], []];
    graph.order.forEach(function (key) {
      var node = graph.nodes[key];
      if (!node) {
        return;
      }
      if (node.roles.focal) {
        bands[1].push(key);
      } else if (node.roles.inbound) {
        bands[0].push(key);
      } else {
        bands[2].push(key);
      }
    });
    var positions = {};
    bands.forEach(function (keys, bandIndex) {
      keys.forEach(function (key, index) {
        positions[key] = { x: bandX(index, keys.length), y: bandYs[bandIndex] };
      });
    });

    var defs = svgElement("defs");
    var marker = svgElement("marker");
    marker.setAttribute("id", "graph-arrow");
    marker.setAttribute("markerWidth", "8");
    marker.setAttribute("markerHeight", "8");
    marker.setAttribute("refX", "8");
    marker.setAttribute("refY", "4");
    marker.setAttribute("orient", "auto");
    var arrow = svgElement("path", "graph-arrow");
    arrow.setAttribute("d", "M0,0 L8,4 L0,8 z");
    marker.appendChild(arrow);
    defs.appendChild(marker);
    svg.appendChild(defs);

    // Edges first so nodes paint on top.
    graph.edges.forEach(function (edge) {
      var from = positions[edge.from];
      var to = positions[edge.to];
      if (!from || !to) {
        return;
      }
      var fromNode = graph.nodes[edge.from];
      var toNode = graph.nodes[edge.to];
      var isTest =
        (fromNode && fromNode.is_test === true) ||
        (toNode && toNode.is_test === true);
      var line = svgElement("line", isTest ? "edge test" : "edge");
      line.setAttribute("x1", String(from.x + NODE_W / 2));
      line.setAttribute("y1", String(from.y + NODE_H / 2));
      line.setAttribute("x2", String(to.x + NODE_W / 2));
      line.setAttribute("y2", String(to.y + NODE_H / 2));
      line.setAttribute("data-from", edge.from);
      line.setAttribute("data-to", edge.to);
      line.setAttribute("marker-end", "url(#graph-arrow)");
      svg.appendChild(line);
    });

    graph.order.forEach(function (key) {
      var node = graph.nodes[key];
      var pos = positions[key];
      if (!node || !pos) {
        return;
      }
      var group = svgElement("g", "graph-node");
      group.setAttribute("tabindex", "0");
      group.setAttribute("role", "button");
      group.setAttribute("aria-label", node.qualified_name || key);
      var rect = svgElement(
        "rect",
        key === graph.selectedKey ? "selected" : null
      );
      rect.setAttribute("x", String(pos.x));
      rect.setAttribute("y", String(pos.y));
      rect.setAttribute("width", String(NODE_W));
      rect.setAttribute("height", String(NODE_H));
      rect.setAttribute("rx", "6");
      rect.setAttribute("ry", "6");
      group.appendChild(rect);
      var label = svgElement("text", "node-label", truncateLabel(displayName(node)));
      label.setAttribute("x", String(pos.x + 10));
      label.setAttribute("y", String(pos.y + 18));
      group.appendChild(label);
      var badges = [];
      if (node.roles.focal) {
        badges.push("FOCAL");
      }
      if (node.roles.inbound) {
        badges.push("IN");
      }
      if (node.roles.outbound) {
        badges.push("OUT");
      }
      if (node.is_test === true) {
        badges.push("TEST");
      }
      badges.forEach(function (badge, index) {
        var badgeText = svgElement("text", "badge", badge);
        badgeText.setAttribute("x", String(pos.x + 10 + index * 36));
        badgeText.setAttribute("y", String(pos.y + NODE_H - 8));
        group.appendChild(badgeText);
      });
      group.addEventListener("click", function () {
        selectNode(key);
      });
      group.addEventListener("keydown", function (event) {
        if (
          event.key === "Enter" ||
          event.key === " " ||
          event.key === "Spacebar"
        ) {
          event.preventDefault();
          selectNode(key);
        }
      });
      svg.appendChild(group);
    });
  }

  function renderCoverage(coverage) {
    var text = coverageNotice(coverage);
    var inbound = coverage && coverage.inbound ? coverage.inbound : null;
    var outbound = coverage && coverage.outbound ? coverage.outbound : null;
    if (inbound || outbound) {
      var sides = "Inbound: " + (inbound ? inbound.returned : 0) + " shown";
      if (inbound && inbound.truncated === true) {
        sides += " (truncated at " + inbound.limit + ")";
      }
      sides += ". Outbound: " + (outbound ? outbound.returned : 0) + " shown";
      if (outbound && outbound.truncated === true) {
        sides += " (truncated at " + outbound.limit + ")";
      }
      sides += ".";
      text = text ? text + " " + sides : sides;
    }
    document.getElementById("graph-coverage").textContent = text;
    graph.coverageNotice = text;
  }

  function setCoverageError(message) {
    document.getElementById("graph-coverage").textContent = message;
    graph.coverageNotice = message;
  }

  function renderCapMessage() {
    var cap = document.getElementById("graph-cap");
    if (graph.trimmed > 0) {
      cap.textContent =
        "Graph node cap reached (" +
        graph.trimmedCap +
        "). " +
        graph.trimmed +
        " related nodes were not shown.";
      cap.hidden = false;
    } else {
      cap.textContent = "";
      cap.hidden = true;
    }
  }

  function appendFact(dl, term, value) {
    dl.appendChild(element("dt", null, term));
    dl.appendChild(element("dd", null, value));
  }

  function selectedNode() {
    if (!graph.selectedKey) {
      return null;
    }
    return graph.nodes[graph.selectedKey] || null;
  }

  function renderDetail() {
    var dl = document.getElementById("graph-detail");
    clearChildren(dl);
    var node = selectedNode();
    if (!node) {
      appendFact(dl, "Selected node", "none");
      return;
    }
    var inboundCount = 0;
    var outboundCount = 0;
    graph.edges.forEach(function (edge) {
      if (edge.to === node.key) {
        inboundCount += 1;
      }
      if (edge.from === node.key) {
        outboundCount += 1;
      }
    });
    var notLoaded = "not loaded \u2014 expand this node to load details";
    var linesText = "unknown";
    if (!node.loaded) {
      linesText = notLoaded;
    } else if (
      typeof node.start_line === "number" &&
      typeof node.end_line === "number"
    ) {
      linesText = node.start_line + "\u2013" + node.end_line;
    }
    var testText = "unknown";
    if (node.is_test === true) {
      testText = "test";
    } else if (node.is_test === false) {
      testText = "not test";
    }
    appendFact(dl, "Name", displayName(node));
    appendFact(dl, "Qualified name", node.qualified_name || node.key);
    appendFact(dl, "File", node.loaded ? node.file_path || "unknown" : notLoaded);
    appendFact(dl, "Lines", linesText);
    appendFact(dl, "Kind", node.label || "unknown");
    appendFact(dl, "Inbound (in view)", String(inboundCount));
    appendFact(dl, "Outbound (in view)", String(outboundCount));
    appendFact(dl, "Test", testText);
    appendFact(
      dl,
      "Reference id",
      node.reference && node.reference.code_reference_id
        ? node.reference.code_reference_id
        : "unknown"
    );
    appendFact(dl, "Coverage", graph.coverageNotice || "unknown");
  }

  function updateButtons() {
    var node = selectedNode();
    var copyButton = document.getElementById("graph-copy");
    var expandButton = document.getElementById("graph-expand");
    copyButton.disabled = node === null;
    expandButton.disabled =
      node === null || node.key === graph.focalKey || node.expanded === true;
  }

  function selectNode(key) {
    if (!graph.nodes[key]) {
      return;
    }
    graph.selectedKey = key;
    renderGraph();
    renderDetail();
    updateButtons();
  }

  // -- focal load and expansion ----------------------------------------

  function loadFocal(key) {
    var status = document.getElementById("graph-results-status");
    status.textContent = "Loading " + key + "\u2026";
    requestJson(
      "/api/graph/node?key=" + encodeURIComponent(key),
      function (payload) {
        buildFromFocal(payload);
        renderCoverage(payload.coverage);
        renderCapMessage();
        renderGraph();
        renderDetail();
        updateButtons();
        var focal = payload && payload.focal ? payload.focal : null;
        var label = focal && focal.name ? focal.name : key;
        status.textContent = "Loaded " + label + ".";
      },
      function (message) {
        status.textContent = message;
        setCoverageError(message);
      }
    );
  }

  function expandSelected() {
    var node = selectedNode();
    if (!node) {
      return;
    }
    var button = document.getElementById("graph-expand");
    button.disabled = true;
    button.textContent = "Expanding\u2026";
    requestJson(
      "/api/graph/node?key=" + encodeURIComponent(node.key),
      function (payload) {
        mergeNeighborhood(node.key, payload);
        renderCoverage(payload.coverage);
        renderCapMessage();
        renderGraph();
        renderDetail();
        button.textContent = "Expand neighbors";
        updateButtons();
      },
      function (message) {
        setCoverageError(message);
        button.textContent = "Expand neighbors";
        updateButtons();
      }
    );
  }

  document.getElementById("graph-expand").addEventListener("click", function () {
    expandSelected();
  });

  function revealCopyValue(value) {
    var input = document.getElementById("graph-copy-value");
    input.value = value;
    input.hidden = false;
    input.focus();
    input.select();
  }

  function copySelected() {
    var node = selectedNode();
    if (!node) {
      return;
    }
    var value = node.qualified_name || node.file_path || node.key;
    var button = document.getElementById("graph-copy");
    var input = document.getElementById("graph-copy-value");
    function copied() {
      input.hidden = true;
      button.textContent = "Copied";
      if (copyResetTimer !== null) {
        window.clearTimeout(copyResetTimer);
      }
      copyResetTimer = window.setTimeout(function () {
        button.textContent = "Copy reference";
      }, 1500);
    }
    if (
      navigator.clipboard &&
      typeof navigator.clipboard.writeText === "function"
    ) {
      navigator.clipboard.writeText(value).then(copied, function () {
        revealCopyValue(value);
      });
    } else {
      revealCopyValue(value);
    }
  }

  document.getElementById("graph-copy").addEventListener("click", function () {
    copySelected();
  });

  // -- stale / unavailable advisory ------------------------------------

  function setAdvisory(text) {
    var advisory = document.getElementById("graph-advisory");
    if (text) {
      advisory.textContent = text;
      advisory.hidden = false;
    } else {
      advisory.textContent = "";
      advisory.hidden = true;
    }
  }

  function loadGraphAdvisory() {
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
        var cbm = payload.cbm || {};
        var next =
          typeof cbm.next_action === "string" && cbm.next_action !== ""
            ? " Next: " + cbm.next_action
            : "";
        if (cbm.state === "STALE") {
          setAdvisory("Graph is stale. Results may reflect an older revision." + next);
          return;
        }
        if (
          cbm.availability === "UNAVAILABLE" ||
          cbm.availability === "UNSUPPORTED" ||
          cbm.availability === "UNTRUSTED"
        ) {
          setAdvisory("Graph search is unavailable." + next);
          return;
        }
        if (cbm.state === "MISSING") {
          setAdvisory(
            "The CBM index is missing for this workspace. Next: " +
              (cbm.next_action || "relinkra cbm index")
          );
          return;
        }
        setAdvisory("");
      })
      .catch(function () {
        setAdvisory("");
      });
  }

  // -- status (VIS-1) ---------------------------------------------------

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

  // -- metrics (VIS-3) -----------------------------------------------

  function yesNoUnknown(value) {
    if (value === true) return "YES";
    if (value === false) return "NO";
    return "UNKNOWN";
  }

  function metricValue(value) {
    if (typeof value === "number" && isFinite(value)) return String(value);
    if (typeof value === "string" && value !== "") return value;
    return "UNKNOWN";
  }

  function setMetric(id, value) {
    setText(id, value);
  }

  function resetMetrics() {
    [
      "metric-final-cpt1", "metric-useful-cpt1", "metric-metadata-cpt1",
      "metric-memory-facts", "metric-code-references", "metric-code-facts",
      "metric-handoffs", "metric-pending", "metric-git-facts",
      "metric-packet-complete", "metric-retrieval-complete",
      "metric-budget-exhausted", "metric-truncated", "metric-context-sufficiency",
      "metric-omitted-sections", "metric-omitted-high", "metric-project-id", "metric-workspace-id",
      "metric-revision", "metric-host-bucket", "metric-currentness"
    ].forEach(function (id) { setMetric(id, "UNKNOWN"); });
    document.getElementById("metrics-meta").textContent = "";
    document.getElementById("metrics-stale").hidden = true;
    clearChildren(document.getElementById("metrics-history-body"));
  }

  function contextSufficiencyText(value) {
    if (!value || typeof value !== "object") return "UNKNOWN";
    var parts = [];
    Object.keys(value).sort().forEach(function (key) {
      if (typeof value[key] === "string") parts.push(key + ": " + value[key]);
    });
    return parts.length ? parts.join(", ") : "UNKNOWN";
  }

  function compositionText(value) {
    value = value || {};
    return "M " + metricValue(value.memory_facts) +
      " · refs " + metricValue(value.code_references) +
      " · facts " + metricValue(value.code_facts) +
      " · handoffs " + metricValue(value.handoffs) +
      " · pending " + metricValue(value.pending) +
      " · git " + metricValue(value.git_facts);
  }

  function renderHistory(historyPayload) {
    var body = document.getElementById("metrics-history-body");
    clearChildren(body);
    (historyPayload && Array.isArray(historyPayload.history) ? historyPayload.history : []).forEach(function (item) {
      var row = element("tr");
      var accounting = item.accounting || {};
      var quality = item.quality || {};
      [
        item.observed_at || "UNKNOWN",
        metricValue(accounting.final_cpt1),
        metricValue(accounting.useful_cpt1),
        metricValue(accounting.metadata_cpt1),
        compositionText(item.composition),
        yesNoUnknown(quality.packet_complete),
        yesNoUnknown(quality.truncated)
      ].forEach(function (value) { row.appendChild(element("td", null, value)); });
      body.appendChild(row);
    });
  }

  function renderMetrics(payload, historyPayload) {
    var observation = payload && payload.observation;
    var status = document.getElementById("metrics-status");
    resetMetrics();
    if (!observation) {
      status.textContent = payload && payload.storage === "degraded"
        ? "Metrics storage is degraded; no valid current observation is available."
        : "No ContextPacket metrics recorded yet. Run an agent through Relinkra first.";
      renderHistory(historyPayload);
      return;
    }
    var accounting = observation.accounting || {};
    var composition = observation.composition || {};
    var quality = observation.quality || {};
    var retrieval = observation.retrieval || {};
    var identity = observation.identity || {};
    setMetric("metric-final-cpt1", metricValue(accounting.final_cpt1));
    setMetric("metric-useful-cpt1", metricValue(accounting.useful_cpt1));
    setMetric("metric-metadata-cpt1", metricValue(accounting.metadata_cpt1));
    setMetric("metric-memory-facts", metricValue(composition.memory_facts));
    setMetric("metric-code-references", metricValue(composition.code_references));
    setMetric("metric-code-facts", metricValue(composition.code_facts));
    setMetric("metric-handoffs", metricValue(composition.handoffs));
    setMetric("metric-pending", metricValue(composition.pending));
    setMetric("metric-git-facts", metricValue(composition.git_facts));
    setMetric("metric-packet-complete", yesNoUnknown(quality.packet_complete));
    setMetric("metric-retrieval-complete", yesNoUnknown(retrieval.complete));
    setMetric("metric-budget-exhausted", yesNoUnknown(quality.budget_exhausted));
    setMetric("metric-truncated", yesNoUnknown(quality.truncated));
    setMetric("metric-context-sufficiency", contextSufficiencyText(quality.context_sufficiency));
    var omittedSections = quality.omitted_sections;
    setMetric("metric-omitted-sections", Array.isArray(omittedSections)
      ? (omittedSections.length ? omittedSections.join(", ") : "NONE")
      : "UNKNOWN");
    setMetric("metric-omitted-high", metricValue(quality.omitted_high_salience));
    setMetric("metric-project-id", metricValue(identity.project_id));
    setMetric("metric-workspace-id", metricValue(identity.workspace_id));
    setMetric("metric-revision", metricValue(identity.revision));
    setMetric("metric-host-bucket", metricValue(observation.host_bucket));
    setMetric("metric-currentness", String(payload.currentness || "unknown").toUpperCase());
    status.textContent = "Latest observation: " + String(payload.currentness || "unknown").toUpperCase();
    if (payload.currentness === "stale") {
      document.getElementById("metrics-stale").hidden = false;
    } else if (payload.currentness === "foreign") {
      status.textContent += ". Metrics belong to another project or workspace.";
    }
    var age = typeof observation.age_seconds === "number" ? Math.round(observation.age_seconds) + "s ago" : "age unknown";
    document.getElementById("metrics-meta").textContent =
      "Observed " + (observation.observed_at || "UNKNOWN") + " (" + age + ") · revision " + (identity.revision || "UNKNOWN");
    renderHistory(historyPayload);
  }

  function loadMetrics() {
    if (metricsLoaded) return;
    var status = document.getElementById("metrics-status");
    requestJson("/api/metrics/current", function (current) {
      fetch("/api/metrics/history", { cache: "no-store", headers: { Accept: "application/json" } })
        .then(function (response) { return response.json(); })
        .then(function (history) { metricsLoaded = true; renderMetrics(current, history); })
        .catch(function () { metricsLoaded = true; renderMetrics(current, null); });
    }, function () { status.textContent = "Metrics are unavailable."; });
  }

  setKind("symbol");
  updateButtons();
  selectTab("status");
})();
