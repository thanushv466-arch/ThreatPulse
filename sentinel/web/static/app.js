/* Sentinel SOC dashboard.
 *
 * SECURITY: everything shown here can contain attacker-controlled text (a
 * logged URL may literally be "<script>..."), so this file never uses
 * innerHTML. Every node is built with createElement + textContent, and the
 * server's Content-Security-Policy blocks inline script as a second layer. */
(function () {
  "use strict";

  var SEV_ORDER = ["critical", "high", "medium", "low"];
  var SEV_VAR = { critical: "--critical", high: "--high", medium: "--medium", low: "--low" };
  var SCENARIO_LABELS = {
    web_attack: "Web application attack",
    ssh_intrusion: "SSH break-in",
    password_spray: "Password spray",
    endpoint_compromise: "Phishing to data theft"
  };
  var state = { view: "overview", severity: "", status: "open", openAlert: null };

  // ------------------------------------------------------------ helpers
  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (key) {
      if (key === "text") node.textContent = attrs[key];
      else if (key === "class") node.className = attrs[key];
      else if (key === "on") Object.keys(attrs.on).forEach(function (evt) { node.addEventListener(evt, attrs.on[evt]); });
      else node.setAttribute(key, attrs[key]);
    });
    (children || []).forEach(function (child) { if (child) node.appendChild(child); });
    return node;
  }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); return node; }
  function $(id) { return document.getElementById(id); }
  function fmt(n) { return Number(n || 0).toLocaleString("en-US"); }
  function clock(iso) { return iso ? iso.slice(11, 19) : ""; }
  function day(iso) { return iso ? iso.slice(0, 10) : ""; }
  function chip(sev) { return el("span", { class: "chip sev-" + sev, text: sev }); }
  function statusLabel(s) { return s === "false_positive" ? "false positive" : s; }

  function api(path, payload) {
    var options = payload ? {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload)
    } : {};
    return fetch(path, options).then(function (res) {
      return res.json().then(function (data) {
        if (!res.ok) throw new Error(data.error || data.message || "Request failed");
        return data;
      });
    });
  }
  var toastTimer;
  function toast(message) {
    var node = $("toast");
    node.textContent = message;
    node.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { node.hidden = true; }, 3200);
  }

  // ------------------------------------------------------------ overview
  function renderFigures(s) {
    var open = SEV_ORDER.reduce(function (sum, k) { return sum + (s.by_severity[k] || 0); }, 0);
    var bar = el("div", { class: "sevbar", title: "Open alerts by severity" });
    SEV_ORDER.forEach(function (k) {
      var part = el("i", { class: "sev-" + k });
      part.style.width = (open ? (100 * (s.by_severity[k] || 0) / open) : 0) + "%";
      bar.appendChild(part);
    });
    var items = [
      [fmt(s.events), "log events analyzed"],
      [fmt(s.open_alerts), "open alerts", bar],
      [fmt(s.open_incidents), "open incidents"],
      [fmt(s.blocked), "sources contained"],
      [fmt(s.pipeline.rules), "detection rules running"]
    ];
    var root = clear($("figures"));
    items.forEach(function (item) {
      root.appendChild(el("div", { class: "figure" }, [el("b", { text: item[0] }), el("span", { text: item[1] }), item[2]]));
    });
  }

  function renderMatrix(s) {
    var root = clear($("matrix"));
    s.tactics.forEach(function (tactic) {
      var hits = s.techniques.filter(function (t) { return t.tactic === tactic.name; });
      var col = el("div", { class: "tactic" + (hits.length ? " is-hit" : "") }, [el("h3", { text: tactic.name })]);
      if (!hits.length) col.appendChild(el("p", { class: "quiet", text: "Nothing detected" }));
      hits.sort(function (a, b) { return b.worst - a.worst; }).forEach(function (t) {
        var sev = ["low", "low", "medium", "high", "critical"][t.worst];
        col.appendChild(el("div", { class: "tech sev-" + sev, title: t.count + " alert(s)" }, [
          el("b", { text: t.technique + (t.count > 1 ? "  x" + t.count : "") }),
          el("span", { text: t.technique_name.replace(/^.*: /, "") })
        ]));
      });
      root.appendChild(col);
    });
  }

  function renderTimeline(s) {
    var root = clear($("timeline"));
    var data = s.timeline;
    if (!data.length) { root.appendChild(el("p", { class: "empty", text: "No events yet." })); return; }
    var NS = "http://www.w3.org/2000/svg", W = 340, H = 120, pad = 14;
    var svg = document.createElementNS(NS, "svg");
    svg.setAttribute("viewBox", "0 0 " + W + " " + H);
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", "Log events and alerts over time");
    var max = Math.max.apply(null, data.map(function (d) { return d.events; })) || 1;
    var bw = W / data.length;
    data.forEach(function (d, i) {
      // square-root scale so a flood does not flatten every other bar
      var h = Math.max(1, (H - pad - 4) * Math.sqrt(d.events / max));
      var rect = document.createElementNS(NS, "rect");
      rect.setAttribute("x", (i * bw + 1).toFixed(1));
      rect.setAttribute("y", (H - h).toFixed(1));
      rect.setAttribute("width", Math.max(bw - 2, 1).toFixed(1));
      rect.setAttribute("height", h.toFixed(1));
      rect.setAttribute("fill", "#3d5f8c");
      var tip = document.createElementNS(NS, "title");
      tip.textContent = clock(d.t) + " UTC: " + d.events + " events, " + d.alerts + " alerts";
      rect.appendChild(tip);
      svg.appendChild(rect);
      if (d.alerts) {
        var dot = document.createElementNS(NS, "circle");
        dot.setAttribute("cx", (i * bw + bw / 2).toFixed(1));
        dot.setAttribute("cy", 7);
        dot.setAttribute("r", Math.min(3 + d.alerts, 6));
        dot.setAttribute("fill", getComputedStyle(document.documentElement).getPropertyValue("--critical"));
        svg.appendChild(dot);
      }
    });
    root.appendChild(svg);
    $("timeline-range").textContent = day(data[0].t) + "  " + clock(data[0].t).slice(0, 5) + " to " +
      clock(data[data.length - 1].t).slice(0, 5) + " UTC";
  }

  function renderBars(id, rows, emptyText, onClick) {
    var root = clear($(id));
    if (!rows.length) { root.appendChild(el("p", { class: "empty", text: emptyText })); return; }
    var max = Math.max.apply(null, rows.map(function (r) { return r[1]; })) || 1;
    rows.forEach(function (r) {
      var fill = el("div", { class: "fill" });
      fill.style.width = Math.max(2, 100 * r[1] / max) + "%";
      root.appendChild(el("div", { class: "barrow" }, [
        el("span", { class: "mono", text: r[0] }),
        el("div", { class: "track" }, [fill]),
        el("span", { class: "n", text: fmt(r[1]) })
      ]));
    });
  }

  function renderAlerts(alerts) {
    var body = clear($("alerts").querySelector("tbody"));
    if (!alerts.length) {
      body.appendChild(el("tr", {}, [el("td", { colspan: "6", class: "empty", text: "No alerts match these filters. Launch a simulated attack to see the pipeline work." })]));
      return;
    }
    alerts.forEach(function (a) {
      var row = el("tr", { tabindex: "0", on: {
        click: function () { openAlert(a.id); },
        keydown: function (e) { if (e.key === "Enter") openAlert(a.id); }
      } }, [
        el("td", { class: "time", text: clock(a.timestamp) }),
        el("td", {}, [chip(a.severity)]),
        el("td", {}, [el("span", { text: a.title }), el("span", { class: "sub", text: a.summary === a.title ? (a.host || "") : a.summary })]),
        el("td", { class: "who", text: a.entity }),
        el("td", {}, [el("span", { class: "mono", text: a.technique }), el("span", { class: "sub", text: a.tactic })]),
        el("td", { class: "status status-" + a.status, text: statusLabel(a.status) })
      ]);
      body.appendChild(row);
    });
  }

  // ------------------------------------------------------------ drawer
  function openAlert(id) {
    api("/api/alerts/" + id).then(function (a) {
      state.openAlert = id;
      var rule = a.rule || {};
      var ctx = a.context || {};
      var drawer = clear($("drawer"));
      var flags = el("div", {});
      (ctx.threat_intel || []).forEach(function (t) {
        flags.appendChild(el("span", { class: "flag", text: "Threat intel: " + t.indicator + " (" + t.category + ")" }));
      });
      if (ctx.asset) flags.appendChild(el("span", { class: "flag info", text: ctx.asset.hostname + ": " + ctx.asset.role + ", " + ctx.asset.criticality + " criticality" }));
      if (a.contained) flags.appendChild(el("span", { class: "flag info", text: "Source already contained" }));

      var facts = el("dl", { class: "facts" });
      [["When", a.timestamp.replace("T", " ").replace("Z", " UTC")], ["Who", a.entity], ["Host", a.host || "n/a"],
       ["User", a.user || "n/a"], ["ATT&CK", a.technique + "  " + a.technique_name + "  (" + a.tactic + ")"],
       ["Rule", a.rule_id + ", " + (rule.type || "") + " rule"], ["Incident", "#" + a.incident_id],
       ["Status", statusLabel(a.status) + (a.note ? ": " + a.note : "")]].forEach(function (f) {
        facts.appendChild(el("dt", { text: f[0] }));
        facts.appendChild(el("dd", { text: f[1] }));
      });

      var evidence = el("div", { class: "evidence" });
      (a.events || []).forEach(function (e) { evidence.appendChild(el("div", { text: e.raw })); });
      if (!a.events || !a.events.length) evidence.appendChild(el("div", { text: "No stored evidence." }));

      function list(items) { return el("ul", {}, (items || []).map(function (t) { return el("li", { text: t }); })); }
      var note = el("input", { placeholder: "Add a note for the audit trail (optional)", maxlength: "500", "aria-label": "Analyst note" });
      function act(status, done) {
        return function () {
          api("/api/alerts/" + id + "/status", { status: status, note: note.value }).then(function () {
            toast(done); closeDrawer(); refresh();
          }).catch(function (err) { toast(err.message); });
        };
      }
      var actions = el("div", { class: "actions" }, [
        note,
        el("button", { class: "btn", text: "Acknowledge", on: { click: act("acknowledged", "Acknowledged") } }),
        el("button", { class: "btn", text: "Close as resolved", on: { click: act("closed", "Closed") } }),
        el("button", { class: "btn", text: "Mark false positive", on: { click: act("false_positive", "Marked false positive") } }),
        (a.src_ip && !a.contained && !ctx.src_internal) ? el("button", { class: "btn btn-danger", text: "Contain " + a.src_ip, on: { click: function () {
          api("/api/contain", { ip: a.src_ip, reason: a.rule_id + " " + a.title }).then(function (r) { toast(r.message); openAlert(id); refresh(); })
            .catch(function (err) { toast(err.message); });
        } } }) : null
      ]);

      [
        el("button", { class: "btn close", text: "Close panel", on: { click: closeDrawer } }),
        chip(a.severity),
        el("h2", { text: a.title }),
        el("p", { class: "muted", text: a.summary }),
        el("section", {}, [flags]),
        el("section", {}, [el("h3", { text: "In plain English" }), el("p", { class: "plain", text: rule.explain || rule.description || "" })]),
        el("section", {}, [facts]),
        el("section", {}, [el("h3", { text: "Evidence: the raw log lines that triggered this (" + (a.events || []).length + ")" }), evidence]),
        el("section", {}, [el("h3", { text: "What to do next" }), list(rule.response)]),
        el("section", {}, [el("h3", { text: "Could this be innocent?" }), list(rule.false_positives)]),
        el("section", {}, [el("h3", { text: "Decide" }), actions])
      ].forEach(function (n) { drawer.appendChild(n); });
      drawer.hidden = false;
      $("scrim").hidden = false;
      drawer.querySelector(".close").focus();
    }).catch(function (err) { toast(err.message); });
  }
  function closeDrawer() { $("drawer").hidden = true; $("scrim").hidden = true; state.openAlert = null; }

  // ------------------------------------------------------------ other views
  function renderIncidents(items) {
    var root = clear($("incident-list"));
    if (!items.length) { root.appendChild(el("p", { class: "empty", text: "No incidents yet." })); return; }
    items.forEach(function (inc) {
      var chain = el("div", { class: "chain" });
      // Tactics in the order they actually happened, not framework order.
      var seen = [];
      inc.alerts.forEach(function (a) { if (seen.indexOf(a.tactic) === -1) seen.push(a.tactic); });
      seen.forEach(function (t, i) {
        if (i) chain.appendChild(el("i", { text: "then" }));
        chain.appendChild(el("span", { text: t }));
      });
      var steps = el("ol", {}, inc.alerts.map(function (a) {
        return el("li", {}, [
          el("span", { class: "mono", text: clock(a.timestamp) }), chip(a.severity),
          el("button", { text: a.title, on: { click: function () { openAlert(a.id); } } }),
          el("span", { class: "status status-" + a.status, text: statusLabel(a.status) })
        ]);
      }));
      root.appendChild(el("section", { class: "panel incident" }, [
        el("div", { class: "risk sev-" + (inc.severity || "low") }, [el("b", { text: String(inc.risk) }), el("span", { text: "risk / 100" })]),
        el("div", {}, [
          el("h3", { text: "Incident #" + inc.id + ": " + inc.entity }),
          el("p", { class: "meta", text: inc.alert_count + " alerts, " + inc.status + ". " + day(inc.first_seen_iso) + " " + clock(inc.first_seen_iso) + " to " + clock(inc.last_seen_iso) + " UTC" }),
          chain, steps
        ])
      ]));
    });
  }

  function renderRules(rules) {
    var root = clear($("rule-list"));
    rules.forEach(function (r) {
      var logic = r.type === "match" ? "Fires on a single matching event"
        : r.type === "anomaly" ? "Fires when a minute is far above the rolling baseline"
        : r.type === "sequence" ? r.count + "+ matching events, then a follow-up event, same " + r.group_by + ", within " + r.window + "s"
        : r.count + "+ " + (r.distinct ? "distinct " + r.distinct + " values" : "events") + " per " + r.group_by + " within " + r.window + "s";
      function list(items) { return el("ul", {}, (items || []).map(function (t) { return el("li", { text: t }); })); }
      root.appendChild(el("details", { class: "panel rule" }, [
        el("summary", {}, [
          el("span", { class: "mono", text: r.id }),
          el("span", {}, [el("strong", { text: r.title }), el("span", { class: "sub muted", text: r.description })]),
          chip(r.severity),
          el("span", {}, [el("span", { class: "mono", text: r.technique }), el("span", { class: "sub muted", text: r.tactic })])
        ]),
        el("div", { class: "body" }, [
          el("div", { class: "plain" }, [el("h4", { text: "In plain English" }), el("p", { text: r.explain })]),
          el("div", {}, [el("h4", { text: "Logic" }), el("p", { text: logic }), el("h4", { text: "Could be innocent when" }), list(r.false_positives)]),
          el("div", {}, [el("h4", { text: "Response playbook" }), list(r.response)])
        ])
      ]));
    });
  }

  function renderResponse(data) {
    var block = clear($("blocklist"));
    if (!data.blocklist.length) block.appendChild(el("p", { class: "empty", text: "Nothing contained yet. Open an alert and choose Contain." }));
    else {
      var rows = data.blocklist.map(function (b) {
        return el("tr", {}, [
          el("td", { class: "mono", text: b.ip }), el("td", { text: b.reason }),
          el("td", { class: "time", text: clock(b.when) }),
          el("td", {}, [el("button", { class: "btn", text: "Release", on: { click: function () {
            api("/api/release", { ip: b.ip }).then(function () { toast("Released " + b.ip); loadView(); }).catch(function (e) { toast(e.message); });
          } } })])
        ]);
      });
      block.appendChild(el("div", { class: "table-wrap" }, [el("table", {}, [el("tbody", {}, rows)])]));
    }
    var audit = clear($("audit"));
    if (!data.audit.length) audit.appendChild(el("p", { class: "empty", text: "No analyst actions recorded yet." }));
    else audit.appendChild(el("div", { class: "table-wrap" }, [el("table", {}, [el("tbody", {}, data.audit.map(function (a) {
      return el("tr", {}, [el("td", { class: "time", text: clock(a.when) }), el("td", { text: a.actor }),
        el("td", { text: a.action.replace(/_/g, " ") }), el("td", { class: "mono", text: a.target }), el("td", { text: a.detail || "" })]);
    }))])]));
  }

  function hunt(event) {
    event.preventDefault();
    var q = $("hunt-q").value.trim();
    var body = clear($("hunt-results").querySelector("tbody"));
    api("/api/events/search?q=" + encodeURIComponent(q)).then(function (data) {
      $("hunt-status").textContent = data.events.length + " matching log lines" + (data.events.length === 200 ? " (showing the newest 200)" : "");
      data.events.forEach(function (e) {
        body.appendChild(el("tr", {}, [
          el("td", { class: "time", text: day(e.timestamp) + " " + clock(e.timestamp) }), el("td", { text: e.source }),
          el("td", { class: "mono", text: e.host }), el("td", { text: e.action + (e.outcome ? " (" + e.outcome + ")" : "") }),
          el("td", { class: "raw", text: e.raw })
        ]));
      });
    }).catch(function (err) { $("hunt-status").textContent = err.message; });
  }

  // ------------------------------------------------------------ plumbing
  function refresh() {
    api("/api/summary").then(function (s) {
      var feed = $("feed-state");
      feed.textContent = s.live ? "Live feed on. Last event " + clock(new Date(s.last_event * 1000).toISOString()) + " UTC" : "Replay mode, no live feed";
      feed.className = s.live ? "is-live" : "";
      if (!$("scenario").options.length) s.scenarios.forEach(function (name) {
        $("scenario").appendChild(el("option", { value: name, text: SCENARIO_LABELS[name] || name }));
      });
      if (state.view !== "overview") return;
      renderFigures(s); renderMatrix(s); renderTimeline(s);
      renderBars("entities", s.top_entities.map(function (e) { return [e.entity, e.alerts]; }), "No alerts yet.");
      renderBars("sources", Object.keys(s.by_source).map(function (k) { return [k, s.by_source[k]]; }).sort(function (a, b) { return b[1] - a[1]; }), "No log sources yet.");
    }).catch(function () { $("feed-state").textContent = "Cannot reach the server"; });
    if (state.view === "overview") {
      var qs = "?limit=150" + (state.status ? "&status=" + state.status : "") + (state.severity ? "&severity=" + state.severity : "");
      api("/api/alerts" + qs).then(function (d) { renderAlerts(d.alerts); });
    }
  }
  function loadView() {
    if (state.view === "incidents") api("/api/incidents").then(function (d) { renderIncidents(d.incidents); });
    if (state.view === "detections") api("/api/rules").then(function (d) { renderRules(d.rules); });
    if (state.view === "response") api("/api/response").then(renderResponse);
    if (state.view === "overview") refresh();
  }

  document.querySelectorAll(".tabs button").forEach(function (button) {
    button.addEventListener("click", function () {
      state.view = button.getAttribute("data-view");
      document.querySelectorAll(".tabs button").forEach(function (b) { b.classList.toggle("is-active", b === button); });
      document.querySelectorAll(".view").forEach(function (v) { v.classList.toggle("is-active", v.id === "view-" + state.view); });
      loadView();
    });
  });
  $("filter-severity").addEventListener("change", function (e) { state.severity = e.target.value; refresh(); });
  $("filter-status").addEventListener("change", function (e) { state.status = e.target.value; refresh(); });
  $("hunt-form").addEventListener("submit", hunt);
  $("scrim").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", function (e) { if (e.key === "Escape") closeDrawer(); });
  $("launch").addEventListener("click", function () {
    var button = $("launch");
    button.disabled = true;
    api("/api/simulate", { scenario: $("scenario").value }).then(function (r) {
      toast("Attack played. " + r.new_alerts + " new alert" + (r.new_alerts === 1 ? "" : "s") + " raised.");
      refresh(); loadView();
    }).catch(function (err) { toast(err.message); }).then(function () { button.disabled = false; });
  });

  refresh();
  setInterval(function () { if (!state.openAlert) refresh(); }, 4000);
})();
