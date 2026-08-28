// Live Logs: a plain EventSource against GET /dashboard/logs/stream (DESIGN.md
// §6.2) — no htmx SSE extension is vendored, so this hand-rolls the three
// things the design doc asks for: append-while-live, pause/resume with a
// new-rows counter, and a reconnect banner. EventSource retries natively on
// its own; this only needs to toggle the banner on open/error.
(function () {
  var table = document.getElementById("logs-table");
  if (!table) return;

  var tbody = document.getElementById("logs-tbody");
  var banner = document.getElementById("stream-error");
  var pauseBtn = document.getElementById("pause-resume");
  var counter = document.getElementById("paused-counter");
  var drawer = document.getElementById("log-drawer");
  var drawerFields = document.getElementById("drawer-fields");
  var drawerClose = document.getElementById("drawer-close");

  var paused = false;
  var pendingCount = 0;
  var buffered = [];

  function verdictCell(ev) {
    return ev.verdict === "accepted"
      ? '<span style="color:var(--ok)">&#10003; accepted</span>'
      : '<span style="color:var(--reject)">&#10007; rejected</span>';
  }

  function rowHTML(ev) {
    return (
      '<tr class="log-row" tabindex="0" data-id="' + ev.id + '"' +
      ' data-time="' + ev.time + '" data-provider="' + ev.provider + '" data-path="' + ev.path + '"' +
      ' data-verdict="' + ev.verdict + '" data-reason="' + ev.reason + '"' +
      ' data-upstream-status="' + ev.upstream_status + '" data-latency-ms="' + ev.latency_ms + '"' +
      ' data-body-bytes="' + ev.body_bytes + '" data-body-sha256="' + ev.body_sha256 + '"' +
      ' data-remote-ip="' + ev.remote_ip + '">' +
      "<td>" + ev.time + "</td>" +
      '<td><span class="badge badge-provider-' + ev.provider + '">' + ev.provider + "</span></td>" +
      "<td><code>" + ev.path + "</code></td>" +
      "<td>" + verdictCell(ev) + "</td>" +
      "<td>" + ev.reason + "</td>" +
      "<td>" + ev.upstream_status + "</td>" +
      "<td>" + ev.latency_ms + "ms</td>" +
      "<td>" + ev.body_bytes + "</td>" +
      "<td><code>" + ev.remote_ip + "</code></td>" +
      "</tr>"
    );
  }

  function prependRows(events) {
    table.hidden = false;
    var html = "";
    for (var i = 0; i < events.length; i++) html += rowHTML(events[i]);
    tbody.insertAdjacentHTML("afterbegin", html);
  }

  function updateCounter() {
    if (pendingCount > 0) {
      counter.hidden = false;
      counter.textContent = pendingCount + " new";
    } else {
      counter.hidden = true;
    }
  }

  pauseBtn.addEventListener("click", function () {
    paused = !paused;
    pauseBtn.textContent = paused ? "Resume" : "Pause";
    if (!paused) {
      if (buffered.length > 0) prependRows(buffered);
      buffered = [];
      pendingCount = 0;
      updateCounter();
    }
  });

  function openDrawer(row) {
    var d = row.dataset;
    var fields = [
      ["ID", d.id], ["Time", d.time], ["Provider", d.provider], ["Path", d.path],
      ["Verdict", d.verdict], ["Reason", d.reason || "—"], ["Upstream status", d.upstreamStatus],
      ["Latency", d.latencyMs + "ms"], ["Body bytes", d.bodyBytes], ["Body SHA-256", d.bodySha256],
      ["Remote IP", d.remoteIp],
    ];
    var html = "";
    for (var i = 0; i < fields.length; i++) {
      html += "<dt>" + fields[i][0] + "</dt><dd><code>" + fields[i][1] + "</code></dd>";
    }
    drawerFields.innerHTML = html;
    drawer.hidden = false;
  }

  document.addEventListener("click", function (e) {
    var row = e.target.closest(".log-row");
    if (row) openDrawer(row);
  });
  document.addEventListener("keydown", function (e) {
    if (e.key !== "Enter") return;
    var row = e.target.closest(".log-row");
    if (row) openDrawer(row);
  });
  drawerClose.addEventListener("click", function () {
    drawer.hidden = true;
  });

  var source = new EventSource(table.getAttribute("data-stream-url"));

  source.onopen = function () {
    banner.hidden = true;
  };
  source.onerror = function () {
    banner.hidden = false;
  };
  source.onmessage = function (e) {
    var events;
    try {
      events = JSON.parse(e.data);
    } catch (err) {
      return;
    }
    if (!events || events.length === 0) return;
    events.reverse(); // stream arrives oldest-first per tick; table is newest-first
    if (paused) {
      buffered = events.concat(buffered);
      pendingCount += events.length;
      updateCounter();
    } else {
      prependRows(events);
    }
  };
})();
