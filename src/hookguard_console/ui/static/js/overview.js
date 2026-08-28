// Overview stat cards poll GET /api/v1/stats/summary every 30s (DESIGN.md
// §7.4). hx-swap="none" on #statcards means htmx fetches but never touches
// the DOM itself — the endpoint returns JSON, not an HTML fragment, so this
// listens for htmx's own completion event and patches the four data-stat
// spans directly instead of asking htmx to swap markup it never received.
(function () {
  document.body.addEventListener("htmx:afterRequest", function (e) {
    if (!e.detail.elt || e.detail.elt.id !== "statcards") return;
    if (!e.detail.successful) return;

    var data;
    try {
      data = JSON.parse(e.detail.xhr.responseText);
    } catch (err) {
      return;
    }

    var accepted = document.querySelector('[data-stat="accepted"]');
    var rejected = document.querySelector('[data-stat="rejected"]');
    var acceptRate = document.querySelector('[data-stat="accept_rate"]');
    var p50 = document.querySelector('[data-stat="p50_latency_ms"]');

    if (accepted) accepted.textContent = data.accepted;
    if (rejected) rejected.textContent = data.rejected;
    if (acceptRate) {
      acceptRate.textContent = data.accepted + data.rejected === 0 ? "—" : Math.round(data.accept_rate * 100) + "%";
    }
    if (p50) p50.textContent = data.p50_latency_ms + "ms";
  });
})();
