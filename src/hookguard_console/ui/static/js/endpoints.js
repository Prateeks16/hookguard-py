// Endpoint form/list behavior: provider-select drives which fields show
// (DESIGN.md §6.2), and delete requires typing the endpoint's path to
// confirm before the DELETE request is sent.
(function () {
  var FIELDS_BY_PROVIDER = {
    stripe: ["secret", "replay"],
    github: ["secret"],
    shopify: ["secret"],
    paypal: ["webhook"],
  };

  // Toggles a class rather than el.style.display. The server renders the
  // initial state with the same class, and an inline display:"" would not
  // clear a class-based display:none -- the two have to agree on a mechanism.
  function applyProviderVisibility(select) {
    var visible = FIELDS_BY_PROVIDER[select.value] || [];
    document.querySelectorAll("[data-provider-field]").forEach(function (el) {
      var key = el.getAttribute("data-provider-field");
      el.classList.toggle("u-hidden", visible.indexOf(key) === -1);
    });
  }

  var select = document.querySelector("[data-provider-select]");
  if (select) {
    select.addEventListener("change", function () {
      applyProviderVisibility(select);
    });
    // Also on load. This never ran on load before, so the server-rendered
    // state was the only thing hiding irrelevant fields -- and the CSP was
    // dropping it, which meant every provider field showed until the select
    // was touched.
    applyProviderVisibility(select);
  }

  document.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-delete-endpoint]");
    if (!btn) return;

    var path = btn.getAttribute("data-endpoint-path");
    var typed = window.prompt('Type the endpoint path "' + path + '" to confirm deletion:');
    if (typed !== path) {
      return;
    }

    var id = btn.getAttribute("data-endpoint-id");
    var csrf = btn.getAttribute("data-csrf-token");
    fetch("/dashboard/endpoints/" + id, {
      method: "DELETE",
      headers: { "X-CSRF-Token": csrf },
    }).then(function () {
      window.location.href = "/dashboard/endpoints";
    });
  });
})();
