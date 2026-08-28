// Dark/light toggle: flips data-theme on <html> and persists to
// localStorage. tokens.css already defines both palettes plus the
// prefers-color-scheme default — this only adds the manual override.
(function () {
  var KEY = "hg-theme";
  var stored = localStorage.getItem(KEY);
  if (stored) {
    document.documentElement.setAttribute("data-theme", stored);
  }

  document.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-theme-toggle]");
    if (!btn) return;
    var current = document.documentElement.getAttribute("data-theme");
    var next = current === "light" ? "dark" : "light";
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem(KEY, next);
  });
})();
