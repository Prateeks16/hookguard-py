// Copy-to-clipboard for the final CTA band's code block (DESIGN.md §4.8).
// Pure progressive enhancement: the <code> text is readable and selectable
// without this script; only the "Copy" button's click behavior needs it.
(function () {
  document.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-copy-target]");
    if (!btn) return;
    var el = document.getElementById(btn.getAttribute("data-copy-target"));
    if (!el || !navigator.clipboard) return;
    navigator.clipboard.writeText(el.textContent).then(function () {
      var original = btn.textContent;
      btn.textContent = "Copied";
      setTimeout(function () { btn.textContent = original; }, 1500);
    });
  });
})();
