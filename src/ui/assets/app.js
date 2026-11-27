// Progressive enhancement only. Nothing here is required to use the UI: the
// forms submit normally, and every destructive action is also enforced on the
// server.
//
// Why this file exists at all: the templates used to carry inline handlers
// (`onsubmit="return confirm('…{{ name }}…')"`). Autoescaping makes that string
// safe as HTML and unsafe as JavaScript — the browser decodes the entities
// before compiling the handler, so a role name containing a quote escaped into
// code. Keeping the message in a data attribute and the code here closes that
// hole, and is what lets the UI ship a CSP without 'unsafe-inline'.
(function () {
  // Confirm before submitting a form that asks for it.
  document.addEventListener("submit", function (event) {
    var form = event.target.closest("form[data-confirm]");
    if (!form) return;
    if (!window.confirm(form.getAttribute("data-confirm"))) {
      event.preventDefault();
    }
  });

  // Rows that navigate on click, for tables where the whole line is the target.
  document.addEventListener("click", function (event) {
    if (event.target.closest("a, button, input, select, textarea, label, form")) return;
    var row = event.target.closest("[data-href]");
    if (row) window.location.href = row.getAttribute("data-href");
  });

  // Select the contents of a read-only field on first click (the one-time
  // token page).
  document.addEventListener("click", function (event) {
    var field = event.target.closest("[data-select-on-click]");
    if (field) field.select();
  });

  // Client-side filter for the playground tool list.
  function filterTools(query) {
    var needle = query.toLowerCase();
    document.querySelectorAll("[data-tool-name]").forEach(function (item) {
      item.style.display =
        !needle || item.getAttribute("data-tool-name").indexOf(needle) !== -1
          ? ""
          : "none";
    });
  }
  document.addEventListener("input", function (event) {
    var input = event.target.closest("[data-filter-tools]");
    if (input) filterTools(input.value);
  });
})();
