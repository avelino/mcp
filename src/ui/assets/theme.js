// Theme handling: system by default, an explicit choice when the reader makes
// one. Kept in its own file (loaded synchronously in <head>) so the page paints
// with the right palette instead of flashing dark first.
(function () {
  var KEY = "mcp-theme"; // "system" | "light" | "dark"
  var root = document.documentElement;

  function stored() {
    try {
      var value = localStorage.getItem(KEY);
      return value === "light" || value === "dark" ? value : "system";
    } catch (e) {
      return "system";
    }
  }

  function apply(choice) {
    if (choice === "system") {
      root.removeAttribute("data-theme");
    } else {
      root.setAttribute("data-theme", choice);
    }
    var meta = document.querySelector('meta[name="color-scheme"]');
    if (meta) {
      meta.setAttribute(
        "content",
        choice === "system" ? "light dark" : choice
      );
    }
    document.querySelectorAll("[data-theme-toggle]").forEach(function (button) {
      button.setAttribute("data-theme-state", choice);
      button.setAttribute(
        "title",
        choice === "system"
          ? "Theme: follow system"
          : "Theme: " + choice
      );
      var label = button.querySelector("[data-theme-label]");
      if (label) {
        label.textContent =
          choice === "system" ? "auto" : choice === "light" ? "light" : "dark";
      }
    });
  }

  apply(stored());

  // The attribute is set before first paint so there is no flash; the label and
  // title live on elements that do not exist yet at this point.
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      apply(stored());
    });
  }

  document.addEventListener("click", function (event) {
    var button = event.target.closest("[data-theme-toggle]");
    if (!button) return;
    var order = ["system", "light", "dark"];
    var next = order[(order.indexOf(stored()) + 1) % order.length];
    try {
      localStorage.setItem(KEY, next);
    } catch (e) {
      /* private mode: the choice lasts for this page only */
    }
    apply(next);
  });

  // With the choice on "system", react when the OS flips.
  if (window.matchMedia) {
    window
      .matchMedia("(prefers-color-scheme: light)")
      .addEventListener("change", function () {
        if (stored() === "system") apply("system");
      });
  }
})();
