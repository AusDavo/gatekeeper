// Apply saved/preferred theme before first paint to avoid a flash. Loaded as a
// blocking script from <head> — kept out of index.html so the CSP needs no
// 'unsafe-inline'.
(function () {
  var t = localStorage.getItem("theme");
  if (
    t === "light" ||
    (!t && window.matchMedia("(prefers-color-scheme: light)").matches)
  ) {
    document.documentElement.classList.add("light");
  }
})();
