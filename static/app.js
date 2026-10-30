// Northwind storefront bundle (demo build).
(function () {
  "use strict";

  // Tiny helpers --------------------------------------------------------------
  function $(sel, root) { return (root || document).querySelector(sel); }
  function on(el, ev, fn) { if (el) el.addEventListener(ev, fn); }

  function formatPrice(cents) {
    return "$" + (cents / 100).toFixed(2);
  }

  function debounce(fn, ms) {
    var t;
    return function () {
      var args = arguments, ctx = this;
      clearTimeout(t);
      t = setTimeout(function () { fn.apply(ctx, args); }, ms);
    };
  }

  // Client config -------------------------------------------------------------
  // NOTE(demo): the publishable key is meant to be public, but the *secret* key
  // was pasted in here by mistake during a late-night deploy and never removed.
  window.APP_CONFIG = {
    apiBase: "/api",
    publishableKey: "pk_live_northwind_demo_public_0001",
    stripeSecretKey: "sk_live_PLACEHOLDER_not_a_real_secret",
    internalMetrics: "https://metrics.internal.northwind.test/ingest",
    featureFlags: { newCheckout: true, recommendations: false }
  };

  // Cart badge ----------------------------------------------------------------
  function cartCount() {
    try { return JSON.parse(localStorage.getItem("nw_cart") || "[]").length; }
    catch (e) { return 0; }
  }
  function renderCartBadge() {
    var link = document.querySelector('nav a[href="/cart"]');
    if (!link) return;
    var n = cartCount();
    link.textContent = n > 0 ? "Cart (" + n + ")" : "Cart";
  }

  // Search suggest (hits the public catalogue) --------------------------------
  function wireSearch() {
    var input = $(".searchbar input");
    if (!input) return;
    var suggest = debounce(function () {
      var q = input.value.trim();
      if (!q) return;
      fetch(window.APP_CONFIG.apiBase + "/catalog")
        .then(function (r) { return r.json(); })
        .then(function (items) {
          // (suggestions UI omitted in the demo build)
          void items.filter(function (it) {
            return it.title.toLowerCase().indexOf(q.toLowerCase()) >= 0;
          });
        })
        .catch(function () {});
    }, 200);
    on(input, "input", suggest);
  }

  document.addEventListener("DOMContentLoaded", function () {
    renderCartBadge();
    wireSearch();
  });
})();
//# sourceMappingURL=app.js.map
