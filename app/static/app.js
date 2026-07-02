/* ScamShield UI — external so the CSP can be script-src 'self' (no unsafe-inline). */
(function () {
  "use strict";
  var UI = {};
  try { UI = JSON.parse(document.getElementById("scamshield-ui").textContent); } catch (e) {}

  var $ = function (id) { return document.getElementById(id); };
  var VCOLOR = { safe: "var(--safe)", suspicious: "var(--warn)", scam: "var(--danger)" };
  var VBG = { safe: "#0f2a1a", suspicious: "#2a230f", scam: "#2a1414" };
  var show = function (el) { el.classList.remove("hidden"); };
  var hide = function (el) { el.classList.add("hidden"); };

  // --- auth (Supabase email-OTP via our same-origin backend proxy) --------- #
  var token = function () { try { return localStorage.getItem("ss_token"); } catch (e) { return null; } };
  var email = function () { try { return localStorage.getItem("ss_email"); } catch (e) { return null; } };
  function setSession(t, e) { try { localStorage.setItem("ss_token", t); localStorage.setItem("ss_email", e); } catch (x) {} }
  function clearSession() { try { localStorage.removeItem("ss_token"); localStorage.removeItem("ss_email"); } catch (x) {} }

  async function authFetch(url, opts) {
    opts = opts || {};
    opts.headers = opts.headers || {};
    var t = token();
    if (t) opts.headers["Authorization"] = "Bearer " + t;
    var r = await fetch(url, opts);
    if (r.status === 401 && t) { clearSession(); refreshAuthUI(); }
    return r;
  }

  var lastContent = "";

  async function check() {
    var content = $("content").value.trim();
    hide($("error"));
    if (!content) { $("error").textContent = UI.empty; show($("error")); return; }
    lastContent = content;
    hide($("empty")); hide($("out")); show($("loading"));
    $("check").disabled = true; $("check").textContent = UI.checking;
    try {
      var res = await authFetch("/api/scan", {
        method: "POST", headers: { "content-type": "application/json" },
        // omit language: the server auto-detects the message's language so the
        // explanation/tips come back in the victim's language (en/hi/hinglish).
        body: JSON.stringify({ content: content, type: "message" })
      });
      if (!res.ok) throw new Error("HTTP " + res.status);
      render(await res.json());
    } catch (e) {
      hide($("loading"));
      $("error").textContent = "Sorry — something went wrong. Please try again.";
      show($("error"));
    } finally {
      $("check").disabled = false; $("check").textContent = UI.check;
    }
  }

  function render(d) {
    hide($("loading")); show($("out"));
    var v = d.verdict || "safe";
    var ring = $("ring");
    ring.style.setProperty("--v", d.score || 0);
    ring.style.setProperty("--c", VCOLOR[v] || "var(--muted)");
    ring.setAttribute("aria-label", UI.score + ": " + (d.score || 0) + " / 100");
    $("ringn").textContent = d.score || 0;
    $("vlabel").textContent = d.label || v;
    $("vlabel").style.color = VCOLOR[v];
    $("vsub").textContent = UI.score + ": " + (d.score || 0) + "/100";
    var type = d.scam_type_name;
    if (type) {
      $("vtype").textContent = UI.likely + ": " + type;
      $("vtype").style.background = VBG[v]; $("vtype").style.color = VCOLOR[v];
      show($("vtype"));
    } else { hide($("vtype")); }
    $("explain").textContent = d.explanation || "";

    var chips = $("chips"); chips.textContent = "";
    (d.categories || []).forEach(function (c) {
      var s = document.createElement("span"); s.className = "chip"; s.textContent = c; chips.appendChild(s);
    });
    $("signalsWrap").style.display = (d.categories && d.categories.length) ? "block" : "none";

    var tips = $("tips"); tips.textContent = "";
    (d.safety_tips || []).forEach(function (t) {
      var li = document.createElement("li"); li.textContent = t; tips.appendChild(li);
    });
    $("tipsWrap").style.display = (d.safety_tips && d.safety_tips.length) ? "block" : "none";

    // build helpline via DOM (no innerHTML) to keep output injection-proof
    var help = $("help"); help.textContent = "";
    var h = d.helpline || {};
    if (h.cyber_helpline) {
      help.appendChild(document.createTextNode("📞 "));
      var num = document.createElement("b"); num.textContent = h.cyber_helpline; help.appendChild(num);
      if (h.cyber_portal) {
        help.appendChild(document.createTextNode(" · "));
        var a = document.createElement("a");
        a.href = h.cyber_portal; a.textContent = h.cyber_portal;
        a.rel = "noopener noreferrer"; a.target = "_blank";
        help.appendChild(a);
      }
      help.style.display = "block";
    } else { help.style.display = "none"; }

    // offer "report as scam" for non-safe results
    lastScamType = d.scam_type || "other";
    var rep = $("report");
    if (rep) {
      rep.textContent = UI.report_this;
      rep.classList.toggle("hidden", v === "safe");
    }
  }

  var lastScamType = "other";

  $("check").addEventListener("click", check);
  $("content").addEventListener("keydown", function (e) {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") check();
  });
  $("copy").addEventListener("click", function () {
    var t = $("vlabel").textContent + " — " + $("explain").textContent;
    if (navigator.clipboard) navigator.clipboard.writeText(t);
    $("copy").textContent = "✓";
    setTimeout(function () { $("copy").textContent = UI.share; }, 1500);
  });

  // On-device QR decode via the native BarcodeDetector — the image never leaves
  // the device (privacy). Falls back with a message where unsupported.
  var qrBtn = $("qr"), qrFile = $("qrfile");
  if (qrBtn && qrFile) {
    qrBtn.addEventListener("click", function () {
      if (!("BarcodeDetector" in window)) {
        $("error").textContent = UI.qr_unsupported; $("error").classList.remove("hidden"); return;
      }
      qrFile.click();
    });
    qrFile.addEventListener("change", async function () {
      var f = qrFile.files && qrFile.files[0];
      if (!f) return;
      $("error").classList.add("hidden");
      try {
        var bmp = await createImageBitmap(f);
        var det = new window.BarcodeDetector({ formats: ["qr_code"] });
        var codes = await det.detect(bmp);
        if (codes && codes.length && codes[0].rawValue) {
          $("content").value = codes[0].rawValue;
          check();
        } else {
          $("error").textContent = UI.qr_none; $("error").classList.remove("hidden");
        }
      } catch (e) {
        $("error").textContent = UI.qr_unsupported; $("error").classList.remove("hidden");
      } finally {
        qrFile.value = "";
      }
    });
  }

  // --- account UI (sign in / history / report / sign out) ------------------ #
  function refreshAuthUI() {
    var signedIn = !!token();
    $("acctstatus").textContent = signedIn ? (UI.signed_in + ": " + (email() || "")) : "";
    $("account").textContent = signedIn ? UI.sign_out : UI.sign_in;
    hide($("auth-email")); hide($("auth-code")); hide($("auth-in"));
    $("autherr").classList.add("hidden");
  }

  function authError(msg) { $("autherr").textContent = msg; $("autherr").classList.remove("hidden"); }

  $("account").addEventListener("click", function () {
    if (token()) { clearSession(); refreshAuthUI(); hide($("authpanel")); return; }
    var panel = $("authpanel");
    if (panel.classList.contains("hidden")) {
      show(panel); refreshAuthUI(); show($("auth-email")); $("email").focus();
    } else { hide(panel); }
  });

  $("sendcode").addEventListener("click", async function () {
    var e = $("email").value.trim().toLowerCase();
    $("autherr").classList.add("hidden");
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e)) { authError("Enter a valid email."); return; }
    $("sendcode").disabled = true;
    try {
      var r = await fetch("/api/auth/request-otp", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: e })
      });
      if (r.status === 501) { authError(UI.auth_unavailable); return; }
      if (!r.ok) { authError("Could not send the code. Try again."); return; }
      hide($("auth-email")); show($("auth-code")); $("code").focus();
    } catch (x) { authError("Could not send the code. Try again."); }
    finally { $("sendcode").disabled = false; }
  });

  $("verifycode").addEventListener("click", async function () {
    var e = $("email").value.trim().toLowerCase(), c = $("code").value.trim();
    $("autherr").classList.add("hidden");
    $("verifycode").disabled = true;
    try {
      var r = await fetch("/api/auth/verify-otp", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: e, token: c })
      });
      if (!r.ok) { authError("Invalid or expired code."); return; }
      var d = await r.json();
      setSession(d.access_token, e);
      refreshAuthUI(); show($("auth-in"));
    } catch (x) { authError("Invalid or expired code."); }
    finally { $("verifycode").disabled = false; }
  });

  $("signout").addEventListener("click", function () { clearSession(); refreshAuthUI(); hide($("authpanel")); });

  $("showhistory").addEventListener("click", async function () {
    var list = $("historylist"); list.textContent = "";
    try {
      var r = await authFetch("/api/history");
      if (!r.ok) { authError("Please sign in again."); return; }
      var rows = await r.json();
      if (!rows.length) { var li = document.createElement("li"); li.textContent = UI.history_empty; list.appendChild(li); return; }
      rows.forEach(function (row) {
        var li = document.createElement("li");
        li.textContent = (row.verdict || "") + " · " + (row.score || 0) + "/100 · " + (row.created_at || "").slice(0, 10);
        list.appendChild(li);
      });
    } catch (x) { authError("Could not load history."); }
  });

  $("report").addEventListener("click", async function () {
    if (!token()) { show($("authpanel")); refreshAuthUI(); show($("auth-email")); $("email").focus(); return; }
    if (!lastContent) return;
    $("report").disabled = true;
    try {
      var r = await authFetch("/api/report", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ pattern: lastContent, category: lastScamType })
      });
      $("report").textContent = r.ok ? UI.report_done : "Try again";
    } catch (x) { $("report").textContent = "Try again"; }
    finally { setTimeout(function () { $("report").disabled = false; $("report").textContent = UI.report_this; }, 2000); }
  });

  refreshAuthUI();

  // Web Share Target: text shared from WhatsApp/SMS arrives as ?text/?url, so
  // prefill and auto-check.
  (function () {
    var p = new URLSearchParams(window.location.search);
    var shared = [p.get("text"), p.get("url")].filter(Boolean).join(" ").trim();
    if (shared) { $("content").value = shared; check(); }
  })();

  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/static/sw.js").catch(function () {});
  }
})();
