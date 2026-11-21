/* RT LENDING CORP. · PASSBOOK — shared by index.html (passbook) and admin.html */
(function () {
  "use strict";
  const enc = new TextEncoder(), dec = new TextDecoder();
  const RT = {};
  RT.DAY = 86400000;

  /* ---------- bytes / crypto ---------- */
  RT.b64u = function (b) {
    const a = new Uint8Array(b); let s = "";
    for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  RT.ub64u = function (s) {
    s = String(s).replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const bin = atob(s), a = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
    return a;
  };
  RT.sha = async (x) => new Uint8Array(await crypto.subtle.digest("SHA-256", typeof x === "string" ? enc.encode(x) : x));
  RT.hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  RT.pidOf = async (link) => RT.hex(await RT.sha("pid|" + link)).slice(0, 24);
  RT.aesKey = async (link) => crypto.subtle.importKey("raw", await RT.sha("aes|" + link), "AES-GCM", false, ["encrypt", "decrypt"]);
  RT.aesRaw = async (raw) => crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
  RT.seal = async (key, obj) => {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(obj)));
    return { iv: RT.b64u(iv), ct: RT.b64u(ct) };
  };
  RT.open = async (key, box) => JSON.parse(dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: RT.ub64u(box.iv) }, key, RT.ub64u(box.ct))));
  RT.proof = async (link, parts) => {
    const k = await crypto.subtle.importKey("raw", await RT.sha("proof|" + link), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return RT.b64u(await crypto.subtle.sign("HMAC", k, enc.encode(parts.join("|")))).slice(0, 22);
  };
  RT.itemHash = async (it) => RT.b64u(await RT.sha(JSON.stringify([it.id, it.title, it.lines]))).slice(0, 16);

  /* ---------- text ---------- */
  RT.esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  RT.peso = (n) => {
    n = Math.round((+n || 0) * 100) / 100;
    const cents = Math.round(Math.abs(n) * 100) % 100 !== 0;
    return (n < 0 ? "−₱" : "₱") + Math.abs(n).toLocaleString("en-US", { minimumFractionDigits: cents ? 2 : 0, maximumFractionDigits: 2 });
  };
  const MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  RT.MON = MON;
  // dates are kept as "YYYY-MM-DD" (Philippine calendar date) and times as "HH:MM"
  RT.dLabel = (d) => { if (!d) return "—"; const [y, m, dd] = d.split("-").map(Number); return MON[m - 1] + " " + dd + ", " + y; };
  RT.tLabel = (t) => { if (!t || t === "00:00") return ""; let [h, m] = t.split(":").map(Number); const ap = h >= 12 ? "PM" : "AM"; h = h % 12 || 12; return h + ":" + String(m).padStart(2, "0") + " " + ap; };
  RT.stamp = (ms) => { // ms → "Nov 16, 2026 7:05 AM" in Philippine time
    const d = new Date(ms + 8 * 3600000), h = d.getUTCHours(), m = d.getUTCMinutes();
    return MON[d.getUTCMonth()] + " " + d.getUTCDate() + ", " + d.getUTCFullYear() + " " + ((h % 12) || 12) + ":" + String(m).padStart(2, "0") + " " + (h >= 12 ? "PM" : "AM");
  };
  RT.ymd = (ms) => { const d = new Date(ms + 8 * 3600000); return d.getUTCFullYear() + "-" + String(d.getUTCMonth() + 1).padStart(2, "0") + "-" + String(d.getUTCDate()).padStart(2, "0"); };
  RT.first = (name) => String(name || "").split(" ")[0] || "";
  RT.title = (s) => String(s || "").toLowerCase().replace(/(^|[\s.-])([a-zñ])/g, (m, a, b) => a + b.toUpperCase());

  /* ---------- the rule: signed / concern / 7 days ---------- */
  RT.need = (it) => (it.signers && it.signers.length ? it.signers : [it.holder]);
  RT.status = (it, now, days) => {
    if (it.void) return { code: "VOID", label: "KINANSELA" };
    const need = RT.need(it), sigs = it.sigs || {};
    const got = need.filter((n) => sigs[n]);
    if (got.length && (it.any || got.length === need.length)) {
      return { code: "SIGNED", label: "PIRMADO", at: Math.max.apply(null, got.map((n) => sigs[n].at)) };
    }
    if ((it.concerns || []).some((c) => !c.resolved)) return { code: "CONCERN", label: "MAY TANONG / TUTOL" };
    const start = it.restart || it.sent, due = start + days * RT.DAY;
    if (now >= due) return { code: "DEEMED", label: "TINANGGAP", at: due, partial: got.length };
    return { code: "PENDING", label: got.length ? "KULANG PA ANG PIRMA" : "PIPIRMAHAN", due, left: Math.max(1, Math.ceil((due - now) / RT.DAY)), partial: got.length };
  };

  /* ---------- signature strokes → SVG path ---------- */
  RT.pathOf = (strokes) => strokes.filter((s) => s.length).map((s) => "M" + s.map((p) => p[0] + " " + p[1]).join("L")).join("");
  RT.strokesOf = (path) => {
    const out = [];
    String(path || "").split("M").filter(Boolean).forEach((seg) => {
      out.push(seg.split("L").map((xy) => xy.trim().split(/\s+/).map(Number)).filter((p) => p.length === 2 && !isNaN(p[0])));
    });
    return out;
  };
  RT.drawStrokes = (ctx, strokes, x, y, w, h, color) => { // strokes are on a 600×200 grid
    const k = Math.min(w / 600, h / 200);
    ctx.save(); ctx.translate(x + (w - 600 * k) / 2, y + (h - 200 * k) / 2); ctx.scale(k, k);
    ctx.lineWidth = 3.2; ctx.lineCap = "round"; ctx.lineJoin = "round"; ctx.strokeStyle = color || "#0B2550";
    strokes.forEach((s) => { if (!s.length) return; ctx.beginPath(); ctx.moveTo(s[0][0], s[0][1]); if (s.length === 1) ctx.lineTo(s[0][0] + 0.5, s[0][1]); s.forEach((p) => ctx.lineTo(p[0], p[1])); ctx.stroke(); });
    ctx.restore();
  };

  /* ---------- signature pad ---------- */
  RT.pad = function (canvas, onChange) {
    const ctx = canvas.getContext("2d"); let strokes = [], cur = null;
    function fit() {
      const r = canvas.getBoundingClientRect(), dpr = window.devicePixelRatio || 1;
      canvas.width = Math.max(1, Math.round(r.width * dpr)); canvas.height = Math.max(1, Math.round(r.height * dpr));
      redraw();
    }
    function redraw() { ctx.setTransform(1, 0, 0, 1, 0, 0); ctx.clearRect(0, 0, canvas.width, canvas.height); RT.drawStrokes(ctx, strokes, 0, 0, canvas.width, canvas.height); }
    function pt(e) { const r = canvas.getBoundingClientRect(); return [Math.round((e.clientX - r.left) / r.width * 600), Math.round((e.clientY - r.top) / r.height * 200)]; }
    canvas.addEventListener("pointerdown", (e) => { e.preventDefault(); try { canvas.setPointerCapture(e.pointerId); } catch (_) {} cur = [pt(e)]; strokes.push(cur); redraw(); onChange && onChange(); });
    canvas.addEventListener("pointermove", (e) => { if (!cur) return; e.preventDefault(); const p = pt(e), q = cur[cur.length - 1]; if (Math.abs(p[0] - q[0]) + Math.abs(p[1] - q[1]) >= 2) { cur.push(p); redraw(); } });
    const end = () => { if (cur) { cur = null; onChange && onChange(); } };
    canvas.addEventListener("pointerup", end); canvas.addEventListener("pointercancel", end); canvas.addEventListener("pointerleave", end);
    new ResizeObserver(fit).observe(canvas);
    return { clear() { strokes = []; redraw(); onChange && onChange(); }, ink() { return strokes.reduce((n, s) => n + s.length, 0); }, path() { return RT.pathOf(strokes); } };
  };

  /* ---------- signed copy (JPEG) ---------- */
  RT.copyJpeg = async function (o) { // o: {head?, co, tagline, title, lines, holder, viewer, role, status, sigs:[{name, role, at, path}], code, id}
    const W = 1080, P = 72, c = document.createElement("canvas"), x = c.getContext("2d");
    const lineH = 40, wrapW = W - 2 * P;
    x.font = "34px Arial";
    function wrap(t, font) { x.font = font; const words = String(t).split(" "), out = []; let l = ""; words.forEach((w) => { const tt = l ? l + " " + w : w; if (x.measureText(tt).width > wrapW && l) { out.push(l); l = w; } else l = tt; }); if (l) out.push(l); return out; }
    const body = []; o.lines.forEach((t) => { wrap(t, "32px Arial").forEach((l, i) => body.push({ t: l, gap: i === 0 })); });
    const H = 520 + body.length * lineH + o.sigs.length * 250 + 220;
    c.width = W; c.height = H; x.fillStyle = "#FFFDF8"; x.fillRect(0, 0, W, H);
    x.fillStyle = "#0B2550"; x.fillRect(0, 0, W, 210);
    x.fillStyle = "#D9B26A"; x.font = "bold 30px Arial"; x.fillText(o.co, P, 78);
    x.fillStyle = "#FFFFFF"; x.font = "bold 50px Georgia"; x.fillText(o.head || "PAGKILALA", P, 142);
    x.fillStyle = "#C9D3E6"; x.font = "24px Arial"; x.fillText(o.tagline || "", P, 182);
    let y = 270; x.fillStyle = "#8C6424"; x.font = "bold 34px Arial";
    wrap(o.title, "bold 34px Arial").forEach((l) => { x.fillText(l, P, y); y += 44; });
    x.fillStyle = "#5B6475"; x.font = "26px Arial"; x.fillText(o.holder + (o.role ? "  ·  " + o.role : ""), P, y + 6); y += 56;
    x.strokeStyle = "#E6DCC6"; x.lineWidth = 2; x.beginPath(); x.moveTo(P, y); x.lineTo(W - P, y); x.stroke(); y += 50;
    x.fillStyle = "#1B2333";
    body.forEach((b) => { if (b.gap) y += 8; x.font = "32px Arial"; x.fillText(b.t, P, y); y += lineH; });
    y += 30;
    o.sigs.forEach((s) => {
      x.fillStyle = "#F4EEDF"; x.fillRect(P, y, W - 2 * P, 170);
      if (s.path) RT.drawStrokes(x, RT.strokesOf(s.path), P + 10, y + 5, W - 2 * P - 20, 160, "#0B2550");
      else { x.fillStyle = "#9AA3B2"; x.font = "italic 28px Arial"; x.fillText("Walang pirma", P + 24, y + 96); }
      x.strokeStyle = "#0B2550"; x.lineWidth = 2; x.beginPath(); x.moveTo(P, y + 172); x.lineTo(W - P, y + 172); x.stroke();
      x.fillStyle = "#0B2550"; x.font = "bold 28px Arial"; x.fillText(s.name, P, y + 210);
      x.fillStyle = "#5B6475"; x.font = "24px Arial"; x.fillText([s.role, s.at ? RT.stamp(s.at) : ""].filter(Boolean).join("  ·  "), P, y + 242);
      y += 270;
    });
    x.fillStyle = o.status.code === "SIGNED" ? "#1E7B34" : (o.status.code === "DEEMED" ? "#8C6424" : "#5B6475");
    x.font = "bold 34px Arial"; x.fillText(o.status.text, P, y + 20);
    x.fillStyle = "#5B6475"; x.font = "22px Arial"; x.fillText("Code " + o.code + "  ·  " + o.id, P, y + 64);
    x.fillText("Prepared by: " + o.co, P, y + 98);
    return await new Promise((res) => c.toBlob(res, "image/jpeg", 0.9));
  };

  /* ---------- Google Form (append-only record) ---------- */
  RT.send = async function (form, name, msg, data) {
    if (!form || !form.url || !form.data) throw new Error("noform");
    const body = new URLSearchParams();
    if (form.name) body.set(form.name, name);
    if (form.msg) body.set(form.msg, msg);
    body.set(form.data, JSON.stringify(data));
    await fetch(form.url, { method: "POST", mode: "no-cors", body });
    return true;
  };

  /* ---------- Mystery Scratch & Win (R5): her scratch card, shared by the passbook and RT Admin ---------- */
  // R6: a prize is a peso amount (0 = BOKYA) or the name of an item, such as Chocolates
  RT.prizeText = (v) => (typeof v === "string" && v.trim() ? v.trim() : +v > 0 ? RT.peso(v) : "BOKYA");
  RT.prizeWin = (v) => (typeof v === "string" ? !!v.trim() : +v > 0);
  RT.scratchLabel = (no, amt) => "MYSTERY SCRATCH · CARD #" + no + " · " + RT.prizeText(amt);
  const XS_CSS = '.xs{color:#2f3542;text-align:center;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;padding:8px 2px 4px}' +
    ".xs .xs-b{display:inline-block;background:#ffeaa7;color:#d35400;font-weight:800;font-size:13px;padding:5px 12px;border-radius:20px;margin-bottom:8px}" +
    ".xs h2.xs-h{margin:4px 0 6px;font-size:22px;font-weight:900;line-height:1.25;color:#2f3542;letter-spacing:0;text-transform:none}" +
    ".xs .xs-s{margin:0 0 16px;font-size:14px;color:#57606f}" +
    ".xs .xs-w{position:relative;width:270px;height:165px;margin:0 auto 14px;border-radius:16px;overflow:hidden;background:linear-gradient(135deg,#fff9e6,#ffeaa7);border:3px dashed #ffa502;box-shadow:inset 0 0 12px rgba(0,0,0,.12)}" +
    ".xs .xs-p{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;z-index:1}" +
    ".xs .xs-a{font-size:46px;font-weight:900;color:#e84118;line-height:1.1}.xs .xs-a.bk{font-size:28px;color:#747d8c}" +
    ".xs .xs-a.it{font-size:32px;padding:0 12px;overflow-wrap:anywhere}.xs .xs-a.it2{font-size:24px}.xs .xs-a.it3{font-size:19px}" +
    ".xs .xs-l{font-size:13px;font-weight:800;color:#2f3542;margin-top:4px}" +
    ".xs .xs-w canvas{position:absolute;inset:0;z-index:2;width:270px;height:165px;touch-action:none;cursor:crosshair}" +
    ".xs .xs-st{background:#f1f2f6;border-radius:12px;padding:10px 12px;font-size:15px;font-weight:700;color:#2f3542}" +
    ".xs .xs-st.win{background:#d4edda;color:#155724}.xs .xs-st.lock{background:#ffeaa7;color:#b33939}" +
    ".xs .xs-n{margin-top:10px;font-size:14px;color:#1e90ff;font-weight:800}.xs .xs-n:empty{display:none}" +
    ".xs .xs-c{margin-top:12px;background:#2f3542;color:#fff;border:0;border-radius:10px;padding:12px 16px;font-size:15px;font-weight:700;cursor:pointer;width:100%;min-height:48px}" +
    "#xsConf{position:fixed;inset:0;pointer-events:none;z-index:999}";
  RT.scratchCard = function (host, o) { // o: {no, amt, locked, note, closeText, onFirst, onReveal, onClose}
    if (!document.getElementById("xsCss")) { const st = document.createElement("style"); st.id = "xsCss"; st.textContent = XS_CSS; document.head.appendChild(st); }
    const esc = RT.esc, win = RT.prizeWin(o.amt), P = RT.prizeText(o.amt), item = typeof o.amt === "string" && win;
    const ic = item ? " it" + (P.length > 22 ? " it3" : P.length > 11 ? " it2" : "") : "";
    host.innerHTML = '<div class="xs"><div class="xs-b">MYSTERY CARD #' + esc(o.no) + "</div>" +
      '<h2 class="xs-h">' + (o.locked ? "🔒 Naka-Lock Na Ang Card Mo!" : "✨ Kaskasin Mo Na!") + "</h2>" +
      '<p class="xs-s">' + (o.locked ? "Isang beses lang pwedeng kaskasin ang card mo." : "Kapag sinimulan nang kaskasin, naka-lock na ito!") + "</p>" +
      '<div class="xs-w"><div class="xs-p"><div class="xs-a' + (win ? ic : " bk") + '">' + (win ? esc(P) : "BOKYA 😢") + '</div><div class="xs-l">' +
      (win ? (o.locked ? "VERIFIED PRIZE MO!" : "CONGRATULATIONS! PANALO KA!") : (o.locked ? "Salamat sa pagsali!" : "Better luck next time!")) + "</div></div>" +
      (o.locked ? "" : '<canvas width="270" height="165" aria-label="Kaskasin dito gamit ang daliri"></canvas>') + "</div>" +
      '<div class="xs-st' + (o.locked ? " lock" : "") + '">' + (o.locked ? (win ? "Verified Premyo Mo: " + esc(P) : "Salamat sa pagsali!") : "Gamitin ang daliri para kaskasin ang silver box 👆") + "</div>" +
      '<div class="xs-n">' + (o.note || "") + "</div>" +
      '<button class="xs-c" type="button">' + esc(o.closeText || "Bumalik sa passbook") + "</button></div>";
    const close = host.querySelector(".xs-c"), st = host.querySelector(".xs-st"), note = host.querySelector(".xs-n"), cv = host.querySelector("canvas");
    close.onclick = () => { if (o.onClose) o.onClose(); };
    const api = { note(h) { note.innerHTML = h || ""; }, revealed: !!o.locked };
    if (!cv) return api;
    const x = cv.getContext("2d");
    const g = x.createLinearGradient(0, 0, 270, 165); g.addColorStop(0, "#bdc3c7"); g.addColorStop(0.5, "#ecf0f1"); g.addColorStop(1, "#95a5a6");
    x.fillStyle = g; x.fillRect(0, 0, 270, 165);
    x.fillStyle = "#2f3542"; x.font = "bold 17px sans-serif"; x.textAlign = "center"; x.fillText("✨ KASKASIN DITO ✨", 135, 80);
    x.font = "12px sans-serif"; x.fillText("Card #" + o.no + " • 1 Scratch Only", 135, 102);
    let down = false, first = false, done = false;
    const pos = (e) => { const r = cv.getBoundingClientRect(); return [(e.clientX - r.left) * 270 / r.width, (e.clientY - r.top) * 165 / r.height]; };
    function reveal() {
      if (done) return; done = true; api.revealed = true; cv.style.display = "none"; close.style.visibility = "";
      if (win) { st.className = "xs-st win"; st.textContent = "🎉 Yehey! Nanalo ka ng " + P + "!"; RT.confetti(); }
      else st.textContent = "Aww, bokya! Bawi na lang sa susunod!";
      RT.chime(win);
      if (o.onReveal) o.onReveal();
    }
    function rub(e) {
      if (done) return;
      if (!first) { first = true; close.style.visibility = "hidden"; if (o.onFirst) o.onFirst(); } // hidden while scratching; the card does not move
      const p = pos(e); x.globalCompositeOperation = "destination-out"; x.beginPath(); x.arc(p[0], p[1], 22, 0, Math.PI * 2); x.fill();
      const d = x.getImageData(0, 0, 270, 165).data; let c = 0;
      for (let i = 3; i < d.length; i += 16) if (d[i] === 0) c++;
      if (c / (d.length / 16) * 100 > 42) reveal();
    }
    cv.addEventListener("pointerdown", (e) => { e.preventDefault(); down = true; try { cv.setPointerCapture(e.pointerId); } catch (_) {} rub(e); });
    cv.addEventListener("pointermove", (e) => { if (down) { e.preventDefault(); rub(e); } });
    const up = () => { down = false; };
    cv.addEventListener("pointerup", up); cv.addEventListener("pointercancel", up);
    api.reveal = reveal;
    return api;
  };
  RT.chime = function (win) { // her win and bokya sounds
    try {
      const ac = new (window.AudioContext || window.webkitAudioContext)();
      (win ? [523.25, 659.25, 783.99, 1046.5] : [300, 220]).forEach((f, i) => {
        const os = ac.createOscillator(), gn = ac.createGain(), t = ac.currentTime + i * 0.11;
        os.type = win ? "triangle" : "sawtooth"; os.frequency.setValueAtTime(f, t);
        gn.gain.setValueAtTime(0.14, t); gn.gain.exponentialRampToValueAtTime(0.001, t + 0.32);
        os.connect(gn); gn.connect(ac.destination); os.start(t); os.stop(t + 0.32);
      });
    } catch (_) {}
  };
  RT.confetti = function () { // her confetti
    let c = document.getElementById("xsConf");
    if (!c) { c = document.createElement("canvas"); c.id = "xsConf"; document.body.appendChild(c); }
    const cx = c.getContext("2d"); c.width = window.innerWidth; c.height = window.innerHeight;
    const cols = ["#ff4757", "#ffa502", "#2ed573", "#1e90ff", "#eccc68"];
    const it = Array.from({ length: 85 }, () => ({ x: Math.random() * c.width, y: Math.random() * c.height - c.height, r: Math.random() * 6 + 4, d: Math.random() * 4 + 2, col: cols[Math.floor(Math.random() * 5)], t: Math.random() * 10 }));
    let fr = 0;
    (function step() {
      cx.clearRect(0, 0, c.width, c.height);
      it.forEach((p) => { cx.fillStyle = p.col; cx.fillRect(p.x, p.y, p.r, p.r * 1.5); p.y += p.d; p.x += Math.sin(fr * 0.05 + p.t) * 1.5; });
      fr++;
      if (fr < 150) requestAnimationFrame(step); else cx.clearRect(0, 0, c.width, c.height);
    })();
  };

  /* ---------- storage (may be missing) ---------- */
  RT.get = (k, d) => { try { const v = localStorage.getItem(k); return v ? JSON.parse(v) : d; } catch (_) { return d; } };
  RT.put = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); return true; } catch (_) { return false; } };

  window.RT = RT;
})();
