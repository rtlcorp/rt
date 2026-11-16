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
  RT.copyJpeg = async function (o) { // o: {co, tagline, title, lines, holder, viewer, role, status, sigs:[{name, role, at, path}], code, id}
    const W = 1080, P = 72, c = document.createElement("canvas"), x = c.getContext("2d");
    const lineH = 40, wrapW = W - 2 * P;
    x.font = "34px Arial";
    function wrap(t, font) { x.font = font; const words = String(t).split(" "), out = []; let l = ""; words.forEach((w) => { const tt = l ? l + " " + w : w; if (x.measureText(tt).width > wrapW && l) { out.push(l); l = w; } else l = tt; }); if (l) out.push(l); return out; }
    const body = []; o.lines.forEach((t) => { wrap(t, "32px Arial").forEach((l, i) => body.push({ t: l, gap: i === 0 })); });
    const H = 520 + body.length * lineH + o.sigs.length * 250 + 220;
    c.width = W; c.height = H; x.fillStyle = "#FFFDF8"; x.fillRect(0, 0, W, H);
    x.fillStyle = "#0B2550"; x.fillRect(0, 0, W, 210);
    x.fillStyle = "#D9B26A"; x.font = "bold 30px Arial"; x.fillText(o.co, P, 78);
    x.fillStyle = "#FFFFFF"; x.font = "bold 50px Georgia"; x.fillText("PAGKILALA", P, 142);
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

  /* ---------- storage (may be missing) ---------- */
  RT.get = (k, d) => { try { const v = localStorage.getItem(k); return v ? JSON.parse(v) : d; } catch (_) { return d; } };
  RT.put = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); return true; } catch (_) { return false; } };

  window.RT = RT;
})();
