/*
 * PCAP Autopsy – minimal canvas charts (no library): axes, step lines, dots, Stevens I-beams,
 * markers, hover read-out, drag-to-zoom on the time axis (double-click resets).
 */
(function (G) {
  'use strict';
  const PA = G.PA || (G.PA = {});

  function css(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || '#888'; }
  function nice(min, max, n) {
    const span = max - min || 1;
    const raw = span / n;
    const mag = Math.pow(10, Math.floor(Math.log10(raw)));
    const f = raw / mag;
    const step = (f < 1.5 ? 1 : f < 3 ? 2 : f < 7 ? 5 : 10) * mag;
    const out = [];
    for (let v = Math.ceil(min / step) * step; v <= max + step * 1e-9; v += step) out.push(Math.abs(v) < step * 1e-9 ? 0 : v);
    return out;
  }

  function create(canvas, spec, onPick) {
    const st = { spec, view: null, picks: [], drag: null, hover: null };
    const tip = document.createElement('div');
    tip.className = 'tip'; tip.hidden = true;
    canvas.parentNode.appendChild(tip);

    function range() {
      const s = st.spec;
      const x0 = st.view ? st.view[0] : s.x.min, x1 = st.view ? st.view[1] : s.x.max;
      let y0 = s.y.min, y1 = s.y.max;
      if (st.view && s.y.auto) {
        // rescale y to what is visible
        let lo = Infinity, hi = -Infinity;
        for (const L of s.layers) {
          const d = L.data, k = L.stride;
          for (let i = 0; i < d.length; i += k) {
            const x = d[i]; if (x < x0 || x > x1) continue;
            const a = d[i + 1], b = L.kind === 'ibeam' ? d[i + 2] : a;
            if (a < lo) lo = a; if (b > hi) hi = b;
          }
        }
        if (lo < hi) { const pad = (hi - lo) * 0.06; y0 = Math.max(s.y.min, lo - pad); y1 = hi + pad; }
      }
      return { x0, x1: x1 > x0 ? x1 : x0 + 1e-3, y0, y1: y1 > y0 ? y1 : y0 + 1 };
    }

    function draw() {
      const s = st.spec;
      const dpr = window.devicePixelRatio || 1;
      const W = canvas.clientWidth, H = canvas.clientHeight;
      if (!W || !H) return;
      canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr);
      const c = canvas.getContext('2d');
      c.setTransform(dpr, 0, 0, dpr, 0, 0);
      c.clearRect(0, 0, W, H);
      const ml = 58, mr = 12, mt = 10, mb = 26;
      const pw = W - ml - mr, ph = H - mt - mb;
      const R = range();
      const X = (v) => ml + (v - R.x0) / (R.x1 - R.x0) * pw;
      const Y = (v) => mt + ph - (v - R.y0) / (R.y1 - R.y0) * ph;
      st.X = X; st.Y = Y; st.box = { ml, mt, pw, ph }; st.R = R;
      const grid = css('--grid'), mut = css('--mut');
      c.font = '11px ' + css('--mono');
      c.fillStyle = mut; c.strokeStyle = grid; c.lineWidth = 1;
      c.textAlign = 'right'; c.textBaseline = 'middle';
      for (const v of nice(R.y0, R.y1, 5)) {
        const y = Math.round(Y(v)) + 0.5;
        c.beginPath(); c.moveTo(ml, y); c.lineTo(ml + pw, y); c.stroke();
        c.fillText(s.y.fmt(v), ml - 6, y);
      }
      c.textAlign = 'center'; c.textBaseline = 'top';
      for (const v of nice(R.x0, R.x1, Math.max(3, Math.floor(pw / 90)))) {
        const x = Math.round(X(v)) + 0.5;
        c.beginPath(); c.moveTo(x, mt); c.lineTo(x, mt + ph); c.stroke();
        c.fillText(s.x.fmt(v), x, mt + ph + 6);
      }
      c.save();
      c.beginPath(); c.rect(ml, mt, pw, ph); c.clip();
      // markers (vertical)
      for (const m of s.markers || []) {
        if (m.x < R.x0 || m.x > R.x1) continue;
        const x = Math.round(X(m.x)) + 0.5;
        c.strokeStyle = m.color; c.globalAlpha = 0.45; c.setLineDash([3, 3]);
        c.beginPath(); c.moveTo(x, mt); c.lineTo(x, mt + ph); c.stroke();
        c.setLineDash([]); c.globalAlpha = 1;
      }
      st.picks = [];
      for (const L of s.layers) {
        const d = L.data, k = L.stride;
        c.strokeStyle = L.color; c.fillStyle = L.color; c.lineWidth = L.width || 1.4;
        c.setLineDash(L.dash || []);
        if (L.kind === 'step' || L.kind === 'line') {
          c.beginPath();
          let started = false, py = 0;
          for (let i = 0; i < d.length; i += k) {
            const x = X(d[i]), y = Y(d[i + 1]);
            if (!started) { c.moveTo(x, y); started = true; }
            else if (L.kind === 'step') { c.lineTo(x, py); c.lineTo(x, y); } else c.lineTo(x, y);
            py = y;
            if (L.pick && d[i] >= R.x0 && d[i] <= R.x1 && st.picks.length < 80000) st.picks.push([x, y, L.pick(d, i)]);
          }
          if (L.fill) { c.stroke(); c.lineTo(X(d[d.length - k] || 0), Y(R.y0)); c.lineTo(X(d[0] || 0), Y(R.y0)); c.closePath(); c.globalAlpha = 0.16; c.fill(); c.globalAlpha = 1; }
          else c.stroke();
        } else if (L.kind === 'dots') {
          const r = L.r || 2;
          for (let i = 0; i < d.length; i += k) {
            if (d[i] < R.x0 || d[i] > R.x1) continue;
            const x = X(d[i]), y = Y(d[i + 1]);
            c.fillStyle = L.colorOf ? L.colorOf(d, i) : L.color;
            c.beginPath(); c.arc(x, y, r, 0, 6.283); c.fill();
            if (L.pick && st.picks.length < 80000) st.picks.push([x, y, L.pick(d, i)]);
          }
        } else if (L.kind === 'ibeam') {
          for (let i = 0; i < d.length; i += k) {
            if (d[i] < R.x0 || d[i] > R.x1) continue;
            const x = X(d[i]), y0 = Y(d[i + 1]), y1 = Y(d[i + 2]);
            const col = L.colorOf ? L.colorOf(d, i) : L.color;
            c.strokeStyle = col;
            c.beginPath(); c.moveTo(x, y0); c.lineTo(x, Math.min(y1, y0 - 1.5)); c.stroke();
            if (L.special && L.special(d, i)) { c.lineWidth = 2; c.beginPath(); c.moveTo(x - 3.5, y1 - 3.5); c.lineTo(x + 3.5, y1 + 3.5); c.moveTo(x + 3.5, y1 - 3.5); c.lineTo(x - 3.5, y1 + 3.5); c.stroke(); c.lineWidth = L.width || 1.4; }
            if (L.pick && st.picks.length < 80000) st.picks.push([x, y1, L.pick(d, i)]);
          }
        }
        c.setLineDash([]);
      }
      // drag selection
      if (st.drag && st.drag.x1 !== undefined) {
        c.fillStyle = css('--accent'); c.globalAlpha = 0.12;
        c.fillRect(Math.min(st.drag.x0, st.drag.x1), mt, Math.abs(st.drag.x1 - st.drag.x0), ph); c.globalAlpha = 1;
      }
      if (st.hover) { c.strokeStyle = css('--fg'); c.lineWidth = 1.5; c.beginPath(); c.arc(st.hover[0], st.hover[1], 5, 0, 6.283); c.stroke(); }
      c.restore();
      if (s.y.label) { c.save(); c.fillStyle = mut; c.translate(11, mt + ph / 2); c.rotate(-Math.PI / 2); c.textAlign = 'center'; c.textBaseline = 'middle'; c.fillText(s.y.label, 0, 0); c.restore(); }
    }
    function nearest(px, py) {
      let best = null, bd = 18 * 18;
      for (const p of st.picks) { const dx = p[0] - px, dy = p[1] - py; const d = dx * dx + dy * dy; if (d < bd) { bd = d; best = p; } }
      return best;
    }
    const pos = (e) => { const r = canvas.getBoundingClientRect(); return [e.clientX - r.left, e.clientY - r.top]; };
    canvas.addEventListener('mousemove', (e) => {
      const [x, y] = pos(e);
      if (st.drag) { st.drag.x1 = x; draw(); return; }
      const p = nearest(x, y);
      st.hover = p;
      if (p) { tip.hidden = false; tip.textContent = p[2].label; const left = Math.min(x + 14, canvas.clientWidth - tip.offsetWidth - 4); tip.style.left = (left + canvas.offsetLeft) + 'px'; tip.style.top = (y + canvas.offsetTop - 34) + 'px'; }
      else tip.hidden = true;
      draw();
    });
    canvas.addEventListener('mouseleave', () => { st.hover = null; tip.hidden = true; if (!st.drag) draw(); });
    canvas.addEventListener('mousedown', (e) => { const [x] = pos(e); st.drag = { x0: x }; });
    window.addEventListener('mouseup', (e) => {
      if (!st.drag) return;
      const d = st.drag; st.drag = null;
      if (d.x1 !== undefined && Math.abs(d.x1 - d.x0) > 8 && st.R) {
        const inv = (px) => st.R.x0 + (px - st.box.ml) / st.box.pw * (st.R.x1 - st.R.x0);
        const a = inv(Math.min(d.x0, d.x1)), b = inv(Math.max(d.x0, d.x1));
        st.view = [Math.max(st.spec.x.min, a), Math.min(st.spec.x.max, b)];
        if (spec.onZoom) spec.onZoom(st.view);
      } else if (e.target === canvas && st.hover && onPick) onPick(st.hover[2]);
      draw();
    });
    canvas.addEventListener('dblclick', () => { st.view = null; if (spec.onZoom) spec.onZoom(null); draw(); });
    const ro = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(() => draw()) : null;
    if (ro) ro.observe(canvas);
    draw();
    return {
      redraw: draw,
      setView(v) { st.view = v; draw(); },
      destroy() { if (ro) ro.disconnect(); tip.remove(); },
      toDataURL() { return canvas.toDataURL('image/png'); },
    };
  }

  PA.charts = { create, nice };
})(typeof globalThis !== 'undefined' ? globalThis : self);
