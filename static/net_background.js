/* Site-wide background: a secure data network.
   Circuit-like traces on a fine grid carry data packets between nodes; a scan
   beam sweeps the page and lights up what it passes; now and then a red
   packet is stopped at a checkpoint node. Decorative only (aria-hidden), drawn
   on one fixed canvas behind the page. It pauses in hidden tabs and is static
   for people who prefer reduced motion. */
(function () {
  'use strict';
  const canvas = document.getElementById('net-bg');
  if (!canvas || !canvas.getContext) return;
  const ctx = canvas.getContext('2d');
  const still = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const CELL = 44;
  const CYAN = '119,220,255', TEAL = '94,234,212', RED = '251,113,133', AMBER = '251,191,36';
  const HEX = ['0x7F3A', 'SHA-256', 'TLS 1.3', 'AES-GCM', '0xC0DE', 'DNSSEC', 'X.509', '0x1E9B', 'HMAC', 'SPF ✓', 'DMARC', '443/tcp'];
  let width = 0, height = 0, cols = 0, rows = 0, ratio = 1;
  let nodes = [], routes = [], packets = [], labels = [], bursts = [], frame = 0, last = 0, scanStart = 0;

  const rand = (a, b) => a + Math.random() * (b - a);
  const pick = list => list[Math.floor(Math.random() * list.length)];

  function route() {
    // An orthogonal trace: alternating horizontal and vertical runs, like a circuit board.
    let x = Math.floor(rand(0, cols + 1)), y = Math.floor(rand(0, rows + 1));
    const points = [[x * CELL, y * CELL]];
    let horizontal = Math.random() < 0.5;
    const turns = 2 + Math.floor(rand(0, 4));
    for (let i = 0; i < turns; i++) {
      const step = (Math.random() < 0.5 ? -1 : 1) * (2 + Math.floor(rand(0, 6)));
      if (horizontal) x = Math.max(0, Math.min(cols, x + step)); else y = Math.max(0, Math.min(rows, y + step));
      const [px, py] = points[points.length - 1];
      if (px !== x * CELL || py !== y * CELL) points.push([x * CELL, y * CELL]);
      horizontal = !horizontal;
    }
    const lengths = [0];
    for (let i = 1; i < points.length; i++) {
      lengths.push(lengths[i - 1] + Math.abs(points[i][0] - points[i - 1][0]) + Math.abs(points[i][1] - points[i - 1][1]));
    }
    return { points, lengths, total: lengths[lengths.length - 1] };
  }

  function at(r, d) {
    d = Math.max(0, Math.min(r.total, d));
    let i = 1;
    while (i < r.lengths.length - 1 && r.lengths[i] < d) i++;
    const [ax, ay] = r.points[i - 1], [bx, by] = r.points[i];
    const span = r.lengths[i] - r.lengths[i - 1] || 1, f = (d - r.lengths[i - 1]) / span;
    return [ax + (bx - ax) * f, ay + (by - ay) * f];
  }

  function packet(r, delay) {
    const threat = Math.random() < 0.12;
    return { route: r, d: -delay, speed: rand(70, 150), threat, color: threat ? RED : Math.random() < 0.3 ? TEAL : CYAN };
  }

  function build() {
    ratio = Math.min(window.devicePixelRatio || 1, 1.5);
    width = window.innerWidth; height = window.innerHeight;
    canvas.width = Math.round(width * ratio); canvas.height = Math.round(height * ratio);
    canvas.style.width = width + 'px'; canvas.style.height = height + 'px';
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    cols = Math.ceil(width / CELL); rows = Math.ceil(height / CELL);
    const area = (width * height) / (1440 * 900);
    routes = Array.from({ length: Math.round(Math.max(12, Math.min(32, 26 * area))) }, route).filter(r => r.total > CELL * 2);
    nodes = [];
    routes.forEach(r => { nodes.push({ x: r.points[0][0], y: r.points[0][1], glow: 0 }); nodes.push({ x: r.points[r.points.length - 1][0], y: r.points[r.points.length - 1][1], glow: 0, end: r }); });
    packets = routes.flatMap(r => [packet(r, rand(0, r.total)), packet(r, rand(r.total, r.total * 2.5))]);
    labels = Array.from({ length: Math.round(Math.max(4, Math.min(10, 8 * area))) }, () => ({ node: pick(nodes), text: pick(HEX), life: rand(0, 1), speed: rand(0.04, 0.09) }));
    bursts = [];
  }

  function drawGrid(scanY) {
    // The whole grid in one path; only the few rows near the scan beam are drawn brighter.
    ctx.lineWidth = 1;
    ctx.strokeStyle = `rgba(${CYAN},0.045)`;
    ctx.beginPath();
    for (let i = 0; i <= rows; i++) { const y = i * CELL + 0.5; ctx.moveTo(0, y); ctx.lineTo(width, y); }
    for (let j = 0; j <= cols; j++) { const x = j * CELL + 0.5; ctx.moveTo(x, 0); ctx.lineTo(x, height); }
    ctx.stroke();
    if (scanY === null) return;
    for (let i = Math.max(0, Math.floor((scanY - 120) / CELL)); i <= Math.min(rows, Math.ceil((scanY + 120) / CELL)); i++) {
      const y = i * CELL + 0.5, near = Math.max(0, 1 - Math.abs(y - scanY) / 120);
      ctx.strokeStyle = `rgba(${CYAN},${near * 0.16})`;
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(width, y); ctx.stroke();
    }
    // Brighter vertical ticks inside the beam: the grid "lit up" by the scan.
    ctx.strokeStyle = `rgba(${CYAN},0.10)`;
    ctx.beginPath();
    for (let j = 0; j <= cols; j++) { const x = j * CELL + 0.5; ctx.moveTo(x, scanY - 60); ctx.lineTo(x, scanY + 60); }
    ctx.stroke();
  }

  function drawTraces(scanY) {
    ctx.lineWidth = 1.2;
    ctx.strokeStyle = `rgba(${CYAN},0.11)`;
    ctx.beginPath();
    routes.forEach(r => r.points.forEach(([x, y], i) => (i ? ctx.lineTo(x + 0.5, y + 0.5) : ctx.moveTo(x + 0.5, y + 0.5))));
    ctx.stroke();
    nodes.forEach(n => {
      const near = scanY === null ? 0 : Math.max(0, 1 - Math.abs(n.y - scanY) / 90);
      const glow = Math.max(n.glow, near);
      ctx.fillStyle = `rgba(${CYAN},${0.22 + glow * 0.6})`;
      ctx.fillRect(n.x - 1.5, n.y - 1.5, 3, 3);
      if (glow > 0.05) {
        ctx.strokeStyle = `rgba(${CYAN},${glow * 0.45})`;
        ctx.strokeRect(n.x - 4.5, n.y - 4.5, 9, 9);
      }
      n.glow *= 0.94;
    });
  }

  function drawPackets(dt) {
    packets.forEach((p, index) => {
      p.d += p.speed * dt;
      const r = p.route;
      if (p.d > r.total) {
        const [ex, ey] = r.points[r.points.length - 1];
        const node = nodes.find(n => n.end === r);
        if (node) node.glow = 1;
        // A threat is stopped at the checkpoint: the node flashes and a ring bursts.
        bursts.push({ x: ex, y: ey, age: 0, color: p.threat ? RED : CYAN, big: p.threat });
        packets[index] = packet(r, rand(CELL, r.total));
        return;
      }
      if (p.d < 0) return;
      const tail = p.threat ? 46 : 70;
      const steps = 6;
      for (let s = 0; s < steps; s++) {
        const a = at(r, p.d - (tail * s) / steps), b = at(r, p.d - (tail * (s + 1)) / steps);
        ctx.strokeStyle = `rgba(${p.color},${0.55 * (1 - s / steps)})`;
        ctx.lineWidth = 1.6;
        ctx.beginPath(); ctx.moveTo(a[0] + 0.5, a[1] + 0.5); ctx.lineTo(b[0] + 0.5, b[1] + 0.5); ctx.stroke();
      }
      const [x, y] = at(r, p.d);
      const halo = ctx.createRadialGradient(x, y, 0, x, y, 9);
      halo.addColorStop(0, `rgba(${p.color},0.55)`); halo.addColorStop(1, `rgba(${p.color},0)`);
      ctx.fillStyle = halo; ctx.fillRect(x - 9, y - 9, 18, 18);
      ctx.fillStyle = `rgba(${p.color},0.95)`;
      ctx.fillRect(x - 1.5, y - 1.5, 3, 3);
    });
  }

  function drawBursts(dt) {
    bursts = bursts.filter(b => (b.age += dt) < 1.1);
    bursts.forEach(b => {
      const k = b.age / 1.1, radius = (b.big ? 26 : 14) * k + 3;
      ctx.strokeStyle = `rgba(${b.color},${(b.big ? 0.75 : 0.4) * (1 - k)})`;
      ctx.lineWidth = b.big ? 1.6 : 1;
      if (b.big) {
        ctx.strokeRect(b.x - radius, b.y - radius, radius * 2, radius * 2);  // a square "blocked" frame
        ctx.strokeStyle = `rgba(${AMBER},${0.5 * (1 - k)})`;
        ctx.beginPath(); ctx.moveTo(b.x - 5, b.y - 5); ctx.lineTo(b.x + 5, b.y + 5); ctx.moveTo(b.x + 5, b.y - 5); ctx.lineTo(b.x - 5, b.y + 5); ctx.stroke();
      } else {
        ctx.beginPath(); ctx.arc(b.x, b.y, radius, 0, Math.PI * 2); ctx.stroke();
      }
    });
  }

  function drawLabels(dt) {
    ctx.font = '10px "Space Mono", monospace';
    labels.forEach(l => {
      l.life += l.speed * dt;
      if (l.life > 1) { l.life = 0; l.node = pick(nodes); l.text = pick(HEX); }
      const alpha = Math.sin(Math.PI * l.life) * 0.22;
      ctx.fillStyle = `rgba(${CYAN},${alpha})`;
      ctx.fillText(l.text, l.node.x + 8, l.node.y - 7);
    });
  }

  function drawScan(scanY) {
    if (scanY === null) return;
    const band = ctx.createLinearGradient(0, scanY - 110, 0, scanY + 6);
    band.addColorStop(0, `rgba(${CYAN},0)`); band.addColorStop(0.8, `rgba(${CYAN},0.06)`); band.addColorStop(1, `rgba(${CYAN},0.16)`);
    ctx.fillStyle = band; ctx.fillRect(0, scanY - 110, width, 116);
    ctx.fillStyle = `rgba(${CYAN},0.4)`; ctx.fillRect(0, scanY + 5, width, 1);
  }

  function scanPosition(time) {
    // Sweep down over 6 s, rest 5 s.
    const cycle = ((time - scanStart) / 1000) % 11;
    return cycle < 6 ? -120 + (height + 240) * (cycle / 6) : null;
  }

  function draw(time) {
    const dt = last ? Math.min(0.05, (time - last) / 1000) : 0.016;
    last = time;
    ctx.clearRect(0, 0, width, height);
    const scanY = still ? null : scanPosition(time);
    drawGrid(scanY);
    drawTraces(scanY);
    if (!still) { drawScan(scanY); drawPackets(dt); drawBursts(dt); drawLabels(dt); }
    if (!still) frame = requestAnimationFrame(draw);
  }

  function start() { cancelAnimationFrame(frame); last = 0; frame = requestAnimationFrame(draw); }

  build();
  if (still) { draw(0); } else { scanStart = performance.now() - 4000; start(); }
  let resizeTimer = 0;
  window.addEventListener('resize', () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => { build(); if (still) draw(0); }, 150);
  });
  document.addEventListener('visibilitychange', () => {
    if (still) return;
    if (document.hidden) cancelAnimationFrame(frame); else start();
  });
})();
