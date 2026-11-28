/* Site-wide background: a secure network.
   A fine grid with circuit traces covers the page and its nodes glow softly one
   after another. Nothing travels along the traces: only the glow moves.
   Decorative only (aria-hidden), drawn on one fixed
   canvas behind the page. It pauses in hidden tabs and is static for people
   who prefer reduced motion. */
(function () {
  'use strict';
  const canvas = document.getElementById('net-bg');
  if (!canvas || !canvas.getContext) return;
  const ctx = canvas.getContext('2d');
  const still = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const CELL = 44, GLINT = 8, SHINE = 1.8;
  const CYAN = '119,220,255';
  let width = 0, height = 0, cols = 0, rows = 0, ratio = 1;
  let layer = null, layerUrl = '', routes = [], glints = [], frame = 0, last = 0, clock = 0;

  const rand = (a, b) => a + Math.random() * (b - a);

  function route() {
    // An orthogonal trace: alternating horizontal and vertical runs, like a circuit board.
    let x = Math.floor(rand(0, cols + 1)), y = Math.floor(rand(0, rows + 1));
    const points = [[x * CELL, y * CELL]];
    let horizontal = Math.random() < 0.6;
    const turns = 2 + Math.floor(rand(0, 3));
    for (let i = 0; i < turns; i++) {
      const step = (Math.random() < 0.5 ? -1 : 1) * (2 + Math.floor(rand(0, 5)));
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

  function drawStatic() {
    // Dots, traces and nodes never change, so they are drawn once to an offscreen layer.
    layer = document.createElement('canvas');
    layer.width = canvas.width; layer.height = canvas.height;
    const c = layer.getContext('2d');
    c.setTransform(ratio, 0, 0, ratio, 0, 0);
    c.lineWidth = 1;
    c.strokeStyle = `rgba(${CYAN},0.05)`;
    c.beginPath();
    for (let i = 0; i <= rows; i++) { const y = i * CELL + 0.5; c.moveTo(0, y); c.lineTo(width, y); }
    for (let j = 0; j <= cols; j++) { const x = j * CELL + 0.5; c.moveTo(x, 0); c.lineTo(x, height); }
    c.stroke();
    c.strokeStyle = `rgba(${CYAN},0.12)`;
    c.beginPath();
    routes.forEach(r => r.points.forEach(([x, y], i) => (i ? c.lineTo(x + 0.5, y + 0.5) : c.moveTo(x + 0.5, y + 0.5))));
    c.stroke();
    c.fillStyle = `rgba(${CYAN},0.45)`;
    routes.forEach(r => {
      const [sx, sy] = r.points[0], [ex, ey] = r.points[r.points.length - 1];
      c.fillRect(sx - 1.2, sy - 1.2, 2.4, 2.4);
      c.fillRect(ex - 1.8, ey - 1.8, 3.6, 3.6);
    });
  }

  function build() {
    ratio = Math.min(window.devicePixelRatio || 1, 1.5);
    width = window.innerWidth; height = window.innerHeight;
    canvas.width = Math.round(width * ratio); canvas.height = Math.round(height * ratio);
    canvas.style.width = width + 'px'; canvas.style.height = height + 'px';
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    cols = Math.ceil(width / CELL); rows = Math.ceil(height / CELL);
    const area = (width * height) / (1440 * 900);
    routes = Array.from({ length: Math.round(Math.max(8, Math.min(20, 16 * area))) }, route).filter(r => r.total > CELL * 3);
    // Both ends of every trace glint now and then, each at its own moment.
    glints = routes.flatMap(r => [r.points[0], r.points[r.points.length - 1]]).map(([x, y], i) => ({ x, y, offset: ((i * 0.618) % 1) * GLINT }));
    drawStatic();
    useLayerAsBackground();
  }

  function drawGlints() {
    // A node catches the light: a soft halo swells and fades around it.
    glints.forEach(g => {
      const k = ((clock + g.offset) % GLINT) / SHINE;
      if (k >= 1) return;
      const v = Math.sin(Math.PI * k);
      ctx.fillStyle = `rgba(${CYAN},${0.12 * v})`;
      ctx.beginPath(); ctx.arc(g.x + 0.5, g.y + 0.5, 3 + 5 * v, 0, Math.PI * 2); ctx.fill();
      ctx.fillStyle = `rgba(201,243,255,${0.85 * v})`;
      ctx.fillRect(g.x - 1.3, g.y - 1.3, 2.6, 2.6);
    });
  }

  function useLayerAsBackground() {
    // The still network becomes the canvas's CSS background, so frames only draw what moves.
    if (still || !layer.toBlob || !window.URL) return;
    const built = layer;
    built.toBlob(blob => {
      if (!blob || built !== layer) return;
      if (layerUrl) URL.revokeObjectURL(layerUrl);
      layerUrl = URL.createObjectURL(blob);
      canvas.style.background = `url(${layerUrl}) 0 0 / ${width}px ${height}px no-repeat`;
      layer = null;
    });
  }

  function draw(time) {
    if (frame && time - last < 30 && !still) { frame = requestAnimationFrame(draw); return; }  // ~30 fps is plenty for slow motion
    const dt = last ? Math.min(0.08, (time - last) / 1000) : 0.016;
    last = time;
    clock += dt;
    ctx.clearRect(0, 0, width, height);
    if (layer) { ctx.save(); ctx.setTransform(1, 0, 0, 1, 0, 0); ctx.drawImage(layer, 0, 0); ctx.restore(); }
    if (still) return;
    drawGlints();
    frame = requestAnimationFrame(draw);
  }

  function start() { cancelAnimationFrame(frame); last = 0; frame = requestAnimationFrame(draw); }

  build();
  if (still) draw(0); else { clock = 4; start(); }
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
