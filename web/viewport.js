// Coordinate-only equivalents of Apeiron's Hilbert kernels. Numerical analysis
// remains in WASM; pointer hit testing must not wait for a worker round trip.
export function d2xy(side, d) {
  let x = 0, y = 0;
  for (let s = 1, t = d; s < side; s *= 2, t = Math.floor(t / 4)) {
    const rx = Math.floor(t / 2) & 1, ry = (t ^ rx) & 1;
    if (!ry) { if (rx) { x = s - 1 - x; y = s - 1 - y; } [x, y] = [y, x]; }
    x += s * rx; y += s * ry;
  }
  return { x, y };
}
export function xy2d(side, x, y) {
  let d = 0;
  for (let s = side / 2; s >= 1; s /= 2) {
    const rx = (x & s) ? 1 : 0, ry = (y & s) ? 1 : 0;
    d += s * s * ((3 * rx) ^ ry);
    if (!ry) { if (rx) { x = s - 1 - x; y = s - 1 - y; } [x, y] = [y, x]; }
  }
  return d;
}
export const worldSide = size => Math.max(2, 2 ** Math.ceil(Math.log2(Math.sqrt(Math.max(1, size)))));
export const baseScale = side => Math.max(1, side / 256);
export function bytePosition(size, offset, curve) {
  const side = worldSide(size);
  const p = curve === 'linear' ? { x: offset % side, y: Math.floor(offset / side) } : d2xy(side, offset);
  return { x: (p.x + .5) / side, y: (p.y + .5) / side };
}
export class Viewport {
  constructor(view = {}) { this.x = view.x || 0; this.y = view.y || 0; this.zoom = view.zoom || 1; }
  snapshot() { return { x: this.x, y: this.y, zoom: this.zoom }; }
  clamp() { const end = 1 - 1 / this.zoom; this.x = Math.max(0, Math.min(end, this.x)); this.y = Math.max(0, Math.min(end, this.y)); }
  zoomAt(factor, ax, ay, maxZoom) {
    const wx = this.x + ax / this.zoom, wy = this.y + ay / this.zoom;
    this.zoom = Math.max(1, Math.min(maxZoom, this.zoom * factor));
    this.x = wx - ax / this.zoom; this.y = wy - ay / this.zoom; this.clamp();
  }
  pan(dx, dy) { this.x -= dx / this.zoom; this.y -= dy / this.zoom; this.clamp(); }
  center(x, y) { this.x = x - .5 / this.zoom; this.y = y - .5 / this.zoom; this.clamp(); }
}
