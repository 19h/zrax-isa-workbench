import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Viewport, d2xy, xy2d, worldSide } from '../viewport.js';

test('fixed Hilbert coordinates round trip and coarse blocks preserve their positions', () => {
  for (const side of [2, 4, 16, 256, 32768]) {
    for (let i = 0; i < Math.min(side * side, 2000); i++) {
      const d = side <= 16 ? i : (i * 524287) % (side * side), p = d2xy(side, d);
      assert.equal(xy2d(side, p.x, p.y), d);
    }
  }
  for (let d = 0; d < 256; d++) {
    const coarse = d2xy(16, d), fine = d2xy(256, d * 256);
    assert.deepEqual({ x: Math.floor(fine.x / 16), y: Math.floor(fine.y / 16) }, coarse);
  }
  assert.equal(worldSide(1024 ** 3), 32768);
});

test('continuous zoom keeps the point under the pointer stationary', () => {
  const camera = new Viewport(), ax = .271, ay = .637;
  const point = { x: ax, y: ay };
  for (let i = 0; i < 80; i++) {
    camera.zoomAt(Math.exp(.02), ax, ay, 2048);
    assert.ok(Math.abs((point.x - camera.x) * camera.zoom - ax) < 1e-12);
    assert.ok(Math.abs((point.y - camera.y) * camera.zoom - ay) < 1e-12);
  }
  assert.ok(camera.zoom > 4 && camera.zoom < 5);
  for (let i = 0; i < 80; i++) camera.zoomAt(Math.exp(-.02), ax, ay, 2048);
  assert.ok(Math.abs(camera.zoom - 1) < 1e-12);
  assert.ok(camera.x < 1e-12 && camera.y < 1e-12);
});

test('pan, bounds, fit and history snapshots are independent of map resolution', () => {
  const camera = new Viewport({ zoom: 4, x: .3, y: .4 }), before = camera.snapshot();
  camera.pan(.1, -.2); assert.ok(Math.abs(camera.x - .275) < 1e-12); assert.ok(Math.abs(camera.y - .45) < 1e-12);
  camera.pan(100, -100); assert.equal(camera.x, 0); assert.equal(camera.y, .75);
  assert.deepEqual(new Viewport(before).snapshot(), before);
  camera.zoomAt(.0001, .5, .5, 8); assert.deepEqual(camera.snapshot(), { x: 0, y: 0, zoom: 1 });
});
