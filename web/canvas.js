export const THRESHOLD = 7.2;
const colors = { void: [8, 7, 6], ink: [36, 31, 27], paper: [216, 206, 195], dark: [217, 43, 113], pink: [255, 61, 139], light: [255, 106, 165] };
const blend = (a, b, t) => a.map((c, i) => c + (b[i] - c) * t);
export const CLASS_COLORS = [colors.void, [107, 96, 88], colors.paper, colors.pink, [255, 255, 255]];
export const PALETTE = new Uint8ClampedArray(801 * 3);
for (let i = 0; i <= 800; i++) {
  const h = i / 100;
  const rgb = h < 0.06 ? colors.void : h < THRESHOLD ? blend(colors.ink, colors.paper, (h / THRESHOLD) ** 1.8)
    : h < (8 + THRESHOLD) / 2 ? blend(colors.dark, colors.pink, (h - THRESHOLD) / (8 - THRESHOLD) * 2)
    : blend(colors.pink, colors.light, (h - THRESHOLD) / (8 - THRESHOLD) * 2 - 1);
  PALETTE.set(rgb, i * 3);
}
const paletteIndex = h => Math.round(Math.max(0, Math.min(8, h)) * 100) * 3;
export function drawMap(canvas, map, curve, mode, indices) {
  const width = map.width || map.side, height = map.height || map.side;
  if (canvas.width !== width || canvas.height !== height) { canvas.width = width; canvas.height = height; }
  const ctx = canvas.getContext('2d');
  const img = ctx.createImageData(width, height);
  for (let d = 0; d < map.done; d++) {
    if (map.cells[d * 6] < 0) continue;
    const p = (map.spatial || curve === 'linear' ? d : indices[d]) * 4;
    if (mode === 'bytes') {
      for (let channel = 0; channel < 3; channel++) {
        let value = 0;
        for (let q = 0; q < 5; q++) value += map.cells[d * 6 + 1 + q] * CLASS_COLORS[q][channel];
        img.data[p + channel] = value;
      }
    } else {
      const k = paletteIndex(map.cells[d * 6]);
      img.data[p] = PALETTE[k]; img.data[p + 1] = PALETTE[k + 1]; img.data[p + 2] = PALETTE[k + 2];
    }
    img.data[p + 3] = 255;
  }
  ctx.putImageData(img, 0, 0);
}
export function drawProfile(canvas, profile, vertical = false) {
  if (!profile?.length) { canvas.getContext('2d').clearRect(0, 0, canvas.width, canvas.height); return; }
  canvas.width = vertical ? 1 : profile.length;
  canvas.height = vertical ? profile.length : 1;
  const ctx = canvas.getContext('2d'), img = ctx.createImageData(canvas.width, canvas.height);
  for (let i = 0; i < profile.length; i++) {
    const k = paletteIndex(profile[i]);
    img.data.set([PALETTE[k], PALETTE[k + 1], PALETTE[k + 2], 255], i * 4);
  }
  ctx.putImageData(img, 0, 0);
}
export function drawLegend(canvas) {
  drawProfile(canvas, Float32Array.from({ length: 161 }, (_, i) => i / 20));
}
export function drawHistogram(canvas, histogram, value) {
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, 256, 48);
  const max = Math.max(1, ...histogram);
  for (let i = 0; i < 256; i++) {
    if (!histogram[i]) continue;
    const height = Math.max(1, Math.round(Math.sqrt(histogram[i] / max) * 46));
    ctx.fillStyle = i === value ? '#ff3d8b' : '#8c8177';
    ctx.fillRect(i, 48 - height, 1, height);
  }
}
export function entropyClass(h) {
  return h < 0.5 ? 'zero fill / low diversity' : h < 3 ? 'sparse / structured' : h < 5 ? 'moderate byte diversity'
    : h < THRESHOLD ? 'mixed byte distribution' : 'high byte diversity';
}
export function complexityClass(ratio) {
  return ratio < .3 ? 'highly compressible' : ratio < .65 ? 'structured' : ratio < .92 ? 'dense' : 'incompressible at this window';
}
