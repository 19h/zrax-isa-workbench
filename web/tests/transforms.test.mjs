import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, baseUrl } from './helpers.mjs';
before(setup); after(teardown);

const fixture = name => readFile(new URL(`../../tests/fixtures/transforms/${name}`, import.meta.url));

// Swap the two bytes of every 16-bit word, as a byte-swapping programmer does.
function swap16(bytes) {
  const out = Buffer.from(bytes);
  for (let i = 0; i + 1 < out.length; i += 2) [out[i], out[i + 1]] = [out[i + 1], out[i]];
  return out;
}

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`byte-swapped raw code is recovered and the transform is recorded through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const bytes = [...swap16(await fixture('aarch64.text.bin'))];
    const p = await page.evaluate(async ({ module, bytes }) => {
      const wasm = await import(module);
      await wasm.default();
      return JSON.parse(wasm.classify(new Uint8Array(bytes)));
    }, { module, bytes });
    assert.ok(!p.error, p.error);
    assert.equal(p.primary.isa, 'a_arch64');
    const applied = p.metadata.find(m => m.key?.custom === 'transform_applied');
    assert.equal(applied?.value, '16-bit byte swap');
  });
}
