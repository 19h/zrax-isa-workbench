import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup); after(teardown);

// NSF: magic, version 1, 3 songs from song 1, load/init 0x8000, play 0x8005,
// then a short 6502 driver at 0x80.
function nsf() {
  const header = Buffer.alloc(0x80);
  header.write('NESM\x1a', 0, 'latin1');
  header.set([1, 3, 1], 5);
  header.writeUInt16LE(0x8000, 8); header.writeUInt16LE(0x8000, 10); header.writeUInt16LE(0x8005, 12);
  return Buffer.concat([header, Buffer.from([0xa9, 0x00, 0x8d, 0x15, 0x40, 0x60])]);
}

// GBS: magic and version 1, 2 songs from song 1, load/init 0x0400, play 0x0402.
function gbs() {
  const header = Buffer.alloc(0x70);
  header.write('GBS\x01', 0, 'latin1');
  header.set([2, 1], 4);
  header.writeUInt16LE(0x0400, 6); header.writeUInt16LE(0x0400, 8); header.writeUInt16LE(0x0402, 10);
  return Buffer.concat([header, Buffer.from([0x3e, 0x80, 0xe0, 0x26, 0xc9])]);
}

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`chiptune programs name their platform CPU through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const fixtures = [['nsf', nsf()], ['gbs', gbs()]].map(([format, bytes]) => ({ format, bytes: [...bytes] }));
    const payloads = await page.evaluate(async ({ module, fixtures }) => {
      const wasm = await import(module);
      await wasm.default();
      return fixtures.map(f => JSON.parse(wasm.classify(new Uint8Array(f.bytes))));
    }, { module, fixtures });
    assert.deepEqual(payloads.map(p => [p.format.format, p.primary.isa]), [['nsf', 'mcs6502'], ['gbs', 'z80']]);
    for (const p of payloads) assert.ok(Object.hasOwn(FORMAT_NAMES, p.format.format));
  });
}
