import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';

before(setup);
after(teardown);

/**
 * Binary plist with three one-byte objects (0x09, true) after the header,
 * a one-byte offset table, and the 32-byte trailer: 5 unused bytes, sort
 * version, offset size 1, reference size 1, then object count, top object
 * and offset table offset as big-endian 64-bit words.
 */
function bplist() {
  const header = Buffer.from('bplist00');
  const objects = Buffer.from([0x09, 0x09, 0x09]);
  const table = Buffer.from([8, 9, 10]);
  const trailer = Buffer.alloc(32);
  trailer[6] = 1;
  trailer[7] = 1;
  trailer.writeBigUInt64BE(3n, 8);
  trailer.writeBigUInt64BE(0n, 16);
  trailer.writeBigUInt64BE(11n, 24);
  return Buffer.concat([header, objects, table, trailer]);
}

/** Information element: id and length (little-endian 32-bit), data padded to four bytes. */
function ie(id, data) {
  const head = Buffer.alloc(8);
  head.writeUInt32LE(id, 0);
  head.writeUInt32LE(data.length, 4);
  const pad = Buffer.alloc((4 - (data.length % 4)) % 4);
  return Buffer.concat([head, data, pad]);
}

/** ath10k board data: magic, NUL and padding, one board with a name and data element. */
function qcaBoard() {
  const magic = Buffer.concat([Buffer.from('QCA-ATH10K-BOARD'), Buffer.alloc(4)]);
  const board = Buffer.concat([ie(0, Buffer.from('bus=pci,vendor=168c')), ie(1, Buffer.alloc(40, 0x5a))]);
  return Buffer.concat([magic, ie(0, board)]);
}

test('data file formats have display names', () => {
  assert.equal(FORMAT_NAMES.bplist, 'Binary Property List');
  assert.equal(FORMAT_NAMES.qcaboard, 'QCA Board Data');
});

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`plists and board data classify as opaque data files through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const inputs = { bplist: [...bplist()], qcaboard: [...qcaBoard()] };
    const results = await page.evaluate(async ({ module, inputs }) => {
      const wasm = await import(module);
      await wasm.default();
      const out = {};
      for (const [name, bytes] of Object.entries(inputs)) {
        const engine = new wasm.WorkbenchEngine(new Uint8Array(bytes));
        try {
          out[name] = JSON.parse(engine.classification());
        } finally {
          engine.free();
        }
      }
      return out;
    }, { module, inputs });
    for (const format of ['bplist', 'qcaboard']) {
      assert.equal(results[format].format.format, format);
      assert.equal(results[format].primary.confidence, 0);
    }
  });
}
