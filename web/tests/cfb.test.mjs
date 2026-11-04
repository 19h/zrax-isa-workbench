import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';

before(setup);
after(teardown);

const SECTOR = 512;
const END_OF_CHAIN = 0xfffffffe;
const FREE = 0xffffffff;
const NO_STREAM = 0xffffffff;

/** A minimal x86-64 ELF header (e_machine 62) padded to 4096 bytes. */
function elf() {
  const v = Buffer.alloc(4096);
  Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]).copy(v);
  v.writeUInt16LE(62, 0x12);
  return v;
}

/** 128-byte directory entry: UTF-16LE name, name length, type, siblings, child, start sector, size. */
function entry(name, type, right, child, start, size) {
  const e = Buffer.alloc(128);
  e.write(name, 0, 'utf16le');
  e.writeUInt16LE(2 * name.length + 2, 0x40);
  e[0x42] = type;
  e.writeUInt32LE(NO_STREAM, 0x44);
  e.writeUInt32LE(right, 0x48);
  e.writeUInt32LE(child, 0x4c);
  e.writeUInt32LE(start, 0x74);
  e.writeUInt32LE(size, 0x78);
  return e;
}

/**
 * Version 3 compound file: header, FAT (sector 0), directory (1), mini FAT
 * (2, empty), then the 4096-byte `Program` stream in sectors 3-10.
 */
function compoundFile() {
  const header = Buffer.alloc(SECTOR);
  Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]).copy(header);
  header.writeUInt16LE(0x3e, 0x18);
  header.writeUInt16LE(3, 0x1a);
  header.writeUInt16LE(0xfffe, 0x1c);
  header.writeUInt16LE(9, 0x1e);
  header.writeUInt16LE(6, 0x20);
  header.writeUInt32LE(1, 0x2c);
  header.writeUInt32LE(1, 0x30);
  header.writeUInt32LE(4096, 0x38);
  header.writeUInt32LE(END_OF_CHAIN, 0x3c);
  header.writeUInt32LE(END_OF_CHAIN, 0x44);
  for (let i = 0; i < 109; i++) header.writeUInt32LE(i === 0 ? 0 : FREE, 0x4c + 4 * i);
  const fat = Buffer.alloc(SECTOR, 0xff);
  fat.writeUInt32LE(0xfffffffd, 0);
  fat.writeUInt32LE(END_OF_CHAIN, 4);
  fat.writeUInt32LE(END_OF_CHAIN, 8);
  for (let n = 3; n <= 10; n++) fat.writeUInt32LE(n === 10 ? END_OF_CHAIN : n + 1, 4 * n);
  const directory = Buffer.concat([
    entry('Root Entry', 5, NO_STREAM, 1, END_OF_CHAIN, 0),
    entry('Program', 2, NO_STREAM, NO_STREAM, 3, 4096),
    Buffer.alloc(256),
  ]);
  return Buffer.concat([header, fat, directory, Buffer.alloc(SECTOR, 0xff), elf()]);
}

test('compound files have a display name', () => {
  assert.equal(FORMAT_NAMES.cfb, 'Compound File');
});

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`a compound file takes its ISA from a recognized stream through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const bytes = [...compoundFile()];
    const payload = await page.evaluate(async ({ module, bytes }) => {
      const wasm = await import(module);
      await wasm.default();
      const engine = new wasm.WorkbenchEngine(new Uint8Array(bytes));
      try {
        return JSON.parse(engine.classification());
      } finally {
        engine.free();
      }
    }, { module, bytes });
    assert.equal(payload.format.format, 'cfb');
    assert.equal(payload.primary.isa, 'x86_64');
    assert.deepEqual(payload.slices.map(s => s.label), ['Program']);
  });
}
