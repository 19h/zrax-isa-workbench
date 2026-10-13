import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

// The synthetic x86-64 ELF header of the compressed-stream fixtures.
const elf = () => readFile(new URL('../../tests/fixtures/compressed/payload.elf', import.meta.url));

// PowerPC: stwu r1,-16(r1); mflr r0; lwz r0,20(r1); mtlr r0; addi r1,r1,16; blr.
const PPC_WORDS = [0x9421fff0, 0x7c0802a6, 0x80010014, 0x7c0803a6, 0x38210010, 0x4e800020];

// `size` bytes of repeated PowerPC code.
function ppcCode(size) {
  const bytes = Buffer.alloc(size);
  for (let at = 0; at + 4 <= size; at += 4) {
    bytes.writeUInt32BE(PPC_WORDS[(at / 4) % PPC_WORDS.length], at);
  }
  return bytes;
}

// The disc header GameCube and Wii share: game and maker code at 0, disc
// number 0 at 6, version 1 at 7, the title at 0x20.
function discHeader(image, gameId, title) {
  image.write(gameId, 0, 'latin1');
  image[7] = 1;
  image.write(title, 0x20, 'latin1');
}

// A DOL: text section 0 at file 0x100 (PowerPC code at 0x80003100), data
// section 0 after it (0x40 B at 0x80100000), entry 0x80003100.
function dol(textSize) {
  const header = Buffer.alloc(0x100);
  header.writeUInt32BE(0x100, 0x00);
  header.writeUInt32BE(0x100 + textSize, 0x1c);
  header.writeUInt32BE(0x80003100, 0x48);
  header.writeUInt32BE(0x80100000, 0x64);
  header.writeUInt32BE(textSize, 0x90);
  header.writeUInt32BE(0x40, 0xac);
  header.writeUInt32BE(0x80003100, 0xe0);
  return Buffer.concat([header, ppcCode(textSize), Buffer.alloc(0x40, 0x5a)]);
}

// A GameCube image: header with the magic at 0x1C, boot DOL at 0x3000 (0x420),
// FST at 0x4000 (0x424, size at 0x428); apploader header at 0x2440 (date,
// entry, code size 0x100, trailer 0) and code; the FST holds the root (3
// entries), `payload.elf` at 0x6000 and `opening.bnr` (zeros) at 0x5000.
async function gamecubeImage() {
  const image = Buffer.alloc(0x6200);
  discHeader(image, 'GZRE01', 'ZRAX SYNTHETIC DISC');
  image.writeUInt32BE(0xc2339f3d, 0x1c);
  image.write('2026/10/13', 0x2440, 'latin1');
  image.writeUInt32BE(0x81200000, 0x2450);
  image.writeUInt32BE(0x100, 0x2454);
  ppcCode(0x100).copy(image, 0x2460);
  dol(0x200).copy(image, 0x3000);
  const names = Buffer.from('\0payload.elf\0opening.bnr\0', 'latin1');
  const fst = Buffer.alloc(3 * 12);
  // Root: directory flag, name offset 0, parent 0, 3 entries.
  fst.writeUInt32BE(0x01000000, 0);
  fst.writeUInt32BE(3, 8);
  // Files: name offset, data offset, size.
  fst.writeUInt32BE(1, 12);
  fst.writeUInt32BE(0x6000, 16);
  fst.writeUInt32BE(256, 20);
  fst.writeUInt32BE(13, 24);
  fst.writeUInt32BE(0x5000, 28);
  fst.writeUInt32BE(0x40, 32);
  Buffer.concat([fst, names]).copy(image, 0x4000);
  image.writeUInt32BE(0x3000, 0x420);
  image.writeUInt32BE(0x4000, 0x424);
  image.writeUInt32BE(fst.length + names.length, 0x428);
  (await elf()).copy(image, 0x6000);
  return image;
}

// A Wii image: header with the magic at 0x18; partition group 0 with an
// UPDATE partition at 0x50000 and a DATA partition at 0x58000 (offsets
// stored >> 2); each partition header names data at 0x1000 (>> 2) of
// 0x1000 B (>> 2); the data holds an ELF header that must stay opaque.
async function wiiImage() {
  const image = Buffer.alloc(0x5a000);
  discHeader(image, 'RZRP01', 'ZRAX WII DISC');
  image.writeUInt32BE(0x5d1c9ea3, 0x18);
  image.writeUInt32BE(2, 0x40000);
  image.writeUInt32BE(0x40020 / 4, 0x40004);
  image.writeUInt32BE(0x50000 / 4, 0x40020);
  image.writeUInt32BE(1, 0x40024);
  image.writeUInt32BE(0x58000 / 4, 0x40028);
  image.writeUInt32BE(0, 0x4002c);
  for (const partition of [0x50000, 0x58000]) {
    image.writeUInt32BE(0x1000 / 4, partition + 0x2b8);
    image.writeUInt32BE(0x1000 / 4, partition + 0x2bc);
    (await elf()).copy(image, partition + 0x1000);
  }
  return image;
}

// One XDVDFS directory entry at `at`: left and right links (4-byte units),
// start sector, size, attributes, name length and name.
function dirent(table, at, { left = 0, right = 0, sector, size, attributes, name }) {
  table.writeUInt16LE(left, at);
  table.writeUInt16LE(right, at + 2);
  table.writeUInt32LE(sector, at + 4);
  table.writeUInt32LE(size, at + 8);
  table[at + 12] = attributes;
  table[at + 13] = name.length;
  table.write(name, at + 14, 'latin1');
}

// An XISO image: the volume descriptor at sector 32 (magic, root table at
// sector 34 of 2048 B, the magic again at 0x7EC); the root table holds
// `default.xbe` (an XBE header at sector 36) and the directory `media`
// (its left subtree), whose table at sector 35 holds `game.xex` (an XEX2
// header at sector 37).
function xisoImage() {
  const sector = 2048;
  const image = Buffer.alloc(38 * sector);
  const descriptor = 32 * sector;
  image.write('MICROSOFT*XBOX*MEDIA', descriptor, 'latin1');
  image.writeUInt32LE(34, descriptor + 0x14);
  image.writeUInt32LE(sector, descriptor + 0x18);
  image.write('MICROSOFT*XBOX*MEDIA', descriptor + 0x7ec, 'latin1');
  const root = Buffer.alloc(sector, 0xff);
  dirent(root, 0, { left: 5, sector: 35, size: sector, attributes: 0x10, name: 'media' });
  dirent(root, 20, { sector: 36, size: 0x200, attributes: 0x20, name: 'default.xbe' });
  root.copy(image, 34 * sector);
  const media = Buffer.alloc(sector, 0xff);
  dirent(media, 0, { sector: 37, size: 0x40, attributes: 0x20, name: 'game.xex' });
  media.copy(image, 35 * sector);
  const xbe = 36 * sector;
  image.write('XBEH', xbe, 'latin1');
  image.writeUInt32LE(0x10000, xbe + 0x104);
  image.writeUInt32LE(0x1000, xbe + 0x10c);
  image.writeUInt32LE((0x11000 ^ 0xa8fc57ab) >>> 0, xbe + 0x128);
  const xex = 37 * sector;
  image.write('XEX2', xex, 'latin1');
  image.writeUInt32BE(1, xex + 4);
  return image;
}

const IMAGES = [
  {
    name: 'gamecube.iso',
    build: gamecubeImage,
    format: 'gamecubedisc',
    variant: 'GameCube disc image',
    isa: 'ppc',
    slices: [['Main executable (DOL)', 'ppc'], ['Apploader', 'ppc'], ['/payload.elf', 'x86_64']],
  },
  {
    name: 'wii.iso',
    build: wiiImage,
    format: 'wiidisc',
    variant: 'Wii disc image',
    isa: { unknown: 0 },
    slices: [['Partition 0.0 (UPDATE)', { unknown: 0 }], ['Partition 0.1 (DATA)', { unknown: 0 }]],
  },
  {
    name: 'game.xiso',
    build: xisoImage,
    format: 'xboxdvd',
    variant: 'XDVDFS image',
    isa: 'x86',
    slices: [['/default.xbe', 'x86'], ['/media/game.xex', 'ppc']],
  },
];

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`console disc images list their components through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const images = await Promise.all(IMAGES.map(async image => ({ name: image.name, bytes: [...await image.build()] })));
    const payloads = await page.evaluate(async ({ module, images }) => {
      const wasm = await import(module);
      await wasm.default();
      return images.map(image => JSON.parse(wasm.classify(new Uint8Array(image.bytes))));
    }, { module, images });
    IMAGES.forEach(({ name, format, variant, isa, slices }, i) => {
      const p = payloads[i];
      assert.ok(!p.error, `${name}: ${p.error}`);
      assert.equal(p.format.format, format, name);
      assert.equal(p.format.variant_name, variant, name);
      assert.deepEqual(p.primary.isa, isa, name);
      assert.deepEqual(p.slices.map(s => [s.label, s.isa]), slices, name);
      assert.ok(Object.hasOwn(FORMAT_NAMES, format), `${format} has a display name`);
    });
    const wii = payloads[1];
    assert.ok(wii.notes.some(n => n.message === 'Partition 0.1 (DATA): opaque; payload ISA analysis skipped'));
    assert.deepEqual(wii.slices.map(s => s.offset), [0x50000, 0x58000]);
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names GameCube discs and keeps stored offsets in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = await gamecubeImage();
    const file = { name: 'game.iso', buffer, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([file]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.gamecubedisc), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'ppc');
    const member = p.slices.find(s => s.label === '/payload.elf');
    const bytes = buffer.subarray(member.offset, member.offset + member.size);
    assert.deepEqual([...bytes.subarray(0, 4)], [0x7f, 0x45, 0x4c, 0x46], 'the stored offset holds the ELF');
  });
}
