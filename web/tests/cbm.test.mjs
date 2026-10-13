import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup); after(teardown);

const SECTOR = 256;

// 6502 at 0xC000: LDA #$01; STA $D020; LDX #$00; LDA $C100,X; STA $0400,X;
// INX; BNE back to the LDA; RTS.
const ROUTINE = [0xa9, 0x01, 0x8d, 0x20, 0xd0, 0xa2, 0x00, 0xbd, 0x00, 0xc1, 0x9d, 0x00, 0x04, 0xe8, 0xd0, 0xf7, 0x60];

// `size` bytes of the routine, repeated.
function code(size) {
  const bytes = Buffer.alloc(size);
  for (let at = 0; at < size; at++) {
    bytes[at] = ROUTINE[at % ROUTINE.length];
  }
  return bytes;
}

// A PRG file: little-endian load address, then the program.
function prg(loadAddress, program) {
  const address = Buffer.alloc(2);
  address.writeUInt16LE(loadAddress, 0);
  return Buffer.concat([address, program]);
}

// Sectors per track of the 1541 zones (VICE manual, D64 section).
function sectorsPerTrack1541(track) {
  if (track <= 17) return 21;
  if (track <= 24) return 19;
  if (track <= 30) return 18;
  return 17;
}

// D64 image offset of `track`/`sector`: the sectors of all earlier tracks.
function offset1541(track, sector) {
  let before = 0;
  for (let t = 1; t < track; t++) {
    before += sectorsPerTrack1541(t);
  }
  return (before + sector) * SECTOR;
}

// D81 image offset: 40 sectors per track.
const offset1581 = (track, sector) => ((track - 1) * 40 + sector) * SECTOR;

// Write `contents` along a chain: each sector links to the next track and
// sector and holds 254 data bytes; the last has track 0 and the index of
// its last used byte.
function writeChain(image, offset, sectors, contents) {
  sectors.forEach(([track, sector], i) => {
    const at = offset(track, sector);
    const piece = contents.subarray(i * 254, (i + 1) * 254);
    const next = sectors[i + 1];
    image[at] = next ? next[0] : 0;
    image[at + 1] = next ? next[1] : piece.length + 1;
    piece.copy(image, at + 2);
  });
}

// A 32-byte directory entry: type, first track and sector, name padded
// with 0xA0, size in sectors (little-endian) at 0x1E.
function writeEntry(image, at, type, first, name, blocks) {
  image[at + 2] = type;
  image[at + 3] = first[0];
  image[at + 4] = first[1];
  image.fill(0xa0, at + 5, at + 21);
  image.write(name, at + 5, 'latin1');
  image.writeUInt16LE(blocks, at + 30);
}

// 35-track D64: BAM at 18/0 (directory link 18/1, DOS version A, disk name
// ZRAX WEB padded with 0xA0, ID ZW, DOS type 2A); directory at 18/1 (link
// 00/FF) with a 600-byte program at 0xC000 on 17/0, 17/10, 17/20 and a SEQ
// file on 19/0.
function d64() {
  const image = Buffer.alloc(683 * SECTOR);
  const bam = offset1541(18, 0);
  image.set([18, 1, 0x41, 0], bam);
  image.fill(0xa0, bam + 0x90, bam + 0xab);
  image.write('ZRAX WEB', bam + 0x90, 'latin1');
  image.write('ZW', bam + 0xa2, 'latin1');
  image.write('2A', bam + 0xa5, 'latin1');
  const program = [[17, 0], [17, 10], [17, 20]];
  writeChain(image, offset1541, program, prg(0xc000, code(600)));
  writeChain(image, offset1541, [[19, 0]], Buffer.from('HELLO\r', 'latin1'));
  const dir = offset1541(18, 1);
  writeEntry(image, dir, 0x82, program[0], 'WEB DEMO', 3);
  writeEntry(image, dir + 32, 0x81, [19, 0], 'NOTES', 1);
  image[dir] = 0;
  image[dir + 1] = 0xff;
  return image;
}

// D81: header at 40/0 (28 03 44 00, name ZRAX D81, ID ZW, 3D), BAM sectors
// 40/1 and 40/2 with version D and complement 0xBB, directory at 40/3 with
// a program at 0x2000 on 39/0 and 39/1.
function d81() {
  const image = Buffer.alloc(3200 * SECTOR);
  const header = offset1581(40, 0);
  image.set([0x28, 0x03, 0x44, 0x00], header);
  image.fill(0xa0, header + 4, header + 0x1d);
  image.write('ZRAX D81', header + 4, 'latin1');
  image.write('ZW', header + 0x16, 'latin1');
  image.write('3D', header + 0x19, 'latin1');
  image.set([0x28, 0x02, 0x44, 0xbb], offset1581(40, 1));
  image.set([0x00, 0xff, 0x44, 0xbb], offset1581(40, 2));
  const program = [[39, 0], [39, 1]];
  writeChain(image, offset1581, program, prg(0x2000, code(400)));
  const dir = offset1581(40, 3);
  writeEntry(image, dir, 0x82, program[0], 'D81 PROG', 2);
  image[dir] = 0;
  image[dir + 1] = 0xff;
  return image;
}

// T64: signature C64 tape image file, version 0x0100, 1 directory entry,
// 1 used, description; one normal PRG record loading 300 bytes at 0x0801
// from offset 0x60.
function t64() {
  const header = Buffer.alloc(64);
  header.write('C64 tape image file', 0, 'latin1');
  header.writeUInt16LE(0x0100, 0x20);
  header.writeUInt16LE(1, 0x22);
  header.writeUInt16LE(1, 0x24);
  header.fill(0x20, 0x28, 0x40);
  header.write('ZRAX WEB TAPE', 0x28, 'latin1');
  const record = Buffer.alloc(32);
  record[0] = 1;
  record[1] = 0x82;
  record.writeUInt16LE(0x0801, 2);
  record.writeUInt16LE(0x0801 + 300, 4);
  record.writeUInt32LE(0x60, 8);
  record.fill(0x20, 16, 32);
  record.write('TAPE PRG', 16, 'latin1');
  return Buffer.concat([header, record, code(300)]);
}

const FIXTURES = [
  ['d64', d64(), 'd64'],
  ['d81', d81(), 'd81'],
  ['t64', t64(), 't64'],
];

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`Commodore images list their programs as 6502 code through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const fixtures = FIXTURES.map(([name, bytes]) => ({ name, bytes: [...bytes] }));
    const payloads = await page.evaluate(async ({ module, fixtures }) => {
      const wasm = await import(module);
      await wasm.default();
      const classify = f => [f.name, JSON.parse(wasm.classify(new Uint8Array(f.bytes)))];
      return Object.fromEntries(fixtures.map(classify));
    }, { module, fixtures });
    for (const [name, , format] of FIXTURES) {
      const p = payloads[name];
      assert.ok(!p.error, `${name}: ${p.error}`);
      assert.equal(p.format.format, format, name);
      assert.equal(p.primary.isa, 'mcs6502', name);
    }
    for (const id of ['d64', 'd71', 'd81', 't64']) {
      assert.ok(Object.hasOwn(FORMAT_NAMES, id), `${id} has a display name`);
    }
    const program = payloads.d64.slices.find(s => s.label === 'PRG "WEB DEMO" at 0xC000');
    assert.deepEqual([program.isa, program.offset, program.size], ['mcs6502', 0x15000, 256]);
    assert.deepEqual(program.decoded, { transform: 'D64 sector chain', offset: 0, size: 600 });
    const seq = payloads.d64.slices.find(s => s.label === 'SEQ "NOTES"');
    assert.deepEqual([seq.isa, seq.offset], [{ unknown: 0 }, 0x17800]);
    assert.ok(payloads.d64.format.confidence < 1, 'D64 detection is weak');
    const d81Program = payloads.d81.slices.find(s => s.label === 'PRG "D81 PROG" at 0x2000');
    assert.deepEqual([d81Program.offset, d81Program.size], [offset1581(39, 0), 512]);
    const tape = payloads.t64.slices.find(s => s.label === 'PRG "TAPE PRG" at 0x0801');
    assert.deepEqual([tape.isa, tape.offset, tape.size], ['mcs6502', 0x60, 300]);
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names D64 images and their disk in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const file = { name: 'demo.d64', buffer: d64(), mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([file]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes('D64 disk image'), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.format.format, 'd64');
    assert.equal(p.primary.isa, 'mcs6502');
    assert.ok(p.metadata.some(m => m.key?.custom === 'cbm_disk_name' && m.value === 'ZRAX WEB'));
  });
}
