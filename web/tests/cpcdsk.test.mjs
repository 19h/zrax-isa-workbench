import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

// A hand-assembled CPC routine: LD HL,0xC000; LD DE,0xC001; LD BC,0x3FFF; LD (HL),0; LDIR; CALL 0xBB18; RET.
const CPC_CODE = [0x21, 0x00, 0xc0, 0x11, 0x01, 0xc0, 0x01, 0xff, 0x3f, 0x36, 0x00, 0xed, 0xb0, 0xcd, 0x18, 0xbb, 0xc9];
const SECTOR_SIZE = 512;
const BLOCK_SIZE = 1024;
const RECORD_SIZE = 128;
const HEADER_SIZE = 128;
// The AMSDOS data format: sector IDs 0xC1-0xC9 stored as logical sectors 0, 5, 1, 6, 2, 7, 3, 8, 4.
const FIRST_SECTOR = 0xc1;
const INTERLEAVE = [0, 5, 1, 6, 2, 7, 3, 8, 4];
const AMSDOS_BINARY = 0x02;
const PLUS3_CODE = 3;
const BODY_SIZE = 300;
const FILE_BLOCK = 2;

const repeat = (code, length) => Buffer.from(Array.from({ length }, (_, i) => code[i % code.length]));

// An AMSDOS header: user 0, name and extension space-padded (1-11), file type (18), load address (21), first-block
// flag 0xFF (23), logical length (24), entry address (26), real length (64), and the 16-bit sum of bytes 0-66 (67).
function amsdosHeader(name, extension, fileType, load, entry, length) {
  const header = Buffer.alloc(HEADER_SIZE);
  header.fill(0x20, 1, 12);
  header.write(name, 1, 'latin1');
  header.write(extension, 9, 'latin1');
  header[18] = fileType;
  header.writeUInt16LE(load, 21);
  header[23] = 0xff;
  header.writeUInt16LE(length, 24);
  header.writeUInt16LE(entry, 26);
  header.writeUInt16LE(length, 64);
  let sum = 0;
  for (let i = 0; i < 67; i++) {
    sum += header[i];
  }
  header.writeUInt16LE(sum, 67);
  return header;
}

// A +3DOS header: `PLUS3DOS`, 0x1A, issue 1, version 0, file length including the header (11), the +3 BASIC header
// (type, length, load address), and the sum of bytes 0-126 modulo 256 (127).
function plus3Header(basicType, length, load) {
  const header = Buffer.alloc(HEADER_SIZE);
  header.write('PLUS3DOS\x1a\x01\x00', 0, 'latin1');
  header.writeUInt32LE(length + HEADER_SIZE, 11);
  header[15] = basicType;
  header.writeUInt16LE(length, 16);
  header.writeUInt16LE(load, 18);
  let sum = 0;
  for (let i = 0; i < 127; i++) {
    sum += header[i];
  }
  header[127] = sum & 0xff;
  return header;
}

// A CP/M directory entry: user 0, `DISC    BIN`, EX 0, S1 0, S2 0, the record count and 8-bit block numbers.
function directoryEntry(records, block) {
  const entry = Buffer.alloc(32);
  entry.fill(0x20, 1, 12);
  entry.write('DISC', 1, 'latin1');
  entry.write('BIN', 9, 'latin1');
  entry[15] = records;
  entry[16] = block;
  return entry;
}

// Track 0 of an extended image: a Track-Info block (`Track-Info\r\n`, track 0, side 0, size code 2, 9 sectors, gap 3
// 0x52, filler 0xE5, then C, H, R, N, ST1, ST2 and the stored length of each sector), zero to 0x100, and the sectors in
// the format's interleave. `contents` holds the track's logical sectors.
function dataTrack(contents) {
  const info = Buffer.alloc(0x100);
  info.write('Track-Info\r\n', 0, 'latin1');
  info[0x14] = 2;
  info[0x15] = INTERLEAVE.length;
  info[0x16] = 0x52;
  info[0x17] = 0xe5;
  const sectors = INTERLEAVE.map((index, position) => {
    const at = 0x18 + position * 8;
    info[at + 2] = FIRST_SECTOR + index;
    info[at + 3] = 2;
    info.writeUInt16LE(SECTOR_SIZE, at + 6);
    return contents.subarray(index * SECTOR_SIZE, (index + 1) * SECTOR_SIZE);
  });
  return Buffer.concat([info, ...sectors]);
}

// An extended disk image of one data-format track holding `DISC.BIN`, an AMSDOS binary in block 2: the signature,
// creator, 1 track, 1 side, the track size table entry (size / 256), zero to 0x100, then the track.
function dataDisk() {
  const contents = Buffer.alloc(INTERLEAVE.length * SECTOR_SIZE, 0xe5);
  const header = amsdosHeader('DISC', 'BIN', AMSDOS_BINARY, 0x4000, 0x4000, BODY_SIZE);
  const file = Buffer.concat([header, repeat(CPC_CODE, BODY_SIZE)]);
  file.copy(contents, FILE_BLOCK * BLOCK_SIZE);
  directoryEntry(Math.ceil(file.length / RECORD_SIZE), FILE_BLOCK).copy(contents, 0);
  const track = dataTrack(contents);
  const info = Buffer.alloc(0x100);
  info.write('EXTENDED CPC DSK File\r\nDisk-Info\r\n', 0, 'latin1');
  info.write('zrax tests', 0x22, 'latin1');
  info[0x30] = 1;
  info[0x31] = 1;
  info[0x34] = track.length / 0x100;
  return Buffer.concat([info, track]);
}

// DISC.BIN starts 128 B into block 2: logical sector 4 (ID 0xC5), the ninth sector stored, after the 0x200 B of
// disk and track information.
const DISC_OFFSET = 0x200 + 8 * SECTOR_SIZE + HEADER_SIZE;

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`CPC disk images and headered files classify through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const code = repeat(CPC_CODE, BODY_SIZE);
    const inputs = [
      dataDisk(),
      Buffer.concat([plus3Header(PLUS3_CODE, code.length, 0x8000), code]),
      Buffer.concat([amsdosHeader('GAME', 'BIN', AMSDOS_BINARY, 0x4000, 0x4010, code.length), code]),
    ];
    const payloads = await page.evaluate(async ({ module, inputs }) => {
      const wasm = await import(module);
      await wasm.default();
      return inputs.map(bytes => JSON.parse(wasm.classify(new Uint8Array(bytes))));
    }, { module, inputs: inputs.map(input => [...input]) });
    const [disk, plus3, amsdos] = payloads;
    assert.ok(!disk.error, disk.error);
    assert.equal(disk.format.format, 'cpcdsk');
    assert.equal(disk.format.variant_name, 'Extended CPC disk image');
    assert.deepEqual([disk.primary.isa, disk.primary.bitwidth, disk.primary.endianness], ['z80', 8, 'little']);
    const disc = disk.slices.find(s => s.label === '0:DISC.BIN');
    assert.ok(disc, '0:DISC.BIN slice');
    assert.deepEqual([disc.isa, disc.offset, disc.size], ['z80', DISC_OFFSET, BODY_SIZE]);
    const note = '0:DISC.BIN: AMSDOS binary; load address 0x4000; entry 0x4000; 300 B';
    assert.ok(disk.notes.some(n => n.message === note), note);
    assert.equal(plus3.format.format, 'plus3dos');
    assert.equal(plus3.primary.isa, 'z80');
    assert.equal(amsdos.format.format, 'amsdos');
    assert.equal(amsdos.primary.isa, 'z80');
    for (const id of ['cpcdsk', 'plus3dos', 'amsdos']) {
      assert.ok(Object.hasOwn(FORMAT_NAMES, id), `${id} has a display name`);
    }
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names CPC disk images in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = dataDisk();
    const upload = { name: 'GAME.DSK', buffer, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([upload]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.cpcdsk), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'z80');
    assert.ok(p.metadata.some(m => m.key?.custom === 'cpcdsk_image_size' && m.value === buffer.length));
  });
}
