import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

const fixture = path => readFile(new URL(`../../tests/fixtures/${path}`, import.meta.url));

// OP-TEE header version 2 (optee_os output_header_v2): magic 'OPTE',
// version 2, arch 1 (AArch64), flags 0, one image record: load address
// high and low words, image ID 0 (pager), size.
function opteeV2() {
  const header = Buffer.alloc(0x1c);
  header.writeUInt32LE(0x4554504f, 0);
  header[4] = 2;
  header[5] = 1;
  header.writeUInt32LE(1, 8);
  header.writeUInt32LE(0x0e100000, 0x10);
  header.writeUInt32LE(0x40000, 0x18);
  return header;
}

// CRC-32 as Amlogic's calc_img_crc: reflected 0xEDB88320, initial
// 0xFFFFFFFF, no final XOR.
function amlogicCrc(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) {
      crc = crc & 1 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1;
    }
  }
  return crc >>> 0;
}

// Amlogic burning image, version 2: 64-byte header (CRC, version, magic
// 0x27B51956, image size, alignment 4, item count), 576-byte item records
// (ID, file type, data offset and size, 256-byte main and sub type), item
// data, CRC over everything after itself. Items: USB/DDR code, a
// PARTITION/boot ELF and its VERIFY record.
function amlogic(code, elf) {
  const verify = Buffer.from('sha1sum ' + createHash('sha1').update(elf).digest('hex'), 'latin1');
  const items = [['USB', 'DDR', code], ['PARTITION', 'boot', elf], ['VERIFY', 'boot', verify]];
  const table = Buffer.alloc(64 + items.length * 576);
  const parts = [table];
  let offset = table.length;
  items.forEach(([main, sub, data], i) => {
    const record = 64 + i * 576;
    table.writeUInt32LE(i, record);
    table.writeBigUInt64LE(BigInt(offset), record + 0x10);
    table.writeBigUInt64LE(BigInt(data.length), record + 0x18);
    table.write(main, record + 0x20, 'latin1');
    table.write(sub, record + 0x120, 'latin1');
    const padded = Buffer.alloc(Math.ceil(data.length / 4) * 4);
    data.copy(padded);
    parts.push(padded);
    offset += padded.length;
  });
  const image = Buffer.concat(parts);
  image.writeUInt32LE(2, 4);
  image.writeUInt32LE(0x27b51956, 8);
  image.writeBigUInt64LE(BigInt(image.length), 0x0c);
  image.writeUInt32LE(4, 0x14);
  image.writeUInt32LE(items.length, 0x18);
  image.writeUInt32LE(amlogicCrc(image.subarray(4)), 0);
  return image;
}

// A barebox image: the assembled A64 ENTRY_PROC head (first 0x50 bytes of
// the fixture), the code, and the image size at 0x2C.
function barebox(head, code) {
  const image = Buffer.concat([head.subarray(0, 0x50), code]);
  image.writeUInt32LE(image.length, 0x2c);
  return image;
}

// An Img3 tag: code (four characters, stored reversed), total length
// (12 + data padded to 4), data length, data.
function img3Tag(code, data) {
  const padded = Math.ceil(data.length / 4) * 4;
  const tag = Buffer.alloc(12 + padded);
  tag.write([...code].reverse().join(''), 0, 'latin1');
  tag.writeUInt32LE(tag.length, 4);
  tag.writeUInt32LE(data.length, 8);
  data.copy(tag, 12);
  return tag;
}

// Img3: magic 'Img3' stored '3gmI', full size, tag area size, SHSH offset
// 0, type 'ibot'; then TYPE and DATA tags.
function img3(payload) {
  const tags = Buffer.concat([img3Tag('TYPE', Buffer.from('tobi', 'latin1')), img3Tag('DATA', payload)]);
  const header = Buffer.alloc(20);
  header.write('3gmI', 0, 'latin1');
  header.writeUInt32LE(20 + tags.length, 4);
  header.writeUInt32LE(tags.length, 8);
  header.write('tobi', 16, 'latin1');
  return Buffer.concat([header, tags]);
}

// 8900: 0x800-byte header ('8900', '1.0', format 4 plaintext, payload
// size, footer signature and certificate offsets from the end of the
// header, certificate length), payload, 0x80-byte signature, certificate.
function apple8900(payload) {
  const header = Buffer.alloc(0x800);
  header.write('89001.0', 0, 'latin1');
  header[7] = 4;
  header.writeUInt32LE(payload.length, 0x0c);
  header.writeUInt32LE(payload.length, 0x10);
  header.writeUInt32LE(payload.length + 0x80, 0x14);
  header.writeUInt32LE(16, 0x18);
  return Buffer.concat([header, payload, Buffer.alloc(0x80, 0x5a), Buffer.alloc(16, 0x30)]);
}

async function fixtures() {
  const arm = await fixture('socboot2/arm.text.bin');
  const aarch64 = await fixture('transforms/aarch64.text.bin');
  const elf = await fixture('compressed/payload.elf');
  return {
    optee: opteeV2(),
    amlogic: amlogic(arm, elf),
    imagewtyPlain: await fixture('bootmisc/imagewty-plain.img'),
    imagewtyEncrypted: await fixture('bootmisc/imagewty-encrypted.img'),
    barebox: barebox(await fixture('bootmisc/barebox-a64-branch.bin'), aarch64),
    img3: img3(elf),
    apple8900: apple8900(elf),
  };
}

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`miscellaneous boot images report format, ISA evidence and slices through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const inputs = Object.entries(await fixtures()).map(([name, bytes]) => ({ name, bytes: [...bytes] }));
    const payloads = await page.evaluate(async ({ module, inputs }) => {
      const wasm = await import(module);
      await wasm.default();
      return Object.fromEntries(inputs.map(f => [f.name, JSON.parse(wasm.classify(new Uint8Array(f.bytes)))]));
    }, { module, inputs });
    for (const [name, p] of Object.entries(payloads)) {
      assert.ok(!p.error, `${name}: ${p.error}`);
      assert.ok(Object.hasOwn(FORMAT_NAMES, p.format.format), `${p.format.format} has a display name`);
    }
    const { optee, amlogic, imagewtyPlain, imagewtyEncrypted, barebox, img3, apple8900 } = payloads;
    const opteeResult = [optee.format.format, optee.primary.isa, optee.primary.source];
    assert.deepEqual(opteeResult, ['opteeimage', 'a_arch64', 'file_format']);
    assert.equal(amlogic.format.format, 'amlogicupgrade');
    assert.equal(amlogic.slices.find(s => s.label === 'USB/DDR').isa, 'arm');
    assert.equal(amlogic.slices.find(s => s.label === 'PARTITION/boot').isa, 'x86_64');
    assert.ok(amlogic.notes.some(n => n.message === '1 VERIFY SHA-1 record verified'));
    for (const p of [imagewtyPlain, imagewtyEncrypted]) {
      assert.equal(p.format.format, 'allwinnerimage');
      const payload = p.slices.find(s => s.label === './payload.fex (12345678/PAYLOAD_00000000)');
      assert.deepEqual([payload.offset, payload.size, payload.isa], [0x1000, 512, 'x86_64']);
    }
    const decrypted = imagewtyEncrypted.slices.find(s => s.label.startsWith('./payload.fex'));
    assert.equal(decrypted.decoded.transform, 'RC6');
    const bareboxResult = [barebox.format.format, barebox.primary.isa, barebox.primary.source];
    assert.deepEqual(bareboxResult, ['bareboximage', 'a_arch64', 'file_format']);
    assert.deepEqual([img3.format.format, img3.primary.isa], ['img3', 'x86_64']);
    assert.equal(img3.slices[0].label, 'ibot');
    assert.deepEqual([apple8900.format.format, apple8900.primary.isa], ['apple8900', 'x86_64']);
    assert.equal(apple8900.slices[0].offset, 0x800);
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names miscellaneous boot image formats in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = await fixture('bootmisc/imagewty-encrypted.img');
    const file = { name: 'livesuit.img', buffer, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([file]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes('Allwinner IMAGEWTY'), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'x86_64');
    assert.ok(p.metadata.some(m => m.key?.custom === 'imagewty_files' && m.value === 3));
  });
}
