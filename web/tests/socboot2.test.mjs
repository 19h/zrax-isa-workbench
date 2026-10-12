import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

const fixture = path => readFile(new URL(`../../tests/fixtures/${path}`, import.meta.url));

const BROM_STAMP = 0x5f0a6c39;
const RC4_KEY = [124, 78, 3, 4, 85, 5, 9, 7, 45, 44, 123, 56, 23, 13, 23, 17];

// eGON stamp checksum: the wrapping sum of all little-endian words, with
// the checksum word at 0x0C replaced by BROM_STAMP_VALUE.
function stampChecksum(image) {
  let sum = 0;
  for (let at = 0; at < image.length; at += 4) {
    const word = at === 0x0c ? BROM_STAMP : image.readUInt32LE(at);
    sum = (sum + word) >>> 0;
  }
  return sum;
}

// eGON.BT0 header: A32 jump to 0x60, magic, checksum, length; the code at
// 0x60; padded to 8 KiB.
function egon(code) {
  const image = Buffer.alloc(8192);
  image.writeUInt32LE(0xea000016, 0);
  image.write('eGON.BT0', 4, 'latin1');
  image.writeUInt32LE(image.length, 0x10);
  code.copy(image, 0x60);
  image.writeUInt32LE(stampChecksum(image), 0x0c);
  return image;
}

// Standard RC4 with the boot ROM key, key stream restarted per call.
function rc4(bytes) {
  const s = [...Array(256).keys()];
  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + s[i] + RC4_KEY[i % 16]) % 256;
    [s[i], s[j]] = [s[j], s[i]];
  }
  let i = 0;
  j = 0;
  for (let n = 0; n < bytes.length; n++) {
    i = (i + 1) % 256;
    j = (j + s[i]) % 256;
    [s[i], s[j]] = [s[j], s[i]];
    bytes[n] ^= s[(s[i] + s[j]) % 256];
  }
}

// Rockchip CRC: MSB-first polynomial 0x04C10DB7, no reflection or XOR.
function rkcrc(bytes) {
  let crc = 0;
  for (const byte of bytes) {
    crc = (crc ^ (byte << 24)) >>> 0;
    for (let bit = 0; bit < 8; bit++) {
      crc = crc & 0x80000000 ? ((crc << 1) ^ 0x04c10db7) >>> 0 : (crc << 1) >>> 0;
    }
  }
  return crc;
}

// RKBOOT loader with one 0x471 entry: the 0x66-byte header (tag, size,
// chip "3399", 0x471 table of one 0x39-byte entry at 0x66, empty 0x472
// and loader tables), the entry (type 1, UTF-16LE name, data offset and
// size), the data padded to 2 KiB and RC4-scrambled as one stream, and
// the RKCRC.
function rkboot(code) {
  const header = Buffer.alloc(0x66 + 0x39);
  header.write('BOOT', 0, 'latin1');
  header.writeUInt16LE(0x66, 4);
  header.write('9933', 0x15, 'latin1');
  header[0x19] = 1;
  header.writeUInt32LE(0x66, 0x1a);
  header[0x1e] = 0x39;
  const blob = Buffer.alloc(Math.ceil(code.length / 2048) * 2048);
  code.copy(blob);
  rc4(blob);
  const entry = 0x66;
  header[entry] = 0x39;
  header.writeUInt32LE(1, entry + 1);
  header.write('rk3399_ddr', entry + 5, 'utf16le');
  header.writeUInt32LE(header.length, entry + 0x2d);
  header.writeUInt32LE(blob.length, entry + 0x31);
  const body = Buffer.concat([header, blob]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32LE(rkcrc(body));
  return Buffer.concat([body, crc]);
}

// GFH record header: "MMM" with version 1, size, type.
function gfhRecord(size, type) {
  const record = Buffer.alloc(size);
  record.write('MMM\x01', 0, 'latin1');
  record.writeUInt16LE(size, 4);
  record.writeUInt16LE(type, 6);
  return record;
}

// EMMC_BOOT device header and BRLYT pointing at a GFH image at 0x600:
// GFH_FILE_INFO (SHA-256 signature type, load address, file length, chain
// size, signature size 32, jump offset), GFH_BROM_CFG requesting an
// AArch64 hand-off, the code, and a SHA-256 over everything before it.
function emmcBoot(code) {
  const info = gfhRecord(0x38, 0);
  info.write('FILE_INFO', 8, 'latin1');
  info[0x1a] = 5;
  info[0x1b] = 1;
  const bromCfg = gfhRecord(0x64, 7);
  bromCfg.writeUInt32LE(0x1000, 8);
  bromCfg[0x55] = 0x64;
  const chain = info.length + bromCfg.length;
  info.writeUInt32LE(0x201000 - chain, 0x1c);
  info.writeUInt32LE(chain + code.length + 32, 0x20);
  info.writeUInt32LE(chain, 0x28);
  info.writeUInt32LE(32, 0x2c);
  info.writeUInt32LE(chain, 0x30);
  const image = Buffer.concat([info, bromCfg, code]);
  const gfh = Buffer.concat([image, createHash('sha256').update(image).digest()]);
  const device = Buffer.alloc(0x600);
  device.write('EMMC_BOOT', 0, 'latin1');
  device.writeUInt32LE(1, 0x0c);
  device.writeUInt32LE(0x200, 0x10);
  device.write('BRLYT', 0x200, 'latin1');
  device.writeUInt32LE(1, 0x208);
  device.writeUInt32LE(0x600, 0x20c);
  device.writeUInt32LE(0x600 + gfh.length, 0x210);
  device.writeUInt32LE(0x42424242, 0x214);
  device.writeUInt32LE(0x10005, 0x218);
  device.writeUInt32LE(0x600, 0x21c);
  return Buffer.concat([device, gfh]);
}

// Qualcomm 80-byte SBL header: codeword, magic, image ID 21, image source
// 80, destination, image and code size, no signature, booting image
// configuration 0xF (AArch64); then the code.
function sbl(code) {
  const header = Buffer.alloc(80, 0xff);
  const words = [0x844bdcd1, 0x73d71034, 21, 0xffffffff, 0xffffffff, 80, 0x08000000, code.length, code.length,
    0x08000000 + code.length, 0, 0x08000000 + code.length, 0, 0, 1, 0xf];
  words.forEach((word, i) => header.writeUInt32LE(word, 4 * i));
  return Buffer.concat([header, code]);
}

// Qualcomm 40-byte version 3 header (coreboot ipqheader.py): APPSBL,
// version 3, destination, sizes and pointers without a signature.
function mbn(code) {
  const header = Buffer.alloc(40);
  const base = 0x4a900000;
  const words = [5, 3, 0, base, code.length, code.length, base + code.length, 0, base + code.length, 0];
  words.forEach((word, i) => header.writeUInt32LE(word, 4 * i));
  return Buffer.concat([header, code]);
}

async function fixtures() {
  const arm = await fixture('socboot2/arm.text.bin');
  const aarch64 = await fixture('transforms/aarch64.text.bin');
  return {
    egon: egon(arm),
    rkboot: rkboot(arm),
    emmc: emmcBoot(aarch64),
    sbl: sbl(aarch64),
    mbn: mbn(arm),
  };
}

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`SoC boot images report format, ISA evidence and slices through ${module}`, async t => {
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
    const { egon, rkboot, emmc, sbl, mbn } = payloads;
    assert.deepEqual([egon.format.format, egon.primary.isa, egon.primary.bitwidth], ['allwinneregon', 'arm', 32]);
    assert.equal(egon.primary.source, 'file_format');
    assert.equal(rkboot.format.format, 'rockchipimage');
    assert.equal(rkboot.slices[0].offset, 0x66 + 0x39);
    assert.equal(rkboot.slices[0].decoded.transform, 'Rockchip RC4');
    assert.equal(rkboot.slices[0].isa, 'arm');
    const emmcResult = [emmc.format.format, emmc.primary.isa, emmc.primary.source];
    assert.deepEqual(emmcResult, ['mediatekpreloader', 'a_arch64', 'file_format']);
    const code = emmc.slices.find(s => s.label === 'Preloader code');
    assert.equal(code.offset, 0x600 + 0x38 + 0x64);
    assert.deepEqual([sbl.format.format, sbl.primary.isa], ['qualcommmbn', 'a_arch64']);
    const mbnResult = [mbn.format.format, mbn.format.variant_name, mbn.primary.isa];
    assert.deepEqual(mbnResult, ['qualcommmbn', 'MBN (40-byte header)', 'arm']);
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names SoC boot image formats in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = (await fixtures()).egon;
    const file = { name: 'boot0.bin', buffer, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([file]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes('Allwinner eGON'), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'arm');
    assert.ok(p.metadata.some(m => m.key?.custom === 'allwinner_length' && m.value === buffer.length));
  });
}
