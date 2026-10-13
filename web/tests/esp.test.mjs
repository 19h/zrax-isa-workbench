import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';

before(setup);
after(teardown);

// RV32IMAC code compiled by clang (tests/fixtures/mcu/README.md).
const riscv32 = () => readFile(new URL('../../tests/fixtures/mcu/riscv32.text.bin', import.meta.url));

// ESP32-C3 memory map (esptool ESP32C3ROM.MEMORY_MAP).
const C3_DROM = 0x3c0a0020;
const C3_IRAM = 0x40380000;
const C3_IROM = 0x42000020;
// ESP32 memory map (esptool ESP32ROM.MEMORY_MAP).
const ESP32_IRAM = 0x40080000;
const ESP32_DRAM = 0x3ffb0000;

// Segment header (load address, length) and data, for each segment.
function segments(list) {
  return Buffer.concat(list.flatMap(({ address, data }) => {
    const header = Buffer.alloc(8);
    header.writeUInt32LE(address, 0);
    header.writeUInt32LE(data.length, 4);
    return [header, data];
  }));
}

// XOR of the segment data seeded with 0xEF, stored as the last byte of a
// 16-byte block after zero padding.
function withChecksum(image, list) {
  let sum = 0xef;
  for (const { data } of list) {
    for (const byte of data) {
      sum ^= byte;
    }
  }
  const padded = Buffer.alloc(image.length + (15 - (image.length % 16)) + 1);
  image.copy(padded);
  padded[padded.length - 1] = sum;
  return padded;
}

// An ESP32-family image: magic 0xE9, segment count, DIO, 4 MiB / 40 MHz,
// entry; WP pin 0xEE, pin drive 0, chip ID, revisions v0.0 to v0.99,
// reserved, hash_appended 1; segments; checksum; SHA-256 of the image.
function esp32Image(chipId, entry, list) {
  const header = Buffer.alloc(24);
  header.set([0xe9, list.length, 2, 0x20]);
  header.writeUInt32LE(entry, 4);
  header[8] = 0xee;
  header.writeUInt16LE(chipId, 12);
  header.writeUInt16LE(99, 17);
  header[23] = 1;
  const image = withChecksum(Buffer.concat([header, segments(list)]), list);
  const digest = createHash('sha256').update(image).digest();
  return Buffer.concat([image, digest]);
}

const strings = length => Buffer.from('ESP-IDF log message %s\n\0'.repeat(length)).subarray(0, length);

// An ESP32-C3 application: strings in DROM, RISC-V code in IRAM and IROM.
async function c3App() {
  const code = await riscv32();
  return esp32Image(0x0005, C3_IRAM, [
    { address: C3_DROM, data: strings(256) },
    { address: C3_IRAM, data: code.subarray(0, 1024) },
    { address: C3_IROM, data: code.subarray(1024) },
  ]);
}

// An ESP32 bootloader: DRAM data and IRAM bytes with the entry point.
function esp32Bootloader() {
  return esp32Image(0x0000, ESP32_IRAM, [
    { address: ESP32_DRAM, data: strings(64) },
    { address: ESP32_IRAM, data: Buffer.alloc(64, 0x36) },
  ]);
}

// A partition record: magic AA 50, type, subtype, offset, size, label,
// flags.
function partition(type, subtype, offset, size, label) {
  const record = Buffer.alloc(32);
  record.set([0xaa, 0x50, type, subtype]);
  record.writeUInt32LE(offset, 4);
  record.writeUInt32LE(size, 8);
  record.write(label, 12, 'latin1');
  return record;
}

// An ESP32 flash dump: the bootloader at 0x1000, the partition table at
// 0x8000 (records, MD5 record, 0xFF terminator) and an 8 KiB factory
// application partition at 0x10000 holding the ESP32-C3 image.
async function esp32Flash() {
  const flash = Buffer.alloc(0x12000, 0xff);
  esp32Bootloader().copy(flash, 0x1000);
  const records = Buffer.concat([
    partition(1, 0x02, 0x9000, 0x1000, 'nvs'),
    partition(0, 0x00, 0x10000, 0x2000, 'factory'),
  ]);
  const md5 = Buffer.alloc(32, 0xff);
  md5.set([0xeb, 0xeb]);
  createHash('md5').update(records).digest().copy(md5, 16);
  Buffer.concat([records, md5]).copy(flash, 0x8000);
  strings(128).copy(flash, 0x9000);
  (await c3App()).copy(flash, 0x10000);
  return flash;
}

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`Espressif images and flash dumps name their chip through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const fixtures = [
      { name: 'app.bin', bytes: [...await c3App()] },
      { name: 'bootloader.bin', bytes: [...esp32Bootloader()] },
      { name: 'flash.bin', bytes: [...await esp32Flash()] },
    ];
    const payloads = await page.evaluate(async ({ module, fixtures }) => {
      const wasm = await import(module);
      await wasm.default();
      return fixtures.map(f => JSON.parse(wasm.classify(new Uint8Array(f.bytes))));
    }, { module, fixtures });
    const [app, bootloader, flash] = payloads;
    for (const p of payloads) {
      assert.ok(!p.error, p.error);
      assert.ok(Object.hasOwn(FORMAT_NAMES, p.format.format), `${p.format.format} has a display name`);
    }
    assert.equal(app.format.format, 'espfirmware');
    assert.equal(app.primary.isa, 'risc_v32');
    assert.deepEqual(app.slices.map(s => [s.label, s.isa, s.offset]), [['Segment 0 (DROM)', { unknown: 0 }, 32]]);
    assert.equal(bootloader.primary.isa, 'xtensa');
    assert.equal(bootloader.primary.variant.name, 'Xtensa LX6');
    assert.equal(flash.format.format, 'espflash');
    const slice = label => flash.slices.find(s => s.label === label);
    assert.equal(slice('Bootloader').isa, 'xtensa');
    assert.equal(slice('Bootloader').offset, 0x1000);
    assert.deepEqual(slice('Partition table').isa, { unknown: 0 });
    assert.deepEqual(slice('nvs').isa, { unknown: 0 });
    assert.equal(slice('factory').isa, 'risc_v32');
    assert.equal(slice('factory').offset, 0x10000);
    assert.ok(flash.notes.some(n => n.message === 'Partition table at 0x8000: 2 partitions; MD5 verified'));
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench shows ESP flash dumps by name in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = await esp32Flash();
    await page.locator('#fileinput').setInputFiles([{ name: 'flash.bin', buffer, mimeType: 'application/octet-stream' }]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.espflash), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.format.format, 'espflash');
    assert.ok(p.metadata.some(m => m.key?.custom === 'esp_partition_1' && m.value === 'app factory at 0x10000, 8 KiB'));
  });
}
