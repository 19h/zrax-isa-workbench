import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { fmtFormatName, isaName } from '../format.js';
before(setup); after(teardown);

function words(values) {
  const bytes = Buffer.alloc(values.length * 4);
  values.forEach((value, i) => bytes.writeUInt32LE(value >>> 0, i * 4));
  return bytes;
}

const fixture = name => readFile(new URL(`../../tests/fixtures/ti/${name}`, import.meta.url));

// RPRC image: "RPRC", entry, reserved, one section, version 1; then one
// section header (address, reserved, size, reserved) and four bytes of code.
const rprc = entry => Buffer.concat([
  words([0x43525052, entry, 0, 1, 1, entry, 0, 4, 0, 0]),
  Buffer.from([1, 2, 3, 4]),
]);

// mmWave radar metaimage with an MSS (Arm) and a DSS (C6000) component.
function radarMetaimage() {
  const mss = rprc(0x1000);
  const dss = rprc(0x2000);
  const header = Buffer.alloc(128);
  words([
    0x5254534d, 2, 37, 0, 0, 128 + mss.length + dss.length, // "MSTR", 2 records, device 37, size
    1, 0x35510000, 128, 0, 0, mss.length, 0, 0, // present, MSS, offset, size
    1, 0xd5510000, 128 + mss.length, 0, 0, dss.length, 0, 0, // present, DSS, offset, size
    0, 0x444e454d, // shared memory, "MEND"
  ]).copy(header);
  return Buffer.concat([header, mss, dss]);
}

// C28x boot table (big-endian): key, eight reserved words, entry 0x3F0000,
// one 1-word section at 0x3F0000, terminator.
const bootTable = Buffer.from('08aa00000000000000000000000000000000003f00000001003f000012340000', 'hex');

// OAD image with a single contiguous segment of eight bytes.
function oad() {
  const image = Buffer.alloc(64, 0xff);
  image.write('CC26x2R1');
  image[18] = 1; // image type
  image.writeUInt32LE(64, 24); // image length
  image.writeUInt32LE(0x1000, 28); // entry
  image.writeUInt16LE(44, 40); // header length
  image[44] = 1; // segment type: contiguous image
  image.writeUInt32LE(20, 48); // segment length
  image.writeUInt32LE(0x1000, 52); // load address
  image.fill(0x12, 56);
  return image;
}

// MCUboot header with a 4-byte image and an AES-128 encryption flag.
function mcuboot() {
  const image = Buffer.alloc(36);
  image.writeUInt32LE(0x96f3b83d);
  image.writeUInt16LE(32, 8); // header size
  image.writeUInt32LE(4, 12); // image size
  image.writeUInt32LE(4, 16); // flags
  return image;
}

// FIP with a single BL33 entry holding an RPRC image.
function fip() {
  const image = rprc(0x1000);
  const fip = Buffer.alloc(96 + image.length);
  fip.writeUInt32LE(0xaa640001);
  fip.writeUInt32LE(12345678, 4); // serial number
  fip.set(Buffer.from('d6d0eea7fcead54b97829934f234b6e4', 'hex'), 16); // BL33 UUID
  fip.writeBigUInt64LE(96n, 32); // offset
  fip.writeBigUInt64LE(BigInt(image.length), 40); // size
  fip.writeBigUInt64LE(BigInt(fip.length), 72); // terminator: package size
  image.copy(fip, 96);
  return fip;
}

// TI-tagged file: identifier, one data record with checksum, end of file.
function tagged() {
  const record = '90000B1234*567';
  const sum = [...record].reduce((total, c) => total + c.charCodeAt(0), 0);
  const checksum = ((-sum) & 0xffff).toString(16).padStart(4, '0').toUpperCase();
  return Buffer.from(`KfixtureF\n${record}${checksum}F\n:\n`);
}

// One Extended Tektronix record; the checksum is the sum of all other digits.
function tek(type, address, bytes) {
  const body = `8${address.toString(16).padStart(8, '0')}${bytes.toString('hex')}`.toUpperCase();
  const prefix = `${(body.length + 5).toString(16).padStart(2, '0')}${type}`.toUpperCase();
  const checksum = [...prefix + body].reduce((sum, digit) => sum + parseInt(digit, 16), 0) & 0xff;
  return `%${prefix}${checksum.toString(16).padStart(2, '0')}${body}\n`;
}

const asciiHex = bytes => Buffer.from(`\x02${[...bytes].map(b => b.toString(16).padStart(2, '0')).join(' ')}\x03`);

// One fixture per TI or shared format ID.
async function formatFixtures() {
  return [
    ['tiboot', bootTable],
    ['tiais', words([0x41504954, 0x58535906, 0x1000])], // "TIPA", jump & close to 0x1000
    ['tirprc', rprc(0x1000)],
    ['timulticore', await fixture('vendor.appimage')],
    ['timcelf', await fixture('vendor.mcelf')],
    ['tiimage', Buffer.concat([words([16, 0x80000000]), Buffer.alloc(16, 0x42)])],
    ['tioad', oad()],
    ['tix509', await fixture('vendor.signed')],
    ['tiasciihex', asciiHex(bootTable)],
    ['titagged', tagged()],
    ['titekhex', Buffer.from(tek(6, 0x1000, Buffer.from([1, 2, 3])) + tek(8, 0x1000, Buffer.alloc(0)))],
    ['mcuboot', mcuboot()],
    ['fip', fip()],
    ['tidata', Buffer.from('1651 1 800 1 2\n0x1234\n0x5678\n')],
  ];
}

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`all additional TI/shared format IDs survive WASM serialization from ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const fixtures = (await formatFixtures()).map(([format, bytes]) => ({ format, bytes: [...bytes] }));
    const payloads = await page.evaluate(async ({ module, fixtures }) => {
      const wasm = await import(module);
      await wasm.default();
      return fixtures.map(f => JSON.parse(wasm.classify(new Uint8Array(f.bytes))));
    }, { module, fixtures });

    const byFormat = {};
    fixtures.forEach(({ format }, i) => {
      const p = payloads[i];
      assert.ok(!p.error, `${format}: ${p.error}`);
      assert.equal(p.format.format, format);
      assert.notEqual(fmtFormatName(format), format.toUpperCase());
      byFormat[format] = p;
    });
    for (const format of ['mcuboot', 'tidata']) {
      assert.deepEqual(byFormat[format].primary.isa, { unknown: 0 });
      assert.deepEqual(byFormat[format].candidates, []);
    }
    assert.equal(byFormat.tiboot.primary.isa, 'ti_c28x');
    assert.equal(byFormat.tiasciihex.primary.isa, 'ti_c28x');

    // A bare AIS magic is a recognized but malformed container.
    const malformed = await page.evaluate(async module => {
      const wasm = await import(module);
      return JSON.parse(wasm.classify(new TextEncoder().encode('TIPA')));
    }, module);
    assert.match(malformed.error, /TI container parse error/);
  });
}

async function open(page, path) {
  if (path.includes('/classic/')) {
    await page.goto(baseUrl + path);
    await page.waitForFunction(() => document.getElementById('version').textContent.startsWith('v'));
  } else {
    await load(page, path);
  }
}

async function rawJson(page, classic) {
  if (classic) await page.getByRole('button', { name: 'Raw JSON' }).click();
  else await page.getByRole('tab', { name: 'json', exact: true }).click();
  return JSON.parse(await page.locator('#jsonRaw').textContent());
}

for (const path of ['/web/index.html', '/dist/index.html', '/web/classic/index.html', '/dist/classic/index.html']) {
  test(`radar roles and TI-generated wrappers display component metadata in ${path}`, async t => {
    const page = await openPage(t);
    const classic = path.includes('/classic/');
    await open(page, path);
    const files = [
      {
        name: 'radar.bin',
        buffer: radarMetaimage(),
        format: 'TI Multicore Appimage',
        check: p => {
          assert.equal(p.primary.isa, 'arm');
          assert.deepEqual(p.slices.map(s => s.isa), ['arm', 'ti_c6000']);
          assert.equal(p.slices[1].offset, 172);
          assert.deepEqual(p.candidates, []);
        },
      },
      {
        name: 'signed.bin',
        buffer: await fixture('vendor.signed'),
        format: 'TI X.509 Boot Image',
        check: p => {
          assert.equal(p.slices[0].label, 'Boot image');
          assert.ok(p.notes.some(n => n.message.includes('not authenticated')));
        },
      },
      {
        name: 'multicore.elf',
        buffer: await fixture('vendor.mcelf'),
        format: 'TI Multicore ELF',
        check: p => {
          assert.deepEqual(p.slices.map(s => s.label), ['Core 4 code segment', 'Core 14 code segment']);
          assert.ok(p.metadata.some(m => m.label === 'Core 14 code segment'));
        },
      },
    ];
    await page.locator('#fileinput').setInputFiles(
      files.map(({ name, buffer }) => ({ name, buffer, mimeType: 'application/octet-stream' })),
    );
    await finished(page, files.length);
    for (const [i, file] of files.entries()) {
      await selectEntry(page, i);
      const content = page.locator(classic ? '#results' : '#classification-content');
      assert.ok((await content.textContent()).includes(file.format), file.name);
      file.check(await rawJson(page, classic));
    }
    assert.equal(isaName('ti_c5400'), 'TI C54x');
  });
}
