import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { setup, teardown, openPage, load, drop, finished, selectEntry } from './helpers.mjs';
before(setup); after(teardown);

const key = Buffer.from('4191e5094ea2fa226bc31f4b98f45484d53599cd2286ee267fe7538fec58c80869d94d91f66ae22a930b87d340bc3c8cfd7d0155ca4ed62ea72fbb179420b0109121b5199e32ca32bb53ef5be884249425c569dd7216be36cf77239f3ce89818b9691da146fab23ae39b57e3904c0c9c4d0dd1651adea63ef7bf8b27e4b08020', 'hex');
function xor(bytes) { for (let i = 0; i < bytes.length; i++) bytes[i] ^= key[i % 128]; }
function firmware(name, encrypted = false) {
  const code = Buffer.from([0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0x48, 0x89, 0x7d, 0xf8, 0x48, 0x89, 0x75, 0xf0, 0x48, 0x8b, 0x45, 0xf8, 0x48, 0x03, 0x45, 0xf0, 0x66, 0x0f, 0x38, 0xdc, 0xc1, 0x48, 0x89, 0xec, 0x5d, 0xc3]);
  const cpu = Buffer.concat(Array.from({ length: 128 }, () => code));
  const chunks = [Buffer.from('2504B     000243')];
  function record(section, block, address, bytes) {
    const header = Buffer.alloc(10); header[0] = section; header[1] = block;
    header.writeUInt32BE(address, 2); header.writeUInt32BE(bytes.length, 6); chunks.push(header, bytes);
  }
  for (let section = 0; section < 5; section++) {
    record(section, 0, 0x100000 + section * 0x40000, section === 1 ? Buffer.from(cpu) : Buffer.alloc(0));
    record(section, 1, 0x13ffea + section * 0x40000, Buffer.alloc(0));
  }
  if (encrypted) xor(cpu);
  record(5, 0, 0x380100, cpu);
  const vectors = Buffer.alloc(encrypted ? 256 : 128, 0xff);
  if (encrypted) { vectors[127] = 0; xor(vectors.subarray(128)); }
  record(5, 1, 0x3fff80, vectors);
  const body = Buffer.concat(chunks), trailer = Buffer.alloc(2);
  let crc = 0xffff;
  for (const byte of body) { crc ^= byte; for (let i = 0; i < 8; i++) crc = crc >>> 1 ^ (crc & 1 ? 0x8408 : 0); }
  trailer.writeUInt16LE(crc ^ 0xffff);
  return { name, mimeType: 'application/octet-stream', buffer: Buffer.concat([body, trailer]) };
}
const payload = async page => JSON.parse(await page.locator('#jsonRaw').textContent());
async function result(page, index) { await selectEntry(page, index); await page.getByRole('tab', { name: 'json', exact: true }).click(); return payload(page); }

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`D10 plaintext and encoded multi-blob files work through batch drop in ${path}`, async t => {
    const page = await openPage(t); await load(page, path);
    await drop(page, [firmware('plain.D10'), firmware('encoded.D10', true)]); await finished(page, 2);
    const a = await result(page, 0), b = await result(page, 1);
    assert.equal(a.format.format, 'd10'); assert.equal(a.primary.isa, 'x86_64');
    assert.deepEqual(b.primary, a.primary); assert.deepEqual(b.candidates, a.candidates); assert.deepEqual(b.extensions, a.extensions);
    assert.deepEqual(a.slices.map(s => s.label), ['CPU 5:0', 'DSP 1:0']);
    assert.equal(a.metadata.find(m => m.key === 'section_count').value, 12);
    assert.ok(b.metadata.some(m => m.label === 'CPU encoding' && m.value.includes('decoded')));
    await page.getByRole('tab', { name: 'classification', exact: true }).click();
    const text = await page.locator('#classification-content').textContent();
    assert.match(text, /AOR D10/); assert.match(text, /CPU 5:0/); assert.match(text, /DSP 1:0/);
    assert.match(text, /FPGA 0:0/); assert.match(text, /DSP 4:0/);
  });
}

test('D10 checksum failure is explicit and retains original-file inspection', async t => {
  const page = await openPage(t); await load(page);
  const file = firmware('broken.D10'); file.buffer[file.buffer.length - 1] ^= 1;
  await page.locator('#fileinput').setInputFiles(file); await finished(page, 1);
  assert.equal(await page.locator('#file-status').textContent(), 'failed');
  assert.match(await page.locator('#classification-content').textContent(), /Invalid checksum.*D10 CRC16/);
  await page.getByRole('tab', { name: 'entropy', exact: true }).click();
  await page.waitForFunction(() => document.getElementById('entropy-map').dataset.state === 'ready');
  await page.getByRole('tab', { name: 'hex', exact: true }).click();
  await page.waitForFunction(() => document.querySelector('#hex-rows .hex-byte[data-offset="0"]')?.textContent === '32');
});

test('requested real D10 firmware exposes RX and two Blackfin DSP blobs in packaged workbench', { skip: !process.env.D10_FIXTURE }, async t => {
  const page = await openPage(t); await load(page, '/dist/index.html');
  await page.locator('#fileinput').setInputFiles(process.env.D10_FIXTURE); await finished(page, 1);
  const p = await result(page, 0);
  assert.equal(p.format.format, 'd10'); assert.equal(p.primary.isa, 'rx');
  assert.deepEqual(p.slices.map(s => [s.label, s.isa, s.offset, s.size]), [
    ['CPU 5:0', 'rx', 0x782ef, 0x77200],
    ['DSP 1:0', 'blackfin', 0x3a6d3, 0x1ec90],
    ['DSP 2:0', 'blackfin', 0x5938d, 0x1ef10],
  ]);
  const body = await readFile(process.env.D10_FIXTURE);
  assert.equal(body.length, 980347);
  assert.equal(p.metadata.filter(m => /^(CPU|DSP|FPGA) \d:\d$/.test(m.label)).length, 12);
  await page.getByRole('tab', { name: 'classification', exact: true }).click();
  const text = await page.locator('#classification-content').textContent();
  assert.match(text, /CPU 5:0.*RX/); assert.match(text, /DSP 1:0.*Blackfin/); assert.match(text, /DSP 2:0.*Blackfin/);
});
