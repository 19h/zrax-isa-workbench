import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, baseUrl } from './helpers.mjs';
before(setup); after(teardown);

const bootTable = Buffer.from(
  '09aa00000201000000010000007e1cce202000040000010046b3e6000098e68a202020200000',
  'hex',
);

async function classify(page, path, file) {
  const classic = path.includes('/classic/');
  if (classic) {
    await page.goto(baseUrl + path);
    await page.waitForFunction(() => document.getElementById('version').textContent.startsWith('v'));
  } else {
    await load(page, path);
  }
  await page.locator('#fileinput').setInputFiles(file);
  await finished(page, 1);
  const text = await page.locator(classic ? '#results' : '#classification-content').textContent();
  assert.match(text, /TI C55x Boot Table/);
  assert.match(text, /TI C55x/);
  assert.match(text, /exact device model is not encoded/);
  if (classic) await page.getByRole('button', { name: 'Raw JSON' }).click();
  else await page.getByRole('tab', { name: 'json', exact: true }).click();
  return JSON.parse(await page.locator('#jsonRaw').textContent());
}

for (const path of ['/web/index.html', '/dist/index.html', '/web/classic/index.html', '/dist/classic/index.html']) {
  test(`TI C55x boot table uses the format parser and displays its load metadata in ${path}`, async t => {
    const page = await openPage(t);
    const p = await classify(page, path, { name: 'boot.bin', mimeType: 'application/octet-stream', buffer: bootTable });
    assert.equal(p.format.format, 'tic55xboot');
    assert.equal(p.primary.isa, 'ti_c5500');
    assert.equal(p.primary.bitwidth, 16);
    assert.equal(p.primary.endianness, 'big');
    assert.equal(p.primary.source, 'file_format');
    assert.equal(p.metadata.find(m => m.key === 'entry_point').value, 0x201);
    assert.equal(p.metadata.find(m => m.key === 'section_count').value, 2);
    assert.equal(p.metadata.find(m => m.label === 'Entry point file offset (B)').value, 25);
    assert.ok(p.metadata.some(m => m.label === 'Load section 1 (code/data)' && m.value.includes('word 0x00007E / byte 0x0000FC; 1 words / 2 B')));
  });
}

for (const path of ['/dist/index.html', '/dist/classic/index.html']) {
  test(`reported RX113 firmware is recognized as TI C55x in ${path}`, { skip: !process.env.TI_C55X_FIXTURE }, async t => {
    const page = await openPage(t);
    const p = await classify(page, path, process.env.TI_C55X_FIXTURE);
    assert.equal(p.format.format, 'tic55xboot');
    assert.equal(p.primary.isa, 'ti_c5500');
    assert.equal(p.primary.source, 'file_format');
    assert.equal(p.metadata.find(m => m.key === 'entry_point').value, 0x4c665);
    assert.equal(p.metadata.find(m => m.key === 'section_count').value, 15);
    assert.equal(p.metadata.find(m => m.label === 'Entry point file offset (B)').value, 0x29207);
  });
}
