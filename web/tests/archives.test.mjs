import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

const fixture = name => readFile(new URL(`../../tests/fixtures/archives/${name}`, import.meta.url));

// Each committed archive holds the synthetic AArch64 ELF `bin/payload.elf`
// and a text member; the fixture, its format ID and the codec named on the
// ELF member's slice (null when it is stored).
const ARCHIVES = [
  ['stored.zip', 'zip', null],
  ['deflate.zip', 'zip', 'DEFLATE'],
  ['descriptor.zip', 'zip', 'DEFLATE'],
  ['zip64.zip', 'zip', 'DEFLATE'],
  ['bzip2.zip', 'zip', 'bzip2'],
  ['lzma.zip', 'zip', 'LZMA'],
  ['xz.zip', 'zip', 'xz'],
  ['zstd.zip', 'zip', 'Zstandard'],
  ['ustar.tar', 'tar', null],
  ['pax.tar', 'tar', null],
  ['gnu.tar', 'tar', null],
  ['newc.cpio', 'cpio', null],
  ['odc.cpio', 'cpio', null],
  ['binary.cpio', 'cpio', null],
];

const OPAQUE = ['encrypted.zip', 'aes.zip', 'deflate64.zip'];

async function classifyAll(page, module, names) {
  const fixtures = await Promise.all(names.map(async name => ({ name, bytes: [...await fixture(name)] })));
  return page.evaluate(async ({ module, fixtures }) => {
    const wasm = await import(module);
    await wasm.default();
    return fixtures.map(f => JSON.parse(wasm.classify(new Uint8Array(f.bytes))));
  }, { module, fixtures });
}

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`archive members are classified on their own bytes through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const payloads = await classifyAll(page, module, ARCHIVES.map(([name]) => name));
    ARCHIVES.forEach(([name, format, transform], i) => {
      const p = payloads[i];
      assert.ok(!p.error, `${name}: ${p.error}`);
      assert.equal(p.format.format, format, name);
      assert.ok(Object.hasOwn(FORMAT_NAMES, format), `${format} has a display name`);
      assert.equal(p.primary.isa, 'a_arch64', name);
      const member = p.slices.find(s => s.label === 'bin/payload.elf');
      assert.ok(member, `${name}: ${JSON.stringify(p.slices)}`);
      assert.equal(member.isa, 'a_arch64', name);
      assert.equal(member.decoded?.transform ?? null, transform, name);
      assert.ok(!p.slices.some(s => s.label === 'notes.txt'), `${name}: text members are not listed`);
    });
  });

  test(`encrypted and Deflate64 ZIP members stay opaque through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const payloads = await classifyAll(page, module, OPAQUE);
    OPAQUE.forEach((name, i) => {
      const p = payloads[i];
      assert.equal(p.format.format, 'zip', name);
      assert.deepEqual(p.primary.isa, { unknown: 0 }, name);
      assert.deepEqual(p.slices ?? [], [], name);
      assert.ok(p.notes.some(n => /opaque/.test(n.message)), `${name}: ${JSON.stringify(p.notes)}`);
    });
  });

  test(`a gzip-compressed CPIO keeps the stored range and the decoded offset through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const [p] = await classifyAll(page, module, ['initramfs.cpio.gz']);
    const stored = await fixture('initramfs.cpio.gz');
    assert.equal(p.format.format, 'gzip');
    assert.equal(p.primary.isa, 'a_arch64');
    const member = p.slices.find(s => s.label === 'bin/payload.elf');
    assert.equal(member.offset, 0);
    assert.equal(member.size, stored.length);
    assert.equal(member.decoded.transform, 'gzip');
    assert.equal(member.decoded.size, 256);
    assert.ok(p.notes.some(n => n.message === 'Decoded payload: CPIO'));
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names archive formats and lists the member in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = await fixture('deflate.zip');
    await page.locator('#fileinput').setInputFiles([{ name: 'firmware.zip', buffer, mimeType: 'application/zip' }]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.zip), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.format.format, 'zip');
    assert.equal(p.primary.isa, 'a_arch64');
    assert.ok(p.metadata.some(m => m.key?.custom === 'zip_crc_verified' && m.value === 2));
  });
}
