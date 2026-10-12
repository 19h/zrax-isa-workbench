import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup); after(teardown);

const fixture = name => readFile(new URL(`../../tests/fixtures/compressed/${name}`, import.meta.url));

// Each committed stream holds the same synthetic x86-64 ELF header.
const STREAMS = [
  ['payload.elf.gz', 'gzip'],
  ['payload.elf.xz', 'xz'],
  ['payload.elf.lzma', 'lzma'],
  ['payload.elf.lz4', 'lz4'],
  ['payload.elf.legacy.lz4', 'lz4'],
  ['payload.elf.zst', 'zstd'],
  ['payload.elf.bz2', 'bzip2'],
  ['payload.elf.lzo', 'lzop'],
  ['payload.elf.lzfse', 'lzfse'],
];

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`compressed streams decode to their ELF payload through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const fixtures = await Promise.all(STREAMS.map(async ([name, format]) => ({ name, format, bytes: [...await fixture(name)] })));
    const payloads = await page.evaluate(async ({ module, fixtures }) => {
      const wasm = await import(module);
      await wasm.default();
      return fixtures.map(f => JSON.parse(wasm.classify(new Uint8Array(f.bytes))));
    }, { module, fixtures });
    fixtures.forEach(({ name, format }, i) => {
      const p = payloads[i];
      assert.ok(!p.error, `${name}: ${p.error}`);
      assert.equal(p.format.format, format, name);
      assert.equal(p.primary.isa, 'x86_64', name);
      assert.ok(Object.hasOwn(FORMAT_NAMES, format), `${format} has a display name`);
      assert.ok(p.notes.some(n => n.message === 'Decoded payload: ELF'), name);
    });
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names compressed formats and keeps stored offsets in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = await fixture('payload.elf.xz');
    await page.locator('#fileinput').setInputFiles([{ name: 'kernel.xz', buffer, mimeType: 'application/octet-stream' }]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes('xz'), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'x86_64');
    assert.ok(p.metadata.some(m => m.key?.custom === 'compressed_stored_size' && m.value === buffer.length));
  });
}
