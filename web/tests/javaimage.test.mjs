import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

const fixture = name => readFile(new URL(`../../tests/fixtures/javaimage/${name}`, import.meta.url));

// jimages written by the JDK's jimage writer from one synthetic module (tests/fixtures/javaimage/README.md), and
// the transform each reports for its class files (none when stored).
const IMAGES = [
  { name: 'sample-le.jimage', variant: 'jimage (little-endian)', transform: undefined },
  { name: 'sample-be.jimage', variant: 'jimage (big-endian)', transform: undefined },
  { name: 'sample-zip.jimage', variant: 'jimage (little-endian)', transform: 'jimage zip' },
  { name: 'sample-compact-cp.jimage', variant: 'jimage (little-endian)', transform: 'jimage compact-cp' },
];
const RESOURCES = [
  '/zrax.sample/zrax/sample/Hello.class',
  '/zrax.sample/zrax/sample/payload.elf',
  '/zrax.sample/module-info.class',
];
const HELLO_SIZE = 995;

const slice = (payload, label) => payload.slices.find(s => s.label === label);

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`jimages and JMODs list their class files through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const names = [...IMAGES.map(image => image.name), 'sample.jmod'];
    const files = await Promise.all(names.map(async name => ({ name, bytes: [...await fixture(name)] })));
    const payloads = await page.evaluate(async ({ module, files }) => {
      const wasm = await import(module);
      await wasm.default();
      return files.map(file => JSON.parse(wasm.classify(new Uint8Array(file.bytes))));
    }, { module, files });
    IMAGES.forEach(({ name, variant, transform }, i) => {
      const p = payloads[i];
      assert.ok(!p.error, `${name}: ${p.error}`);
      assert.equal(p.format.format, 'jimage', name);
      assert.equal(p.format.variant_name, variant, name);
      assert.equal(p.primary.isa, 'jvm', name);
      assert.deepEqual(p.slices.map(s => s.label), RESOURCES, name);
      assert.deepEqual(p.slices.map(s => s.isa), ['jvm', 'x86_64', 'jvm'], name);
      const hello = slice(p, RESOURCES[0]);
      assert.equal(hello.decoded?.transform, transform, name);
      assert.equal(hello.decoded ? hello.decoded.size : hello.size, HELLO_SIZE, name);
    });
    const jmod = payloads[IMAGES.length];
    assert.ok(!jmod.error, jmod.error);
    assert.equal(jmod.format.format, 'jmod');
    assert.equal(jmod.primary.isa, 'jvm');
    assert.deepEqual(jmod.slices.map(s => [s.label, s.offset]), [['ZIP archive', 4]]);
    assert.ok(Object.hasOwn(FORMAT_NAMES, 'jimage'), 'jimage has a display name');
    assert.ok(Object.hasOwn(FORMAT_NAMES, 'jmod'), 'jmod has a display name');
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names jimages and keeps stored resource offsets in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = await fixture('sample-le.jimage');
    await page.locator('#fileinput').setInputFiles([{ name: 'modules', buffer, mimeType: 'application/octet-stream' }]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.jimage), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'jvm');
    const hello = slice(p, RESOURCES[0]);
    const stored = buffer.subarray(hello.offset, hello.offset + 4);
    assert.deepEqual([...stored], [0xca, 0xfe, 0xba, 0xbe], 'the stored offset holds the class file');
    assert.ok(p.metadata.some(m => m.key?.custom === 'jimage_resources' && m.value === 4));
  });
}
