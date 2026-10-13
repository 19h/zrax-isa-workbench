import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { gunzipSync } from 'node:zlib';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

const fixture = name => readFile(new URL(`../../tests/fixtures/adf/${name}`, import.meta.url));

// amitools images of the same tree (tests/fixtures/adf/README.md): the Hunk executables in walk order. The root's
// files come in hash-table order; the three file_* names share one slot and form a hash chain.
const MEMBERS = ['/hello', '/café', '/file_5u', '/file_24', '/file_1a', '/c/run', '/c/deep/big'];
const LONG_NAME = '/A file name that is longer than thirty characters';
const FLOPPIES = [
  { name: 'ofs.adf.gz', variant: 'AmigaDOS DD floppy', dosType: 'DOS\\0', transform: 'AmigaDOS OFS data blocks' },
  { name: 'ffs.adf.gz', variant: 'AmigaDOS DD floppy', dosType: 'DOS\\1', transform: 'AmigaDOS FFS data blocks' },
  { name: 'dircache.adf.gz', variant: 'AmigaDOS DD floppy', dosType: 'DOS\\5', transform: 'AmigaDOS FFS data blocks' },
  { name: 'longnames.adf.gz', variant: 'AmigaDOS DD floppy', dosType: 'DOS\\7', transform: 'AmigaDOS FFS data blocks' },
  { name: 'hd.adf.gz', variant: 'AmigaDOS HD floppy', dosType: 'DOS\\3', transform: 'AmigaDOS FFS data blocks' },
];
// /c/deep/big: a Hunk executable with 80 KiB of code, reassembled across two extension blocks.
const BIG_SIZE = 81956;
const RDB_SLICES = ['DH0:/hello', 'DH0:/c/run', 'DH1:/tool', 'File system DOS\\3 version 45.13'];
const HUNK_HEADER = [0x00, 0x00, 0x03, 0xf3];

const slice = (payload, label) => payload.slices.find(s => s.label === label);
const custom = (payload, key) => payload.metadata.find(m => m.key?.custom === key)?.value;

function members(floppy) {
  if (floppy.name !== 'longnames.adf.gz') return MEMBERS;
  return [...MEMBERS.slice(0, 5), LONG_NAME, ...MEMBERS.slice(5)];
}

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`Amiga disk images list their Hunk executables through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    // The images travel gzip-compressed (a few KiB each) and are decompressed in the page; the last one is
    // classified as committed, so the classifier decodes the gzip stream and reports the image inside.
    const inputs = [];
    for (const name of [...FLOPPIES.map(floppy => floppy.name), 'rdb.hdf.gz']) {
      inputs.push({ name, bytes: [...await fixture(name)], decompress: true });
    }
    inputs.push({ name: 'ffs.adf.gz', bytes: [...await fixture('ffs.adf.gz')], decompress: false });
    const payloads = await page.evaluate(async ({ module, inputs }) => {
      const wasm = await import(module);
      await wasm.default();
      const gunzip = async bytes => {
        const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'));
        return new Uint8Array(await new Response(stream).arrayBuffer());
      };
      const results = [];
      for (const input of inputs) {
        const stored = new Uint8Array(input.bytes);
        const image = input.decompress ? await gunzip(stored) : stored;
        results.push(JSON.parse(wasm.classify(image)));
      }
      return results;
    }, { module, inputs });
    payloads.forEach((p, i) => assert.ok(!p.error, `${inputs[i].name}: ${p.error}`));

    FLOPPIES.forEach((floppy, i) => {
      const p = payloads[i];
      assert.equal(p.format.format, 'adf', floppy.name);
      assert.equal(p.format.variant_name, floppy.variant, floppy.name);
      assert.equal(p.primary.isa, 'm68k', floppy.name);
      const expected = floppy.name === 'ffs.adf.gz' ? [...members(floppy), 'Boot block code'] : members(floppy);
      assert.deepEqual(p.slices.map(s => s.label), expected, floppy.name);
      assert.ok(p.slices.every(s => s.isa === 'm68k'), `${floppy.name}: members are classified on their own`);
      const big = slice(p, '/c/deep/big');
      assert.equal(big.decoded.transform, floppy.transform, floppy.name);
      assert.equal(big.decoded.size, BIG_SIZE, floppy.name);
      assert.equal(custom(p, 'adf_dos_type'), floppy.dosType, floppy.name);
      assert.equal(custom(p, 'adf_member_count'), members(floppy).length, floppy.name);
    });

    const ffs = payloads[1];
    const boot = slice(ffs, 'Boot block code');
    assert.equal(boot.offset, 12);
    assert.equal(boot.size, 1012);
    assert.equal(boot.bitwidth, 32);
    assert.equal(boot.endianness, 'big');
    const primaryNote = 'Primary ISA selected from /hello; other components are listed separately';
    assert.ok(ffs.notes.some(n => n.message === primaryNote));

    const rdb = payloads[FLOPPIES.length];
    assert.equal(rdb.format.format, 'amigahdf');
    assert.equal(rdb.format.variant_name, 'Rigid Disk Block');
    assert.equal(rdb.primary.isa, 'm68k');
    assert.deepEqual(rdb.slices.map(s => s.label), RDB_SLICES);
    assert.equal(slice(rdb, 'File system DOS\\3 version 45.13').decoded.transform, 'RDB LoadSeg blocks');
    assert.equal(custom(rdb, 'adf_partition_0_volume_name'), 'Work');

    const gzip = payloads[FLOPPIES.length + 1];
    assert.equal(gzip.format.format, 'gzip');
    assert.equal(gzip.primary.isa, 'm68k');
    assert.deepEqual(gzip.slices.map(s => s.label), [...MEMBERS, 'Boot block code']);
    assert.ok(gzip.notes.some(n => n.message === `Decoded payload: ${FORMAT_NAMES.adf}`), JSON.stringify(gzip.notes));

    for (const id of ['adf', 'amigahdf']) assert.ok(Object.hasOwn(FORMAT_NAMES, id), `${id} has a display name`);
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names ADF images and keeps stored member offsets in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = gunzipSync(await fixture('ffs.adf.gz'));
    const file = { name: 'disk.adf', buffer, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([file]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.adf), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'm68k');
    const hello = slice(p, '/hello');
    const stored = buffer.subarray(hello.offset, hello.offset + hello.size);
    assert.deepEqual([...stored.subarray(0, 4)], HUNK_HEADER, 'the stored offset holds the Hunk executable');
  });
}
