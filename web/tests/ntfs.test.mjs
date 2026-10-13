import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { gunzipSync } from 'node:zlib';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';

before(setup);
after(teardown);

// The volumes are committed gzip-compressed; the tests classify the volumes themselves.
const fixture = async name => gunzipSync(await readFile(new URL(`../../tests/fixtures/ntfs/${name}.gz`, import.meta.url)));

// linked.exe's first name in its attribute list: a 200-character hard link.
const LINKED = `/bin/${'L'.repeat(200)}1`;

// ntfs-3g volumes (tests/fixtures/ntfs/README.md): the recognized members in
// MFT record order, the ISA each classifies as, and for members that are not
// stored as they are, the transform and the decoded size.
const IMAGES = [
  {
    name: 'ntfs.img',
    members: [
      ['/payload.elf', 'x86_64', 'NTFS update sequence', 256],
      ['/Program Files/Zrax/app.exe', 'x86_64'],
      ['/notes.txt:payload.macho', 'a_arch64'],
      ['/compressed/zrax.macho', 'a_arch64', 'NTFS LZNT1', 102400],
      ['/sparse.elf', 'x86_64', 'NTFS runs', 135168],
      ['/bin/fragmented.elf', 'x86_64', 'NTFS runs', 40960],
      [LINKED, 'x86_64'],
      [`${LINKED}:payload.elf`, 'x86_64'],
    ],
  },
  {
    name: 'ntfs-4k.img',
    members: [
      ['/payload.elf', 'x86_64', 'NTFS update sequence', 256],
      ['/Program Files/Zrax/app.exe', 'x86_64'],
      ['/compressed/zrax.macho', 'a_arch64', 'NTFS LZNT1', 102400],
    ],
  },
  {
    name: 'ntfs-512.img',
    members: [
      ['/payload.elf', 'x86_64', 'NTFS update sequence', 256],
      ['/compressed/zrax.macho', 'a_arch64', 'NTFS LZNT1', 102400],
      ['/bin/fragmented.elf', 'x86_64', 'NTFS runs', 10240],
    ],
  },
];

const slice = (payload, label) => payload.slices.find(s => s.label === label);

// Classify buffers in the page; they cross into it as base64 text.
async function classifyAll(page, module, buffers) {
  const inputs = buffers.map(buffer => buffer.toString('base64'));
  return page.evaluate(async ({ module, inputs }) => {
    const wasm = await import(module);
    await wasm.default();
    return inputs.map(base64 => JSON.parse(wasm.classify(Uint8Array.from(atob(base64), c => c.charCodeAt(0)))));
  }, { module, inputs });
}

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`NTFS volumes list their recognized files and streams through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const buffers = await Promise.all(IMAGES.map(image => fixture(image.name)));
    const payloads = await classifyAll(page, module, buffers);
    IMAGES.forEach(({ name, members }, i) => {
      const p = payloads[i];
      assert.ok(!p.error, `${name}: ${p.error}`);
      assert.equal(p.format.format, 'ntfs', name);
      assert.equal(p.format.variant_name, 'NTFS', name);
      assert.equal(p.primary.isa, 'x86_64', `${name}: the first member decides`);
      assert.deepEqual(p.slices.map(s => s.label), members.map(([label]) => label), name);
      for (const [label, isa, transform, size] of members) {
        const member = slice(p, label);
        assert.equal(member.isa, isa, `${name} ${label}`);
        if (transform) {
          assert.equal(member.decoded.transform, transform, `${name} ${label}`);
          assert.equal(member.decoded.size, size, `${name} ${label}`);
        } else {
          assert.equal(member.decoded, undefined, `${name} ${label}: stored as it is`);
        }
      }
      assert.ok(p.notes.some(n => n.message.startsWith('NTFS 3.1 volume')), name);
    });
    assert.ok(Object.hasOwn(FORMAT_NAMES, 'ntfs'), 'ntfs has a display name');
    const main = payloads[0];
    assert.ok(main.metadata.some(m => m.key?.custom === 'ntfs_volume_name' && m.value === 'ZRAX'));
    assert.ok(main.notes.some(n => n.message.includes('decoded from LZNT1 compression units')));
    assert.ok(main.notes.some(n => n.message.includes('counted, not followed')));
  });
}

// The first 960 KiB of ntfs.img, as a container that decodes only part of a
// volume hands it on: the members whose data lies in it are listed.
const TRUNCATED_END = 0xf0000;
const TRUNCATED_MEMBERS = ['/payload.elf', '/Program Files/Zrax/app.exe', '/notes.txt:payload.macho'];

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`a truncated NTFS volume lists the files present through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const prefix = (await fixture('ntfs.img')).subarray(0, TRUNCATED_END);
    const [p] = await classifyAll(page, module, [prefix]);
    assert.ok(!p.error, p.error);
    assert.equal(p.format.format, 'ntfs');
    assert.deepEqual(p.slices.map(s => s.label), TRUNCATED_MEMBERS);
    assert.ok(p.slices.every(s => s.offset + s.size <= TRUNCATED_END), 'members lie inside the input');
    assert.ok(p.notes.some(n => n.message.startsWith('Volume truncated: 960 KiB of 4193792 B present')));
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names NTFS volumes and keeps stored member offsets in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = await fixture('ntfs.img');
    const file = { name: 'volume.img', buffer, mimeType: 'application/octet-stream' };
    await page.locator('#fileinput').setInputFiles([file]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.ntfs), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'x86_64');
    const member = slice(p, '/Program Files/Zrax/app.exe');
    const pe = buffer.subarray(member.offset, member.offset + member.size);
    assert.deepEqual([...pe.subarray(0, 2)], [0x4d, 0x5a], 'the stored offset holds the PE');
  });
}
