// The all-files certificates view: distinct certificates across open files,
// issuer links between files, navigation to each copy, the download-all
// formats and the stored ZIP writer behind them.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { crc32 as zlibCrc32 } from 'node:zlib';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, holdRead, releaseRead } from './helpers.mjs';
import { crc32, zipArchive } from '../zip.js';

before(setup);
after(teardown);

const fixture = name => readFile(new URL(`../../tests/fixtures/certificates/${name}`, import.meta.url));

/** Deterministic noise from a 32-bit linear congruential generator. */
function noise(length, seed) {
  const data = Buffer.alloc(length);
  let state = seed;
  for (let i = 0; i < length; i++) {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    data[i] = state >>> 24;
  }
  return data;
}

/** A file of `length` noise bytes with each `[offset, bytes]` part copied in. */
function binary(name, length, seed, parts) {
  const buffer = noise(length, seed);
  for (const [offset, bytes] of parts) bytes.copy(buffer, offset);
  return { name, mimeType: 'application/octet-stream', buffer };
}

/**
 * Four files whose certificates chain only across files: the root in
 * `a.bin` (0x10) and `c.bin` (0x600), the intermediate in `b.bin` (0x20), the
 * leaf in `c.bin` (0x100), and nothing in `d.bin`.
 */
async function spreadChain() {
  const root = await fixture('root.der');
  return [
    binary('a.bin', 0x800, 11, [[0x10, root]]),
    binary('b.bin', 0x800, 12, [[0x20, await fixture('intermediate.der')]]),
    binary('c.bin', 0x1000, 13, [[0x100, await fixture('leaf.der')], [0x600, root]]),
    binary('d.bin', 0x400, 14, []),
  ];
}

/** The PEM blocks of `chain.pem`: leaf, intermediate, root. */
async function chainBlocks() {
  const text = (await fixture('chain.pem')).toString('utf8');
  return text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\n/g);
}

/** Entries of a stored ZIP archive, read through its central directory (APPNOTE 4.3.12, 4.3.16). */
function unzip(data) {
  const end = data.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  assert.ok(end >= 0, 'end of central directory record');
  const count = data.readUInt16LE(end + 10);
  assert.equal(data.readUInt16LE(end + 8), count);
  let at = data.readUInt32LE(end + 16);
  assert.equal(data.readUInt32LE(end + 12), end - at, 'central directory size');
  const entries = [];
  for (let i = 0; i < count; i++) {
    assert.equal(data.readUInt32LE(at), 0x0201_4b50);
    const nameLength = data.readUInt16LE(at + 28);
    const size = data.readUInt32LE(at + 24);
    const local = data.readUInt32LE(at + 42);
    assert.equal(data.readUInt32LE(local), 0x0403_4b50);
    const start = local + 30 + data.readUInt16LE(local + 26) + data.readUInt16LE(local + 28);
    entries.push({
      name: data.toString('utf8', at + 46, at + 46 + nameLength),
      flags: data.readUInt16LE(at + 8),
      method: data.readUInt16LE(at + 10),
      crc: data.readUInt32LE(at + 16),
      compressedSize: data.readUInt32LE(at + 20),
      bytes: data.subarray(start, start + size),
    });
    at += 46 + nameLength + data.readUInt16LE(at + 30) + data.readUInt16LE(at + 32);
  }
  return entries;
}

/** Wait until an element's text matches the regular expression `source`. */
async function elementText(page, id, source) {
  const matches = ([id, source]) => new RegExp(source).test(document.getElementById(id)?.textContent || '');
  await page.waitForFunction(matches, [id, source]);
}

const button = (page, name) => page.getByRole('button', { name, exact: true });

async function openAllCertificates(page, files) {
  await page.locator('#fileinput').setInputFiles(files);
  await finished(page, files.length);
  await button(page, 'Certificates in all files').click();
  await elementText(page, 'all-certificates-status', 'found in|no certificates|no open files');
}

async function treeRows(page) {
  const items = page.getByRole('tree', { name: 'All certificates' }).getByRole('treeitem');
  return items.evaluateAll(nodes => nodes.map(node => [
    node.querySelector('.certificate-name').textContent,
    node.getAttribute('aria-level'),
    node.querySelector('.certificate-details').textContent,
  ]));
}

async function downloadText(page, name) {
  const [download] = await Promise.all([page.waitForEvent('download'), button(page, name).click()]);
  return { name: download.suggestedFilename(), data: await readFile(await download.path()) };
}

test('the ZIP writer stores UTF-8 names, sizes and CRC-32 values', async () => {
  const files = [
    { name: 'a.txt', bytes: new TextEncoder().encode('hello') },
    { name: 'ünïcode/é.bin', bytes: Uint8Array.from(noise(1000, 5)) },
    { name: 'empty', bytes: new Uint8Array() },
  ];
  const data = Buffer.from(await zipArchive(files, new Date(2026, 10, 1, 12, 30, 10)).arrayBuffer());
  const entries = unzip(data);
  assert.deepEqual(entries.map(e => e.name), files.map(f => f.name));
  for (const [i, entry] of entries.entries()) {
    assert.deepEqual([...entry.bytes], [...files[i].bytes]);
    assert.equal(entry.crc, zlibCrc32(files[i].bytes));
    assert.equal(entry.flags, 0x0800);
    assert.equal(entry.method, 0);
    assert.equal(entry.compressedSize, files[i].bytes.length);
  }
  // DOS time 12:30:10 and date 2026-11-01 in the first local header.
  assert.equal(data.readUInt16LE(10), (12 << 11) | (30 << 5) | 5);
  assert.equal(data.readUInt16LE(12), ((2026 - 1980) << 9) | (11 << 5) | 1);
  assert.equal(crc32(new TextEncoder().encode('123456789')), 0xcbf4_3926);
  assert.equal(unzip(Buffer.from(await zipArchive([]).arrayBuffer())).length, 0);
  const tooMany = Array.from({ length: 0x10000 }, (_, i) => ({ name: String(i), bytes: new Uint8Array() }));
  assert.throws(() => zipArchive(tooMany), /Too many files for a ZIP archive: 65536/);
});

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the all-files view links certificates across files into one distinct tree in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    await openAllCertificates(page, await spreadChain());
    assert.match(await button(page, 'Certificates in all files').getAttribute('class'), /\bactive\b/);
    assert.equal(await page.locator('#status-mode').textContent(), 'ALL CERTS');
    assert.equal(await page.locator('#files-panel').isVisible(), false);
    assert.equal(await page.locator('#all-certificates-scope').textContent(), 'across 4 open files');
    assert.equal(await page.locator('#all-certificates-status').textContent(),
      '4 found in 3 of 4 files (3 distinct) · signatures and chains not verified; issuer links compare encoded names');
    assert.deepEqual(await treeRows(page), [
      ['Zrax Fixture Root CA', '1', 'self-issuedca×2RSA 2048 · in 2 files'],
      ['Zrax Fixture Intermediate CA', '2', 'caEC 256 · b.bin @ 0x00000020'],
      ['Zrax Fixture Code Signing', '3', 'Ed25519 255 · c.bin @ 0x00000100'],
    ]);

    const detail = page.locator('#all-certificates-detail');
    const items = page.getByRole('tree', { name: 'All certificates' }).getByRole('treeitem');
    assert.equal(await items.first().getAttribute('aria-selected'), 'true');
    assert.match(await detail.textContent(), /found2 copies in 2 files/);
    assert.match(await detail.textContent(), /signature not verified/);
    const copies = detail.getByRole('table', { name: 'Copies of this certificate' }).locator('tbody tr');
    const cells = rows => rows.map(row => [...row.cells].slice(0, 3).map(cell => cell.textContent));
    assert.deepEqual(await copies.evaluateAll(cells), [
      ['a.bin', '0x00000010', '876 B DER'],
      ['c.bin', '0x00000600', '876 B DER'],
    ]);

    await items.nth(2).click();
    assert.match(await detail.textContent(), /name match/);
    await detail.getByRole('button', { name: 'go to issuer' }).click();
    assert.equal(await items.nth(1).getAttribute('aria-selected'), 'true');
    await page.getByRole('tree', { name: 'All certificates' }).focus();
    await page.keyboard.press('ArrowUp');
    assert.equal(await items.first().getAttribute('aria-selected'), 'true');

    // The filter also matches file names and lists matches flat.
    await page.getByRole('searchbox', { name: 'Filter all certificates' }).fill('c.bin');
    assert.deepEqual((await treeRows(page)).map(([name, level]) => [name, level]), [
      ['Zrax Fixture Root CA', '1'],
      ['Zrax Fixture Code Signing', '1'],
    ]);
  });

  test(`copies open in their file's certificates tab and hex view in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    await openAllCertificates(page, await spreadChain());
    const detail = page.locator('#all-certificates-detail');
    await detail.getByRole('button', { name: 'c.bin', exact: true }).click();
    await elementText(page, 'file-name', '^c\\.bin$');
    const certificatesTab = page.getByRole('tab', { name: 'certificates', exact: true });
    assert.equal(await certificatesTab.getAttribute('aria-selected'), 'true');
    await elementText(page, 'certificates-status', 'found');
    const selected = page.getByRole('tree', { name: 'Certificates' }).locator('[aria-selected="true"]');
    assert.equal(await selected.locator('.certificate-name').textContent(), 'Zrax Fixture Root CA');
    assert.match(await page.locator('#certificates-detail').textContent(), /offset0x00000600/);

    await button(page, 'Certificates in all files').click();
    await detail.getByRole('button', { name: 'show c.bin 0x00000600 in hex' }).click();
    await elementText(page, 'file-name', '^c\\.bin$');
    assert.equal(await page.getByRole('tab', { name: 'hex', exact: true }).getAttribute('aria-selected'), 'true');
    await elementText(page, 'hex-selection-info', '^sel 876 bytes$');
  });

  test(`download all writes every distinct certificate in tree order in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    await openAllCertificates(page, await spreadChain());
    const [leaf, intermediate, root] = await chainBlocks();
    const ders = [await fixture('root.der'), await fixture('intermediate.der'), await fixture('leaf.der')];
    const names = ['00-Zrax_Fixture_Root_CA', '01-Zrax_Fixture_Intermediate_CA', '02-Zrax_Fixture_Code_Signing'];

    const bundle = await downloadText(page, '↓ pem bundle');
    assert.equal(bundle.name, 'all-certificates.pem');
    assert.equal(bundle.data.toString('utf8'), root + intermediate + leaf);

    const derZip = await downloadText(page, '↓ der .zip');
    assert.equal(derZip.name, 'all-certificates.der.zip');
    const derEntries = unzip(derZip.data);
    assert.deepEqual(derEntries.map(e => e.name), names.map(name => `${name}.der`));
    assert.deepEqual(derEntries.map(e => Buffer.from(e.bytes)), ders);
    assert.deepEqual(derEntries.map(e => e.crc), ders.map(der => zlibCrc32(der)));

    const pemZip = await downloadText(page, '↓ pem .zip');
    assert.equal(pemZip.name, 'all-certificates.pem.zip');
    const pemEntries = unzip(pemZip.data);
    assert.deepEqual(pemEntries.map(e => e.name), names.map(name => `${name}.pem`));
    assert.deepEqual(pemEntries.map(e => e.bytes.toString('utf8')), [root, intermediate, leaf]);

    const json = await downloadText(page, '↓ json');
    assert.equal(json.name, 'all-certificates.json');
    const report = JSON.parse(json.data.toString('utf8'));
    assert.equal(report.notes[0], 'Signatures and chains not verified; issuer links compare encoded names only');
    assert.deepEqual(report.files.map(f => [f.name, f.certificates]), [
      ['a.bin', 1], ['b.bin', 1], ['c.bin', 2], ['d.bin', 0],
    ]);
    assert.deepEqual(report.certificates.map(c => [c.index, c.issuer_index, c.self_issued]),
      [[0, null, true], [1, 0, false], [2, 1, false]]);
    assert.deepEqual(report.certificates[0].occurrences.map(o => [o.file, o.name, o.offset, o.encoding]),
      [[0, 'a.bin', 0x10, 'der'], [2, 'c.bin', 0x600, 'der']]);
    assert.equal(report.certificates[2].summary.subject_cn, 'Zrax Fixture Code Signing');
  });

  test(`files added in the all-files view join it in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    await openAllCertificates(page, [binary('plain.bin', 0x400, 3, [])]);
    assert.equal(await page.locator('#all-certificates-status').textContent(),
      'no certificates found in 1 file (DER and PEM scanned)');
    for (const name of ['↓ pem bundle', '↓ pem .zip', '↓ der .zip', '↓ json']) {
      assert.equal(await button(page, name).isDisabled(), true, name);
    }
    await page.locator('#fileinput').setInputFiles([
      binary('expired.bin', 0x800, 4, [[0x33, await fixture('expired.der')]]),
      binary('chain.bin', 0x1800, 5, [[0x200, await fixture('chain.pem')]]),
    ]);
    await elementText(page, 'all-certificates-status', '^4 found in 2 of 3 files \\(4 distinct\\)');
    assert.equal(await page.locator('#all-certificates').isVisible(), true);
    assert.equal(await page.locator('#status-mode').textContent(), 'ALL CERTS');
    assert.equal(await button(page, '↓ json').isDisabled(), false);
    assert.deepEqual((await treeRows(page)).map(([name, level]) => [name, level]), [
      ['Zrax Fixture Expired', '1'],
      ['Zrax Fixture Root CA', '1'],
      ['Zrax Fixture Intermediate CA', '2'],
      ['Zrax Fixture Code Signing', '3'],
    ]);
  });
}

test('copies gain their enclosing regions when their file finishes classification', async t => {
  const page = await openPage(t);
  await holdRead(page, 'chain.pem');
  await load(page);
  // `plain.bin` stays selected, so only the all-files view notices the result for `chain.pem`.
  const pem = { name: 'chain.pem', mimeType: 'application/x-pem-file', buffer: await fixture('chain.pem') };
  await page.locator('#fileinput').setInputFiles([binary('plain.bin', 0x400, 3, []), pem]);
  await page.waitForFunction(() => window.readHeld);
  // Certificate scanning does not wait for classification.
  await button(page, 'Certificates in all files').click();
  await elementText(page, 'all-certificates-status', '^3 found in 1 of 2 files');
  const leaf = page.getByRole('tree', { name: 'All certificates' }).getByRole('treeitem').nth(2);
  await leaf.click();
  const within = page.getByRole('table', { name: 'Copies of this certificate' }).locator('tbody td').nth(3);
  assert.equal(await within.textContent(), '—');
  await releaseRead(page);
  await finished(page, 2);
  assert.equal(await page.locator('#status-file').textContent(), 'plain.bin');
  await page.waitForFunction(() => {
    const cell = document.querySelector('[aria-label="Copies of this certificate"] tbody td:nth-child(4)');
    return cell?.textContent !== '—';
  });
  assert.equal(await within.textContent(), 'certificate 0 (Zrax Fixture Code Signing)');
  assert.equal(await leaf.getAttribute('aria-selected'), 'true');
});

for (const viewport of [{ width: 1100, height: 800 }, { width: 900, height: 1000 }]) {
  test(`the all-files view fits a ${viewport.width} px window`, async t => {
    const page = await openPage(t, { viewport });
    await load(page);
    const files = await spreadChain();
    files[0].name = 'sep-firmware-j717.RELEASE.im4p.decrypted-with-a-long-name.bin';
    await openAllCertificates(page, files);
    const layout = await page.evaluate(() => {
      const fits = element => element.scrollWidth <= element.clientWidth;
      const names = [...document.querySelectorAll('#all-certificates-tree .certificate-name')];
      return {
        clippedNames: names.filter(name => !fits(name)).map(name => name.textContent),
        barFits: fits(document.querySelector('#all-certificates > .bar')),
        treeFits: fits(document.getElementById('all-certificates-tree')),
        detailFits: fits(document.getElementById('all-certificates-detail')),
        exportsShown: [...document.querySelectorAll('[data-all-certificates-export]')]
          .every(b => b.getBoundingClientRect().right <= document.documentElement.clientWidth),
      };
    });
    assert.deepEqual(layout, { clippedNames: [], barFits: true, treeFits: true, detailFits: true, exportsShown: true });
  });
}
