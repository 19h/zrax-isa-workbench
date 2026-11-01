import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';

before(setup);
after(teardown);

const fixture = name => readFile(new URL(`../../tests/fixtures/${name}`, import.meta.url));

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

/** Noise with the root DER at 0x101, the PEM chain at 0x800 and the expired DER at 0x2001. */
async function firmware() {
  const data = noise(0x3000, 7);
  (await fixture('certificates/root.der')).copy(data, 0x101);
  (await fixture('certificates/chain.pem')).copy(data, 0x800);
  (await fixture('certificates/expired.der')).copy(data, 0x2001);
  return { name: 'firmware.bin', mimeType: 'application/octet-stream', buffer: data };
}

/** DER element with a one-octet identifier and a minimal length. */
function der(identifier, contents) {
  const n = contents.length;
  const length = n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, n >> 8, n & 0xff];
  return Buffer.concat([Buffer.from([identifier, ...length]), contents]);
}

/** Children of the outer SEQUENCE of `data`, whose identifiers are one octet. */
function children(data) {
  const header = at => {
    const first = data[at + 1];
    if (!(first & 0x80)) return [2, first];
    const count = first & 0x7f;
    let length = 0;
    for (let i = 0; i < count; i++) length = (length << 8) | data[at + 2 + i];
    return [2 + count, length];
  };
  const items = [];
  for (let at = header(0)[0]; at < data.length;) {
    const [size, length] = header(at);
    items.push(data.subarray(at, at + size + length));
    at += size + length;
  }
  return items;
}

/** `synthetic.im4m` with its placeholder chain replaced by the fixture root and intermediate. */
async function manifest() {
  const parts = children(await fixture('apple/synthetic.im4m'));
  const certificates = [await fixture('certificates/root.der'), await fixture('certificates/intermediate.der')];
  const chain = der(0x30, Buffer.concat(certificates));
  const data = der(0x30, Buffer.concat([...parts.slice(0, 4), chain]));
  return { name: 'manifest.im4m', mimeType: 'application/octet-stream', buffer: data };
}

/** Wait until an element's text matches the regular expression `source`. */
async function elementText(page, id, source) {
  const matches = ([id, source]) => new RegExp(source).test(document.getElementById(id)?.textContent || '');
  await page.waitForFunction(matches, [id, source]);
}

const tab = (page, name) => page.getByRole('tab', { name, exact: true });
const button = (page, name) => page.getByRole('button', { name, exact: true });

async function openCertificates(page, file, count) {
  await page.locator('#fileinput').setInputFiles([file]);
  await finished(page, 1);
  if (count != null) await elementText(page, 'certificates-count', count ? `^${count}$` : '^$');
  await page.keyboard.press('6');
  await elementText(page, 'certificates-status', 'found|no certificates');
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the certificates tab shows a name-linked chain with honest wording in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    await openCertificates(page, await firmware(), 5);
    assert.equal(await tab(page, 'certificates').getAttribute('aria-selected'), 'true');
    const status = await page.locator('#certificates-status').textContent();
    assert.match(status, /^5 found \(4 distinct\) · signatures and chains not verified; issuer links compare/);
    const tree = page.getByRole('tree', { name: 'Certificates' });
    const items = tree.getByRole('treeitem');
    const levels = await items.evaluateAll(nodes => nodes.map(node => [
      node.querySelector('.certificate-name').textContent,
      node.getAttribute('aria-level'),
    ]));
    assert.deepEqual(levels, [
      ['Zrax Fixture Root CA', '1'],
      ['Zrax Fixture Intermediate CA', '2'],
      ['Zrax Fixture Code Signing', '3'],
      ['Zrax Fixture Expired', '1'],
    ]);
    assert.match(await items.first().textContent(), /×2/);
    const detail = page.locator('#certificates-detail');
    assert.match(await detail.textContent(), /signature not verified/);
    assert.match(await detail.textContent(), /within validity period by this computer's clock/);
    await items.nth(3).click();
    assert.match(await detail.locator('.badge').first().textContent(), /^expired$/);
    await items.nth(2).click();
    const altNames = 'alt namesDNS:fixture.zrax.invalid, email:fixture@zrax.invalid, IP:192.0.2.1';
    assert.ok((await detail.textContent()).includes(altNames));
    assert.match(await detail.textContent(), /name match/);
    await page.getByRole('button', { name: 'go to issuer [2]' }).click();
    assert.equal(await items.nth(1).getAttribute('aria-selected'), 'true');
    await page.getByRole('searchbox', { name: 'Filter certificates' }).fill('expired');
    assert.equal(await items.count(), 1);
  });

  test(`certificate downloads match the fixtures and open as X.509 files in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    await openCertificates(page, await firmware(), 5);
    const items = page.getByRole('tree', { name: 'Certificates' }).getByRole('treeitem');
    await items.nth(2).click();
    const [der] = await Promise.all([page.waitForEvent('download'), button(page, '↓ der').click()]);
    assert.equal(der.suggestedFilename(), 'firmware.bin.cert-1.der');
    assert.deepEqual(await readFile(await der.path()), await fixture('certificates/leaf.der'));
    const [pem] = await Promise.all([page.waitForEvent('download'), button(page, '↓ pem').click()]);
    const chain = (await fixture('certificates/chain.pem')).toString('utf8');
    assert.ok(chain.startsWith(await readFile(await pem.path(), 'utf8')), 'PEM matches the OpenSSL leaf block');

    await button(page, 'show in hex').click();
    assert.equal(await tab(page, 'hex').getAttribute('aria-selected'), 'true');
    await elementText(page, 'hex-selection-info', '^sel 768 bytes$');

    await page.keyboard.press('6');
    await button(page, 'open as file').click();
    await elementText(page, 'file-name', '^firmware\\.bin\\.cert-1\\.der$');
    await elementText(page, 'classification-band', 'x\\.509 certificate');
    await elementText(page, 'certificates-count', '^1$');
    assert.equal(FORMAT_NAMES.x509, 'X.509 Certificate');
  });

  test(`certificates in an IM4M chain name their enclosing structure in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    await openCertificates(page, await manifest(), 2);
    const detail = page.locator('#certificates-detail');
    await elementText(page, 'certificates-detail', 'within');
    assert.match(await detail.textContent(), /withinIM4M manifest > IM4M certificate chain/);
  });

  test(`files without certificates say what was scanned in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const plain = { name: 'plain.bin', mimeType: 'application/octet-stream', buffer: noise(4096, 3) };
    await openCertificates(page, plain, 0);
    const status = await page.locator('#certificates-status').textContent();
    assert.equal(status, 'no certificates found in 4.0 KiB (DER and PEM scanned)');
    assert.equal(await tab(page, 'certificates').textContent(), 'certificates');
  });
}

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`a PEM bundle classifies as an opaque X.509 file with DER members through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const bytes = [...await fixture('certificates/chain.pem')];
    const result = await page.evaluate(async ({ module, bytes }) => {
      const wasm = await import(module);
      await wasm.default();
      const engine = new wasm.WorkbenchEngine(new Uint8Array(bytes));
      try {
        return { payload: JSON.parse(engine.classification()), subfiles: JSON.parse(engine.subfiles()) };
      } finally { engine.free(); }
    }, { module, bytes });
    assert.equal(result.payload.format.format, 'x509');
    assert.equal(result.payload.primary.confidence, 0);
    assert.deepEqual(result.subfiles.map(s => [s.label, s.transform, s.opaque]), [
      ['certificate 0 (Zrax Fixture Code Signing)', 'base64', true],
      ['certificate 1 (Zrax Fixture Intermediate CA)', 'base64', true],
      ['certificate 2 (Zrax Fixture Root CA)', 'base64', true],
    ]);
  });
}
