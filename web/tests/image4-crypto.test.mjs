import assert from 'node:assert/strict';
import { createCipheriv } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, baseUrl, elf } from './helpers.mjs';

before(setup);
after(teardown);

test('the packaged workbench retains the adapted parser and AES license notices', async t => {
  const page = await openPage(t);
  const response = await page.request.get(baseUrl + '/dist/THIRD-PARTY-FIRMWARE-PARSERS.txt');
  assert.equal(response.status(), 200);
  const text = await response.text();
  for (const name of ['ftab-dump', 'uarp-dump', 'img4-dump', 'Permission is hereby granted']) {
    assert.ok(text.includes(name), name);
  }
});

const KEY = Buffer.alloc(32, 0x12);
const IV = Buffer.alloc(16, 0x34);
const KEY_HEX = KEY.toString('hex').toUpperCase();
const IV_HEX = IV.toString('hex').toUpperCase();
const kernel = () => readFile(new URL('../../tests/fixtures/apple/kernel.macho', import.meta.url));

// DER tag, definite length, contents. Long lengths use the minimal number
// of big-endian octets; the Image4 parser is not used to build fixtures.
function der(tag, payload) {
  const length = [];
  for (let size = payload.length; size > 0; size >>>= 8) length.unshift(size & 0xff);
  const prefix = payload.length < 128 ? [payload.length] : [0x80 | length.length, ...length];
  return Buffer.concat([Buffer.from([tag, ...prefix]), payload]);
}
const sequence = items => der(0x30, Buffer.concat(items));

// IM4P: magic, role krnl, description, ciphertext, optional DER keybag
// (production class 1, sixteen-byte IV, thirty-two-byte key).
function im4p(plaintext, mode, keybag = false) {
  const cipher = createCipheriv(`aes-256-${mode}`, KEY, IV);
  cipher.setAutoPadding(false);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const fields = [der(0x16, Buffer.from('IM4P')), der(0x16, Buffer.from('krnl')),
    der(0x16, Buffer.from('Browser AES fixture')), der(0x04, ciphertext)];
  if (keybag) fields.push(der(0x04, sequence([
    sequence([der(0x02, Buffer.from([1])), der(0x04, IV), der(0x04, KEY)]),
  ])));
  return sequence(fields);
}

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`keybag AES modes and manual material work through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const plaintext = await kernel();
    const inputs = ['cbc', 'ctr'].map(mode => [...im4p(plaintext, mode, true)]);
    const manual = [...im4p(plaintext, 'ctr')];
    const result = await page.evaluate(async ({ module, inputs, manual, key, iv }) => {
      const wasm = await import(module);
      await wasm.default();
      const automatic = inputs.map(data => JSON.parse(wasm.classify(new Uint8Array(data))));
      const engine = new wasm.WorkbenchEngine(new Uint8Array(manual));
      try {
        const info = JSON.parse(engine.image4_info());
        const bytes = [...engine.decrypt_image4(key, iv, 'auto')];
        return { automatic, info, bytes };
      } finally { engine.free(); }
    }, { module, inputs, manual, key: KEY_HEX, iv: IV_HEX });
    for (const payload of result.automatic) {
      assert.equal(payload.primary.isa, 'a_arch64');
      assert.ok(payload.notes.some(note => note.message.includes('not authenticated')));
    }
    assert.equal(result.info.keybags.length, 0);
    assert.deepEqual(result.bytes, [...plaintext]);
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`a queued decrypt reply cannot create a child after navigation in ${path}`, async t => {
    const page = await openPage(t);
    await page.addInitScript(() => {
      const OriginalWorker = window.Worker;
      window.Worker = class extends OriginalWorker {
        addEventListener(type, listener, ...options) {
          if (type !== 'message') return super.addEventListener(type, listener, ...options);
          super.addEventListener(type, event => {
            if (event.data.type === 'decrypted') {
              window.decryptReplyHeld = true;
              window.releaseDecryptReply = () => listener.call(this, event);
            } else {
              listener.call(this, event);
            }
          }, ...options);
        }
      };
    });
    await load(page, path);
    await page.locator('#fileinput').setInputFiles([
      { name: 'queued.im4p', buffer: im4p(await kernel(), 'ctr'), mimeType: 'application/octet-stream' },
    ]);
    await finished(page, 1);
    await page.locator('#fileinput').setInputFiles([elf('other.elf')]);
    await finished(page, 2);
    await page.locator('.file-entry').filter({ hasText: 'queued.im4p' }).click();
    await page.getByRole('textbox', { name: 'AES key', exact: true }).fill(KEY_HEX);
    await page.getByRole('textbox', { name: 'AES IV', exact: true }).fill(IV_HEX);
    await page.waitForFunction(() => window.decryptReplyHeld === true);
    await page.locator('.file-entry').filter({ hasText: 'other.elf' }).click();
    await page.evaluate(() => window.releaseDecryptReply());
    assert.equal(await page.locator('.file-entry').count(), 2);
    await page.locator('.file-entry').filter({ hasText: 'queued.im4p' }).click();
    assert.equal(await page.locator('#crypto-status').textContent(), 'Decryption canceled');
    assert.equal(await page.getByRole('button', { name: 'open decrypted payload', exact: true }).count(), 0);
  });

  test(`removing an Image4 during the debounce cannot create a stale child in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    await page.locator('#fileinput').setInputFiles([
      { name: 'removed.im4p', buffer: im4p(await kernel(), 'ctr'), mimeType: 'application/octet-stream' },
    ]);
    await finished(page, 1);
    await page.getByRole('textbox', { name: 'AES key', exact: true }).fill(KEY_HEX);
    await page.getByRole('textbox', { name: 'AES IV', exact: true }).fill(IV_HEX);
    await page.getByRole('button', { name: 'Remove file', exact: true }).click();
    await page.waitForTimeout(600);
    assert.equal(await page.locator('.file-entry').count(), 0);
  });

  test(`inline custom material opens a decrypted subfile without prompts in ${path}`, async t => {
    const page = await openPage(t);
    let dialogs = 0;
    page.on('dialog', async dialog => { dialogs++; await dialog.dismiss(); });
    await load(page, path);
    await page.locator('#fileinput').setInputFiles([
      { name: 'encrypted.im4p', buffer: im4p(await kernel(), 'ctr'), mimeType: 'application/octet-stream' },
    ]);
    await finished(page, 1);
    await page.getByRole('textbox', { name: 'AES key', exact: true }).fill(KEY_HEX);
    await page.getByRole('textbox', { name: 'AES IV', exact: true }).fill(IV_HEX);
    await page.getByRole('button', { name: 'open decrypted payload', exact: true }).waitFor();
    await finished(page, 2);
    assert.equal(await page.locator('#file-name').textContent(), 'encrypted.im4p');
    assert.match(await page.locator('#crypto-status').textContent(), /not authenticated/);
    const stored = await page.evaluate(() => localStorage.getItem('isawb.v2') || '');
    assert.ok(!stored.includes(KEY_HEX));
    assert.ok(!(await page.locator('#log-lines').textContent()).includes(KEY_HEX));
    await page.getByRole('button', { name: 'open decrypted payload', exact: true }).click();
    assert.equal(await page.locator('#file-name').textContent(), 'krnl.decrypted');
    assert.match(await page.locator('#classification-content').textContent(), /Mach-O/);
    await page.getByRole('tab', { name: 'hex', exact: true }).click();
    await page.waitForFunction(() => [...document.querySelectorAll('#hex-rows .hex-byte')]
      .slice(0, 4).map(cell => cell.textContent).join(' ') === 'CF FA ED FE');
    await page.getByRole('navigation', { name: 'Container path' }).getByRole('button', { name: 'encrypted.im4p' }).click();
    await page.getByRole('tab', { name: 'classification', exact: true }).click();
    await page.getByRole('textbox', { name: 'AES key', exact: true }).fill('bad');
    assert.match(await page.locator('#crypto-status').textContent(), /hexadecimal required/);
    assert.equal(dialogs, 0);
  });

  test(`encoded keybag material is read-only in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    await page.locator('#fileinput').setInputFiles([
      { name: 'keybag.im4p', buffer: im4p(await kernel(), 'cbc', true), mimeType: 'application/octet-stream' },
    ]);
    await finished(page, 1);
    const key = page.getByRole('textbox', { name: 'AES key', exact: true });
    const iv = page.getByRole('textbox', { name: 'AES IV', exact: true });
    assert.equal(await key.inputValue(), KEY_HEX);
    assert.equal(await iv.inputValue(), IV_HEX);
    assert.equal(await key.evaluate(input => input.readOnly), true);
    assert.equal(await iv.evaluate(input => input.readOnly), true);
    await page.getByRole('button', { name: 'open krnl', exact: true }).click();
    await finished(page, 2);
    assert.match(await page.locator('#classification-content').textContent(), /Mach-O/);
  });

  test(`raw decryption candidates require an explicit mode in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    await page.locator('#fileinput').setInputFiles([
      { name: 'raw.im4p', buffer: im4p(Buffer.alloc(64, 0x5a), 'cbc'), mimeType: 'application/octet-stream' },
    ]);
    await finished(page, 1);
    await page.getByRole('textbox', { name: 'AES key', exact: true }).fill(KEY_HEX);
    await page.getByRole('textbox', { name: 'AES IV', exact: true }).fill(IV_HEX);
    await page.waitForFunction(() => document.querySelector('#crypto-status').textContent.includes('Unknown Image4 plaintext'));
    assert.equal(await page.getByRole('button', { name: 'open decrypted payload', exact: true }).count(), 0);
    await page.getByRole('combobox', { name: 'AES mode', exact: true }).selectOption('cbc');
    await page.getByRole('button', { name: 'open decrypted payload', exact: true }).waitFor();
    assert.match(await page.locator('#crypto-status').textContent(), /AES-CBC candidate decoded; not authenticated/);
  });
}
