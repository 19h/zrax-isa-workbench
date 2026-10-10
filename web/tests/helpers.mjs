import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve, sep } from 'node:path';
import { chromium } from 'playwright';
export const root = fileURLToPath(new URL('../../', import.meta.url));
let server, browser;
export let baseUrl;
export async function setup() {
  server = createServer(async (req, res) => {
    try {
      const path = resolve(root, '.' + new URL(req.url, 'http://localhost').pathname);
      if (!path.startsWith(root)) { res.writeHead(403).end(); return; }
      const body = await readFile(path);
      const mime = path.endsWith('.wasm') ? 'application/wasm' : path.endsWith('.js') ? 'text/javascript' : path.endsWith('.css') ? 'text/css' : path.endsWith('.ttf') ? 'font/ttf' : 'text/html';
      res.writeHead(200, { 'Content-Type': mime }).end(body);
    } catch { res.writeHead(404).end(); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
  browser = await chromium.launch({ headless: true, ...(process.env.BROWSER_PATH ? { executablePath: process.env.BROWSER_PATH } : {}) });
}
export async function teardown() { await browser?.close(); if (server) await new Promise(resolve => server.close(resolve)); }
export async function openPage(t, options = {}) {
  const page = await browser.newPage({ viewport: options.viewport || { width: 1440, height: 1000 }, acceptDownloads: true });
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  page.on('worker', worker => worker.on('close', () => {}));
  t.after(async () => { await page.close(); assert.deepEqual(errors, [], 'No uncaught browser errors'); });
  return page;
}
export async function load(page, path = '/web/index.html') {
  await page.goto(baseUrl + path);
  await page.waitForFunction(() => document.getElementById('status-engine').textContent.includes('Apeiron/WASM'));
}
export function elf(name, machine = 62, size = 64) {
  const buffer = Buffer.alloc(size);
  buffer.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
  buffer.writeUInt16LE(1, 16); buffer.writeUInt16LE(machine, 18); buffer.writeUInt32LE(1, 20);
  buffer.writeUInt16LE(64, 52); buffer.writeUInt16LE(56, 54); buffer.writeUInt16LE(64, 58);
  return { name, mimeType: 'application/octet-stream', buffer };
}
export async function drop(page, files) {
  await page.evaluate(files => {
    const transfer = new DataTransfer();
    for (const file of files) transfer.items.add(new File([new Uint8Array(file.bytes)], file.name));
    for (const type of ['dragenter', 'dragover', 'drop']) document.body.dispatchEvent(new DragEvent(type, { dataTransfer: transfer, bubbles: true, cancelable: true }));
  }, files.map(file => ({ name: file.name, bytes: [...file.buffer] })));
}
export async function finished(page, total) {
  await page.waitForFunction(total => { const p = document.getElementById('batch-progress'); return p.max === total && p.value === total; }, total);
}
export async function selectEntry(page, index = 0) {
  if (await page.locator('#batch').isVisible()) await page.locator('.batch-file').nth(index).click();
  else await page.locator('.file-entry').nth(index).click();
}
export async function holdRead(page, name) {
  await page.addInitScript(() => {
    const Original = window.Worker;
    window.Worker = class extends Original {
      constructor(...args) { super(...args); window.testWorker = this; this.addEventListener('message', e => { if (e.data.type === 'test-read-held') window.readHeld = true; }); }
    };
  });
  await page.route('**/analysis-worker.js', async route => {
    const response = await route.fetch();
    const source = await response.text();
    const hook = `const originalTestRead = File.prototype.arrayBuffer;\nFile.prototype.arrayBuffer = async function() { if (this.name === ${JSON.stringify(name)}) { postMessage({type:'test-read-held'}); await new Promise(resolve => { const listener = e => { if(e.data.type === 'test-release-read') { self.removeEventListener('message',listener); resolve(); } }; self.addEventListener('message',listener); }); } return originalTestRead.call(this); };\n`;
    await route.fulfill({ response, body: hook + source });
  });
}
export async function releaseRead(page) { await page.evaluate(() => window.testWorker.postMessage({ type: 'test-release-read' })); }
