import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished } from './helpers.mjs';

before(setup);
after(teardown);

const URL_TEXT = 'https://example.invalid/zrax';
const PATH_TEXT = '/usr/lib/libzrax.so';
const WIDE_TEXT = 'Wide Résumé';

/**
 * Noise-free sample: each string is preceded and followed by 0x01 bytes so
 * runs do not join. Offsets: URL at 0x10, path at 0x40, UTF-8 at 0x80,
 * UTF-16LE at 0xC0 (even, so it has no big-endian twin).
 */
function sample() {
  const data = Buffer.alloc(0x100, 0x01);
  data.write(URL_TEXT, 0x10, 'ascii');
  data.write(PATH_TEXT, 0x40, 'ascii');
  data.write('Grüße aus Köln', 0x80, 'utf8');
  data.write(WIDE_TEXT, 0xc0, 'utf16le');
  return { name: 'strings.bin', mimeType: 'application/octet-stream', buffer: data };
}

const LONG_TEXT = '/System/Library/PrivateFrameworks/CoreSymbolication.framework/Versions/A/CoreSymbolication';

/** One 90-character path at 0x10, between 0x01 bytes. */
function longSample() {
  const data = Buffer.alloc(0x100, 0x01);
  data.write(LONG_TEXT, 0x10, 'ascii');
  return { name: 'long.bin', mimeType: 'application/octet-stream', buffer: data };
}

/** Column headers on screen, the text column's share of the grid, and what overflows. */
function gridLayout(page) {
  return page.evaluate(() => {
    const grid = document.getElementById('strings-grid').getBoundingClientRect();
    const text = document.querySelector('#strings-rows .strings-row[data-position] .col-text').getBoundingClientRect();
    const headers = [...document.querySelectorAll('#strings-head [role=columnheader]')]
      .filter(header => header.getBoundingClientRect().width > 0);
    const bytes = document.getElementById('strings-bytes');
    const inspector = document.getElementById('strings-inspector');
    const dumpLines = bytes.textContent.split('\n').filter(line => !line.startsWith('…'));
    return {
      headers: headers.map(header => header.textContent.replace(/[▲▼]/g, '').trim()),
      textShare: text.width / grid.width,
      headersInside: headers.every(header => header.getBoundingClientRect().right <= grid.right + 0.5),
      bytesFit: bytes.scrollWidth <= bytes.clientWidth,
      inspectorFits: inspector.scrollWidth <= inspector.clientWidth,
      dumpLineLengths: [...new Set(dumpLines.map(line => line.length))],
    };
  });
}

/** 200 000 NUL-terminated strings `s000000`..`s199999`, 8 B each. */
function manyStrings() {
  const count = 200000;
  const data = Buffer.alloc(count * 8);
  for (let i = 0; i < count; i++) data.write(`s${String(i).padStart(6, '0')}`, i * 8, 'ascii');
  return { name: 'many.bin', mimeType: 'application/octet-stream', buffer: data };
}

async function openStrings(page, file) {
  await page.locator('#fileinput').setInputFiles([file]);
  await finished(page, 1);
  await page.keyboard.press('5');
  await elementText(page, 'strings-status', /scanned/);
  await page.locator(ROWS).first().waitFor();
}

const ROWS = '#strings-rows .strings-row[data-position]';
const texts = page => page.locator(`${ROWS} .strings-text`).allTextContents();
const search = page => page.getByRole('searchbox', { name: 'Search strings' });
const button = (page, name) => page.getByRole('button', { name, exact: true });

/** Wait until the grid shows `count` rows. */
async function rowCount(page, count) {
  await page.waitForFunction(([rows, count]) => document.querySelectorAll(rows).length === count, [ROWS, count]);
}

/** Wait until the first row, or the selected row, has this text. */
async function rowText(page, text, selected = false) {
  const selector = selected ? '#strings-rows .strings-row.selected .strings-text' : `${ROWS} .strings-text`;
  const matches = ([selector, text]) => document.querySelector(selector)?.textContent === text;
  await page.waitForFunction(matches, [selector, text]);
}

/** Wait until an element's text matches `pattern`. */
async function elementText(page, id, pattern) {
  await page.waitForFunction(([id, source]) => new RegExp(source).test(document.getElementById(id)?.textContent || ''),
    [id, pattern.source]);
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the strings tab lists, searches, filters and sorts strings in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    await page.evaluate(() => localStorage.clear());
    await openStrings(page, sample());
    assert.equal(await page.getByRole('tab', { name: 'strings', exact: true }).getAttribute('aria-selected'), 'true');
    const all = await texts(page);
    for (const expected of [URL_TEXT, PATH_TEXT, 'Grüße aus Köln', WIDE_TEXT]) {
      assert.ok(all.includes(expected), `${expected} in ${all}`);
    }

    await search(page).fill('EXAMPLE');
    await rowCount(page, 1);
    assert.equal(await page.locator('#strings-rows mark').first().textContent(), 'example');
    await button(page, 'Match case').click();
    await elementText(page, 'strings-status', /^0 of/);
    await button(page, 'Match case').click();

    await button(page, 'Regular expression').click();
    await search(page).fill('(');
    await page.waitForFunction(() => !document.getElementById('strings-problem').hidden);
    assert.match(await page.locator('#strings-problem').textContent(), /^Invalid regular expression/);
    assert.equal(await search(page).getAttribute('aria-invalid'), 'true');
    await search(page).fill('^/usr/.*\\.so$');
    await rowCount(page, 1);
    assert.deepEqual(await texts(page), [PATH_TEXT]);
    await button(page, 'Regular expression').click();
    await search(page).fill('');

    await button(page, 'path').click();
    await rowCount(page, 1);
    assert.deepEqual(await texts(page), [PATH_TEXT]);
    await button(page, 'path').click();

    await button(page, 'utf-16le').click();
    await rowCount(page, 3);
    assert.ok(!(await texts(page)).includes(WIDE_TEXT));
    await button(page, 'utf-16le').click();

    await button(page, 'Sort by len').click();
    await page.locator('[role=columnheader][aria-sort=ascending] [data-strings-sort="chars"]').waitFor();
    await rowText(page, WIDE_TEXT);
    await button(page, 'Sort by len').click();
    await rowText(page, URL_TEXT);
    assert.equal(await page.locator('[role=columnheader][aria-sort=descending]').count(), 1);
  });

  test(`a string opens as a hex selection and exports as CSV in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    await page.evaluate(() => localStorage.clear());
    await openStrings(page, sample());
    await page.locator('#strings-rows .strings-row', { hasText: PATH_TEXT }).click();
    assert.match(await page.locator('#strings-inspector').textContent(), /offset0x00000040 \(64\)/);
    await elementText(page, 'strings-bytes', /00000040 {2}2F 75 73 72/);
    await page.keyboard.press('Enter');
    assert.equal(await page.getByRole('tab', { name: 'hex', exact: true }).getAttribute('aria-selected'), 'true');
    await elementText(page, 'hex-selection-info', new RegExp(`^sel ${PATH_TEXT.length} bytes$`));
    await page.locator('#hex-rows [data-offset="64"].byte-selected').first().waitFor();

    await page.keyboard.press('5');
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      button(page, 'Export as CSV').click(),
    ]);
    assert.equal(download.suggestedFilename(), 'strings.bin.strings.csv');
    const csv = await readFile(await download.path(), 'utf8');
    assert.ok(csv.startsWith('offset,size,chars,encoding,tags,clipped,region,text\r\n'), csv);
    assert.ok(csv.includes(`64,19,19,ascii,path,false,,${PATH_TEXT}\r\n`), csv);
    assert.ok(csv.includes(`192,22,11,utf16le,,false,,${WIDE_TEXT}\r\n`), csv);
  });

  test(`the text column keeps the width and the byte preview fits the inspector in ${path}`, async t => {
    const page = await openPage(t, { viewport: { width: 1440, height: 900 } });
    await load(page, path);
    await page.evaluate(() => localStorage.clear());
    await openStrings(page, longSample());
    await page.locator(ROWS).first().click();
    await elementText(page, 'strings-bytes', /^00000010 {2}2F 53 79 73/);

    // Size and tags drop out first; the file has no labelled regions.
    const narrow = await gridLayout(page);
    assert.deepEqual(narrow.headers, ['offset', 'enc', 'len', 'text']);
    assert.ok(narrow.textShare > 0.5, `text column is ${narrow.textShare} of the grid`);
    assert.ok(narrow.headersInside, 'column headers stay inside the grid');
    assert.ok(narrow.bytesFit && narrow.inspectorFits, 'byte preview fits without scrolling');
    assert.equal(narrow.dumpLineLengths.length, 1, `uneven dump lines ${narrow.dumpLineLengths}`);

    await page.setViewportSize({ width: 1920, height: 1080 });
    await page.waitForFunction(() => document.querySelectorAll('#strings-head [role=columnheader]')[5].offsetWidth > 0);
    const wide = await gridLayout(page);
    assert.deepEqual(wide.headers, ['offset', 'enc', 'len', 'size', 'tags', 'text']);
    assert.ok(wide.textShare > 0.5, `text column is ${wide.textShare} of the grid`);
    assert.ok(wide.headersInside && wide.bytesFit && wide.inspectorFits, JSON.stringify(wide));
  });

  test(`the hex context menu and selection open matching strings in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    await page.evaluate(() => localStorage.clear());
    await openStrings(page, sample());
    await page.keyboard.press('3');
    await page.locator('#goto-offset').fill('0x80');
    await page.locator('#goto-offset').press('Enter');
    await page.evaluate(() => document.querySelector('[data-action="strings-here"]').click());
    await rowText(page, 'Grüße aus Köln', true);
    assert.equal(await page.getByRole('tab', { name: 'strings', exact: true }).getAttribute('aria-selected'), 'true');
  });

  test(`a catastrophic regular expression is stopped without replaying it in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    await page.evaluate(() => localStorage.clear());
    const data = Buffer.alloc(64, 0x01);
    data.write(`${'a'.repeat(40)}!`, 8, 'ascii');
    await openStrings(page, { name: 'backtrack.bin', mimeType: 'application/octet-stream', buffer: data });
    await button(page, 'Regular expression').click();
    await search(page).fill('^(a+)+$');
    await elementText(page, 'strings-problem', /stopped responding for 4 s and was cancelled/);
    await search(page).fill('a{10}');
    await rowCount(page, 1);
    assert.equal(await page.locator('#strings-problem').isHidden(), true);
  });

  test(`two hundred thousand strings stay virtualized and reach the end by keyboard in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    await page.evaluate(() => localStorage.clear());
    await openStrings(page, manyStrings());
    await elementText(page, 'strings-status', /^200,000 of 200,000 strings/);
    const rendered = await page.locator('#strings-rows .strings-row').count();
    assert.ok(rendered > 5 && rendered < 100, `${rendered} rows in the DOM`);
    await page.locator('#strings-rows .strings-row[data-position]').first().click();
    await page.keyboard.press('End');
    await rowText(page, 's199999', true);
    assert.equal(await page.locator('#strings-grid').getAttribute('aria-rowcount'), '200001');
  });
}
