import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  StringIndex, compileQuery, csvField, emptyCounts, exportParts, filterRange, sortView,
} from '../strings-index.js';

const ENCODINGS = ['ascii', 'utf8', 'utf16le', 'utf16be'];
const TAGS = [[1, 'url'], [2, 'email'], [8, 'path']];

// Scanner rows: [offset, size, chars, encoding index, tag bits, clipped, text].
function sampleIndex() {
  const index = new StringIndex(ENCODINGS, TAGS);
  index.append([
    [0x10, 22, 22, 0, 1, false, 'https://example.invalid'],
    [0x40, 10, 5, 2, 0, false, 'Hello'],
    [0x80, 9, 9, 0, 8, false, '/usr/bin/'],
    [0x100, 5, 4, 1, 0, false, 'Köln'],
    [0x200, 4096, 4096, 0, 0, true, 'A'.repeat(64)],
  ]);
  return index;
}

function run(index, spec) {
  const query = compileQuery(spec);
  const matches = [];
  const counts = emptyCounts(index);
  filterRange(index, query, 0, index.length, matches, counts);
  return { view: sortView(index, matches, spec.sort), counts };
}

test('rows keep their fields and the store caps its length', () => {
  const index = sampleIndex();
  assert.equal(index.length, 5);
  assert.deepEqual(index.row(1), {
    index: 1, offset: 0x40, size: 10, chars: 5, encoding: 'utf16le',
    tags: [], clipped: false, text: 'Hello', region: -1,
  });
  assert.deepEqual(index.row(0).tags, ['url']);
  assert.equal(index.row(4).clipped, true);
  const capped = new StringIndex(ENCODINGS, TAGS);
  assert.equal(capped.append([[0, 4, 4, 0, 0, false, 'abcd'], [8, 4, 4, 0, 0, false, 'efgh']], 1), 1);
  assert.equal(capped.length, 1);
});

test('plain search is case-insensitive unless asked, and regex errors are reported', () => {
  const index = sampleIndex();
  assert.deepEqual(run(index, { search: 'hello' }).view, [1]);
  assert.deepEqual(run(index, { search: 'hello', caseSensitive: true }).view, []);
  assert.deepEqual(run(index, { search: '^/usr/.*/$', regex: true }).view, [2]);
  assert.deepEqual(run(index, { search: '[\\w-]+\\.invalid', regex: true }).view, [0]);
  assert.match(compileQuery({ search: '(', regex: true }).error, /^Invalid regular expression/);
});

test('facet chips filter rows but counts ignore them', () => {
  const index = sampleIndex();
  const { view, counts } = run(index, { encodings: 0b0001, tags: 0 });
  assert.deepEqual(view, [0, 2, 4]);
  assert.deepEqual(counts.encodings, [3, 1, 1, 0]);
  const tagged = run(index, { tags: 8 });
  assert.deepEqual(tagged.view, [2]);
  assert.equal(tagged.counts.tags.get(1), 1);
});

test('minimum length, byte range and region scope narrow the base set', () => {
  const index = sampleIndex();
  assert.deepEqual(run(index, { minChars: 9 }).view, [0, 2, 4]);
  assert.deepEqual(run(index, { range: { start: 0x40, end: 0x89 } }).view, [1, 2]);
  index.setRegions([
    { label: '__TEXT', kind: 'segment', offset: 0, size: 0x100 },
    { label: '__TEXT,__cstring', kind: 'section', offset: 0x80, size: 0x20 },
  ]);
  assert.equal(index.region(2), 1);
  assert.equal(index.region(1), 0);
  assert.equal(index.region(3), -1);
  assert.deepEqual(run(index, { region: 1 }).view, [2]);
});

test('sorts are stable with scan order as the tie-break', () => {
  const index = sampleIndex();
  assert.deepEqual(run(index, { sort: { key: 'chars', dir: 'asc' } }).view, [3, 1, 2, 0, 4]);
  assert.deepEqual(run(index, { sort: { key: 'chars', dir: 'desc' } }).view, [4, 0, 2, 1, 3]);
  assert.deepEqual(run(index, { sort: { key: 'text', dir: 'asc' } }).view, [2, 4, 1, 3, 0]);
  assert.deepEqual(run(index, { sort: { key: 'offset', dir: 'desc' } }).view, [4, 3, 2, 1, 0]);
  assert.deepEqual(run(index, { sort: { key: 'encoding', dir: 'asc' } }).view, [0, 2, 4, 3, 1]);
});

test('exports quote CSV fields and write one JSON object per string', async () => {
  const index = sampleIndex();
  index.append([[0x300, 7, 7, 0, 0, false, 'a,"b"\tc']]);
  assert.equal(csvField('a,"b"'), '"a,""b"""');
  const csv = exportParts(index, [5], 'csv').join('');
  assert.equal(csv, 'offset,size,chars,encoding,tags,clipped,region,text\r\n768,7,7,ascii,,false,,"a,""b""\tc"\r\n');
  const json = JSON.parse(exportParts(index, [0, 2], 'json').join(''));
  assert.deepEqual(json.map(s => s.text), ['https://example.invalid', '/usr/bin/']);
  assert.deepEqual(json[0].tags, ['url']);
  assert.equal(exportParts(index, [1, 3], 'txt').join(''), 'Hello\nKöln\n');
});
