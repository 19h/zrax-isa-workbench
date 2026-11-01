// Strings and certificate scans for the workbench. Files are read in slices
// and streamed through the WASM scanners, so no resident copy is kept; the
// analysis worker stays free for hex and map requests. Queries run here in
// slices and yield between them, so a newer request supersedes an older one.
import init, {
  StringScan, CertificateScan, CertificateLinks, string_encoding_ids, string_tag_ids, certificate_window_overlap,
} from '../pkg/zrax.js';
import { SCAN_PROTOCOL } from './protocol.js';
import { StringIndex, compileQuery, emptyCounts, exportParts, filterRange, sortView } from './strings-index.js';

// Bytes read per slice.
const CHUNK_SIZE = 4 * 1024 * 1024;
// Rows filtered between yields.
const QUERY_SLICE = 50000;
// Bounds on one file's string index.
const MAX_STRINGS = 1000000;
const MAX_TEXT_CHARS = 128 * 1024 * 1024;
// String indexes kept for recently viewed files.
const MAX_INDEXES = 3;

const scans = new Map();
const latest = new Map();
let encodingIds = [];
let tagIds = [];
let overlap = 0;
let ready = false;
const waiting = [];

// Yield to queued messages without timer clamping. Scans and queries run
// concurrently, so each pending continuation gets its own channel message.
const yieldChannel = new MessageChannel();
const resumes = [];
yieldChannel.port1.onmessage = () => resumes.shift()?.();
const yieldTask = () => new Promise(resolve => {
  resumes.push(resolve);
  yieldChannel.port2.postMessage(0);
});
const send = (message, transfer = []) => postMessage(message, transfer);
const isCurrent = job => latest.get(`${job.type}:${job.id}`) === job.request;

/** Keep at most MAX_INDEXES string indexes, dropping the least recently used. */
function touch(id, state) {
  scans.delete(id);
  scans.set(id, state);
  while (scans.size > MAX_INDEXES) scans.delete(scans.keys().next().value);
}

function tagCounts(counts) {
  const result = {};
  for (const [bit, id] of tagIds) result[id] = counts.tags.get(bit) || 0;
  return result;
}

function encodingCounts(counts) {
  return Object.fromEntries(encodingIds.map((id, i) => [id, counts.encodings[i]]));
}

function rowsOf(state, from, count) {
  const view = state.view?.matches || [];
  return view.slice(from, from + count).map(i => state.index.row(i));
}

async function scanStrings(job) {
  const existing = scans.get(job.id);
  if (existing && existing.minChars === job.minChars && existing.encodings === job.encodings) {
    existing.index.setRegions(job.regions);
    touch(job.id, existing);
    if (existing.done) {
      send({ type: 'strings-done', id: job.id, request: existing.request, total: existing.index.length,
        truncated: existing.truncated, elapsed: existing.elapsed });
    }
    return;
  }
  const index = new StringIndex(encodingIds, tagIds);
  index.setRegions(job.regions);
  const state = {
    request: job.request, minChars: job.minChars, encodings: job.encodings, index,
    done: false, truncated: false, elapsed: 0, view: null,
  };
  touch(job.id, state);
  const started = performance.now();
  const scanner = new StringScan(job.minChars, job.encodings);
  const keep = rows => {
    const kept = index.append(rows, MAX_STRINGS);
    if (kept < rows.length || index.textChars > MAX_TEXT_CHARS) state.truncated = true;
  };
  try {
    const size = job.file.size;
    for (let start = 0; start < size && !state.truncated; start += CHUNK_SIZE) {
      // A scan stops when a new scan or `forget` replaces its index; a
      // request that only refreshes regions reuses it and must not stop it.
      const buffer = await job.file.slice(start, start + CHUNK_SIZE).arrayBuffer();
      if (scans.get(job.id) !== state) return;
      keep(JSON.parse(scanner.push(new Uint8Array(buffer))));
      send({ type: 'strings-progress', id: job.id, request: job.request,
        scanned: Math.min(size, start + CHUNK_SIZE), total: size, found: index.length });
      await yieldTask();
      if (scans.get(job.id) !== state) return;
    }
    if (!state.truncated) keep(JSON.parse(scanner.finish()));
  } finally {
    scanner.free();
  }
  state.done = true;
  state.elapsed = performance.now() - started;
  send({ type: 'strings-done', id: job.id, request: job.request, total: index.length,
    truncated: state.truncated, elapsed: state.elapsed });
}

async function queryStrings(job) {
  const state = scans.get(job.id);
  if (!state) throw new Error('Strings were not scanned for this file.');
  const query = compileQuery(job.query);
  if (query.error) {
    state.view = { request: job.request, matches: [] };
    send({ type: 'strings-view', id: job.id, request: job.request, total: 0, from: 0, rows: [],
      counts: null, scanned: state.index.length, done: state.done, invalid: query.error });
    return;
  }
  const { index } = state;
  const length = index.length;
  const matches = [];
  const counts = emptyCounts(index);
  for (let from = 0; from < length; from += QUERY_SLICE) {
    filterRange(index, query, from, Math.min(length, from + QUERY_SLICE), matches, counts);
    if (from + QUERY_SLICE < length) {
      send({
        type: 'strings-query-progress', id: job.id, request: job.request, filtered: from + QUERY_SLICE, total: length,
      });
      await yieldTask();
      if (!isCurrent(job)) return;
    }
  }
  state.view = { request: job.request, matches: sortView(index, matches, job.query.sort) };
  send({
    type: 'strings-view', id: job.id, request: job.request, total: state.view.matches.length,
    from: job.from, rows: rowsOf(state, job.from, job.count),
    counts: { encodings: encodingCounts(counts), tags: tagCounts(counts) },
    scanned: length, done: state.done, truncated: state.truncated,
  });
}

function stringRows(job) {
  const state = scans.get(job.id);
  if (!state?.view || state.view.request !== job.view) return;
  send({ type: 'strings-rows', id: job.id, request: job.request, view: job.view, from: job.from,
    rows: rowsOf(state, job.from, job.count) });
}

/**
 * Position in the current view of the string that contains `offset`, or
 * else of the nearest string after it; -1 when there is none.
 */
function locateString(job) {
  const state = scans.get(job.id);
  const matches = state?.view?.matches || [];
  let containing = -1;
  let following = -1;
  for (let p = 0; p < matches.length; p++) {
    const start = state.index.offsets[matches[p]];
    const end = start + state.index.sizes[matches[p]];
    if (start <= job.offset && job.offset < end) {
      containing = p;
      break;
    }
    if (start > job.offset && (following < 0 || start < state.index.offsets[matches[following]])) following = p;
  }
  const position = containing >= 0 ? containing : following;
  send({ type: 'strings-located', id: job.id, request: job.request, position });
}

function exportStrings(job) {
  const state = scans.get(job.id);
  if (!state?.view) throw new Error('Nothing to export yet.');
  const types = { txt: 'text/plain', csv: 'text/csv', json: 'application/json' };
  const blob = new Blob(exportParts(state.index, state.view.matches, job.format), { type: types[job.format] });
  send({ type: 'strings-export', id: job.id, request: job.request, format: job.format, blob,
    count: state.view.matches.length });
}

async function scanCertificates(job) {
  const scan = new CertificateScan();
  try {
    const size = job.file.size;
    for (let start = 0; start < size; start += CHUNK_SIZE) {
      const end = Math.min(size, start + CHUNK_SIZE + overlap);
      const buffer = await job.file.slice(start, end).arrayBuffer();
      if (!isCurrent(job)) return;
      scan.push_window(new Uint8Array(buffer), BigInt(start), Math.min(CHUNK_SIZE, size - start));
      send({ type: 'certificates-progress', id: job.id, request: job.request,
        scanned: Math.min(size, start + CHUNK_SIZE), total: size });
      await yieldTask();
      if (!isCurrent(job)) return;
    }
    const report = JSON.parse(scan.finish());
    if (report.error) throw new Error(report.error);
    send({ type: 'certificates', id: job.id, request: job.request, report });
  } finally {
    scan.free();
  }
}

/** Duplicate and issuer links among DER certificates gathered from several files. */
function linkCertificates(job) {
  const links = new CertificateLinks();
  try {
    for (const der of job.ders) links.push(der);
    const result = JSON.parse(links.finish());
    if (result.error) throw new Error(result.error);
    send({ type: 'certificates-links', id: job.id, request: job.request, links: result });
  } finally {
    links.free();
  }
}

const handlers = {
  'strings-scan': scanStrings,
  'strings-query': queryStrings,
  'strings-rows': stringRows,
  'strings-locate': locateString,
  'strings-export': exportStrings,
  certificates: scanCertificates,
  'certificates-link': linkCertificates,
};

async function handle(job) {
  if (job.type === 'forget') {
    scans.delete(job.id);
    for (const key of [...latest.keys()]) if (key.endsWith(`:${job.id}`)) latest.delete(key);
    return;
  }
  if (job.type === 'clear') {
    scans.clear();
    latest.clear();
    return;
  }
  const handler = handlers[job.type];
  if (!handler) return;
  latest.set(`${job.type}:${job.id}`, job.request);
  try {
    await handler(job);
  } catch (error) {
    const message = String(error.message || error);
    send({ type: 'error', id: job.id, request: job.request, operation: job.type, error: message });
  }
}

self.addEventListener('message', ({ data }) => {
  if (ready) handle(data);
  else waiting.push(data);
});

try {
  await init();
  encodingIds = JSON.parse(string_encoding_ids());
  tagIds = JSON.parse(string_tag_ids());
  overlap = certificate_window_overlap();
  ready = true;
  send({ type: 'ready', protocol: SCAN_PROTOCOL, encodingIds, tagIds });
  for (const job of waiting.splice(0)) handle(job);
} catch (error) {
  send({ type: 'boot-error', error: `Failed to load the scanners: ${error.message || error}` });
}
