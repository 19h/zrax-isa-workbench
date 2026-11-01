// The strings tab: a virtual grid over the scan worker's string index, with
// search, facet chips, scope, sorting, an inspector and links to the hex
// view. The worker holds the strings; this module requests one query result
// and then pages of rows as the grid scrolls.
import { esc, fmtSize } from './format.js';
import { hx } from './hex-utils.js';

const PAGE_ROWS = 256;
const OVERSCAN_ROWS = 8;
const SEARCH_DEBOUNCE_MS = 150;
const PROGRESS_REFRESH_MS = 300;
const PREVIEW_BYTES = 64;
// Inspector byte-preview layouts, widest first; the first that fits is used.
const DUMP_LAYOUTS = [
  { bytes: 16, ascii: true },
  { bytes: 16, ascii: false },
  { bytes: 8, ascii: true },
  { bytes: 8, ascii: false },
  { bytes: 4, ascii: true },
  { bytes: 4, ascii: false },
];
const MAX_COPY_ROWS = 10000;
const MAX_HIGHLIGHTS = 64;
// Browsers cap element heights (Firefox near 17.9 million CSS pixels); taller
// lists scroll proportionally through this extent.
const MAX_SCROLL_PX = 8000000;
const PREFS_KEY = 'isawb.strings.v1';
const MIN_CHARS = 3;
const MAX_CHARS = 255;
const DEFAULT_PREFS = {
  minChars: 4,
  encodings: ['ascii', 'utf8', 'utf16le'],
  sort: { key: 'offset', dir: 'asc' },
  caseSensitive: false,
  regex: false,
};
const ENCODING_LABELS = { ascii: 'ascii', utf8: 'utf-8', utf16le: 'utf-16le', utf16be: 'utf-16be' };
const COLUMNS = [
  { key: 'offset', label: 'offset' },
  { key: 'region', label: 'region' },
  { key: 'encoding', label: 'enc' },
  { key: 'chars', label: 'len' },
  { key: 'size', label: 'size' },
  { key: 'tags', label: 'tags' },
  { key: 'text', label: 'text' },
];

const $ = id => document.getElementById(id);

function loadPrefs() {
  let saved = {};
  try {
    saved = JSON.parse(localStorage.getItem(PREFS_KEY)) || {};
  } catch {
    // Storage is optional.
  }
  const minChars = Number.isInteger(saved.minChars) && saved.minChars >= MIN_CHARS && saved.minChars <= MAX_CHARS
    ? saved.minChars
    : DEFAULT_PREFS.minChars;
  const validEncodings = Array.isArray(saved.encodings)
    && saved.encodings.length > 0
    && saved.encodings.every(id => id in ENCODING_LABELS);
  const encodings = validEncodings ? saved.encodings : DEFAULT_PREFS.encodings;
  const sort = COLUMNS.some(c => c.key === saved.sort?.key) && ['asc', 'desc'].includes(saved.sort?.dir)
    ? saved.sort
    : DEFAULT_PREFS.sort;
  return {
    minChars,
    encodings,
    sort,
    caseSensitive: saved.caseSensitive === true,
    regex: saved.regex === true,
  };
}

function savePrefs(prefs) {
  try {
    localStorage.setItem(PREFS_KEY, JSON.stringify(prefs));
  } catch {
    // Storage is optional.
  }
}

/** Text with tabs and control characters made visible, escaped for HTML. */
function visibleText(text) {
  return esc(text).replace(/\t/g, '<span class="strings-control" title="tab">⇥</span>');
}

/** Match ranges of the current search in `text`, at most MAX_HIGHLIGHTS. */
function matchRanges(text, spec) {
  if (!spec.search) return [];
  const ranges = [];
  if (spec.regex) {
    let pattern;
    try {
      pattern = new RegExp(spec.search, spec.caseSensitive ? 'g' : 'gi');
    } catch {
      return [];
    }
    for (const match of text.matchAll(pattern)) {
      if (!match[0].length) continue;
      ranges.push([match.index, match.index + match[0].length]);
      if (ranges.length >= MAX_HIGHLIGHTS) break;
    }
    return ranges;
  }
  const haystack = spec.caseSensitive ? text : text.toLowerCase();
  const needle = spec.caseSensitive ? spec.search : spec.search.toLowerCase();
  let at = haystack.indexOf(needle);
  while (at >= 0 && ranges.length < MAX_HIGHLIGHTS) {
    ranges.push([at, at + needle.length]);
    at = haystack.indexOf(needle, at + needle.length);
  }
  return ranges;
}

/** The text with search matches wrapped in `<mark>`. */
function highlighted(text, spec) {
  const ranges = matchRanges(text, spec);
  let html = '';
  let at = 0;
  for (const [start, end] of ranges) {
    html += visibleText(text.slice(at, start)) + `<mark>${visibleText(text.slice(start, end))}</mark>`;
    at = end;
  }
  return html + visibleText(text.slice(at));
}

/** A C string literal for the text. */
function cLiteral(text) {
  const escaped = [...text].map(c => {
    if (c === '\\') return '\\\\';
    if (c === '"') return '\\"';
    if (c === '\t') return '\\t';
    const code = c.codePointAt(0);
    if (code < 0x20 || code === 0x7f) return `\\x${code.toString(16).padStart(2, '0')}`;
    return c;
  });
  return `"${escaped.join('')}"`;
}

/** The bytes as ASCII, with `.` for anything outside 0x20-0x7E. */
function printable(bytes) {
  return Array.from(bytes, b => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.')).join('');
}

/** Characters in one preview line: offset, two spaces, bytes, then optionally two spaces and their ASCII. */
function dumpLineChars(layout, offsetDigits) {
  const ascii = layout.ascii ? 2 + layout.bytes : 0;
  return offsetDigits + 2 + layout.bytes * 3 - 1 + ascii;
}

/** The widest preview layout whose lines fit in `pre` without scrolling. */
function fitDumpLayout(pre, offsetDigits) {
  const probe = document.createElement('span');
  probe.textContent = '0'.repeat(32);
  pre.append(probe);
  const charWidth = probe.getBoundingClientRect().width / 32;
  probe.remove();
  const style = getComputedStyle(pre);
  const available = pre.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight);
  const columns = charWidth ? Math.floor(available / charWidth) : 0;
  const fitting = DUMP_LAYOUTS.find(layout => dumpLineChars(layout, offsetDigits) <= columns);
  return fitting || DUMP_LAYOUTS[DUMP_LAYOUTS.length - 1];
}

export function createStringsView(scanner, hooks) {
  const prefs = loadPrefs();
  const files = new Map();
  let entry = null;
  let active = false;
  let rowHeight = 0;
  let searchTimer = 0;
  let refreshTimer = 0;
  // Bytes shown in the inspector, kept so a resize can lay them out again.
  let preview = null;
  let inspectorWidth = 0;

  function fileState(target) {
    let state = files.get(target.id);
    if (!state) {
      state = {
        search: '',
        tags: 0,
        scope: 'file',
        scan: null,
        view: null,
        query: 0,
        pages: new Map(),
        pending: new Set(),
        selected: -1,
        anchor: -1,
        detail: null,
        scrollTop: 0,
        regions: null,
        copyRequest: 0,
        locate: null,
      };
      files.set(target.id, state);
    }
    return state;
  }

  function encodingMask(ids) {
    return ids.reduce((mask, id) => mask | (1 << scanner.encodingIds.indexOf(id)), 0);
  }

  function spec(state) {
    const range = state.scope === 'selection' ? hooks.hexSelection() : null;
    const region = state.scope.startsWith('region:') ? Number(state.scope.slice(7)) : -1;
    return {
      search: state.search,
      caseSensitive: prefs.caseSensitive,
      regex: prefs.regex,
      encodings: encodingMask(prefs.encodings),
      tags: state.tags,
      minChars: prefs.minChars,
      range,
      region,
      sort: prefs.sort,
    };
  }

  // --- worker requests ---------------------------------------------------

  /** Start or reuse a scan whose floor and encodings cover the preferences. */
  function ensureScan(state) {
    // Encoding bits come from the worker's identifiers; wait for them.
    if (!scanner.ready) return false;
    const mask = encodingMask(prefs.encodings);
    const scan = state.scan;
    const covers = scan && scan.minChars <= prefs.minChars && (scan.mask & mask) === mask && !scan.failed;
    if (covers && state.regions === entry.regions) return false;
    const minChars = covers ? scan.minChars : prefs.minChars;
    const encodings = covers ? scan.mask : mask | (scan && !scan.failed ? scan.mask : 0);
    state.regions = entry.regions;
    const request = scanner.post({
      type: 'strings-scan', id: entry.id, file: entry.file, minChars, encodings, regions: entry.regions || [],
    });
    if (!covers) {
      state.scan = {
        request, minChars, mask: encodings, scanned: 0, total: entry.size, found: 0, done: false, elapsed: 0,
      };
      state.view = null;
      state.pages.clear();
    }
    return true;
  }

  /** The part of a query that can stall the worker: the search itself. */
  function searchKey(query) {
    return JSON.stringify([query.search, query.regex, query.caseSensitive]);
  }

  function query(state, keepSelection = false) {
    if (!entry || !state.scan) return;
    const current = spec(state);
    if (state.blocked && state.blocked === searchKey(current)) return;
    state.blocked = null;
    const first = Math.max(0, firstVisibleRow(state) - OVERSCAN_ROWS);
    const from = Math.floor(first / PAGE_ROWS) * PAGE_ROWS;
    state.query = scanner.post({
      type: 'strings-query', id: entry.id, query: current, from, count: PAGE_ROWS * 2,
    });
    if (!keepSelection) {
      state.selected = -1;
      state.anchor = -1;
    }
  }

  function scheduleQuery(state) {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      state.scrollTop = 0;
      $('strings-scroller').scrollTop = 0;
      query(state);
    }, SEARCH_DEBOUNCE_MS);
  }

  function requestPage(state, page) {
    if (!state.view || state.pages.has(page) || state.pending.has(page)) return;
    state.pending.add(page);
    scanner.post({
      type: 'strings-rows', id: entry.id, view: state.view.request, from: page * PAGE_ROWS, count: PAGE_ROWS,
    });
  }

  function rowAt(state, position) {
    return state.pages.get(Math.floor(position / PAGE_ROWS))?.[position % PAGE_ROWS] || null;
  }

  // --- messages ----------------------------------------------------------

  scanner.subscribe(data => {
    if (data.type === 'ready') {
      if (entry && active) refresh();
      return;
    }
    const state = files.get(data.id);
    if (data.type === 'boot-error' || data.type === 'restarted') {
      // Do not replay the search that stalled the worker until it is edited.
      if (state && data.query) state.blocked = searchKey(data.query);
      for (const s of files.values()) {
        s.scan = null;
        s.view = null;
        s.pages.clear();
        s.pending.clear();
      }
      if (entry && active) {
        const current = fileState(entry);
        current.error = data.reason || data.error;
        if (data.type === 'restarted') ensureScan(current);
        render();
      }
      return;
    }
    if (!state) return;
    if (data.type === 'strings-progress' && data.request === state.scan?.request) {
      Object.assign(state.scan, { scanned: data.scanned, total: data.total, found: data.found });
      if (!refreshTimer) {
        refreshTimer = setTimeout(() => {
          refreshTimer = 0;
          if (entry?.id === data.id && active) query(state, true);
        }, PROGRESS_REFRESH_MS);
      }
      if (entry?.id === data.id) renderStatus(state);
    } else if (data.type === 'strings-done' && state.scan) {
      if (data.request === state.scan.request) {
        Object.assign(state.scan, { done: true, found: data.total, truncated: data.truncated, elapsed: data.elapsed });
      }
      if (entry?.id === data.id && active) query(state, true);
    } else if (data.type === 'strings-view' && data.request === state.query) {
      state.view = {
        request: data.request,
        total: data.total,
        counts: data.counts || state.view?.counts,
        invalid: data.invalid || '',
      };
      state.pages.clear();
      state.pending.clear();
      const page = Math.floor(data.from / PAGE_ROWS);
      if (data.rows.length) state.pages.set(page, data.rows.slice(0, PAGE_ROWS));
      if (data.rows.length > PAGE_ROWS) state.pages.set(page + 1, data.rows.slice(PAGE_ROWS));
      state.error = '';
      state.retried = false;
      if (state.locate != null) {
        scanner.post({ type: 'strings-locate', id: data.id, offset: state.locate });
        state.locate = null;
      }
      if (entry?.id === data.id && active) render();
    } else if (data.type === 'strings-rows' && data.request === state.copyRequest) {
      // A copy reply spans the selection, not a page: never cache it.
      finishCopy(state, data.rows);
    } else if (data.type === 'strings-rows' && data.view === state.view?.request) {
      const page = Math.floor(data.from / PAGE_ROWS);
      state.pending.delete(page);
      state.pages.set(page, data.rows);
      if (entry?.id === data.id && active) {
        renderRows(state);
        if (state.selected >= 0 && Math.floor(state.selected / PAGE_ROWS) === page) renderInspector(state);
      }
    } else if (data.type === 'strings-located' && entry?.id === data.id && data.position >= 0) {
      select(state, data.position, false);
      scrollToRow(state, data.position);
    } else if (data.type === 'strings-export') {
      const name = `${entry?.name || 'strings'}.strings.${data.format}`;
      hooks.download(name, data.blob);
      hooks.log('info', `exported ${data.count.toLocaleString()} strings as ${data.format}`);
    } else if (data.type === 'error' && data.operation === 'strings-query' && !state.retried) {
      // The worker keeps few indexes; an evicted file is scanned again, once.
      state.retried = true;
      state.scan = null;
      if (entry?.id === data.id && active) {
        ensureScan(state);
        query(state, true);
      }
    } else if (data.type === 'error' && data.operation.startsWith('strings')) {
      if (data.operation === 'strings-scan' && state.scan) state.scan.failed = true;
      state.error = data.error;
      hooks.log('error', `strings: ${data.error}`);
      if (entry?.id === data.id) renderStatus(state);
    }
  });

  // --- rendering ---------------------------------------------------------

  function measureRowHeight() {
    if (rowHeight) return rowHeight;
    const probe = document.createElement('div');
    probe.className = 'strings-row';
    probe.innerHTML = '<span>0</span>';
    $('strings-rows').append(probe);
    const measured = probe.getBoundingClientRect().height;
    probe.remove();
    // A hidden panel measures zero; keep measuring until it is shown.
    if (!measured) return 25;
    rowHeight = measured;
    return rowHeight;
  }

  function visibleRows() {
    return Math.max(1, Math.floor($('strings-scroller').clientHeight / measureRowHeight()));
  }

  function geometry(state) {
    const total = state.view?.total || 0;
    const scroller = $('strings-scroller');
    const extent = Math.min(total * measureRowHeight(), MAX_SCROLL_PX);
    const maxScroll = Math.max(0, extent - scroller.clientHeight);
    const maxFirst = Math.max(0, total - visibleRows());
    return { total, extent, maxScroll, maxFirst };
  }

  function firstVisibleRow(state) {
    const { maxScroll, maxFirst } = geometry(state);
    if (!maxScroll) return 0;
    return Math.min(maxFirst, Math.round(($('strings-scroller').scrollTop / maxScroll) * maxFirst));
  }

  function scrollToRow(state, position) {
    const { maxScroll, maxFirst } = geometry(state);
    const first = firstVisibleRow(state);
    const visible = visibleRows();
    let target = first;
    if (position < first) target = position;
    else if (position >= first + visible) target = position - visible + 1;
    if (target !== first && maxFirst) $('strings-scroller').scrollTop = (target / maxFirst) * maxScroll;
    renderRows(state);
  }

  function regionLabel(region) {
    return entry?.regions?.[region]?.label ?? '';
  }

  function regionPath(row) {
    const regions = entry?.regions || [];
    return regions
      .filter(r => row.offset >= r.offset && row.offset + row.size <= r.offset + r.size)
      .sort((a, b) => b.size - a.size)
      .map(r => r.label);
  }

  function offsetText(offset) {
    return hooks.offsetBase() === 'dec' ? String(offset) : `0x${hx(offset)}`;
  }

  /**
   * Size the offset column for the file's largest offset, and drop the region
   * column when the file has no labelled regions.
   */
  function fitColumns() {
    const grid = $('strings-grid');
    const widest = entry ? offsetText(Math.max(0, entry.size - 1)).length : 10;
    grid.style.setProperty('--strings-offset-chars', String(widest));
    grid.classList.toggle('no-regions', !entry?.regions?.length);
  }

  function renderRows(state) {
    fitColumns();
    const container = $('strings-rows');
    const { total, extent } = geometry(state);
    $('strings-spacer').style.height = `${extent}px`;
    $('strings-grid').setAttribute('aria-rowcount', String(total + 1));
    const first = firstVisibleRow(state);
    const count = Math.min(total - first, visibleRows() + 1);
    container.style.transform = `translateY(${$('strings-scroller').scrollTop}px)`;
    const current = spec(state);
    const html = [];
    for (let p = first; p < first + count; p++) {
      const row = rowAt(state, p);
      if (!row) {
        requestPage(state, Math.floor(p / PAGE_ROWS));
        html.push(`<div class="strings-row placeholder" role="row" aria-rowindex="${p + 2}"><span role="gridcell">…</span></div>`);
        continue;
      }
      const low = Math.min(state.anchor < 0 ? state.selected : state.anchor, state.selected);
      const high = Math.max(state.anchor, state.selected);
      const chosen = p === state.selected || (state.anchor >= 0 && p >= low && p <= high);
      const tags = row.tags.map(tag => `<span class="strings-tag tag-${esc(tag)}">${esc(tag)}</span>`).join('');
      const clipped = row.clipped ? '<span class="strings-clipped" title="clipped at 4096 characters">…</span>' : '';
      html.push(`<div class="strings-row${chosen ? ' selected' : ''}" id="strings-row-${p}" role="row" aria-rowindex="${p + 2}" aria-selected="${chosen}" data-position="${p}">`
        + `<span role="gridcell" class="col-offset strings-offset">${esc(offsetText(row.offset))}</span>`
        + `<span role="gridcell" class="col-region strings-region" title="${esc(regionPath(row).join(' > '))}">${esc(regionLabel(row.region))}</span>`
        + `<span role="gridcell" class="col-encoding strings-encoding">${esc(ENCODING_LABELS[row.encoding] || row.encoding)}</span>`
        + `<span role="gridcell" class="col-chars strings-number">${row.chars}</span>`
        + `<span role="gridcell" class="col-size strings-number">${esc(fmtSize(row.size))}</span>`
        + `<span role="gridcell" class="col-tags strings-tags-cell">${tags}</span>`
        + `<span role="gridcell" class="col-text strings-text">${highlighted(row.text, current)}${clipped}</span>`
        + '</div>');
    }
    container.innerHTML = html.join('');
    const activeRow = state.selected >= first && state.selected < first + count ? `strings-row-${state.selected}` : '';
    if (activeRow) $('strings-grid').setAttribute('aria-activedescendant', activeRow);
    else $('strings-grid').removeAttribute('aria-activedescendant');
    for (const page of state.pages.keys()) {
      if (Math.abs(page * PAGE_ROWS - first) > PAGE_ROWS * 8) state.pages.delete(page);
    }
  }

  function renderHead() {
    $('strings-head').innerHTML = COLUMNS.map(({ key, label }) => {
      const sorted = prefs.sort.key === key;
      const direction = sorted ? (prefs.sort.dir === 'asc' ? 'ascending' : 'descending') : 'none';
      const arrow = sorted ? (prefs.sort.dir === 'asc' ? ' ▲' : ' ▼') : '';
      return `<span role="columnheader" aria-sort="${direction}" class="col-${key} strings-${key}-head">`
        + `<button type="button" data-strings-sort="${key}" aria-label="Sort by ${label}" title="Sort by ${label}">${label}${arrow}</button></span>`;
    }).join('');
  }

  function renderChips(state) {
    const counts = state.view?.counts;
    $('strings-encodings').innerHTML = scanner.encodingIds.map(id => {
      const on = prefs.encodings.includes(id);
      const count = counts?.encodings?.[id];
      const empty = count === 0 ? ' empty' : '';
      return `<button type="button" class="chip${empty}" data-strings-encoding="${id}" aria-pressed="${on}" aria-label="${ENCODING_LABELS[id]}"`
        + ` title="${count == null ? '' : `${count.toLocaleString()} strings`}">${ENCODING_LABELS[id]}`
        + `${count == null ? '' : ` <span class="count" aria-hidden="true">${count.toLocaleString()}</span>`}</button>`;
    }).join('');
    $('strings-tags').innerHTML = scanner.tagIds.map(([bit, id]) => {
      const on = (state.tags & bit) !== 0;
      const count = counts?.tags?.[id] ?? 0;
      const empty = count === 0 ? ' empty' : '';
      return `<button type="button" class="chip tag-${id}${empty}" data-strings-tag="${bit}" aria-pressed="${on}" aria-label="${id}"`
        + ` title="${count.toLocaleString()} strings; lexical pattern match">${id} <span class="count" aria-hidden="true">${count.toLocaleString()}</span></button>`;
    }).join('');
  }

  function renderScope(state) {
    const select = $('strings-scope');
    const selection = hooks.hexSelection();
    const regions = (entry?.regions || []).slice(0, 200);
    const options = [
      ['file', 'whole file'],
      ...(selection ? [['selection', `hex selection (${fmtSize(selection.end - selection.start)})`]] : []),
      ...regions.map((r, i) => [`region:${i}`, `${r.kind}: ${r.label}`]),
    ];
    if (!options.some(([value]) => value === state.scope)) state.scope = 'file';
    select.innerHTML = options.map(([value, label]) => `<option value="${esc(value)}">${esc(label)}</option>`).join('');
    select.value = state.scope;
  }

  function renderStatus(state) {
    const parts = [];
    const scan = state.scan;
    if (state.view) {
      parts.push(`${state.view.total.toLocaleString()} of ${(scan?.found || 0).toLocaleString()} strings`);
    }
    if (scan && !scan.done) {
      parts.push(`scanning ${scan.total ? Math.floor((scan.scanned / scan.total) * 100) : 0}%`);
    } else if (scan?.done) {
      parts.push(`scanned ${fmtSize(entry.size)} in ${(scan.elapsed / 1000).toFixed(1)} s`);
    }
    if (scan?.truncated) parts.push('stopped at the string limit; raise the minimum length or narrow encodings');
    const problem = state.view?.invalid || state.error || '';
    $('strings-status').textContent = parts.join(' · ');
    $('strings-problem').textContent = problem;
    $('strings-problem').hidden = !problem;
    $('strings-search').setAttribute('aria-invalid', String(Boolean(state.view?.invalid)));
  }

  async function renderInspector(state) {
    const panel = $('strings-inspector');
    const row = state.selected >= 0 ? rowAt(state, state.selected) : null;
    if (!row) {
      preview = null;
      panel.innerHTML = '<p class="muted">select a string to inspect it</p>';
      return;
    }
    const path = regionPath(row);
    panel.innerHTML = `<header class="bar"><span>[ string ]</span><span class="spacer"></span>`
      + `<button type="button" data-strings-action="hex">show in hex</button></header>`
      + `<pre class="strings-full">${visibleText(row.text)}${row.clipped ? '\n…' : ''}</pre>`
      + '<dl class="strings-facts">'
      + `<dt>offset</dt><dd>0x${hx(row.offset)} (${row.offset})</dd>`
      + `<dt>end</dt><dd>0x${hx(row.offset + row.size)}</dd>`
      + `<dt>size</dt><dd>${esc(fmtSize(row.size))}</dd>`
      + `<dt>length</dt><dd>${row.chars.toLocaleString()} characters${row.clipped ? ' (text clipped at 4096)' : ''}</dd>`
      + `<dt>encoding</dt><dd>${esc(ENCODING_LABELS[row.encoding] || row.encoding)}</dd>`
      + `<dt>tags</dt><dd>${row.tags.length ? `${esc(row.tags.join(', '))} <small class="muted">pattern match</small>` : '—'}</dd>`
      + `<dt>region</dt><dd>${path.length ? esc(path.join(' > ')) : '—'}</dd>`
      + '</dl>'
      + '<div class="strings-actions">'
      + '<button type="button" data-strings-action="copy-text">copy text</button>'
      + '<button type="button" data-strings-action="copy-literal">copy as C literal</button>'
      + '<button type="button" data-strings-action="copy-offset">copy offset</button>'
      + (row.region >= 0 ? '<button type="button" data-strings-action="region">only this region</button>' : '')
      + '</div>'
      + '<h2>[ bytes ]</h2><pre class="strings-bytes" id="strings-bytes">…</pre>';
    preview = null;
    const target = entry;
    const end = row.offset + Math.min(row.size, PREVIEW_BYTES);
    const bytes = new Uint8Array(await target.file.slice(row.offset, end).arrayBuffer());
    if (target !== entry || rowAt(state, state.selected) !== row) return;
    preview = { offset: row.offset, size: row.size, bytes };
    renderPreview();
  }

  /** Write the byte preview with as many bytes per line as the inspector fits. */
  function renderPreview() {
    const pre = $('strings-bytes');
    if (!preview || !pre) return;
    const { offset, size, bytes } = preview;
    const offsetDigits = hx(offset + bytes.length).length;
    const layout = fitDumpLayout(pre, offsetDigits);
    const lines = [];
    for (let i = 0; i < bytes.length; i += layout.bytes) {
      const line = bytes.subarray(i, i + layout.bytes);
      const hexText = Array.from(line, b => hx(b, 2)).join(' ');
      const columns = layout.ascii ? `${hexText.padEnd(layout.bytes * 3 - 1)}  ${printable(line)}` : hexText;
      lines.push(`${hx(offset + i, offsetDigits)}  ${columns}`);
    }
    if (size > PREVIEW_BYTES) lines.push(`… ${fmtSize(size - PREVIEW_BYTES)} more`);
    pre.textContent = lines.join('\n');
  }

  function render() {
    if (!entry || !active) return;
    const state = fileState(entry);
    $('strings-search').value = state.search;
    $('strings-min').value = String(prefs.minChars);
    $('strings-case').setAttribute('aria-pressed', String(prefs.caseSensitive));
    $('strings-regex').setAttribute('aria-pressed', String(prefs.regex));
    renderHead();
    renderChips(state);
    renderScope(state);
    renderStatus(state);
    renderRows(state);
    renderInspector(state);
  }

  // --- selection and actions ---------------------------------------------

  function select(state, position, extend) {
    const total = state.view?.total || 0;
    if (!total) return;
    const next = Math.max(0, Math.min(total - 1, position));
    if (extend) {
      if (state.anchor < 0) state.anchor = state.selected < 0 ? next : state.selected;
    } else {
      state.anchor = -1;
    }
    state.selected = next;
    scrollToRow(state, next);
    renderInspector(state);
  }

  function selectedRow(state) {
    return state.selected >= 0 ? rowAt(state, state.selected) : null;
  }

  function showInHex(state) {
    const row = selectedRow(state);
    if (row) hooks.showRange(row.offset, row.offset + row.size);
  }

  function copyRows(state) {
    if (state.selected < 0) return;
    const low = state.anchor < 0 ? state.selected : Math.min(state.anchor, state.selected);
    const high = state.anchor < 0 ? state.selected : Math.max(state.anchor, state.selected);
    const count = Math.min(high - low + 1, MAX_COPY_ROWS);
    state.copyRequest = scanner.post({
      type: 'strings-rows', id: entry.id, view: state.view.request, from: low, count,
    });
    if (high - low + 1 > MAX_COPY_ROWS) {
      hooks.log('info', `copying the first ${MAX_COPY_ROWS.toLocaleString()} selected strings`);
    }
  }

  function finishCopy(state, rows) {
    state.copyRequest = 0;
    hooks.copy(rows.map(row => row.text).join('\n'));
  }

  function act(action) {
    const state = fileState(entry);
    const row = selectedRow(state);
    if (action === 'hex') showInHex(state);
    else if (action === 'copy-text' && row) hooks.copy(row.text);
    else if (action === 'copy-literal' && row) hooks.copy(cLiteral(row.text));
    else if (action === 'copy-offset' && row) hooks.copy(`0x${hx(row.offset)}`);
    else if (action === 'region' && row) {
      state.scope = `region:${row.region}`;
      renderScope(state);
      scheduleQuery(state);
    }
  }

  // --- events ------------------------------------------------------------

  $('strings-search').addEventListener('input', event => {
    if (!entry) return;
    const state = fileState(entry);
    state.search = event.target.value;
    scheduleQuery(state);
  });
  $('strings-search').addEventListener('keydown', event => {
    if (event.key === 'Escape' && event.target.value) {
      event.target.value = '';
      event.target.dispatchEvent(new Event('input'));
      event.preventDefault();
    } else if (event.key === 'ArrowDown' || event.key === 'Enter') {
      $('strings-grid').focus();
      const state = fileState(entry);
      if (state.selected < 0) select(state, 0, false);
      event.preventDefault();
    }
  });
  for (const [id, key] of [['strings-case', 'caseSensitive'], ['strings-regex', 'regex']]) {
    $(id).addEventListener('click', () => {
      prefs[key] = !prefs[key];
      savePrefs(prefs);
      $(id).setAttribute('aria-pressed', String(prefs[key]));
      if (entry) scheduleQuery(fileState(entry));
    });
  }
  $('strings-min').addEventListener('change', event => {
    const value = Number(event.target.value);
    if (!Number.isInteger(value) || value < MIN_CHARS || value > MAX_CHARS) {
      event.target.setAttribute('aria-invalid', 'true');
      return;
    }
    event.target.removeAttribute('aria-invalid');
    prefs.minChars = value;
    savePrefs(prefs);
    if (!entry) return;
    const state = fileState(entry);
    ensureScan(state);
    scheduleQuery(state);
  });
  $('strings-scope').addEventListener('change', event => {
    if (!entry) return;
    const state = fileState(entry);
    state.scope = event.target.value;
    scheduleQuery(state);
  });
  $('strings-view').addEventListener('click', event => {
    if (!entry) return;
    const state = fileState(entry);
    const button = event.target.closest('button');
    const rowNode = event.target.closest('.strings-row[data-position]');
    if (button?.dataset.stringsSort) {
      const key = button.dataset.stringsSort;
      prefs.sort = { key, dir: prefs.sort.key === key && prefs.sort.dir === 'asc' ? 'desc' : 'asc' };
      savePrefs(prefs);
      renderHead();
      query(state);
    } else if (button?.dataset.stringsEncoding) {
      const id = button.dataset.stringsEncoding;
      const on = prefs.encodings.includes(id);
      if (on && prefs.encodings.length === 1) return;
      prefs.encodings = on ? prefs.encodings.filter(e => e !== id) : [...prefs.encodings, id];
      savePrefs(prefs);
      ensureScan(state);
      renderChips(state);
      scheduleQuery(state);
    } else if (button?.dataset.stringsTag) {
      state.tags ^= Number(button.dataset.stringsTag);
      renderChips(state);
      scheduleQuery(state);
    } else if (button?.dataset.stringsExport) {
      scanner.post({ type: 'strings-export', id: entry.id, format: button.dataset.stringsExport });
    } else if (button?.dataset.stringsAction) {
      act(button.dataset.stringsAction);
    } else if (rowNode) {
      $('strings-grid').focus();
      select(state, Number(rowNode.dataset.position), event.shiftKey);
    }
  });
  $('strings-rows').addEventListener('dblclick', event => {
    const rowNode = event.target.closest('.strings-row[data-position]');
    if (!rowNode || !entry) return;
    const state = fileState(entry);
    select(state, Number(rowNode.dataset.position), false);
    showInHex(state);
  });
  $('strings-scroller').addEventListener('scroll', () => {
    if (!entry) return;
    const state = fileState(entry);
    state.scrollTop = $('strings-scroller').scrollTop;
    renderRows(state);
  });
  $('strings-grid').addEventListener('keydown', event => {
    if (!entry) return;
    const state = fileState(entry);
    const page = visibleRows();
    const moves = {
      ArrowDown: 1,
      ArrowUp: -1,
      PageDown: page,
      PageUp: -page,
      Home: -Infinity,
      End: Infinity,
    };
    if (event.key in moves) {
      const base = state.selected < 0 ? 0 : state.selected;
      const step = moves[event.key];
      const target = Number.isFinite(step) ? base + step : step < 0 ? 0 : (state.view?.total || 1) - 1;
      select(state, target, event.shiftKey);
      event.preventDefault();
      event.stopPropagation();
    } else if (event.key === 'Enter') {
      showInHex(state);
      event.preventDefault();
    } else if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'c') {
      copyRows(state);
      event.preventDefault();
    } else if (event.key === 'Escape' && state.anchor >= 0) {
      state.anchor = -1;
      renderRows(state);
    }
  });
  new ResizeObserver(() => {
    if (entry && active) renderRows(fileState(entry));
  }).observe($('strings-scroller'));
  new ResizeObserver(() => {
    const width = $('strings-inspector').clientWidth;
    if (width === inspectorWidth) return;
    inspectorWidth = width;
    renderPreview();
  }).observe($('strings-inspector'));

  /** Scan and query the current entry when needed, then render it. */
  function refresh(changed = false) {
    const state = fileState(entry);
    const started = ensureScan(state);
    if (changed || started || !state.view) {
      $('strings-scroller').scrollTop = state.scrollTop;
      query(state, true);
    }
    render();
  }

  // --- public interface --------------------------------------------------

  return {
    /** Follow the selected entry and whether the strings tab is shown. */
    sync(nextEntry, nextActive) {
      const changed = nextEntry !== entry;
      entry = nextEntry;
      active = nextActive && Boolean(entry);
      if (!active) return;
      refresh(changed);
    },
    /** Focus the search field (the `/` shortcut). */
    focusSearch() {
      $('strings-search').focus();
      $('strings-search').select();
    },
    /** Limit the view to the hex selection. */
    showSelection() {
      if (!entry) return;
      const state = fileState(entry);
      state.scope = 'selection';
      state.view = null;
    },
    /** Select the string at or after `offset` once the next view is ready. */
    locate(offset) {
      if (!entry) return;
      const state = fileState(entry);
      state.locate = offset;
      state.view = null;
    },
    forget(id) {
      files.delete(id);
      scanner.forget(id);
    },
    clear() {
      for (const id of files.keys()) scanner.forget(id);
      files.clear();
    },
  };
}
