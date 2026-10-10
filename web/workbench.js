import { esc, fmtSize, isaName, fmtEndian, fmtSource, fmtFormatName, fmtVariant, fmtMetaValue, fmtCat } from './format.js';
import { hx, ENC, encChar, parseGoto, fmtF, unixT, utf8At } from './hex-utils.js';
import { drawMap, drawProfile, drawLegend, drawHistogram, entropyClass, complexityClass } from './canvas.js';
import { Viewport, worldSide, baseScale, bytePosition, xy2d } from './viewport.js';
import { WORKBENCH_PROTOCOL } from './protocol.js';

const $ = id => document.getElementById(id);
const text = (id, value) => { $(id).textContent = value; };
const setHidden = (id, hidden) => { $(id).hidden = hidden; };
const entries = new Map(), layouts = new Map(), counts = { queued: 0, analyzing: 0, done: 0, error: 0 };
const archTally = new Map(), formatTally = new Map();
let saved = {};
try { saved = JSON.parse(localStorage.getItem('isawb.v2')) || {}; } catch { /* Storage is optional. */ }
const choose = (value, options, fallback) => options.includes(value) ? value : fallback;
const ui = {
  view: 'file', tab: choose(saved.tab, ['classification', 'entropy', 'hex', 'json'], 'classification'),
  sideOpen: typeof saved.sideOpen === 'boolean' ? saved.sideOpen : innerWidth >= 1000,
  logOpen: saved.logOpen === true, curve: choose(saved.curve, ['hilbert', 'linear'], 'hilbert'),
  mode: choose(saved.mode, ['entropy', 'bytes'], 'entropy'),
  columns: choose(saved.columns, [8, 16, 24, 32], 16), group: choose(saved.group, [1, 2, 4, 8], 4),
  encoding: choose(saved.encoding, ENC.map(x => x[0]), 'ascii'), offsetBase: choose(saved.offsetBase, ['hex', 'dec'], 'hex'),
  endian: null, filter: 'all', sort: 'queue', selected: null, cursor: 0, hover: null, anchor: null,
  hexTop: 0,
};
let nextId = 1, requestId = 0, ready = false, engineError = '', version = '', map = null;
let hexData = null, probeData = null, selectionData = null;
let lastHexKey = '', lastProbeKey = '', lastSelectionKey = '';
let hexRequest = 0, probeRequest = 0, selectionRequest = 0, probeTimer = 0, paintFrame = 0;
let dragDepth = 0, hexDragging = false, hexDragAnchor = null;
let camera = new Viewport(), detail = null, detailTimer = 0, historyTimer = 0, cameraFrame = 0, mapDrag = null, skipMapClick = false;
let paintedBaseKey = '';
const mapCache = new Map();
const log = [];
const worker = new Worker(new URL('./analysis-worker.js', import.meta.url), { type: 'module' });
const selected = () => entries.get(ui.selected);
const clampOffset = offset => Math.max(0, Math.min(Math.max(0, (selected()?.size || 0) - 1), Math.floor(offset)));
const probeOffset = () => ui.hover ?? ui.cursor;
const archId = isa => typeof isa === 'object' ? isaName(isa).toLowerCase() : isa === 'x86_64' ? isa : String(isa).replaceAll('_', '');
const archLabel = payload => payload.slices?.length > 1 ? [...new Set(payload.slices.map(x => archId(x.isa)))].join(' + ') : archId(payload.primary.isa);
const statusLabel = status => ({ queued: 'queued', analyzing: 'analyzing', done: 'done', error: 'failed' })[status];
const glyph = status => ({ queued: '[ ]', analyzing: '[*]', done: '[+]', error: '[-]' })[status];
const byteClass = value => value === 0 ? 'byte-zero' : value === 255 ? 'byte-ff' : value < 32 || value === 127 ? 'byte-control' : value < 127 ? 'byte-ascii' : 'byte-high';
const panel = (label, body, count = '') => `<section class="panel"><header>[ ${esc(label)} ] <span class="muted">${esc(count)}</span></header><div class="panel-body">${body}</div></section>`;
const row = (key, value) => `<div class="metadata-row"><span>${esc(key)}</span><span>${esc(value)}</span></div>`;
const tally = (table, key, delta) => { const n = (table.get(key) || 0) + delta; n ? table.set(key, n) : table.delete(key); };

function persist() {
  const { tab, sideOpen, logOpen, curve, mode, columns, group, encoding, offsetBase } = ui;
  try { localStorage.setItem('isawb.v2', JSON.stringify({ tab, sideOpen, logOpen, curve, mode, columns, group, encoding, offsetBase })); } catch { /* Storage is optional. */ }
}
function pushLog(tone, message) {
  log.push({ tone, message });
  if (log.length > 400) log.shift();
  const line = document.createElement('div');
  line.className = `log-line log-${tone}`;
  line.textContent = `${tone === 'cmd' ? '$' : tone === 'done' ? '[+]' : tone === 'error' ? '[-]' : '[i]'} ${message}`;
  $('log-lines').append(line);
  while ($('log-lines').children.length > 400) $('log-lines').firstElementChild.remove();
  $('log-lines').scrollTop = $('log-lines').scrollHeight;
}
function showError(message) {
  text('error', message); setHidden('error', false); pushLog('error', message);
}
function setStatus(entry, status) {
  if (entry.status !== status) { counts[entry.status]--; counts[status]++; entry.status = status; }
}
function enqueue(files) {
  if (!files.length) return;
  if (engineError) { showError(engineError); return; }
  setHidden('error', true);
  const added = [];
  for (const file of Array.from(files)) {
    const entry = { id: nextId++, file, name: file.name, size: file.size, status: 'queued', payload: null, error: '', profile: null, mean: null, elapsed: null, cursor: 0 };
    entries.set(entry.id, entry); counts.queued++; added.push(entry);
    createEntry(entry); updateEntry(entry);
  }
  worker.postMessage({ type: 'add', files: added.map(({ id, file }) => ({ id, file })) });
  pushLog('cmd', `queue ${added.map(x => JSON.stringify(x.name)).join(' ')}`);
  if (added.length === 1) selectFile(added[0].id);
  else { if (!selected()) selectFile(added[0].id); ui.view = 'batch'; ui.filter = 'all'; }
  renderSummary(); renderBatchOrder(); renderChrome();
}
function createEntry(entry) {
  const button = document.createElement('button');
  button.type = 'button'; button.className = 'file-entry'; button.dataset.fileId = entry.id;
  button.innerHTML = '<span class="file-glyph"></span><span class="file-info"><span class="file-name"></span><span class="file-sub"></span></span><span class="file-size"></span>';
  button.querySelector('.file-name').textContent = entry.name;
  button.querySelector('.file-size').textContent = fmtSize(entry.size);
  $('file-list').append(button); entry.button = button;
  const tr = document.createElement('tr'); tr.dataset.fileId = entry.id;
  tr.innerHTML = '<td class="batch-status"></td><td><button class="batch-file" type="button"></button><span class="batch-error"></span></td><td class="batch-architecture"></td><td class="batch-bits"></td><td class="batch-endian"></td><td class="batch-format"></td><td class="batch-confidence"></td><td class="batch-source"></td><td class="batch-size"></td><td><canvas class="batch-profile" width="1024" height="1"></canvas><span class="batch-mean"></span></td><td class="batch-time"></td>';
  tr.querySelector('.batch-file').textContent = entry.name;
  tr.querySelector('.batch-size').textContent = fmtSize(entry.size);
  entry.tr = tr; $('batch-rows').append(tr);
}
function updateEntry(entry) {
  const { status, payload: p } = entry;
  const sub = p ? `${archLabel(p)} · ${p.primary.bitwidth}-bit ${p.primary.endianness} · ${fmtFormatName(p.format.format).toLowerCase()}`
    : entry.error || statusLabel(status);
  entry.button.title = `${entry.name}\n${sub}`;
  entry.button.querySelector('.file-glyph').className = `file-glyph ${status}`;
  entry.button.querySelector('.file-glyph').textContent = glyph(status);
  entry.button.querySelector('.file-sub').textContent = sub;
  const cell = (className, value) => { entry.tr.querySelector('.' + className).textContent = value; };
  const st = entry.tr.querySelector('.batch-status'); st.className = `batch-status ${status}`; st.textContent = glyph(status); st.title = statusLabel(status);
  cell('batch-error', entry.error); cell('batch-architecture', p ? archLabel(p) : '—');
  cell('batch-bits', p?.primary.bitwidth ?? '—'); cell('batch-endian', p?.primary.endianness ?? '—');
  cell('batch-format', p ? fmtFormatName(p.format.format).toLowerCase() : '—');
  cell('batch-confidence', p ? `${(p.primary.confidence * 100).toFixed(1)}%` : '—');
  cell('batch-source', p ? fmtSource(p.primary.source).toLowerCase() : '—');
  cell('batch-mean', entry.mean == null ? '—' : entry.mean.toFixed(2));
  cell('batch-time', entry.elapsed == null ? '—' : entry.elapsed.toFixed(1));
  entry.tr.querySelector('.batch-file').title = entry.name;
  drawProfile(entry.tr.querySelector('canvas'), entry.profile);
  applyFilter(entry);
}
function applyFilter(entry) {
  const matches = ui.filter === 'all' || entry.status === ui.filter || ui.filter === 'pending' && ['queued', 'analyzing'].includes(entry.status);
  entry.tr.hidden = !matches;
}
function renderBatchOrder() {
  const list = [...entries.values()];
  const compare = { name: (a, b) => a.name.localeCompare(b.name), size: (a, b) => b.size - a.size,
    confidence: (a, b) => (b.payload?.primary.confidence ?? -1) - (a.payload?.primary.confidence ?? -1),
    entropy: (a, b) => (b.mean ?? -1) - (a.mean ?? -1) }[ui.sort];
  if (compare) list.sort(compare);
  for (const entry of list) { applyFilter(entry); $('batch-rows').append(entry.tr); }
  setHidden('batch-no-match', list.some(entry => !entry.tr.hidden));
}
function renderSummary() {
  const total = entries.size, pending = counts.queued + counts.analyzing;
  const summary = `${counts.done} done · ${counts.error} failed${pending ? ` · ${pending} pending` : ''}`;
  text('file-count', total); text('side-summary', summary); text('batch-summary', `${total} file${total === 1 ? '' : 's'} · ${summary}`);
  text('status-counts', `${total} files · ${summary}`);
  for (const [filter, count] of Object.entries({ all: total, done: counts.done, error: counts.error, pending })) text(`count-${filter}`, count);
  $('batch-progress').max = total || 1; $('batch-progress').value = counts.done + counts.error;
  $('batch').setAttribute('aria-busy', String(pending > 0));
  $('batch-tallies').innerHTML = [archTally, formatTally].map((table, i) => table.size ? `<span class="muted">${i ? 'format' : 'arch'}</span>${[...table].sort((a, b) => b[1] - a[1]).map(([name, n]) => `<span class="tag">${esc(name)} ${n}</span>`).join('')}` : '').join('');
  const matching = ui.filter === 'all' ? total : ui.filter === 'pending' ? pending : counts[ui.filter];
  setHidden('batch-no-match', matching > 0);
}
function renderChrome() {
  const entry = selected();
  setHidden('files-panel', !ui.sideOpen || ui.view === 'batch');
  setHidden('empty-view', ui.view !== 'file' || Boolean(entry));
  setHidden('file-view', ui.view !== 'file' || !entry);
  setHidden('batch', ui.view !== 'batch'); setHidden('analysis-log', !ui.logOpen);
  $('toggle-files').classList.toggle('active', ui.sideOpen && ui.view === 'file');
  $('toggle-files').setAttribute('aria-expanded', String(ui.sideOpen && ui.view === 'file'));
  $('toggle-log').classList.toggle('active', ui.logOpen);
  document.querySelector('[data-action="file-view"]').classList.toggle('active', ui.view === 'file');
  document.querySelector('[data-action="batch-view"]').classList.toggle('active', ui.view === 'batch');
  for (const button of document.querySelectorAll('[data-tab]')) { const on = button.dataset.tab === ui.tab; button.setAttribute('aria-selected', String(on)); button.tabIndex = on ? 0 : -1; }
  for (const tab of ['classification', 'entropy', 'hex', 'json']) setHidden(`${tab}-view`, ui.tab !== tab);
  for (const button of document.querySelectorAll('[data-curve]')) button.classList.toggle('active', button.dataset.curve === ui.curve);
  for (const button of document.querySelectorAll('[data-mode]')) button.classList.toggle('active', button.dataset.mode === ui.mode);
  for (const button of document.querySelectorAll('[data-filter]')) button.classList.toggle('active', button.dataset.filter === ui.filter);
  $('classification-band').classList.toggle('compact', ui.tab !== 'classification');
  $('hex-columns').value = ui.columns; $('hex-group').value = ui.group; $('hex-encoding').value = ui.encoding; $('hex-offset').value = ui.offsetBase;
  text('status-mode', ui.view === 'batch' ? 'BATCH' : ui.tab === 'classification' ? 'CLASSIFY' : ui.tab.toUpperCase());
  text('status-file', entry?.name || 'no file');
  text('status-classification', entry?.payload ? `${archLabel(entry.payload)} · ${entry.payload.primary.bitwidth}-bit ${entry.payload.primary.endianness} · ${fmtFormatName(entry.payload.format.format).toLowerCase()}` : '');
  persist();
  requestAnimationFrame(() => { sizeMap(); syncView(); });
}
function selectFile(id) {
  const entry = entries.get(id); if (!entry) return;
  const previous = selected(); if (previous) { rememberView(); previous.camera = camera.snapshot(); previous.cursor = ui.cursor; previous.button.classList.remove('selected'); previous.button.removeAttribute('aria-current'); previous.tr.classList.remove('selected'); }
  cancelInteractive();
  ui.selected = id; ui.view = 'file'; ui.cursor = Math.min(entry.cursor, Math.max(0, entry.size - 1));
  ui.hover = ui.anchor = ui.endian = null; ui.hexTop = Math.max(0, Math.floor(ui.cursor / ui.columns) - 5);
  camera = new Viewport(entry.camera);
  if (!entry.history) { entry.history = [camera.snapshot()]; entry.historyIndex = 0; }
  entry.button.classList.add('selected'); entry.button.setAttribute('aria-current', 'true'); entry.tr.classList.add('selected');
  renderSelected(); renderEntropyInspector(); renderDataInspector(); renderChrome();
}
function renderSelected() {
  const entry = selected(); if (!entry) return;
  text('file-name', entry.name); text('file-size', fmtSize(entry.size));
  text('file-status', statusLabel(entry.status)); $('file-status').className = `badge ${entry.status}`;
  const p = entry.payload, pr = p?.primary;
  const title = p ? archLabel(p) : entry.status === 'error' ? 'unclassified' : statusLabel(entry.status);
  const sub = p ? p.slices?.length > 1 ? [...new Set(p.slices.map(s => isaName(s.isa)))].join(' + ') : isaName(pr.isa) : entry.error || 'waiting for classification';
  const fields = p ? [['bitwidth', `${pr.bitwidth}-bit`], ['endianness', fmtEndian(pr.endianness).toLowerCase()], ['format', fmtFormatName(p.format.format).toLowerCase()], ['confidence', `${(pr.confidence * 100).toFixed(1)}%`, `via ${fmtSource(pr.source).toLowerCase()}`], ...(p.extensions?.length ? [['extensions', p.extensions.length]] : [])]
    : [['size', fmtSize(entry.size)], ...(entry.elapsed == null ? [] : [['analyzed in', `${entry.elapsed.toFixed(1)} ms`]])];
  $('classification-band').innerHTML = `<div class="hero"><div class="hero-label">instruction set architecture</div><div class="hero-isa ${entry.status === 'error' ? 'error' : ''}">${esc(title)}</div><div class="hero-sub">${esc(sub)}</div></div>${fields.map(([key, value, detail]) => `<div class="hero-field"><div class="hero-field-label">${esc(key)}</div><span class="hero-field-value">${esc(value)}</span>${detail ? `<span class="hero-field-sub">${esc(detail)}</span>` : ''}</div>`).join('')}`;
  renderClassification(entry);
  const json = JSON.stringify(p || { error: entry.error || 'Classification pending.' }, null, 2);
  text('jsonRaw', json); text('json-meta', `${entry.name}.json · ${json.length.toLocaleString()} chars`);
  text('profile-mean', entry.mean == null ? 'waiting for analysis' : `sampled mean ${entry.mean.toFixed(4)} bits/byte`);
  for (const id of ['hero-profile', 'entropy-profile']) drawProfile($(id), entry.profile);
  drawProfile($('hex-profile'), entry.profile, true);
  text('endian-note', p ? `classified ${fmtEndian(pr.endianness).toLowerCase()} · ${archLabel(p)}` : 'unclassified · little-endian interpretation');
  updateEndianButtons();
}
function renderClassification(entry) {
  const p = entry.payload;
  if (!p) {
    $('classification-content').innerHTML = panel(entry.status === 'error' ? 'classification failed' : 'classification pending', `<p class="${entry.status === 'error' ? 'error' : 'muted'}">${esc(entry.error || 'This file is queued for analysis.')}</p><p class="muted">Entropy and hex inspection are available independently of architecture classification.</p><button data-action="open-entropy">inspect entropy</button>`);
    return;
  }
  let html = '<div class="classification-grid">' + panel('format', row('format', fmtFormatName(p.format.format)) + row('confidence', `${(p.format.confidence * 100).toFixed(1)}%`) + (p.format.magic_offset == null ? '' : row('magic offset', '0x' + hx(p.format.magic_offset))) + (p.format.variant_name ? row('variant', p.format.variant_name) : ''));
  if (p.metadata?.length) html += panel('metadata', p.metadata.map(m => row(m.label, fmtMetaValue(m))).join(''), p.metadata.length);
  html += '</div>';
  if (p.slices?.length) html += panel('contained architectures', p.slices.map(s => row(`${s.label ? s.label + ' · ' : ''}${isaName(s.isa)}`, `${s.bitwidth}-bit ${s.endianness} · 0x${hx(s.offset)} · ${fmtSize(s.size)}${s.variant ? ' · ' + fmtVariant(s.variant) : ''}`)).join(''), p.slices.length);
  if (p.extensions?.length) {
    const groups = Map.groupBy ? Map.groupBy(p.extensions, x => x.category) : p.extensions.reduce((m, x) => m.set(x.category, [...(m.get(x.category) || []), x]), new Map());
    html += panel('isa extensions', [...groups].map(([category, extensions]) => `<div class="metadata-row"><span>${esc(fmtCat(category).toLowerCase())}</span><span class="tags">${extensions.map(x => `<span class="tag" title="${esc(`${(x.confidence * 100).toFixed(0)}% · ${x.source}`)}">${esc(x.name)}</span>`).join('')}</span></div>`).join(''), p.extensions.length);
  }
  if (p.candidates?.length) {
    const max = Math.max(1, ...p.candidates.map(c => Math.abs(c.raw_score)));
    html += panel('heuristic candidates', p.candidates.map(c => `<div class="candidate-row"><span>${esc(archId(c.isa))}</span><small class="muted candidate-meta">${c.bitwidth}-bit ${esc(c.endianness)}</small><div class="track"><i style="width:${Math.max(0, Math.min(100, Math.abs(c.raw_score) / max * 100))}%"></i></div><small class="score">${esc(c.raw_score.toLocaleString())} bits</small><small class="muted score">${(c.confidence * 100).toFixed(1)}%</small></div>`).join(''), p.candidates.length);
  }
  if (p.notes?.length) html += panel('notes', p.notes.map(n => `<div class="note"><span class="${n.level === 'error' ? 'error' : 'muted'}">[${esc(n.level)}]</span> ${esc(n.message)}${n.context ? ` <span class="muted">(${esc(n.context)})</span>` : ''}</div>`).join(''), p.notes.length);
  $('classification-content').innerHTML = html;
}

function cancelInteractive() {
  worker.postMessage({ type: 'cancel', operations: ['map', 'detail', 'hex', 'probe', 'selection'] });
  map = detail = hexData = probeData = selectionData = null;
  paintedBaseKey = '';
  lastHexKey = lastProbeKey = lastSelectionKey = '';
  clearTimeout(probeTimer);
  clearTimeout(detailTimer); clearTimeout(historyTimer);
  $('hex-rows').replaceChildren(); $('mini-hex').replaceChildren(); $('map-details').replaceChildren();
  $('entropy-map').getContext('2d').clearRect(0, 0, $('entropy-map').width, $('entropy-map').height);
  $('map-minimap').getContext('2d').clearRect(0, 0, 128, 128);
  $('entropy-map').dataset.state = 'idle'; $('data-values').innerHTML = row('value', '—');
  setHidden('cursor-box', true); setHidden('hover-box', true); setHidden('selection-panel', true);
  hexRequest = probeRequest = selectionRequest = ++requestId;
}
function syncView() {
  if (!ready || !selected() || ui.view !== 'file') return;
  if (ui.tab === 'entropy') { requestMap(); updateMapMarkers(); requestHex(); requestProbe(); }
  else if (ui.tab === 'hex') { requestHex(); requestProbe(); requestSelection(); }
  renderStatusCursor();
}
function sizeMap() {
  if (ui.tab !== 'entropy' || ui.view !== 'file') return;
  const stage = $('map-stage');
  const size = Math.max(64, Math.floor(Math.min(stage.clientWidth - 32, stage.clientHeight - 32)));
  $('map-frame').style.width = $('map-frame').style.height = `${size}px`;
  applyCamera();
}
function requestMap() {
  const entry = selected(); if (!entry?.size) { text('map-progress', 'empty file'); setHidden('map-progress', false); return; }
  const key = `${entry.id}:${ui.curve}:base`;
  if (map?.key === key) return;
  worker.postMessage({ type: 'cancel', operations: ['map', 'detail'] });
  detail = null; $('map-details').replaceChildren();
  map = mapCache.get(key) || createSpatialMap(entry, key, baseScale(worldSide(entry.size)), 0, 0);
  $('entropy-map').dataset.state = map.done >= map.count ? 'ready' : 'computing';
  if (map.done < map.count) sendMap(map, 'map');
  paintMap();
  applyCamera();
}
function createSpatialMap(entry, key, scale, x, y, width = Math.min(256, worldSide(entry.size) / scale), height = width) {
  const side = worldSide(entry.size) / scale, count = width * height;
  return { spatial: true, key, id: entry.id, curve: ui.curve, request: ++requestId,
    worldSide: worldSide(entry.size), scale, side, x, y, width, height, bpc: scale * scale,
    start: 0, span: entry.size, count, cells: new Float32Array(count * 6).fill(-1), done: 0, phase: 'waiting for analysis worker' };
}
function sendMap(layer, type) {
  const { id, request, worldSide, scale, x, y, width, height } = layer;
  worker.postMessage({ type, id, request, worldSide, scale, x, y, width, height, linear: layer.curve === 'linear' });
}
function cacheMap(layer) {
  mapCache.delete(layer.key); mapCache.set(layer.key, layer);
  while (mapCache.size > 12) mapCache.delete(mapCache.keys().next().value);
}
function requestDetail() {
  if (!map || map.done < map.count || ui.tab !== 'entropy' || ui.view !== 'file') return;
  const scale = Math.max(1, map.scale / 2 ** Math.floor(Math.log2(camera.zoom)));
  if (scale >= map.scale) { detail = null; return; }
  const side = map.worldSide / scale;
  const width = Math.min(256, Math.ceil(side / camera.zoom) + 1);
  const x = Math.max(0, Math.min(side - width, Math.floor(camera.x * side)));
  const y = Math.max(0, Math.min(side - width, Math.floor(camera.y * side)));
  const key = `${map.id}:${ui.curve}:${scale}:${x}:${y}:${width}`;
  if (detail?.key === key) return;
  const cached = mapCache.get(key);
  detail = cached || createSpatialMap(selected(), key, scale, x, y, width);
  map.detailError = ''; renderMapProgress();
  if (!cached) sendMap(detail, 'detail');
  else { cacheMap(cached); paintMap(); }
}
function applyCamera() {
  if (camera.zoom < 2 && detail) { worker.postMessage({ type: 'cancel', operations: ['detail'] }); detail = null; }
  $('map-frame').dataset.zoom = camera.zoom; $('map-frame').dataset.x = camera.x; $('map-frame').dataset.y = camera.y;
  if (cameraFrame) return;
  cameraFrame = requestAnimationFrame(() => {
    cameraFrame = 0;
    const size = $('map-frame').clientWidth;
    $('map-world').style.transform = `translate(${-camera.x * size * camera.zoom}px, ${-camera.y * size * camera.zoom}px) scale(${camera.zoom})`;
    const box = $('minimap-view'); box.style.left = `${camera.x * 100}%`; box.style.top = `${camera.y * 100}%`; box.style.width = box.style.height = `${100 / camera.zoom}%`;
    updateMapMarkers();
    renderMapProgress();
  });
  clearTimeout(detailTimer); detailTimer = setTimeout(requestDetail, 90);
}
function rememberView() {
  clearTimeout(historyTimer); historyTimer = 0;
  const entry = selected(); if (!entry?.history) return;
  const view = camera.snapshot(), last = entry.history[entry.historyIndex];
  if (last && Math.abs(view.zoom - last.zoom) < 1e-9 && Math.abs(view.x - last.x) < 1e-9 && Math.abs(view.y - last.y) < 1e-9) return;
  entry.history.splice(entry.historyIndex + 1); entry.history.push(view);
  if (entry.history.length > 64) entry.history.shift();
  entry.historyIndex = entry.history.length - 1; updateMapMarkers();
}
function scheduleHistory() { clearTimeout(historyTimer); historyTimer = setTimeout(rememberView, 250); }
function navigateHistory(direction) {
  rememberView();
  const entry = selected(); if (!entry?.history) return;
  entry.historyIndex = Math.max(0, Math.min(entry.history.length - 1, entry.historyIndex + direction));
  camera = new Viewport(entry.history[entry.historyIndex]); ui.hover = null;
  applyCamera(); renderEntropyInspector();
}
function renderMapProgress() {
  if (!map) return;
  const pending = map.done < map.count ? map : detail?.done < detail?.count ? detail : null;
  const error = map.error || map.detailError;
  text('map-progress', error || (pending ? pending.done === 0 ? pending.phase : `${pending === map ? 'computing' : 'refining'} ${Math.round(pending.done / pending.count * 100)}%` : ''));
  setHidden('map-progress', !pending && !error);
}
function paintMap() {
  if (paintFrame) return;
  paintFrame = requestAnimationFrame(() => {
    paintFrame = 0;
    if (!map || !selected() || map.id !== ui.selected) return;
    const baseKey = `${map.key}:${map.done}:${ui.mode}`;
    if (paintedBaseKey !== baseKey) {
      drawMap($('entropy-map'), map, ui.curve, ui.mode); paintedBaseKey = baseKey;
      const ctx = $('map-minimap').getContext('2d'); ctx.imageSmoothingEnabled = false; ctx.clearRect(0, 0, 128, 128); ctx.drawImage($('entropy-map'), 0, 0, 128, 128);
    }
    const visible = [...new Map([...mapCache.values(), ...(detail && detail.done >= detail.count ? [detail] : [])].map(layer => [layer.key, layer])).values()]
      .filter(layer => layer.id === map.id && layer.curve === ui.curve && layer.scale < map.scale
        && layer.x / layer.side < camera.x + 1 / camera.zoom && (layer.x + layer.width) / layer.side > camera.x
        && layer.y / layer.side < camera.y + 1 / camera.zoom && (layer.y + layer.height) / layer.side > camera.y)
      .sort((a, b) => b.scale - a.scale);
    const nodes = new Map([...$('map-details').children].map(node => [node.dataset.key, node]));
    for (const layer of visible) {
      let canvas = nodes.get(layer.key);
      if (!canvas) { canvas = document.createElement('canvas'); canvas.className = 'map-detail'; canvas.dataset.key = layer.key;
        canvas.style.left = `${layer.x / layer.side * 100}%`; canvas.style.top = `${layer.y / layer.side * 100}%`;
        canvas.style.width = `${layer.width / layer.side * 100}%`; canvas.style.height = `${layer.height / layer.side * 100}%`; }
      if (canvas.dataset.mode !== ui.mode) { drawMap(canvas, layer, ui.curve, ui.mode); canvas.dataset.mode = ui.mode; }
      $('map-details').append(canvas); nodes.delete(layer.key);
    }
    for (const node of nodes.values()) node.remove();
    renderMapProgress();
    updateMapMarkers(); renderEntropyInspector();
  });
}
function updateMapMarkers() {
  const entry = selected(); if (!entry) return;
  const g = detail?.done >= detail?.count ? detail : map;
  text('map-range', `cell ${fmtSize(g?.bpc || 1)}  ${camera.zoom.toFixed(2)}×  · fixed file coordinates`);
  const history = entry.history || [];
  document.querySelector('[data-action="view-back"]').disabled = entry.historyIndex <= 0;
  document.querySelector('[data-action="view-forward"]').disabled = entry.historyIndex >= history.length - 1;
  const positionBox = (id, offset) => {
    const hidden = !map || offset == null || offset >= entry.size;
    setHidden(id, hidden); if (hidden) return;
    const p = bytePosition(entry.size, offset, ui.curve), scale = g?.scale || 1, side = worldSide(entry.size);
    const el = $(id), cell = scale / side * 100;
    el.style.left = `${Math.floor(p.x * side / scale) * cell}%`; el.style.top = `${Math.floor(p.y * side / scale) * cell}%`;
    el.style.width = el.style.height = `${cell}%`;
    el.style.minWidth = el.style.minHeight = `${4 / camera.zoom}px`;
    el.style.borderWidth = el.style.outlineWidth = `${1 / camera.zoom}px`;
  };
  positionBox('cursor-box', ui.cursor); positionBox('hover-box', ui.hover);
  setHidden('entropy-legend', ui.mode !== 'entropy'); setHidden('byte-legend', ui.mode !== 'bytes');
  $('strip-ticks').innerHTML = [0, .25, .5, .75, 1].map(q => `<span>0x${hx(Math.floor(q * entry.size))}</span>`).join('');
  $('strip-cursor').style.left = `${ui.cursor / Math.max(1, entry.size) * 100}%`;
  setHidden('view-bracket', true); // A Hilbert viewport is not a contiguous byte interval; the spatial minimap shows it exactly.
}
function offsetAt(event) {
  if (!map || map.id !== ui.selected) return null;
  const rect = $('map-frame').getBoundingClientRect(), side = map.worldSide;
  const x = Math.floor((camera.x + (event.clientX - rect.left) / rect.width / camera.zoom) * side);
  const y = Math.floor((camera.y + (event.clientY - rect.top) / rect.height / camera.zoom) * side);
  if (x < 0 || y < 0 || x >= side || y >= side) return null;
  const d = ui.curve === 'linear' ? y * side + x : xy2d(side, x, y);
  return d < selected().size ? d : null;
}
function setCursor(offset, anchor = null, center = false) {
  if (!selected() || !Number.isFinite(offset)) return;
  ui.cursor = clampOffset(offset); ui.hover = null; ui.anchor = anchor;
  const entry = selected(), row = Math.floor(ui.cursor / ui.columns), visible = hexVisibleRows();
  if (center) ui.hexTop = row - Math.floor(visible / 3);
  else if (row < ui.hexTop) ui.hexTop = row;
  else if (row >= ui.hexTop + visible) ui.hexTop = row - visible + 1;
  ui.hexTop = clampHexTop(ui.hexTop);
  const p = bytePosition(entry.size, ui.cursor, ui.curve);
  if (p.x < camera.x || p.y < camera.y || p.x > camera.x + 1 / camera.zoom || p.y > camera.y + 1 / camera.zoom) { rememberView(); camera.center(p.x, p.y); applyCamera(); scheduleHistory(); }
  updateMapMarkers(); renderEntropyInspector(); syncView();
}
function zoom(direction) {
  const entry = selected(); if (!entry?.size) return;
  rememberView();
  if (direction === 0) camera = new Viewport();
  else { const p = bytePosition(entry.size, ui.cursor, ui.curve); camera.zoomAt(direction > 0 ? 2 : .5,
    Math.max(0, Math.min(1, (p.x - camera.x) * camera.zoom)), Math.max(0, Math.min(1, (p.y - camera.y) * camera.zoom)), Math.max(8, worldSide(entry.size) / 16)); }
  ui.hover = null; applyCamera(); rememberView(); renderEntropyInspector();
}
function requestProbe() {
  const entry = selected(); if (!entry?.size) { renderEntropyInspector(); renderDataInspector(); return; }
  const offset = probeOffset(), length = Math.min(entry.size, 4096), start = Math.max(0, Math.min(entry.size - length, Math.floor(offset / length) * length));
  const key = `${entry.id}:${offset}:${start}`;
  if (lastProbeKey === key) return;
  lastProbeKey = key; clearTimeout(probeTimer);
  const request = probeRequest = ++requestId;
  renderDataInspector();
  probeTimer = setTimeout(() => worker.postMessage({ type: 'probe', id: entry.id, request, start, length, offset }), 40);
}
function cellAt(offset) {
  if (!map || !selected()?.size) return null;
  const p = bytePosition(selected().size, offset, ui.curve);
  const layers = [map, ...mapCache.values(), ...(detail ? [detail] : [])]
    .filter(layer => layer.id === map.id && layer.curve === ui.curve).sort((a, b) => a.scale - b.scale);
  for (const layer of layers) {
    const x = Math.floor(p.x * layer.side), y = Math.floor(p.y * layer.side);
    if (x < layer.x || x >= layer.x + layer.width || y < layer.y || y >= layer.y + layer.height) continue;
    const index = (y - layer.y) * layer.width + x - layer.x;
    if (index >= layer.done || layer.cells[index * 6] < 0) continue;
    const origin = ui.curve === 'linear' ? y * layer.scale * layer.worldSide + x * layer.scale
      : xy2d(layer.side, x, y) * layer.bpc;
    return { layer, index, origin, h: layer.cells[index * 6] };
  }
  return null;
}
function renderEntropyInspector() {
  const entry = selected(); if (!entry) return;
  const probe = probeOffset(), cell = cellAt(probe), h = cell?.h;
  text('probe-kind', ui.hover == null ? 'cursor' : 'hover'); $('probe-kind').classList.toggle('accent', ui.hover == null);
  text('probe-hex', entry.size ? '0x' + hx(probe) : '—'); text('probe-dec', entry.size ? probe.toLocaleString('en-US') : '—');
  text('probe-cell', cell ? `#${Math.floor(cell.origin / cell.layer.bpc)} · ${fmtSize(cell.layer.bpc)}` : '—');
  const a = cell?.origin ?? probe;
  text('probe-range', !entry.size ? '—' : cell && ui.curve === 'linear' && cell.layer.scale > 1
    ? `${cell.layer.scale} × ${cell.layer.scale} B @ 0x${hx(a)} · row stride ${fmtSize(map.worldSide)}`
    : `0x${hx(a)}–0x${hx(Math.min(entry.size, a + (cell?.layer.bpc || 1)) - 1)}`);
  text('entropy-label', (cell?.layer.bpc || 0) < 256 ? `shannon, ${fmtSize(Math.min(entry.size, 256))} context` : 'shannon, cell');
  text('entropy-value', h == null ? '—' : h.toFixed(4)); $('entropy-meter').value = h || 0; text('entropy-class', h == null ? 'waiting for cell analysis' : `class ${entropyClass(h)}`);
  const stats = probeData?.offset === probe ? probeData.stats : null;
  const ratio = stats?.deflate_ratio;
  text('complexity-value', ratio == null ? '—' : `${(ratio * 100).toFixed(2)}%`);
  $('complexity-meter').value = Math.min(1, ratio || 0);
  text('complexity-class', ratio == null ? 'waiting for window analysis' : `class ${complexityClass(ratio)}`);
  text('complexity-window', stats ? `${fmtSize(stats.length)} window @ 0x${hx(stats.start)} · raw DEFLATE level 6` : '');
  if (stats) {
    const hist = stats.histogram, top = hist.indexOf(Math.max(...hist)), unique = hist.filter(x => x > 0).length;
    drawHistogram($('histogram'), hist, probeData.bytes[0]);
    text('histogram-summary', `${unique} distinct · top 0x${hx(top, 2)} ${(hist[top] / Math.max(1, stats.length) * 100).toFixed(1)}% · ${fmtSize(stats.length)} window`);
  } else { $('histogram').getContext('2d').clearRect(0, 0, 256, 48); text('histogram-summary', ''); }
  renderStatusCursor();
}
function renderStatusCursor() {
  const h = cellAt(probeOffset())?.h;
  text('status-cursor', selected()?.size ? `${ui.hover == null ? 'cursor' : 'hover'} 0x${hx(probeOffset())}${Number.isFinite(h) ? ` · ${h.toFixed(2)} bits/byte` : ''}` : '');
}
function hexVisibleRows() { return Math.max(1, Math.floor(($('hex-viewport').clientHeight - 28) / 20)); }
function clampHexTop(top) { return Math.max(0, Math.min(Math.max(0, Math.ceil((selected()?.size || 0) / ui.columns) - hexVisibleRows()), Math.floor(top))); }
function requestHex() {
  const entry = selected(); if (!entry) return;
  let start, length;
  if (ui.tab === 'entropy') {
    const rows = Math.min(12, Math.ceil(entry.size / 8));
    start = Math.max(0, Math.min(Math.floor(probeOffset() / 8) * 8 - 40, Math.max(0, Math.ceil(entry.size / 8) * 8 - rows * 8)));
    length = rows * 8;
  } else { ui.hexTop = clampHexTop(ui.hexTop); start = ui.hexTop * ui.columns; length = hexVisibleRows() * ui.columns; }
  const key = `${entry.id}:${ui.tab}:${start}:${length}`;
  if (lastHexKey === key) { renderHex(); return; }
  lastHexKey = key;
  const request = hexRequest = ++requestId;
  worker.postMessage({ type: 'hex', id: entry.id, request, start, length });
}
function renderHex() {
  const entry = selected(); if (!entry || !hexData || hexData.id !== entry.id) return;
  const { bytes, start } = hexData;
  if (ui.tab === 'entropy') {
    let html = '';
    for (let r = 0; r < Math.ceil(bytes.length / 8); r++) {
      const offset = start + r * 8;
      const chunk = bytes.subarray(r * 8, r * 8 + 8);
      html += `<div class="mini-row"><span class="mini-offset ${probeOffset() >= offset && probeOffset() < offset + 8 ? 'accent-text' : ''}">${hx(offset)}</span>${Array.from(chunk, (b, c) => `<button data-offset="${offset + c}" class="${byteClass(b)} ${offset + c === probeOffset() ? 'byte-cursor' : ''}" title="0x${hx(offset + c)}">${hx(b, 2)}</button>`).join('')}<span class="mini-ascii">${Array.from(chunk, (b, c) => `<button data-offset="${offset + c}" class="${offset + c === probeOffset() ? 'byte-cursor' : ''}" title="0x${hx(offset + c)}">${esc(b >= 32 && b < 127 ? String.fromCharCode(b) : '.')}</button>`).join('')}</span></div>`;
    }
    $('mini-hex').innerHTML = html;
    return;
  }
  if (ui.tab !== 'hex') return;
  const cols = ui.columns, group = ui.group, utf16 = ui.encoding.startsWith('utf16');
  const selection = ui.anchor == null ? null : [Math.min(ui.anchor, ui.cursor), Math.max(ui.anchor, ui.cursor)];
  const classes = (offset, b) => `${byteClass(b)} ${offset === ui.cursor ? 'byte-cursor' : selection && offset >= selection[0] && offset <= selection[1] ? 'byte-selected' : ''}`;
  const gap = c => c < cols - 1 && (c + 1) % group === 0 ? 8 : 0;
  $('hex-head').innerHTML = `<span class="hex-off">offset</span><span class="hex-bytes">${Array.from({ length: cols }, (_, c) => `<span class="hex-byte" style="margin-right:${gap(c)}px">${hx(c, 2)}</span>`).join('')}</span><span class="hex-text">${esc(ui.encoding)}</span>`;
  let html = '';
  for (let r = 0; r < Math.ceil(bytes.length / cols); r++) {
    const offset = start + r * cols, chunk = bytes.subarray(r * cols, r * cols + cols);
    const hex = Array.from({ length: cols }, (_, c) => c < chunk.length ? `<span data-offset="${offset + c}" class="hex-byte ${classes(offset + c, chunk[c])}" style="margin-right:${gap(c)}px">${hx(chunk[c], 2)}</span>` : `<span class="hex-byte" style="margin-right:${gap(c)}px"></span>`).join('');
    let chars = '';
    for (let c = 0; c < chunk.length; c += utf16 ? 2 : 1) {
      let ch;
      if (utf16) {
        if (c + 1 >= chunk.length) ch = '.';
        else { const value = ui.encoding === 'utf16le' ? chunk[c] | chunk[c + 1] << 8 : chunk[c] << 8 | chunk[c + 1]; ch = value >= 32 && (value < 127 || value >= 160 && value < 0xd800 || value > 0xdfff && value < 0xfffe) ? String.fromCharCode(value) : '.'; }
      } else ch = encChar(ui.encoding, chunk[c])[0];
      const hit = ui.cursor === offset + c || utf16 && ui.cursor === offset + c + 1;
      chars += `<span data-offset="${offset + c}" class="hex-char ${hit ? 'byte-cursor' : classes(offset + c, chunk[c])}" style="width:${utf16 ? 18 : 9}px">${esc(ch)}</span>`;
    }
    const off = ui.offsetBase === 'hex' ? hx(offset) : String(offset).padStart(String(entry.size).length, ' ');
    html += `<div class="hex-row"><span class="hex-off ${ui.cursor >= offset && ui.cursor < offset + cols ? 'accent-text' : ''}">${off}</span><span class="hex-bytes">${hex}</span><span class="hex-text">${chars}</span></div>`;
  }
  $('hex-rows').innerHTML = html;
  const totalRows = Math.max(1, Math.ceil(entry.size / cols));
  $('hex-thumb').style.top = `${ui.hexTop / totalRows * 100}%`; $('hex-thumb').style.height = `${Math.min(100, hexVisibleRows() / totalRows * 100)}%`;
  $('hex-cursor-tick').style.top = `${ui.cursor / Math.max(1, entry.size) * 100}%`;
  $('hex-track').setAttribute('aria-valuenow', Math.round(ui.hexTop / totalRows * 100));
  text('hex-location', entry.size ? `cursor 0x${hx(ui.cursor)} · ${ui.cursor}` : 'empty file');
  text('hex-row-info', `row ${Math.floor(ui.cursor / cols).toLocaleString()} of ${totalRows.toLocaleString()} · ${cols} × ${hexVisibleRows()} visible`);
  text('hex-selection-info', selection ? `sel ${(selection[1] - selection[0] + 1).toLocaleString()} bytes` : '');
  requestSelection();
}
function updateEndianButtons() {
  const endian = ui.endian || (selected()?.payload?.primary.endianness === 'big' ? 'big' : 'little');
  for (const button of document.querySelectorAll('[data-endian]')) button.classList.toggle('active', button.dataset.endian === endian);
}
function renderDataInspector() {
  updateEndianButtons();
  const classified = selected()?.payload?.primary.endianness, endian = ui.endian || (classified === 'big' ? 'big' : 'little');
  text('endian-note', `${endian}-endian interpretation · ${classified ? `classified ${classified}-endian` : 'unclassified'}${ui.endian && ui.endian !== classified ? ' · overridden' : ''}`);
  if (!probeData?.bytes.length || probeData.offset !== ui.cursor) { $('data-values').innerHTML = row('value', '—'); return; }
  const bytes = probeData.bytes, n = bytes.length, dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const little = (ui.endian || (selected()?.payload?.primary.endianness === 'big' ? 'big' : 'little')) === 'little';
  const values = [['bin', bytes[0].toString(2).padStart(8, '0').replace(/^(\d{4})/, '$1 ')], ['u8', bytes[0], '0x' + hx(bytes[0], 2)], ['i8', dv.getInt8(0)]];
  for (const width of [16, 32, 64]) {
    const length = width / 8;
    for (const sign of ['u', 'i']) {
      let value = '—', hex = '';
      if (n >= length) {
        const method = width === 64 ? sign === 'u' ? 'getBigUint64' : 'getBigInt64' : `get${sign === 'u' ? 'Uint' : 'Int'}${width}`;
        value = dv[method](0, little).toString();
        if (sign === 'u') hex = '0x' + dv[method](0, little).toString(16).toUpperCase().padStart(length * 2, '0');
      }
      values.push([sign + width, value, hex]);
    }
  }
  values.push(['f32', n >= 4 ? fmtF(dv.getFloat32(0, little), 7) : '—'], ['f64', n >= 8 ? fmtF(dv.getFloat64(0, little), 15) : '—'], ['utf-8', utf8At(bytes)], ['time32', n >= 4 ? unixT(dv.getUint32(0, little)) : '—']);
  $('data-values').innerHTML = values.map(([key, value, detail]) => `<div class="data-row" data-value-type="${key}"><span>${key}</span><span class="value">${esc(value)}${detail ? `<small>${esc(detail)}</small>` : ''}</span></div>`).join('');
}
function requestSelection() {
  const entry = selected(), active = entry && ui.anchor != null && ui.anchor !== ui.cursor;
  setHidden('selection-panel', !active);
  if (!active) { lastSelectionKey = ''; selectionData = null; return; }
  const start = Math.min(ui.anchor, ui.cursor), length = Math.abs(ui.anchor - ui.cursor) + 1;
  text('selection-size', `${length.toLocaleString()} bytes · 0x${hx(start)}–0x${hx(start + length - 1)}`);
  const key = `${entry.id}:${start}:${length}`;
  if (lastSelectionKey === key) return;
  lastSelectionKey = key; selectionData = null; text('selection-entropy', 'computing selection entropy…');
  const request = selectionRequest = ++requestId;
  worker.postMessage({ type: 'selection', id: entry.id, request, start, length: Math.min(length, 4 * 1024 ** 2) });
}

worker.addEventListener('message', ({ data }) => {
  if (data.type === 'ready') {
    if (data.protocol !== WORKBENCH_PROTOCOL) {
      engineError = 'Workbench/worker build mismatch. Reload the page to load matching assets.';
      showError(engineError); text('loading', engineError); text('status-engine', 'build mismatch');
      worker.terminate();
      for (const entry of entries.values()) if (['queued', 'analyzing'].includes(entry.status)) { entry.error = engineError; setStatus(entry, 'error'); updateEntry(entry); }
      renderSummary(); renderSelected(); return;
    }
    ready = true; version = data.version;
    for (const { side, indices } of data.layouts) {
      const inverse = new Uint32Array(indices.length);
      for (let d = 0; d < indices.length; d++) inverse[indices[d]] = d;
      layouts.set(side, { indices, inverse });
    }
    text('version', version); text('status-engine', `isa-classifier ${version} · Apeiron/WASM`);
    text('loading', 'engine ready · ELF, PE, Mach-O, firmware, or any binary blob');
    pushLog('info', `classifier ${version} and Apeiron analysis engine ready`); syncView();
    return;
  }
  if (data.type === 'boot-error') {
    engineError = data.error; showError(data.error); text('loading', 'Engine initialization failed. Reload to retry.'); text('status-engine', 'engine unavailable');
    return;
  }
  const entry = entries.get(data.id); if (!entry) return;
  if (data.type === 'status') {
    setStatus(entry, data.status); updateEntry(entry); renderSummary();
    if (ui.selected === entry.id) renderSelected();
  } else if (data.type === 'result') {
    entry.payload = data.payload; entry.error = data.error || ''; entry.elapsed = data.elapsed ?? null;
    entry.profile = data.profile || null; entry.mean = data.mean ?? null;
    setStatus(entry, entry.payload ? 'done' : 'error');
    if (entry.payload) { tally(archTally, archLabel(entry.payload), 1); tally(formatTally, fmtFormatName(entry.payload.format.format).toLowerCase(), 1); }
    updateEntry(entry); renderSummary(); if (ui.sort !== 'queue') renderBatchOrder();
    pushLog(entry.payload ? 'done' : 'error', `${entry.name} · ${entry.payload ? `${archLabel(entry.payload)} · ${entry.payload.primary.bitwidth}-bit ${entry.payload.primary.endianness}` : entry.error}${entry.elapsed == null ? '' : ` · ${entry.elapsed.toFixed(1)} ms`}`);
    text('announcement', `${entry.name}: ${statusLabel(entry.status)}`);
    if (ui.selected === entry.id) { renderSelected(); renderChrome(); }
  } else if (data.type === 'operation-status' && ui.selected === entry.id) {
    const layer = data.operation === 'detail' ? detail : map;
    if (layer?.request === data.request) { layer.phase = data.phase; text('map-progress', data.phase); setHidden('map-progress', false); }
  } else if (data.type === 'map-tile' && ui.selected === entry.id) {
    const layer = data.operation === 'detail' ? detail : map;
    if (layer?.request === data.request) { layer.cells.set(data.cells, data.from * 6); layer.done = data.from + data.cells.length / 6; if (layer === map) paintMap(); }
  } else if (data.type === 'map-done' && ui.selected === entry.id) {
    const layer = data.operation === 'detail' ? detail : map;
    if (layer?.request === data.request) {
      cacheMap(layer);
      if (layer === map) { $('entropy-map').dataset.state = 'ready'; $('entropy-map').dataset.cells = map.count; requestDetail(); }
      else $('map-frame').dataset.detail = layer.key;
      paintMap();
    }
  } else if (data.type === 'hex' && data.request === hexRequest && ui.selected === entry.id) {
    hexData = data; renderHex();
  } else if (data.type === 'probe' && data.request === probeRequest && ui.selected === entry.id) {
    probeData = data; renderEntropyInspector(); renderDataInspector();
  } else if (data.type === 'selection' && data.request === selectionRequest && ui.selected === entry.id && ui.anchor != null) {
    selectionData = data;
    text('selection-entropy', `entropy ${data.stats.entropy.toFixed(4)} bits/byte${Math.abs(ui.anchor - ui.cursor) + 1 > data.bytes.length ? ' · first 4 MiB sampled' : ''}`);
  } else if (data.type === 'error' && ui.selected === entry.id) {
    pushLog('error', `${entry.name}: ${data.operation}: ${data.error}`);
    if (data.operation === 'map' && map?.request === data.request) { map.error = data.error; text('map-progress', data.error); setHidden('map-progress', false); $('entropy-map').dataset.state = 'error'; }
    else if (data.operation === 'detail' && detail?.request === data.request) { map.detailError = data.error; detail = null; renderMapProgress(); }
    else if (data.operation === 'hex' && data.request === hexRequest) { $('hex-rows').textContent = data.error; $('mini-hex').textContent = data.error; }
  }
});
worker.addEventListener('error', event => {
  engineError = `Analysis worker failed: ${event.message || 'unknown error'}`;
  showError(engineError); ready = false; text('status-engine', 'worker failed');
  for (const entry of entries.values()) if (['queued', 'analyzing'].includes(entry.status)) { entry.error = engineError; setStatus(entry, 'error'); updateEntry(entry); }
  renderSummary(); renderSelected();
});
function removeFile(id) {
  const entry = entries.get(id); if (!entry) return;
  const order = [...entries.keys()], index = order.indexOf(id);
  worker.postMessage({ type: 'remove', id });
  counts[entry.status]--;
  if (entry.payload) { tally(archTally, archLabel(entry.payload), -1); tally(formatTally, fmtFormatName(entry.payload.format.format).toLowerCase(), -1); }
  entries.delete(id); entry.button.remove(); entry.tr.remove();
  for (const [key, layer] of mapCache) if (layer.id === id) mapCache.delete(key);
  if (ui.selected === id) {
    cancelInteractive(); ui.selected = null;
    const rest = [...entries.keys()]; if (rest.length) selectFile(rest[Math.min(index, rest.length - 1)]);
    else { ui.view = 'file'; renderChrome(); }
  }
  renderSummary(); pushLog('info', `removed ${entry.name}`);
}
function clearFiles() {
  const n = entries.size;
  worker.postMessage({ type: 'clear' }); cancelInteractive(); entries.clear(); mapCache.clear();
  for (const key of Object.keys(counts)) counts[key] = 0;
  archTally.clear(); formatTally.clear();
  $('file-list').replaceChildren(); $('batch-rows').replaceChildren();
  ui.selected = null; ui.cursor = 0; ui.hover = ui.anchor = null; ui.view = 'file';
  if (!engineError) setHidden('error', true);
  renderSummary(); renderChrome(); pushLog('info', `cleared ${n} files`);
}
function changeTab(tab) {
  ui.tab = tab; ui.view = 'file'; ui.hover = null;
  if (tab === 'hex') ui.hexTop = clampHexTop(Math.floor(ui.cursor / ui.columns) - Math.floor(hexVisibleRows() / 3));
  lastHexKey = ''; renderChrome();
}
function download(name, content, type) {
  const blob = content instanceof Blob ? content : new Blob([content], { type });
  const url = URL.createObjectURL(blob), a = document.createElement('a');
  a.href = url; a.download = name; document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
async function copy(value, button) {
  try { await navigator.clipboard.writeText(value); text('announcement', 'Copied to clipboard.'); if (button) { const before = button.textContent; button.textContent = 'copied'; setTimeout(() => { button.textContent = before; }, 1200); } }
  catch (e) { showError(`Clipboard copy failed: ${e.message || e}`); }
}
function exportedEntries() {
  return [...entries.values()].map(e => ({ file: e.name, size: e.size, status: e.status, ...(e.payload ? { payload: e.payload } : {}), ...(e.error ? { error: e.error } : {}), mean_profile_entropy: e.mean, elapsed_ms: e.elapsed }));
}
function exportCsv() {
  const quote = value => { const str = String(value ?? ''); return /[",\r\n]/.test(str) ? '"' + str.replaceAll('"', '""') + '"' : str; };
  const head = ['file', 'size', 'status', 'format', 'isa', 'bitwidth', 'endianness', 'confidence', 'source', 'mean_profile_entropy', 'elapsed_ms', 'error'];
  const rows = [...entries.values()].map(e => [e.name, e.size, e.status, e.payload?.format.format, e.payload ? archLabel(e.payload) : '', e.payload?.primary.bitwidth, e.payload?.primary.endianness, e.payload?.primary.confidence, e.payload?.primary.source, e.mean, e.elapsed, e.error]);
  download('isa-batch.csv', [head, ...rows].map(values => values.map(quote).join(',')).join('\r\n'), 'text/csv');
}
async function copySelection(button) {
  const entry = selected(); if (!entry || ui.anchor == null) return;
  const start = Math.min(ui.anchor, ui.cursor), length = Math.abs(ui.anchor - ui.cursor) + 1;
  const bytes = new Uint8Array(await entry.file.slice(start, start + Math.min(length, 1024 ** 2)).arrayBuffer());
  await copy(Array.from(bytes, b => hx(b, 2)).join(' '), button);
  if (bytes.length < length) pushLog('info', `copied first ${fmtSize(bytes.length)} of ${fmtSize(length)} selected; download preserves the complete selection`);
}
const actions = {
  browse: () => $('fileinput').click(),
  'file-view': () => { ui.view = 'file'; renderChrome(); },
  'batch-view': () => { ui.view = 'batch'; renderChrome(); },
  'toggle-side': () => { ui.sideOpen = !(ui.sideOpen && ui.view === 'file'); ui.view = 'file'; renderChrome(); },
  'toggle-log': () => { ui.logOpen = !ui.logOpen; renderChrome(); },
  clear: clearFiles, remove: () => removeFile(ui.selected),
  'open-entropy': () => changeTab('entropy'), 'open-hex': () => changeTab('hex'),
  'zoom-in': () => zoom(1), 'zoom-out': () => zoom(-1), 'zoom-fit': () => zoom(0),
  'view-back': () => navigateHistory(-1), 'view-forward': () => navigateHistory(1),
  'copy-json': button => copy($('jsonRaw').textContent, button),
  'download-json': () => selected() && download(selected().name + '.json', $('jsonRaw').textContent, 'application/json'),
  'export-json': () => download('isa-batch.json', JSON.stringify(exportedEntries(), null, 2), 'application/json'), 'export-csv': exportCsv,
  'copy-offset': button => copy('0x' + hx(ui.cursor), button),
  'copy-selection': copySelection,
  'download-file': () => selected() && download(selected().name, selected().file),
  'download-selection': () => { const e = selected(); if (e && ui.anchor != null) { const start = Math.min(ui.anchor, ui.cursor), end = Math.max(ui.anchor, ui.cursor) + 1; download(`${e.name}.${hx(start)}-${hx(end - 1)}.bin`, e.file.slice(start, end)); } },
  'clear-selection': () => { ui.anchor = null; requestSelection(); renderHex(); },
  'clear-log': () => { log.length = 0; $('log-lines').replaceChildren(); },
};
document.addEventListener('click', event => {
  const target = event.target.closest('button');
  if (target?.dataset.action && actions[target.dataset.action]) actions[target.dataset.action](target);
  else if (target?.dataset.tab) changeTab(target.dataset.tab);
  else if (target?.dataset.curve) { ui.curve = target.dataset.curve; requestMap(); renderChrome(); }
  else if (target?.dataset.mode) { ui.mode = target.dataset.mode; paintMap(); renderChrome(); }
  else if (target?.dataset.endian) { ui.endian = target.dataset.endian; renderDataInspector(); }
  else if (target?.dataset.filter) { ui.filter = target.dataset.filter; renderBatchOrder(); renderChrome(); }
  else if (target?.dataset.offset) { setCursor(Number(target.dataset.offset)); }
  else { const entryNode = event.target.closest('[data-file-id]'); if (entryNode) selectFile(Number(entryNode.dataset.fileId)); }
  if (!event.target.closest('#context-menu')) setHidden('context-menu', true);
  else if (target) setHidden('context-menu', true);
});
$('fileinput').addEventListener('change', () => { enqueue($('fileinput').files); $('fileinput').value = ''; });
$('batch-sort').addEventListener('change', event => { ui.sort = event.target.value; renderBatchOrder(); });
for (const [id, property] of [['hex-columns', 'columns'], ['hex-group', 'group'], ['hex-encoding', 'encoding'], ['hex-offset', 'offsetBase']]) {
  $(id).addEventListener('change', event => { ui[property] = ['columns', 'group'].includes(property) ? Number(event.target.value) : event.target.value; lastHexKey = ''; if (property === 'columns') ui.hexTop = clampHexTop(Math.floor(ui.cursor / ui.columns) - 5); syncView(); persist(); });
}
$('goto-offset').addEventListener('keydown', event => {
  if (event.key === 'Escape') { event.target.blur(); return; }
  if (event.key !== 'Enter') return;
  const value = parseGoto(event.target.value, ui.cursor, selected()?.size || 0);
  if (value == null || !Number.isSafeInteger(value)) { event.target.setAttribute('aria-invalid', 'true'); pushLog('error', `Cannot parse offset ${JSON.stringify(event.target.value)}`); return; }
  event.target.removeAttribute('aria-invalid'); setCursor(value, null, true); event.target.blur();
});
const hasFiles = event => Array.from(event.dataTransfer?.types || []).includes('Files');
window.addEventListener('dragenter', event => { if (hasFiles(event)) { event.preventDefault(); dragDepth++; setHidden('drag-overlay', false); } });
window.addEventListener('dragover', event => { if (hasFiles(event)) { event.preventDefault(); event.dataTransfer.dropEffect = 'copy'; } });
window.addEventListener('dragleave', event => { if (dragDepth) { dragDepth = Math.max(0, dragDepth - 1); if (!dragDepth) setHidden('drag-overlay', true); } });
window.addEventListener('drop', event => { if (!hasFiles(event)) return; event.preventDefault(); dragDepth = 0; setHidden('drag-overlay', true); enqueue(event.dataTransfer.files || []); });
window.addEventListener('blur', () => { dragDepth = 0; setHidden('drag-overlay', true); hexDragging = false; mapDrag = null; $('map-frame').classList.remove('panning'); });
$('map-frame').addEventListener('pointermove', event => {
  if (event.target.closest('#map-overview')) return;
  if (mapDrag?.id === event.pointerId) {
    const size = event.currentTarget.clientWidth, dx = event.clientX - mapDrag.x, dy = event.clientY - mapDrag.y;
    if (Math.hypot(event.clientX - mapDrag.originX, event.clientY - mapDrag.originY) > 3) mapDrag.moved = true;
    if (mapDrag.moved) { camera.pan(dx / size, dy / size); ui.hover = null; event.currentTarget.classList.add('panning'); applyCamera(); }
    mapDrag.x = event.clientX; mapDrag.y = event.clientY; return;
  }
  const offset = offsetAt(event); if (offset !== ui.hover) { ui.hover = offset; updateMapMarkers(); renderEntropyInspector(); requestHex(); requestProbe(); }
});
$('map-frame').addEventListener('pointerdown', event => {
  if (![0, 1].includes(event.button) || event.target.closest('#map-overview') || !map) return;
  event.preventDefault(); event.currentTarget.focus(); rememberView(); event.currentTarget.setPointerCapture(event.pointerId);
  mapDrag = { id: event.pointerId, x: event.clientX, y: event.clientY, originX: event.clientX, originY: event.clientY, moved: false };
});
function endMapDrag(event) {
  if (mapDrag?.id !== event.pointerId) return;
  skipMapClick = mapDrag.moved; mapDrag = null; $('map-frame').classList.remove('panning'); rememberView();
}
$('map-frame').addEventListener('pointerup', endMapDrag);
$('map-frame').addEventListener('pointercancel', endMapDrag);
$('map-frame').addEventListener('pointerleave', () => { if (mapDrag) return; ui.hover = null; updateMapMarkers(); renderEntropyInspector(); requestHex(); requestProbe(); });
$('map-frame').addEventListener('click', event => {
  if (event.target.closest('#map-overview')) return;
  if (skipMapClick) { skipMapClick = false; return; }
  const offset = offsetAt(event); if (offset != null) setCursor(offset);
});
$('map-frame').addEventListener('wheel', event => {
  event.preventDefault(); if (!map) return;
  if (!historyTimer) rememberView();
  const rect = event.currentTarget.getBoundingClientRect(), delta = event.deltaY * (event.deltaMode === 1 ? 16 : event.deltaMode === 2 ? rect.height : 1);
  const ax = Math.max(0, Math.min(1, (event.clientX - rect.left) / rect.width)), ay = Math.max(0, Math.min(1, (event.clientY - rect.top) / rect.height));
  camera.zoomAt(Math.exp(Math.max(-1, Math.min(1, -delta * .002))), ax, ay, Math.max(8, map.worldSide / 16));
  ui.hover = offsetAt(event); applyCamera(); scheduleHistory(); renderEntropyInspector(); requestHex(); requestProbe();
}, { passive: false });
$('map-frame').addEventListener('contextmenu', event => { if (event.target.closest('#map-overview')) return; event.preventDefault(); const offset = offsetAt(event); if (offset != null) setCursor(offset); const menu = $('context-menu'); menu.hidden = false; menu.style.left = `${Math.min(event.clientX, innerWidth - 184)}px`; menu.style.top = `${Math.min(event.clientY, innerHeight - menu.offsetHeight - 4)}px`; menu.querySelector('button').focus(); });
$('map-overview').addEventListener('pointerdown', event => {
  if (!map || event.button !== 0) return;
  event.preventDefault(); event.stopPropagation(); rememberView(); const el = event.currentTarget; el.setPointerCapture(event.pointerId);
  const go = e => { const rect = el.getBoundingClientRect(); camera.center((e.clientX - rect.left) / rect.width, (e.clientY - rect.top) / rect.height); ui.hover = null; applyCamera(); };
  go(event); el.addEventListener('pointermove', go);
  const end = () => { el.removeEventListener('pointermove', go); rememberView(); };
  el.addEventListener('pointerup', end, { once: true }); el.addEventListener('pointercancel', end, { once: true });
});
for (const id of ['hero-profile', 'entropy-profile']) $(id).addEventListener('click', event => { const e = selected(); if (!e?.size) return; const rect = event.currentTarget.getBoundingClientRect(); const offset = Math.floor(Math.max(0, Math.min(1, (event.clientX - rect.left) / rect.width)) * (e.size - 1)); if (id === 'hero-profile') changeTab('entropy'); setCursor(offset); });
$('hex-viewport').addEventListener('wheel', event => { if (Math.abs(event.deltaX) > Math.abs(event.deltaY)) return; event.preventDefault(); ui.hexTop = clampHexTop(ui.hexTop + Math.sign(event.deltaY) * Math.max(1, Math.floor(Math.abs(event.deltaY) / 20))); requestHex(); }, { passive: false });
$('hex-viewport').addEventListener('pointerdown', event => { const byte = event.target.closest('[data-offset]'); if (event.button !== 0 || !byte) return; event.preventDefault(); hexDragging = true; hexDragAnchor = event.shiftKey ? ui.anchor ?? ui.cursor : Number(byte.dataset.offset); setCursor(Number(byte.dataset.offset), hexDragAnchor); });
$('hex-viewport').addEventListener('pointermove', event => { const byte = event.target.closest('[data-offset]'); if (hexDragging && event.buttons & 1 && byte) setCursor(Number(byte.dataset.offset), hexDragAnchor); });
window.addEventListener('pointerup', () => { hexDragging = false; if (ui.anchor === ui.cursor) { ui.anchor = null; requestSelection(); } });
$('hex-track').addEventListener('pointerdown', event => {
  const track = event.currentTarget; event.preventDefault(); track.setPointerCapture(event.pointerId);
  const go = e => { const rect = track.getBoundingClientRect(); ui.hexTop = clampHexTop(Math.round((e.clientY - rect.top) / rect.height * Math.ceil((selected()?.size || 0) / ui.columns) - hexVisibleRows() / 2)); requestHex(); };
  go(event); track.addEventListener('pointermove', go);
  track.addEventListener('pointerup', () => track.removeEventListener('pointermove', go), { once: true });
});

document.addEventListener('keydown', event => {
  const key = event.key, target = event.target;
  if (event.altKey && ui.tab === 'entropy' && ['ArrowLeft', 'ArrowRight'].includes(key) && !target.closest('input, select, textarea')) { event.preventDefault(); navigateHistory(key === 'ArrowLeft' ? -1 : 1); return; }
  if (!target.closest('input, select, textarea') && (event.metaKey || event.ctrlKey) && key.toLowerCase() === 'c' && ui.tab === 'hex' && ui.anchor != null) { event.preventDefault(); copySelection(); return; }
  if (target.closest('input, select, textarea') || event.altKey || event.metaKey || event.ctrlKey) return;
  if (!$('context-menu').hidden) {
    if (key === 'Escape') { setHidden('context-menu', true); $('map-frame').focus(); event.preventDefault(); return; }
    if (key === 'ArrowDown' || key === 'ArrowUp') { const buttons = [...$('context-menu').querySelectorAll('button')], index = buttons.indexOf(target); buttons[(index + (key === 'ArrowDown' ? 1 : -1) + buttons.length) % buttons.length].focus(); event.preventDefault(); return; }
  }
  if (target.matches('[role="tab"]') && ['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(key)) {
    const tabs = [...document.querySelectorAll('[role="tab"]')], i = tabs.indexOf(target);
    const next = key === 'Home' ? 0 : key === 'End' ? tabs.length - 1 : (i + (key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
    changeTab(tabs[next].dataset.tab); tabs[next].focus(); event.preventDefault(); return;
  }
  if (target.id === 'hex-track' && ['ArrowUp', 'ArrowDown', 'PageUp', 'PageDown', 'Home', 'End'].includes(key)) {
    ui.hexTop = clampHexTop(key === 'Home' ? 0 : key === 'End' ? Infinity : ui.hexTop + (key === 'ArrowUp' ? -1 : key === 'ArrowDown' ? 1 : key === 'PageUp' ? -hexVisibleRows() : hexVisibleRows()));
    requestHex(); event.preventDefault(); return;
  }
  if (key === 'j' || key === 'k') { const ids = [...entries.keys()], i = ids.indexOf(ui.selected), id = ids[Math.max(0, Math.min(ids.length - 1, i + (key === 'j' ? 1 : -1)))]; if (id) selectFile(id); return; }
  if (['1', '2', '3', '4'].includes(key)) { changeTab(['classification', 'entropy', 'hex', 'json'][Number(key) - 1]); return; }
  if (key === 'o') { actions.browse(); return; }
  if (key === 'f') { actions['toggle-side'](); return; }
  if (key === 'b') { ui.view = ui.view === 'batch' ? 'file' : 'batch'; renderChrome(); return; }
  if (key === '`') { actions['toggle-log'](); return; }
  if (key === 'Delete' && selected()) { actions.remove(); return; }
  if (!selected() || ui.view !== 'file') return;
  if (ui.tab === 'hex') {
    let next = null;
    if (key === 'ArrowLeft') next = ui.cursor - 1;
    else if (key === 'ArrowRight') next = ui.cursor + 1;
    else if (key === 'ArrowUp') next = ui.cursor - ui.columns;
    else if (key === 'ArrowDown') next = ui.cursor + ui.columns;
    else if (key === 'PageUp') next = ui.cursor - hexVisibleRows() * ui.columns;
    else if (key === 'PageDown') next = ui.cursor + hexVisibleRows() * ui.columns;
    else if (key === 'Home') next = ui.cursor - ui.cursor % ui.columns;
    else if (key === 'End') next = ui.cursor - ui.cursor % ui.columns + ui.columns - 1;
    else if (key === 'Escape') { ui.anchor = null; requestSelection(); renderHex(); }
    else if (key === 'g') { $('goto-offset').focus(); $('goto-offset').select(); event.preventDefault(); }
    if (next != null) { event.preventDefault(); setCursor(next, event.shiftKey ? ui.anchor ?? ui.cursor : null); }
  } else if (ui.tab === 'entropy') {
    const move = { ArrowLeft: -1, ArrowRight: 1, ArrowUp: -8, ArrowDown: 8 }[key];
    if (move != null) { event.preventDefault(); setCursor(probeOffset() + move); }
    else if (key === '[' || key === ']') {
      const cell = cellAt(ui.cursor), step = cell ? ui.curve === 'linear' ? cell.layer.scale : cell.layer.bpc : 1;
      setCursor((cell?.origin ?? ui.cursor) + (key === '[' ? -1 : 1) * step);
    }
    else if (['z', '+', '='].includes(key)) zoom(1);
    else if (['x', '-'].includes(key)) zoom(-1);
    else if (key === '0') zoom(0);
    else if (key === 'h') { ui.curve = ui.curve === 'hilbert' ? 'linear' : 'hilbert'; requestMap(); renderChrome(); }
    else if (key === 'c') { ui.mode = ui.mode === 'entropy' ? 'bytes' : 'entropy'; paintMap(); renderChrome(); }
  }
});
const resize = new ResizeObserver(() => { sizeMap(); if (ui.tab === 'hex' && selected()) { lastHexKey = ''; requestHex(); } });
resize.observe($('map-stage')); resize.observe($('hex-viewport'));
window.addEventListener('beforeunload', () => worker.terminate());
drawLegend($('legend')); renderSummary(); renderChrome();
