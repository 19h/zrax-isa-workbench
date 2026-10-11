import init, { classify, classifier_version } from '../../pkg/zrax.js';

import { esc, fmtSize, isaName, fmtEndian, fmtSource, fmtFormatName, fmtFormat, fmtVariant, fmtMetaValue, fmtCat, fmtExtSrc } from '../format.js';

const dropzone  = document.getElementById('dropzone');
const fileinput = document.getElementById('fileinput');
const loading   = document.getElementById('loading');
const loadingText = document.getElementById('loading-text');
const errorEl   = document.getElementById('error');
const resultsEl = document.getElementById('results');
const batchEl = document.getElementById('batch');
const fileList = document.getElementById('file-list');
const batchSummary = document.getElementById('batch-summary');
const batchProgress = document.getElementById('batch-progress');

let classifierState = 'loading';
let processing = false;
let generation = 0;
let nextId = 1;
let selectedId = null;
let queue = [];
let queueIndex = 0;
let completed = 0;
let failed = 0;
const entries = new Map();
let dragDepth = 0;

// Prevent the browser from navigating to files dropped outside the drop zone.
window.addEventListener('dragover', e => {
  if (Array.from(e.dataTransfer?.types || []).includes('Files')) e.preventDefault();
});
window.addEventListener('drop', e => {
  if (Array.from(e.dataTransfer?.types || []).includes('Files')) e.preventDefault();
  dragDepth = 0;
  dropzone.classList.remove('dragover');
});

dropzone.addEventListener('dragenter', e => {
  if (!Array.from(e.dataTransfer?.types || []).includes('Files')) return;
  e.preventDefault();
  dragDepth++;
  dropzone.classList.add('dragover');
});
dropzone.addEventListener('dragover', e => {
  if (!Array.from(e.dataTransfer?.types || []).includes('Files')) return;
  e.preventDefault();
  e.dataTransfer.dropEffect = 'copy';
});
dropzone.addEventListener('dragleave', e => {
  e.preventDefault();
  dragDepth = Math.max(0, dragDepth - 1);
  if (!dragDepth) dropzone.classList.remove('dragover');
});
dropzone.addEventListener('drop', e => {
  e.preventDefault();
  enqueueFiles(e.dataTransfer?.files || []);
});
fileinput.addEventListener('change', () => {
  enqueueFiles(fileinput.files || []);
  // Permit selecting the same files again, including after clearing the queue.
  fileinput.value = '';
});
fileList.addEventListener('click', e => {
  const row = e.target.closest('tr[data-file-id]');
  if (row) selectFile(Number(row.dataset.fileId));
});
document.getElementById('clear-files').addEventListener('click', () => {
  // Invalidate an outstanding read so its result cannot enter a new batch.
  generation++;
  queue = [];
  queueIndex = 0;
  entries.clear();
  completed = failed = 0;
  selectedId = null;
  fileList.replaceChildren();
  resultsEl.replaceChildren();
  resultsEl.classList.remove('visible');
  if (classifierState !== 'error') errorEl.classList.remove('visible');
  updateBatch();
});

function enqueueFiles(files) {
  if (!files.length) return;
  if (classifierState === 'error') {
    showError('Classifier unavailable. Reload the page to try again.');
    return;
  }
  errorEl.classList.remove('visible');
  const rows = document.createDocumentFragment();
  for (const file of Array.from(files)) {
    const entry = {
      id: nextId++, file, name: file.name, size: file.size,
      status: 'queued', payload: null, elapsed: 0, error: '',
      row: document.createElement('tr'),
    };
    entry.row.dataset.fileId = entry.id;
    entry.row.innerHTML = `<td>
      <button class="batch-file" type="button" title="${esc(entry.name)}" aria-controls="results">${esc(entry.name)}</button>
      <div class="batch-file-size">${fmtSize(entry.size)}</div>
    </td><td class="batch-architecture">&mdash;</td><td class="batch-format">&mdash;</td>
    <td><span class="batch-status queued">Queued</span></td>`;
    entries.set(entry.id, entry);
    queue.push(entry);
    rows.append(entry.row);
  }
  fileList.append(rows);
  if (selectedId === null) selectFile(entries.keys().next().value);
  updateBatch();
  processQueue();
}

async function processQueue() {
  if (processing || classifierState !== 'ready') return;
  processing = true;
  try {
    while (queueIndex < queue.length) {
      const entry = queue[queueIndex++];
      const batchGeneration = generation;
      entry.status = 'analyzing';
      updateEntry(entry);
      updateBatch(entry);
      // Yield before synchronous classification so status and user input can render.
      await new Promise(resolve => setTimeout(resolve, 0));
      if (batchGeneration !== generation) continue;
      try {
        const data = new Uint8Array(await entry.file.arrayBuffer());
        if (batchGeneration !== generation) continue;
        const start = performance.now();
        const payload = JSON.parse(classify(data));
        entry.elapsed = performance.now() - start;
        if (payload.error) throw new Error(payload.error);
        entry.payload = payload;
        entry.status = 'done';
        completed++;
      } catch (e) {
        if (batchGeneration !== generation) continue;
        entry.status = 'error';
        entry.error = String(e.message || e);
        failed++;
      } finally {
        // Retain classification data, not all the original binary contents.
        entry.file = null;
      }
      updateEntry(entry);
      updateBatch();
    }
  } finally {
    queue = [];
    queueIndex = 0;
    processing = false;
    updateBatch();
  }
}

function updateEntry(entry) {
  const status = entry.row.querySelector('.batch-status');
  status.className = `batch-status ${entry.status}`;
  status.textContent = { queued: 'Queued', analyzing: 'Analyzing', done: 'Done', error: 'Failed' }[entry.status];
  if (entry.payload) {
    const p = entry.payload;
    entry.row.querySelector('.batch-architecture').textContent = p.slices?.length > 1
      ? [...new Set(p.slices.map(s => isaName(s.isa)))].join(' + ') : isaName(p.primary.isa);
    entry.row.querySelector('.batch-format').textContent = fmtFormat(p.format);
  }
  if (selectedId === entry.id) renderSelected();
}

function updateBatch(activeEntry) {
  const total = entries.size;
  const pending = total - completed - failed;
  batchEl.hidden = !total;
  batchSummary.textContent = `${total} file${total === 1 ? '' : 's'} · ${completed} done · ${failed} failed${pending ? ` · ${pending} pending` : ''}`;
  batchProgress.max = total || 1;
  batchProgress.value = completed + failed;
  batchEl.setAttribute('aria-busy', String(pending > 0));
  loading.classList.toggle('active', classifierState === 'loading' || pending > 0);
  loadingText.textContent = classifierState === 'loading' ? 'Loading classifier…'
    : activeEntry ? `Analyzing ${activeEntry.name}`
    : pending ? 'Processing file queue…' : '';
}

function selectFile(id) {
  if (!entries.has(id)) return;
  const previous = entries.get(selectedId);
  if (previous) {
    previous.row.classList.remove('selected');
    previous.row.querySelector('button').removeAttribute('aria-current');
  }
  selectedId = id;
  const entry = entries.get(id);
  entry.row.classList.add('selected');
  entry.row.querySelector('button').setAttribute('aria-current', 'true');
  renderSelected();
}

function renderSelected() {
  const entry = entries.get(selectedId);
  if (!entry) return;
  if (entry.status === 'done') {
    render(entry.payload, entry.name, entry.size, entry.elapsed);
  } else {
    const message = entry.status === 'error' ? `Analysis failed: ${entry.error}`
      : entry.status === 'analyzing' ? 'Analyzing this file…' : 'Queued for analysis.';
    resultsEl.innerHTML = `<div class="result-message ${entry.status === 'error' ? 'error' : ''}"><strong>${esc(entry.name)}</strong>${esc(message)}</div>`;
    resultsEl.classList.add('visible');
  }
}

function showError(msg) {
  errorEl.textContent = msg;
  errorEl.classList.add('visible');
}

async function boot() {
  updateBatch();
  try {
    await init();
    document.getElementById('version').textContent = `v${classifier_version()}`;
    classifierState = 'ready';
    updateBatch();
    processQueue();
  } catch (e) {
    classifierState = 'error';
    for (const entry of entries.values()) {
      entry.file = null;
      entry.status = 'error';
      entry.error = 'Classifier could not be loaded.';
      failed++;
      updateEntry(entry);
    }
    queue = [];
    queueIndex = 0;
    updateBatch();
    showError(`Failed to load classifier: ${e.message || e}`);
  }
}
boot();

// ==== Rendering ====

function render(p, filename, size, elapsed) {
  let html = '';

  // -- File banner
  html += `<div class="file-banner">
    <div class="file-icon">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
        <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/>
      </svg>
    </div>
    <div class="file-info">
      <div class="file-name">${esc(filename)}</div>
      <div class="file-meta">
        <span>${fmtSize(size)}</span>
        <span>${esc(fmtFormat(p.format))}</span>
      </div>
    </div>
  </div>`;

  // -- Hero: primary classification
  const pr = p.primary;
  const conf = pr.confidence;
  const confPct = (conf * 100).toFixed(1);
  const confCls = conf >= 0.8 ? 'conf-high' : conf >= 0.4 ? 'conf-mid' : 'conf-low';

  const hasSlices = p.slices && p.slices.length > 1;
  const heroTitle = hasSlices
    ? [...new Set(p.slices.map(s => isaName(s.isa)))].join(' + ')
    : isaName(pr.isa);
  const heroSub = hasSlices
    ? `${p.format.format === 'mach_o_fat' ? 'Universal binary' : 'Multi-component container'} &middot; ${p.slices.length} slices &middot; ${esc(fmtSource(pr.source))}`
    : `${pr.bitwidth}-bit ${esc(fmtEndian(pr.endianness))} &middot; ${esc(fmtSource(pr.source))}`;

  html += `<div class="hero">
    <div class="hero-isa">${esc(heroTitle)}</div>
    <div class="hero-isa-sub">${heroSub}</div>`;

  if (pr.variant) {
    html += `<span class="variant-tag">${esc(fmtVariant(pr.variant))}</span>`;
  }

  html += `<div class="hero-grid">
      <div class="hero-field">
        <div class="hero-field-label">Confidence</div>
        <div class="confidence-meter">
          <span class="hero-field-value">${confPct}%</span>
          <div class="confidence-track"><div class="confidence-fill ${confCls}" style="width:${confPct}%"></div></div>
        </div>
      </div>
      <div class="hero-field">
        <div class="hero-field-label">Bitwidth</div>
        <div class="hero-field-value mono">${pr.bitwidth}-bit</div>
      </div>
      <div class="hero-field">
        <div class="hero-field-label">Endianness</div>
        <div class="hero-field-value mono">${esc(fmtEndian(pr.endianness))}</div>
      </div>
      <div class="hero-field">
        <div class="hero-field-label">Source</div>
        <div class="hero-field-value">${esc(fmtSource(pr.source))}</div>
      </div>
    </div>
  </div>`;

  // -- Format section
  const fmt = p.format;
  html += collapsible('File Format', null, `
    <div class="format-grid">
      <div>
        <div class="fmt-field-label">Format</div>
        <div class="fmt-field-value">${esc(fmtFormatName(fmt.format))}</div>
      </div>
      <div>
        <div class="fmt-field-label">Confidence</div>
        <div class="fmt-field-value">${(fmt.confidence * 100).toFixed(0)}%</div>
      </div>
      ${fmt.magic_offset != null ? `<div>
        <div class="fmt-field-label">Magic Offset</div>
        <div class="fmt-field-value">0x${fmt.magic_offset.toString(16).toUpperCase()}</div>
      </div>` : ''}
      ${fmt.variant_name ? `<div>
        <div class="fmt-field-label">Variant</div>
        <div class="fmt-field-value">${esc(fmt.variant_name)}</div>
      </div>` : ''}
    </div>
  `);

  // -- Slices (fat Mach-O architectures or labelled firmware components)
  if (p.slices && p.slices.length > 0) {
    let cards = '';
    for (const s of p.slices) {
      const extChips = (s.extensions || [])
        .map(e => `<span class="slice-ext">${esc(e.name)}</span>`)
        .join('');
      const variantStr = s.variant ? ` <span style="color:var(--text-3)">${esc(fmtVariant(s.variant))}</span>` : '';
      cards += `<div class="slice-card">
        <div class="slice-isa">${s.label ? esc(s.label) + ' &middot; ' : ''}${esc(isaName(s.isa))}${variantStr}</div>
        <div class="slice-meta">${fmtSize(s.size)}</div>
        <div class="slice-detail">
          <span class="slice-detail-item">${s.bitwidth}-bit</span>
          <span class="slice-detail-item">${esc(fmtEndian(s.endianness))}</span>
          <span class="slice-detail-item">offset 0x${s.offset.toString(16).toUpperCase()}</span>
          ${extChips}
        </div>
      </div>`;
    }
    html += collapsible('Contained Architectures', p.slices.length, `<div class="slice-list">${cards}</div>`);
  }

  // -- Metadata
  if (p.metadata && p.metadata.length > 0) {
    let rows = '';
    for (const m of p.metadata) {
      rows += `<tr><td class="mk">${esc(m.label)}</td><td class="mv">${esc(fmtMetaValue(m))}</td></tr>`;
    }
    html += collapsible('Metadata', p.metadata.length, `<table class="meta-table">${rows}</table>`);
  }

  // -- Extensions
  if (p.extensions && p.extensions.length > 0) {
    let chips = '';
    for (const e of p.extensions) {
      const cat = (e.category || 'other').replace(/([A-Z])/g, '_$1').toLowerCase();
      const confStr = (e.confidence * 100).toFixed(0);
      const title = `${fmtCat(e.category)} \u00b7 ${confStr}% \u00b7 ${fmtExtSrc(e.source)}`;
      chips += `<span class="ext-chip cat-${esc(cat)}" title="${esc(title)}">${esc(e.name)}<span class="ext-conf">${confStr}%</span></span>`;
    }
    html += collapsible('ISA Extensions', p.extensions.length, `<div class="ext-grid">${chips}</div>`);
  }

  // -- Candidates
  if (p.candidates && p.candidates.length > 0) {
    const maxScore = Math.max(...p.candidates.map(c => Math.abs(c.raw_score)), 1);
    let rows = '';
    for (let i = 0; i < p.candidates.length; i++) {
      const c = p.candidates[i];
      const pct = Math.max((Math.abs(c.raw_score) / maxScore) * 100, 2);
      const rank = i === 0 ? 'rank-0' : i === 1 ? 'rank-1' : i === 2 ? 'rank-2' : 'rank-n';
      rows += `<div class="cand-row">
        <div class="cand-name">${esc(isaName(c.isa))}</div>
        <div class="cand-bar-track"><div class="cand-bar-fill ${rank}" style="width:${pct.toFixed(1)}%"></div></div>
        <div class="cand-score" title="Accumulated classifier evidence in bits; bars are relative to the largest candidate">${c.raw_score.toLocaleString()} bits</div>
      </div>
      <div class="cand-detail" title="Candidate evidence share; not a posterior probability">${c.bitwidth}-bit &middot; ${esc(fmtEndian(c.endianness))} &middot; ${(c.confidence * 100).toFixed(1)}%</div>`;
    }
    html += collapsible('Heuristic Candidates', p.candidates.length, `<div class="cand-list">${rows}</div>`);
  }

  // -- Notes
  if (p.notes && p.notes.length > 0) {
    let items = '';
    for (const n of p.notes) {
      items += `<div class="note-item">
        <span class="note-badge ${n.level}">${n.level}</span>
        <span class="note-msg">${esc(n.message)}${n.context ? ` <span class="note-ctx">(${esc(n.context)})</span>` : ''}</span>
      </div>`;
    }
    html += collapsible('Notes', p.notes.length, items);
  }

  // -- JSON
  html += `<div class="json-section">
    <button class="json-btn" id="jsonToggle" type="button" aria-controls="jsonRaw" aria-expanded="false">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
        <polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>
      </svg>
      Raw JSON
    </button>
    <div class="json-panel" id="jsonRaw">${esc(JSON.stringify(p, null, 2))}</div>
  </div>`;

  // -- Footer
  html += `<div class="footer-bar">
    <span>Analyzed ${fmtSize(size)}</span>
    <span class="timing">${elapsed.toFixed(1)} ms</span>
  </div>`;

  resultsEl.innerHTML = html;
  resultsEl.classList.add('visible');

  // Wire collapsibles
  resultsEl.querySelectorAll('.section-header').forEach(hdr => {
    hdr.addEventListener('click', () => {
      const collapsed = hdr.closest('.section').classList.toggle('collapsed');
      hdr.setAttribute('aria-expanded', String(!collapsed));
    });
  });

  // Wire JSON toggle
  document.getElementById('jsonToggle').addEventListener('click', () => {
    const raw = document.getElementById('jsonRaw');
    const btn = document.getElementById('jsonToggle');
    const isVis = raw.classList.toggle('visible');
    btn.setAttribute('aria-expanded', String(isVis));
    btn.querySelector('svg').style.color = isVis ? 'var(--accent)' : '';
  });
}

// ==== Components ====

function collapsible(title, count, body) {
  const badge = count != null ? `<span class="section-count">${count}</span>` : '';
  return `<div class="section">
    <button class="section-header" type="button" aria-expanded="true">
      <span class="section-title">${esc(title)}${badge}</span>
      <svg class="section-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>
    </button>
    <div class="section-body">${body}</div>
  </div>`;
}


