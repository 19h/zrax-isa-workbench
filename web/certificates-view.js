// The certificates tab: certificates found anywhere in the file, as a tree of
// issuer links with a detail pane. Scanning runs in the scan worker as soon
// as a file is selected, so the tab can show a count. Signatures and chains
// are never verified; the view says so wherever it shows a link.
import { esc, fmtSize } from './format.js';
import { hx } from './hex-utils.js';

const $ = id => document.getElementById(id);
const PEM_TYPE = 'application/x-pem-file';

const KEY_USAGE_LABELS = {
  digitalSignature: 'digital signature',
  nonRepudiation: 'non-repudiation',
  keyEncipherment: 'key encipherment',
  dataEncipherment: 'data encipherment',
  keyAgreement: 'key agreement',
  keyCertSign: 'certificate signing',
  cRLSign: 'CRL signing',
  encipherOnly: 'encipher only',
  decipherOnly: 'decipher only',
};

/** Validity relative to this computer's clock, which the library never reads. */
function validity(summary, now = Date.now() / 1000) {
  if (now < summary.not_before_unix) return { state: 'future', label: 'not yet valid' };
  if (now > summary.not_after_unix) return { state: 'expired', label: 'expired' };
  return { state: 'valid', label: 'within validity period' };
}

/** DER bytes from the canonical PEM text of a certificate. */
function derBytes(pem) {
  const body = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  return Uint8Array.from(atob(body), c => c.charCodeAt(0));
}

function displayName(certificate) {
  const summary = certificate.summary;
  if (!summary) return 'unparsed PEM block';
  return summary.subject_cn || summary.subject || '(empty subject)';
}

/**
 * Tree order: each root (no issuer link) followed by the certificates it
 * links to, depth first. Duplicates are folded into their first occurrence;
 * certificates reachable only through an issuer cycle come last at level 1.
 */
function treeOrder(certificates) {
  const children = new Map();
  for (const c of certificates) {
    if (c.duplicate_of != null || c.issuer_index == null) continue;
    if (!children.has(c.issuer_index)) children.set(c.issuer_index, []);
    children.get(c.issuer_index).push(c.index);
  }
  const order = [];
  const visited = new Set();
  const visit = (index, level) => {
    if (visited.has(index)) return;
    visited.add(index);
    order.push({ index, level });
    for (const child of children.get(index) || []) visit(child, level + 1);
  };
  for (const c of certificates) {
    if (c.duplicate_of == null && c.issuer_index == null) visit(c.index, 1);
  }
  for (const c of certificates) {
    if (c.duplicate_of == null) visit(c.index, 1);
  }
  return order;
}

function matchesFilter(certificate, filter) {
  if (!filter) return true;
  const summary = certificate.summary || {};
  return [summary.subject, summary.issuer, summary.serial, certificate.sha256, certificate.error]
    .some(value => value && value.toLowerCase().includes(filter));
}

export function createCertificatesView(scanner, hooks) {
  const files = new Map();
  let entry = null;
  let active = false;

  function fileState(target) {
    let state = files.get(target.id);
    if (!state) {
      state = { request: 0, report: null, error: '', scanned: 0, selected: -1, filter: '' };
      files.set(target.id, state);
    }
    return state;
  }

  function start(target) {
    const state = fileState(target);
    if (state.request) return;
    state.report = null;
    state.error = '';
    state.request = scanner.post({ type: 'certificates', id: target.id, file: target.file });
  }

  scanner.subscribe(data => {
    if (data.type === 'boot-error' || data.type === 'restarted') {
      for (const state of files.values()) {
        if (!state.report) state.request = 0;
      }
      if (entry) start(entry);
      return;
    }
    const state = files.get(data.id);
    if (!state || data.request !== state.request) return;
    if (data.type === 'certificates-progress') {
      state.scanned = data.scanned;
    } else if (data.type === 'certificates') {
      state.report = data.report;
      const unique = data.report.certificates.filter(c => c.duplicate_of == null);
      if (state.selected < 0 && unique.length) state.selected = unique[0].index;
    } else if (data.type === 'error' && data.operation === 'certificates') {
      state.error = data.error;
    } else {
      return;
    }
    if (entry?.id === data.id) render();
  });

  function renderBadge(state) {
    const count = state.report?.certificates.length;
    $('certificates-count').textContent = count ? String(count) : '';
  }

  function enclosing(certificate) {
    return (entry?.regions || [])
      .filter(r => certificate.offset >= r.offset && certificate.offset + certificate.stored_size <= r.offset + r.size)
      .sort((a, b) => b.size - a.size)
      .map(r => r.label);
  }

  function renderTree(state) {
    const report = state.report;
    const tree = $('certificates-tree');
    if (!report) {
      tree.innerHTML = '';
      return;
    }
    const certificates = report.certificates;
    const filter = state.filter.toLowerCase();
    const items = filter
      ? certificates
        .filter(c => c.duplicate_of == null && matchesFilter(c, filter))
        .map(c => ({ index: c.index, level: 1 }))
      : treeOrder(certificates);
    const copies = new Map();
    for (const c of certificates) {
      if (c.duplicate_of != null) copies.set(c.duplicate_of, (copies.get(c.duplicate_of) || 1) + 1);
    }
    const now = Date.now() / 1000;
    tree.innerHTML = items.map(({ index, level }) => {
      const c = certificates[index];
      const summary = c.summary;
      const status = summary ? validity(summary, now) : { state: 'error', label: 'not parsed' };
      const key = summary
        ? [summary.public_key_algorithm, summary.public_key_bits].filter(Boolean).join(' ')
        : '';
      const count = copies.get(index);
      return `<div class="certificate-item" role="treeitem" id="certificate-item-${index}" aria-level="${level}"`
        + ` aria-selected="${index === state.selected}" data-certificate="${index}" style="--level: ${level - 1}">`
        + `<span class="validity-dot ${status.state}" title="${esc(status.label)}"></span>`
        + `<span class="certificate-name">${esc(displayName(c))}</span>`
        + (c.self_issued ? '<span class="badge">self-issued</span>' : '')
        + (summary?.is_ca ? '<span class="badge">ca</span>' : '')
        + (count ? `<span class="badge" title="${count} identical copies in this file">×${count}</span>` : '')
        + `<span class="certificate-meta muted">${esc(key)} · ${c.encoding} · 0x${hx(c.offset)}</span>`
        + '</div>';
    }).join('') || '<p class="muted">no certificates match the filter</p>';
    const selected = state.selected >= 0 ? `certificate-item-${state.selected}` : '';
    if (selected && $(selected)) tree.setAttribute('aria-activedescendant', selected);
    else tree.removeAttribute('aria-activedescendant');
  }

  function fact(label, value, extra = '') {
    return `<dt>${esc(label)}</dt><dd>${value}${extra}</dd>`;
  }

  function renderDetail(state) {
    const panel = $('certificates-detail');
    const certificate = state.report?.certificates[state.selected];
    if (!certificate) {
      panel.innerHTML = '';
      return;
    }
    const summary = certificate.summary;
    const location = enclosing(certificate);
    const occurrences = state.report.certificates
      .filter(c => c.index === certificate.index || c.duplicate_of === certificate.index)
      .map(c => `0x${hx(c.offset)}`);
    const actions = '<div class="certificate-actions">'
      + '<button type="button" data-certificate-action="hex">show in hex</button>'
      + '<button type="button" data-certificate-action="der">↓ der</button>'
      + '<button type="button" data-certificate-action="pem">↓ pem</button>'
      + '<button type="button" data-certificate-action="open">open as file</button>'
      + '</div>';
    const locationFacts = fact('offset', `0x${hx(certificate.offset)} (${certificate.offset})`)
      + fact('stored', `${esc(fmtSize(certificate.stored_size))} ${certificate.encoding.toUpperCase()}`)
      + fact('DER size', esc(fmtSize(certificate.der_size)))
      + fact('within', location.length ? esc(location.join(' > ')) : '—')
      + (occurrences.length > 1 ? fact('copies', esc(occurrences.join(', '))) : '')
      + fact('SHA-256', `<code>${esc(certificate.sha256)}</code>`,
        ' <button type="button" class="small" data-certificate-action="copy-sha">copy</button>');
    if (!summary) {
      panel.innerHTML = `<header class="bar"><strong>unparsed PEM block</strong></header>`
        + `<p class="certificate-error">${esc(certificate.error || 'not a certificate')}</p>`
        + `<dl class="certificate-facts">${locationFacts}</dl>${actions}`;
      return;
    }
    const status = validity(summary);
    const issuer = certificate.issuer_index != null
      ? ` <button type="button" class="small" data-certificate-select="${certificate.issuer_index}">go to issuer [${certificate.issuer_index}]</button>`
      : '';
    const keyText = [
      summary.public_key_algorithm,
      summary.public_key_bits && `${summary.public_key_bits}-bit`,
      summary.curve && `(${summary.curve})`,
    ].filter(Boolean).join(' ');
    const list = values => (values.length ? esc(values.join(', ')) : '—');
    const constraints = summary.is_ca == null ? '—'
      : `${summary.is_ca ? 'CA' : 'not a CA'}${summary.path_len == null ? '' : `, path length ${summary.path_len}`}`;
    const extensionRows = summary.extensions.map(e => `<tr><td>${esc(e.name)}</td><td><code>${esc(e.oid)}</code></td><td>${e.critical ? 'critical' : ''}</td></tr>`).join('');
    panel.innerHTML = `<header class="bar"><strong>${esc(displayName(certificate))}</strong>`
      + `<span class="badge validity-${status.state}" title="by this computer's clock">${esc(status.label)}</span>`
      + (certificate.self_issued ? '<span class="badge">self-issued</span>' : '')
      + '<span class="spacer"></span><span class="muted">signature not verified</span></header>'
      + '<dl class="certificate-facts">'
      + fact('subject', esc(summary.subject))
      + fact('issuer', esc(summary.issuer), issuer + (certificate.issuer_index != null ? ' <small class="muted">name match</small>' : ''))
      + fact('serial', `<code>${esc(summary.serial)}</code>`)
      + fact('version', `v${summary.version}`)
      + fact('not before', esc(summary.not_before))
      + fact('not after', esc(summary.not_after), ` <small class="muted">${esc(status.label)} by this computer's clock</small>`)
      + fact('public key', esc(keyText))
      + fact('signature', `<span title="${esc(summary.signature_oid)}">${esc(summary.signature_algorithm)}</span>`)
      + fact('constraints', esc(constraints))
      + fact('key usage', list(summary.key_usage.map(u => KEY_USAGE_LABELS[u] || u)))
      + fact('extended', list(summary.extended_key_usage))
      + fact('alt names', list(summary.subject_alt_names))
      + fact('subject key', summary.subject_key_id ? `<code>${esc(summary.subject_key_id)}</code>` : '—')
      + fact('authority key', summary.authority_key_id ? `<code>${esc(summary.authority_key_id)}</code>` : '—')
      + locationFacts
      + '</dl>'
      + actions
      + (extensionRows ? '<section class="panel"><header>[ extensions ]</header><div class="panel-body results-table-scroll">'
        + `<table class="results-table" aria-label="Certificate extensions"><thead><tr><th scope="col">name</th><th scope="col">oid</th><th scope="col">flag</th></tr></thead><tbody>${extensionRows}</tbody></table>`
        + '</div></section>' : '');
  }

  function renderStatus(state) {
    const report = state.report;
    let message;
    if (state.error) {
      message = state.error;
    } else if (!report) {
      const percent = entry.size ? Math.floor((state.scanned / entry.size) * 100) : 0;
      message = `scanning ${percent}% for DER and PEM certificates…`;
    } else if (!report.certificates.length) {
      message = `no certificates found in ${fmtSize(entry.size)} (DER and PEM scanned)`;
    } else {
      const unique = report.certificates.filter(c => c.duplicate_of == null).length;
      message = `${report.certificates.length} found (${unique} distinct)`
        + ' · signatures and chains not verified; issuer links compare encoded names';
      if (report.truncated) message += ' · stopped at the certificate limit';
    }
    $('certificates-status').textContent = message;
  }

  function render() {
    if (!entry) return;
    const state = fileState(entry);
    renderBadge(state);
    if (!active) return;
    $('certificates-filter').value = state.filter;
    renderStatus(state);
    renderTree(state);
    renderDetail(state);
  }

  function selectCertificate(state, index) {
    state.selected = index;
    renderTree(state);
    renderDetail(state);
    $(`certificate-item-${index}`)?.scrollIntoView({ block: 'nearest' });
  }

  function act(action) {
    const state = fileState(entry);
    const certificate = state.report?.certificates[state.selected];
    if (!certificate) return;
    const base = `${entry.name}.cert-${certificate.index}`;
    if (action === 'hex') {
      hooks.showRange(certificate.offset, certificate.offset + certificate.stored_size);
    } else if (action === 'der') {
      hooks.download(`${base}.der`, new Blob([derBytes(certificate.pem)]));
    } else if (action === 'pem') {
      hooks.download(`${base}.pem`, new Blob([certificate.pem], { type: PEM_TYPE }));
    } else if (action === 'open') {
      hooks.openDerivedFile(entry, derBytes(certificate.pem), `${base}.der`, `certificate-${certificate.index}`);
    } else if (action === 'copy-sha') {
      hooks.copy(certificate.sha256);
    }
  }

  function exportAll(format) {
    const state = fileState(entry);
    if (!state.report) return;
    if (format === 'json') {
      const json = new Blob([JSON.stringify(state.report, null, 2)], { type: 'application/json' });
      hooks.download(`${entry.name}.certificates.json`, json);
      return;
    }
    const unique = state.report.certificates.filter(c => c.duplicate_of == null && c.summary);
    hooks.download(`${entry.name}.certificates.pem`, new Blob(unique.map(c => c.pem), { type: PEM_TYPE }));
  }

  $('certificates-view').addEventListener('click', event => {
    if (!entry) return;
    const state = fileState(entry);
    const button = event.target.closest('button');
    const item = event.target.closest('[data-certificate]');
    if (button?.dataset.certificateAction) act(button.dataset.certificateAction);
    else if (button?.dataset.certificateSelect) selectCertificate(state, Number(button.dataset.certificateSelect));
    else if (button?.dataset.certificatesExport) exportAll(button.dataset.certificatesExport);
    else if (item) {
      selectCertificate(state, Number(item.dataset.certificate));
      $('certificates-tree').focus();
    }
  });
  $('certificates-tree').addEventListener('dblclick', event => {
    if (event.target.closest('[data-certificate]')) act('hex');
  });
  $('certificates-tree').addEventListener('keydown', event => {
    if (!entry) return;
    const state = fileState(entry);
    const nodes = $('certificates-tree').querySelectorAll('[data-certificate]');
    const items = [...nodes].map(node => Number(node.dataset.certificate));
    if (!items.length) return;
    const position = items.indexOf(state.selected);
    const moves = { ArrowDown: 1, ArrowUp: -1, Home: -Infinity, End: Infinity };
    if (event.key in moves) {
      const step = moves[event.key];
      const last = items.length - 1;
      const next = Number.isFinite(step) ? Math.max(0, Math.min(last, position + step)) : step < 0 ? 0 : last;
      selectCertificate(state, items[next]);
      event.preventDefault();
      event.stopPropagation();
    } else if (event.key === 'Enter') {
      act('hex');
      event.preventDefault();
    }
  });
  $('certificates-filter').addEventListener('input', event => {
    if (!entry) return;
    const state = fileState(entry);
    state.filter = event.target.value;
    renderTree(state);
  });

  return {
    /** Follow the selected entry; scanning starts whether or not the tab is shown. */
    sync(nextEntry, nextActive) {
      entry = nextEntry;
      active = nextActive && Boolean(entry);
      if (!entry) {
        $('certificates-count').textContent = '';
        return;
      }
      start(entry);
      render();
    },
    forget(id) {
      files.delete(id);
    },
    clear() {
      files.clear();
    },
  };
}
