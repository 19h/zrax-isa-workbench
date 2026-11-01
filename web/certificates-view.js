// The certificates tab: certificates found anywhere in the file, as a tree of
// issuer links with a detail pane. Scanning runs in the scan worker as soon
// as a file is selected, so the tab can show a count. Signatures and chains
// are never verified; the view says so wherever it shows a link.
import { esc, fmtSize } from './format.js';
import { hx } from './hex-utils.js';
import {
  PEM_TYPE, certificateDetail, derBytes, enclosingRegions, fact, keyLabel, matchesFilter, treeItem, treeOrder,
} from './certificate-common.js';

const $ = id => document.getElementById(id);

export function createCertificatesView(store, hooks) {
  // Selection and filter per file; the reports live in the store.
  const views = new Map();
  let entry = null;
  let active = false;
  let revealPending = false;

  function viewState(target) {
    let view = views.get(target.id);
    if (!view) {
      view = { selected: -1, filter: '' };
      views.set(target.id, view);
    }
    return view;
  }

  /** The current file's view state and scan; selects the first distinct certificate once a report exists. */
  function current() {
    const view = viewState(entry);
    const scan = store.get(entry.id);
    const report = scan?.report || null;
    if (report && view.selected < 0) {
      const first = report.certificates.find(c => c.duplicate_of == null);
      if (first) view.selected = first.index;
    }
    return { view, scan, report };
  }

  store.subscribe(id => {
    if (entry && entry.id === id) render();
  });

  function renderBadge(report) {
    const count = report?.certificates.length;
    $('certificates-count').textContent = count ? String(count) : '';
  }

  function renderTree(view, report) {
    const tree = $('certificates-tree');
    if (!report) {
      tree.innerHTML = '';
      return;
    }
    const certificates = report.certificates;
    const filter = view.filter.toLowerCase();
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
      const certificate = certificates[index];
      const count = copies.get(index);
      const meta = [keyLabel(certificate.summary), certificate.encoding, `0x${hx(certificate.offset)}`]
        .filter(Boolean).join(' · ');
      return treeItem({
        id: `certificate-item-${index}`,
        index,
        level,
        selected: index === view.selected,
        certificate,
        copies: count,
        copiesTitle: `${count} identical copies in this file`,
        meta,
        now,
      });
    }).join('') || '<p class="muted">no certificates match the filter</p>';
    const selected = view.selected >= 0 ? `certificate-item-${view.selected}` : '';
    if (selected && $(selected)) tree.setAttribute('aria-activedescendant', selected);
    else tree.removeAttribute('aria-activedescendant');
  }

  function renderDetail(view, report) {
    const panel = $('certificates-detail');
    const certificate = report?.certificates[view.selected];
    if (!certificate) {
      panel.innerHTML = '';
      return;
    }
    const location = enclosingRegions(entry.regions, certificate);
    const occurrences = report.certificates
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
    const issuerLink = certificate.issuer_index != null
      ? ` <button type="button" class="small" data-certificate-select="${certificate.issuer_index}">go to issuer [${certificate.issuer_index}]</button>`
      : '';
    panel.innerHTML = certificateDetail({ certificate, issuerLink, locationFacts, actions });
  }

  function renderStatus(scan, report) {
    let message;
    if (scan?.error) {
      message = scan.error;
    } else if (!report) {
      const percent = entry.size ? Math.floor(((scan?.scanned || 0) / entry.size) * 100) : 0;
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
    const { view, scan, report } = current();
    renderBadge(report);
    if (!active) return;
    $('certificates-filter').value = view.filter;
    renderStatus(scan, report);
    renderTree(view, report);
    renderDetail(view, report);
    if (revealPending) {
      revealPending = false;
      $(`certificate-item-${view.selected}`)?.scrollIntoView({ block: 'nearest' });
    }
  }

  function selectCertificate(index) {
    const { view, report } = current();
    view.selected = index;
    renderTree(view, report);
    renderDetail(view, report);
    $(`certificate-item-${index}`)?.scrollIntoView({ block: 'nearest' });
  }

  function act(action) {
    const { view, report } = current();
    const certificate = report?.certificates[view.selected];
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
    const { report } = current();
    if (!report) return;
    if (format === 'json') {
      const json = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
      hooks.download(`${entry.name}.certificates.json`, json);
      return;
    }
    const unique = report.certificates.filter(c => c.duplicate_of == null && c.summary);
    hooks.download(`${entry.name}.certificates.pem`, new Blob(unique.map(c => c.pem), { type: PEM_TYPE }));
  }

  $('certificates-view').addEventListener('click', event => {
    if (!entry) return;
    const button = event.target.closest('button');
    const item = event.target.closest('[data-certificate]');
    if (button?.dataset.certificateAction) act(button.dataset.certificateAction);
    else if (button?.dataset.certificateSelect) selectCertificate(Number(button.dataset.certificateSelect));
    else if (button?.dataset.certificatesExport) exportAll(button.dataset.certificatesExport);
    else if (item) {
      selectCertificate(Number(item.dataset.certificate));
      $('certificates-tree').focus();
    }
  });
  $('certificates-tree').addEventListener('dblclick', event => {
    if (event.target.closest('[data-certificate]')) act('hex');
  });
  $('certificates-tree').addEventListener('keydown', event => {
    if (!entry) return;
    const { view } = current();
    const nodes = $('certificates-tree').querySelectorAll('[data-certificate]');
    const items = [...nodes].map(node => Number(node.dataset.certificate));
    if (!items.length) return;
    const position = items.indexOf(view.selected);
    const moves = { ArrowDown: 1, ArrowUp: -1, Home: -Infinity, End: Infinity };
    if (event.key in moves) {
      const step = moves[event.key];
      const last = items.length - 1;
      const next = Number.isFinite(step) ? Math.max(0, Math.min(last, position + step)) : step < 0 ? 0 : last;
      selectCertificate(items[next]);
      event.preventDefault();
      event.stopPropagation();
    } else if (event.key === 'Enter') {
      act('hex');
      event.preventDefault();
    }
  });
  $('certificates-filter').addEventListener('input', event => {
    if (!entry) return;
    viewState(entry).filter = event.target.value;
    const { view, report } = current();
    renderTree(view, report);
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
      store.scan(entry, true);
      render();
    },
    /** Select certificate `index` of the current file, clearing the filter, and scroll to it when shown. */
    reveal(index) {
      if (!entry) return;
      const view = viewState(entry);
      view.selected = index;
      view.filter = '';
      revealPending = true;
      render();
    },
    forget(id) {
      views.delete(id);
    },
    clear() {
      views.clear();
    },
  };
}
