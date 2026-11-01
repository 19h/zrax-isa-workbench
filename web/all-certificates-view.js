// The all-files certificates view: every certificate found in the open files,
// made unique by the SHA-256 of its DER encoding, as one tree of issuer links
// with a detail pane that lists where each copy lies. Links across files
// follow the library's rules (`certificates::link`: encoded names, then key
// identifiers) and run in the scan worker. Signatures and chains are never
// verified; the view says so wherever it shows a link.
import { esc, fmtSize } from './format.js';
import { hx } from './hex-utils.js';
import {
  PEM_TYPE, certificateDetail, derBytes, displayName, enclosingRegions, fact, keyLabel, matchesFilter, treeItem,
  treeOrder,
} from './certificate-common.js';
import { zipArchive } from './zip.js';

const $ = id => document.getElementById(id);
// Delay before rebuilding after a scan reports, so a burst of messages from
// several files rebuilds the tree once.
const REBUILD_DELAY_MS = 150;
// Scan worker job id of the link request; a newer request supersedes it.
const LINK_JOB_ID = 'all-files';
// Longest part of a download name taken from a certificate's subject.
const MAX_STEM_CHARS = 60;
const NOT_VERIFIED_NOTE = 'Signatures and chains not verified; issuer links compare encoded names only';
const DISTINCT_NOTE = 'Certificates are distinct by the SHA-256 of their DER encoding; occurrences list every copy';

const plural = (count, one, many = `${one}s`) => `${count} ${count === 1 ? one : many}`;

/** A file-name-safe stem from a certificate's display name. */
function nameStem(certificate) {
  const stem = displayName(certificate)
    .replace(/[^A-Za-z0-9._-]+/g, '_')
    .replace(/^[._]+|_+$/g, '')
    .slice(0, MAX_STEM_CHARS);
  return stem || 'certificate';
}

/**
 * Distinct certificates as report-shaped records numbered in tree order, so
 * the tree, the downloads and the JSON report agree. `links` are by
 * position in `distinct`.
 */
function buildModel(distinct, links) {
  const records = distinct.map(({ certificate, occurrences }, index) => ({
    index,
    sha256: certificate.sha256,
    der_size: certificate.der_size,
    pem: certificate.pem,
    summary: certificate.summary,
    error: certificate.error,
    issuer_index: links[index]?.issuer_index ?? null,
    self_issued: links[index]?.self_issued ?? false,
    duplicate_of: null,
    occurrences,
    fileCount: new Set(occurrences.map(o => o.entry.id)).size,
  }));
  const order = treeOrder(records);
  const position = new Map(order.map(({ index }, p) => [index, p]));
  return order.map(({ index, level }, p) => {
    const record = records[index];
    const issuer = record.issuer_index == null ? null : position.get(record.issuer_index);
    return { ...record, index: p, level, issuer_index: issuer };
  });
}

/** How many copies of a certificate were found, e.g. `3 copies in 2 files`. */
function copiesLabel(certificate) {
  const copies = plural(certificate.occurrences.length, 'copy', 'copies');
  return `${copies} in ${plural(certificate.fileCount, 'file')}`;
}

/** Where the copies of a certificate lie, for its tree row. */
function locationLabel(certificate) {
  if (certificate.fileCount > 1) return `in ${plural(certificate.fileCount, 'file')}`;
  const [first] = certificate.occurrences;
  if (certificate.occurrences.length > 1) return first.entry.name;
  return `${first.entry.name} @ 0x${hx(first.certificate.offset)}`;
}

function copiesPanel(certificate) {
  const rows = certificate.occurrences.map(({ entry, certificate: copy }, position) => {
    const within = enclosingRegions(entry.regions, copy);
    const offset = `0x${hx(copy.offset)}`;
    return '<tr>'
      + `<td><button type="button" data-occurrence="${position}" data-occurrence-action="open" title="Show in the certificates tab of this file">${esc(entry.name)}</button></td>`
      + `<td>${offset}</td>`
      + `<td>${esc(fmtSize(copy.stored_size))} ${copy.encoding.toUpperCase()}</td>`
      + `<td>${within.length ? esc(within.join(' > ')) : '—'}</td>`
      + `<td><button type="button" data-occurrence="${position}" data-occurrence-action="hex" aria-label="show ${esc(entry.name)} ${offset} in hex">hex</button></td>`
      + '</tr>';
  }).join('');
  return '<section class="panel certificate-copies">'
    + `<header>[ found in ] <span class="muted">${certificate.occurrences.length}</span></header>`
    + '<div class="results-table-scroll"><table class="results-table" aria-label="Copies of this certificate">'
    + '<thead><tr><th scope="col">file</th><th scope="col">offset</th><th scope="col">stored</th>'
    + '<th scope="col">within</th><th scope="col"><span class="sr-only">actions</span></th></tr></thead>'
    + `<tbody>${rows}</tbody></table></div></section>`;
}

export function createAllCertificatesView(store, scanner, hooks) {
  let active = false;
  let rebuildTimer = 0;
  // Links of the distinct set whose SHA-256 list is `linkedKey`, by
  // first-occurrence position. A request for `pendingKey` may be in flight.
  let links = [];
  let linkedKey = '';
  let pendingKey = '';
  let linkRequest = 0;
  let linkError = '';
  let certificates = [];
  let progress = { files: 0, scanned: 0, failed: 0, truncated: 0, withCertificates: 0, found: 0 };
  // The tree and detail are redrawn only when the certificates change.
  let modelKey = '';
  let renderedKey = null;
  let selectedSha = '';
  let filter = '';

  /** Distinct certificates of every scanned file, in first-occurrence order, and scan progress. */
  function collect() {
    const entries = hooks.entries();
    const bySha = new Map();
    const distinct = [];
    const counts = { files: entries.length, scanned: 0, failed: 0, truncated: 0, withCertificates: 0, found: 0 };
    for (const entry of entries) {
      const scan = store.get(entry.id);
      if (scan?.error) counts.failed++;
      if (!scan?.report) continue;
      const report = scan.report;
      counts.scanned++;
      if (report.truncated) counts.truncated++;
      if (report.certificates.length) counts.withCertificates++;
      counts.found += report.certificates.length;
      for (const certificate of report.certificates) {
        let item = bySha.get(certificate.sha256);
        if (!item) {
          item = { certificate, occurrences: [] };
          bySha.set(certificate.sha256, item);
          distinct.push(item);
        }
        item.occurrences.push({ entry, certificate });
      }
    }
    return { distinct, counts };
  }

  function requestLinks(key, distinct) {
    pendingKey = key;
    linkRequest = scanner.post({
      type: 'certificates-link',
      id: LINK_JOB_ID,
      ders: distinct.map(item => derBytes(item.certificate.pem)),
    });
  }

  function rebuild() {
    clearTimeout(rebuildTimer);
    rebuildTimer = 0;
    const { distinct, counts } = collect();
    progress = counts;
    const key = distinct.map(item => item.certificate.sha256).join(',');
    if (key === linkedKey) {
      certificates = buildModel(distinct, links);
      modelKey = `${key}:${counts.found}:${counts.scanned}`;
    } else if (key !== pendingKey) {
      requestLinks(key, distinct);
    }
    render();
  }

  function scheduleRebuild() {
    if (!rebuildTimer) rebuildTimer = setTimeout(rebuild, REBUILD_DELAY_MS);
  }

  store.subscribe(() => {
    if (active) scheduleRebuild();
  });

  scanner.subscribe(data => {
    if (!linkRequest) return;
    if (data.type === 'boot-error' || data.type === 'restarted') {
      // The request was lost with the worker; the rebuild asks again.
      linkRequest = 0;
      pendingKey = '';
      if (active) scheduleRebuild();
      return;
    }
    if (data.request !== linkRequest) return;
    if (data.type === 'certificates-links') {
      links = data.links;
      linkError = '';
    } else if (data.type === 'error' && data.operation === 'certificates-link') {
      // Show the certificates without links rather than nothing.
      links = [];
      linkError = data.error;
    } else {
      return;
    }
    linkedKey = pendingKey;
    pendingKey = '';
    linkRequest = 0;
    rebuild();
  });

  const isBusy = () => progress.scanned + progress.failed < progress.files || Boolean(pendingKey);
  const selectedCertificate = () => certificates.find(c => c.sha256 === selectedSha);
  const matches = (certificate, needle) => matchesFilter(certificate, needle)
    || certificate.occurrences.some(o => o.entry.name.toLowerCase().includes(needle));

  function statusMessage() {
    const { files, scanned, failed, truncated, withCertificates, found } = progress;
    if (!files) return 'no open files; add files to list the certificates they contain';
    if (scanned + failed < files) {
      const sofar = found ? ` · ${found} found so far` : '';
      return `scanning ${scanned + failed} of ${plural(files, 'file')} for DER and PEM certificates…${sofar}`;
    }
    if (pendingKey) return `linking ${found} certificates across files by issuer name…`;
    const parts = found
      ? [
        `${found} found in ${withCertificates} of ${plural(scanned, 'file')} (${certificates.length} distinct)`,
        'signatures and chains not verified; issuer links compare encoded names',
      ]
      : [`no certificates found in ${plural(scanned, 'file')} (DER and PEM scanned)`];
    if (failed) parts.push(`${plural(failed, 'file')} could not be scanned`);
    if (truncated) parts.push(`stopped at the certificate limit in ${plural(truncated, 'file')}`);
    if (linkError) parts.push(`issuer links unavailable: ${linkError}`);
    return parts.join(' · ');
  }

  function renderTree() {
    const tree = $('all-certificates-tree');
    if (!certificates.length) {
      tree.innerHTML = '';
      tree.removeAttribute('aria-activedescendant');
      return;
    }
    const needle = filter.toLowerCase();
    const items = needle
      ? certificates.filter(c => matches(c, needle)).map(c => ({ certificate: c, level: 1 }))
      : certificates.map(c => ({ certificate: c, level: c.level }));
    const now = Date.now() / 1000;
    tree.innerHTML = items.map(({ certificate, level }) => {
      const copies = certificate.occurrences.length;
      return treeItem({
        id: `all-certificate-item-${certificate.index}`,
        index: certificate.index,
        level,
        selected: certificate.sha256 === selectedSha,
        certificate,
        copies: copies > 1 ? copies : 0,
        copiesTitle: copiesLabel(certificate),
        meta: [keyLabel(certificate.summary), locationLabel(certificate)].filter(Boolean).join(' · '),
        now,
      });
    }).join('') || '<p class="muted">no certificates match the filter</p>';
    const selected = selectedCertificate();
    const id = selected ? `all-certificate-item-${selected.index}` : '';
    if (id && $(id)) tree.setAttribute('aria-activedescendant', id);
    else tree.removeAttribute('aria-activedescendant');
  }

  function renderDetail() {
    const panel = $('all-certificates-detail');
    const certificate = selectedCertificate();
    if (!certificate) {
      panel.innerHTML = '';
      return;
    }
    const locationFacts = fact('DER size', esc(fmtSize(certificate.der_size)))
      + fact('found', esc(copiesLabel(certificate)))
      + fact('SHA-256', `<code>${esc(certificate.sha256)}</code>`,
        ' <button type="button" class="small" data-certificate-action="copy-sha">copy</button>');
    const actions = '<div class="certificate-actions">'
      + '<button type="button" data-certificate-action="der">↓ der</button>'
      + '<button type="button" data-certificate-action="pem">↓ pem</button>'
      + '</div>';
    const issuerLink = certificate.issuer_index != null
      ? ` <button type="button" class="small" data-certificate-select="${certificate.issuer_index}">go to issuer</button>`
      : '';
    panel.innerHTML = certificateDetail({
      certificate, issuerLink, locationFacts, actions, sections: copiesPanel(certificate),
    });
  }

  function render() {
    if (!active) return;
    if (!selectedCertificate() && certificates.length) selectedSha = certificates[0].sha256;
    $('all-certificates-scope').textContent = `across ${plural(progress.files, 'open file')}`;
    $('all-certificates-status').textContent = statusMessage();
    const disabled = isBusy() || !certificates.length;
    for (const button of document.querySelectorAll('[data-all-certificates-export]')) button.disabled = disabled;
    if (renderedKey === modelKey) return;
    renderedKey = modelKey;
    renderTree();
    renderDetail();
  }

  function select(index) {
    const certificate = certificates[index];
    if (!certificate) return;
    selectedSha = certificate.sha256;
    renderTree();
    renderDetail();
    $(`all-certificate-item-${index}`)?.scrollIntoView({ block: 'nearest' });
  }

  function act(action) {
    const certificate = selectedCertificate();
    if (!certificate) return;
    if (action === 'der') {
      hooks.download(`${nameStem(certificate)}.der`, new Blob([derBytes(certificate.pem)]));
    } else if (action === 'pem') {
      hooks.download(`${nameStem(certificate)}.pem`, new Blob([certificate.pem], { type: PEM_TYPE }));
    } else if (action === 'copy-sha') {
      hooks.copy(certificate.sha256);
    }
  }

  function openOccurrence(position, action) {
    const copy = selectedCertificate()?.occurrences[position];
    if (!copy) return;
    const { entry, certificate } = copy;
    const end = certificate.offset + certificate.stored_size;
    if (action === 'open') hooks.openCertificate(entry.id, certificate.index);
    else if (action === 'hex') hooks.showBytes(entry.id, certificate.offset, end);
  }

  /** The report behind the JSON download: files, then distinct certificates with every copy. */
  function jsonReport() {
    const entries = hooks.entries();
    const fileIndex = new Map(entries.map((entry, index) => [entry.id, index]));
    const files = entries.map(entry => {
      const scan = store.get(entry.id);
      return {
        name: entry.name,
        size: entry.size,
        certificates: scan?.report ? scan.report.certificates.length : null,
        truncated: scan?.report?.truncated ?? false,
        ...(scan?.error ? { error: scan.error } : {}),
      };
    });
    const distinct = certificates.map(c => ({
      index: c.index,
      sha256: c.sha256,
      der_size: c.der_size,
      issuer_index: c.issuer_index,
      self_issued: c.self_issued,
      ...(c.summary ? { summary: c.summary } : { error: c.error }),
      pem: c.pem,
      occurrences: c.occurrences.map(({ entry, certificate }) => ({
        file: fileIndex.get(entry.id),
        name: entry.name,
        offset: certificate.offset,
        stored_size: certificate.stored_size,
        encoding: certificate.encoding,
        within: enclosingRegions(entry.regions, certificate),
      })),
    }));
    return { notes: [NOT_VERIFIED_NOTE, DISTINCT_NOTE], files, certificates: distinct };
  }

  function exportAll(format) {
    if (isBusy() || !certificates.length) return;
    // Unparsed PEM blocks are not certificates; only the JSON report lists them.
    const parsed = certificates.filter(c => c.summary);
    const width = Math.max(2, String(certificates.length - 1).length);
    const archiveName = (certificate, extension) => {
      const number = String(certificate.index).padStart(width, '0');
      return `${number}-${nameStem(certificate)}.${extension}`;
    };
    try {
      if (format === 'pem') {
        hooks.download('all-certificates.pem', new Blob(parsed.map(c => c.pem), { type: PEM_TYPE }));
      } else if (format === 'pem-zip') {
        const encoder = new TextEncoder();
        const files = parsed.map(c => ({ name: archiveName(c, 'pem'), bytes: encoder.encode(c.pem) }));
        hooks.download('all-certificates.pem.zip', zipArchive(files));
      } else if (format === 'der-zip') {
        const files = parsed.map(c => ({ name: archiveName(c, 'der'), bytes: derBytes(c.pem) }));
        hooks.download('all-certificates.der.zip', zipArchive(files));
      } else if (format === 'json') {
        const json = JSON.stringify(jsonReport(), null, 2);
        hooks.download('all-certificates.json', new Blob([json], { type: 'application/json' }));
      }
    } catch (error) {
      hooks.error(`Certificate export failed: ${error.message || error}`);
    }
  }

  $('all-certificates').addEventListener('click', event => {
    const button = event.target.closest('button');
    const item = event.target.closest('[data-certificate]');
    if (button?.dataset.certificateAction) act(button.dataset.certificateAction);
    else if (button?.dataset.certificateSelect) select(Number(button.dataset.certificateSelect));
    else if (button?.dataset.allCertificatesExport) exportAll(button.dataset.allCertificatesExport);
    else if (button?.dataset.occurrenceAction) {
      openOccurrence(Number(button.dataset.occurrence), button.dataset.occurrenceAction);
    }
    else if (item) {
      select(Number(item.dataset.certificate));
      $('all-certificates-tree').focus();
    }
  });
  $('all-certificates-tree').addEventListener('keydown', event => {
    const nodes = $('all-certificates-tree').querySelectorAll('[data-certificate]');
    const items = [...nodes].map(node => Number(node.dataset.certificate));
    if (!items.length) return;
    const position = items.indexOf(selectedCertificate()?.index);
    const moves = { ArrowDown: 1, ArrowUp: -1, Home: -Infinity, End: Infinity };
    if (!(event.key in moves)) return;
    const step = moves[event.key];
    const last = items.length - 1;
    const next = Number.isFinite(step) ? Math.max(0, Math.min(last, position + step)) : step < 0 ? 0 : last;
    select(items[next]);
    event.preventDefault();
    event.stopPropagation();
  });
  $('all-certificates-filter').addEventListener('input', event => {
    filter = event.target.value;
    renderTree();
  });

  return {
    /** Show or hide the view; while shown, every open file is scanned. */
    sync(nextActive) {
      active = nextActive;
      if (!active) {
        clearTimeout(rebuildTimer);
        rebuildTimer = 0;
        return;
      }
      for (const entry of hooks.entries()) store.scan(entry);
      // Regions and names may have changed while hidden.
      renderedKey = null;
      rebuild();
    },
    /** Redraw when file `id`, which may hold certificates, gains the regions shown as `within`. */
    refresh(id) {
      if (!active || !store.get(id)?.report?.certificates.length) return;
      renderedKey = null;
      scheduleRebuild();
    },
  };
}
