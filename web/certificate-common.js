// Pieces shared by the certificates tab (one file) and the all-files
// certificates view: validity by this computer's clock, tree order over
// issuer links, tree rows and the decoded-field facts of the detail pane.
// Signatures and chains are never verified; the shared markup says so.
import { esc } from './format.js';

export const PEM_TYPE = 'application/x-pem-file';

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
export function validity(summary, now = Date.now() / 1000) {
  if (now < summary.not_before_unix) return { state: 'future', label: 'not yet valid' };
  if (now > summary.not_after_unix) return { state: 'expired', label: 'expired' };
  return { state: 'valid', label: 'within validity period' };
}

/** DER bytes from the canonical PEM text of a certificate. */
export function derBytes(pem) {
  const body = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  return Uint8Array.from(atob(body), c => c.charCodeAt(0));
}

export function displayName(certificate) {
  const summary = certificate.summary;
  if (!summary) return 'unparsed PEM block';
  return summary.subject_cn || summary.subject || '(empty subject)';
}

/** Public key algorithm and size for a tree row, e.g. `RSA 4096`. */
export function keyLabel(summary) {
  if (!summary) return '';
  return [summary.public_key_algorithm, summary.public_key_bits].filter(Boolean).join(' ');
}

/**
 * Tree order: each root (no issuer link) followed by the certificates it
 * links to, depth first. Duplicates are folded into their first occurrence;
 * certificates reachable only through an issuer cycle come last at level 1.
 */
export function treeOrder(certificates) {
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

/** Whether the subject, issuer, serial, SHA-256 or error contains `filter` (lowercase). */
export function matchesFilter(certificate, filter) {
  if (!filter) return true;
  const summary = certificate.summary || {};
  return [summary.subject, summary.issuer, summary.serial, certificate.sha256, certificate.error]
    .some(value => value && value.toLowerCase().includes(filter));
}

/** Labels of the regions that contain a certificate occurrence, outermost first. */
export function enclosingRegions(regions, certificate) {
  return (regions || [])
    .filter(r => certificate.offset >= r.offset && certificate.offset + certificate.stored_size <= r.offset + r.size)
    .sort((a, b) => b.size - a.size)
    .map(r => r.label);
}

export function fact(label, value, extra = '') {
  return `<dt>${esc(label)}</dt><dd>${value}${extra}</dd>`;
}

/**
 * One tree row: validity dot and name, then badges and a meta line. `copies`
 * is the number of identical copies, or 0 for none; `copiesTitle` explains it.
 */
export function treeItem({ id, index, level, selected, certificate, copies, copiesTitle, meta, now }) {
  const summary = certificate.summary;
  const status = summary ? validity(summary, now) : { state: 'error', label: 'not parsed' };
  const badges = (certificate.self_issued ? '<span class="badge">self-issued</span>' : '')
    + (summary?.is_ca ? '<span class="badge">ca</span>' : '')
    + (copies ? `<span class="badge" title="${esc(copiesTitle)}">×${copies}</span>` : '');
  return `<div class="certificate-item" role="treeitem" id="${esc(id)}" aria-level="${level}"`
    + ` aria-selected="${selected}" data-certificate="${index}" style="--level: ${level - 1}">`
    + `<span class="validity-dot ${status.state}" title="${esc(status.label)}"></span>`
    + `<span class="certificate-name">${esc(displayName(certificate))}</span>`
    + `<span class="certificate-details"><span class="certificate-badges">${badges}</span>`
    + `<span class="certificate-meta muted">${esc(meta)}</span></span>`
    + '</div>';
}

/** Facts from the subject through the authority key identifier. */
function summaryFacts(certificate, issuerLink) {
  const summary = certificate.summary;
  const status = validity(summary);
  const keyText = [
    summary.public_key_algorithm,
    summary.public_key_bits && `${summary.public_key_bits}-bit`,
    summary.curve && `(${summary.curve})`,
  ].filter(Boolean).join(' ');
  const list = values => (values.length ? esc(values.join(', ')) : '—');
  const constraints = summary.is_ca == null ? '—'
    : `${summary.is_ca ? 'CA' : 'not a CA'}${summary.path_len == null ? '' : `, path length ${summary.path_len}`}`;
  const nameMatch = certificate.issuer_index != null ? ' <small class="muted">name match</small>' : '';
  return fact('subject', esc(summary.subject))
    + fact('issuer', esc(summary.issuer), issuerLink + nameMatch)
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
    + fact('authority key', summary.authority_key_id ? `<code>${esc(summary.authority_key_id)}</code>` : '—');
}

function extensionsPanel(summary) {
  const rows = summary.extensions.map(e => `<tr><td>${esc(e.name)}</td><td><code>${esc(e.oid)}</code></td>`
    + `<td>${e.critical ? 'critical' : ''}</td></tr>`).join('');
  if (!rows) return '';
  return '<section class="panel"><header>[ extensions ]</header><div class="panel-body results-table-scroll">'
    + '<table class="results-table" aria-label="Certificate extensions"><thead><tr><th scope="col">name</th>'
    + `<th scope="col">oid</th><th scope="col">flag</th></tr></thead><tbody>${rows}</tbody></table>`
    + '</div></section>';
}

/**
 * The detail pane of one certificate: heading, decoded fields, the caller's
 * location facts and actions, then `sections` and the extensions.
 * `issuerLink` is markup placed after the issuer name.
 */
export function certificateDetail({ certificate, issuerLink = '', locationFacts, actions, sections = '' }) {
  const summary = certificate.summary;
  if (!summary) {
    return '<header class="certificate-heading"><strong>unparsed PEM block</strong></header>'
      + `<p class="certificate-error">${esc(certificate.error || 'not a certificate')}</p>`
      + `<dl class="certificate-facts">${locationFacts}</dl>${actions}${sections}`;
  }
  const status = validity(summary);
  return `<header class="certificate-heading"><strong>${esc(displayName(certificate))}</strong>`
    + `<span class="badge validity-${status.state}" title="by this computer's clock">${esc(status.label)}</span>`
    + (certificate.self_issued ? '<span class="badge">self-issued</span>' : '')
    + '<span class="muted">signature not verified</span></header>'
    + '<dl class="certificate-facts">'
    + summaryFacts(certificate, issuerLink)
    + locationFacts
    + '</dl>'
    + actions
    + sections
    + extensionsPanel(summary);
}
