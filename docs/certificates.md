# X.509 certificate scanning

`zrax::certificates` finds X.509 certificates anywhere in a byte buffer and
decodes their fields: DER structures embedded in firmware, executables and
signature blobs, and PEM text blocks. It is byte inspection like the hex
view. It does not feed the code model, does not change classification, and
runs on opaque members as well.

## Provenance

The scanner and the algorithm, curve and key-size tables are ported from
the MIT-licensed [cert-dump](https://github.com/19h/cert-dump) 3.0.1,
commit `0c4baea` (same author), files `src/scanner.rs` and
`src/parser.rs`. Like cert-dump, the port uses `x509-parser` 0.16 (MIT or
Apache-2.0). The code was rewritten to this repository's rules; the
differences are listed below.

| Source | Used for |
| --- | --- |
| RFC 5280, section 4.1 | `Certificate` and `TBSCertificate` structure; version values |
| RFC 5280, section 3.2 | "Self-issued": equal subject and issuer names |
| RFC 7468, sections 2 and 5 | `CERTIFICATE` encapsulation boundaries, base64 body, 64-character lines |
| X.690, sections 8.1.3 and 10.1 | Definite, minimal DER lengths |

## What is found

All offsets and sizes are bytes in the scanned buffer.

| Encoding | Candidate | Accepted when |
| --- | --- | --- |
| DER | Every `0x30` byte | Minimal definite length of up to 4 octets; size at most 1 MiB; first element a `SEQUENCE` beginning with `A0 03 02 01 0v` (v at most 2) or `INTEGER`; `x509-parser` consumes it exactly |
| PEM | `-----BEGIN CERTIFICATE-----` | A later `-----END CERTIFICATE-----` within 2 MiB; the body is strict base64 once ASCII whitespace is removed; decoded size at most 1 MiB |

- An `END` marker closes the nearest preceding `BEGIN` marker; earlier
  unterminated `BEGIN` markers are ignored.
- A PEM block whose base64 decodes but is not a certificate is still
  reported, with `error` and no `summary`.
- DER tags inside certificates already found are candidates as well, so a
  certificate embedded in another one is reported too, and results do not
  depend on window boundaries.
- `offset` is the start of the DER structure or of the `BEGIN` marker.
  `stored_size` covers the DER structure or the PEM block through its `END`
  marker.

Each certificate carries `der_size`, the SHA-256 of its DER encoding, a
canonical re-encoding as PEM (64-character lines), and a `summary`:
version, serial, subject and issuer names (full DN and first common name),
validity as RFC 3339 UTC and Unix seconds, public key algorithm, size and
curve, signature algorithm, basic constraints, key usage, extended key
usage, subject alternative names, key identifiers, and every extension's
OID, short name and critical flag. An OID missing from the ported tables
is shown in dotted form.

## Links and what they do not establish

- `duplicate_of` is the index of the first certificate with the same DER
  encoding (same SHA-256).
- `self_issued` means the encoded subject and issuer names are equal. The
  signature is not checked, so this is not "self-signed".
- `issuer_index` points at another certificate whose encoded subject equals
  this certificate's encoded issuer. When several match, the one whose
  subject key identifier equals this certificate's authority key identifier
  wins; otherwise the lowest index. Duplicates are never chosen.
- **No signature, chain, revocation or validity check is performed.** The
  report says so in its notes. Validity status relative to the current time
  is left to viewers, because the library never reads the clock; results
  depend only on the bytes. (`x509-parser`'s `Validity::is_valid` would also
  panic on `wasm32-unknown-unknown`.)

## Certificate files

A file that holds only certificates is classified as format `x509`
("X.509 Certificate"), an opaque container with an unknown ISA.

| Layout | Detection | Accepted when |
| --- | --- | --- |
| DER | Weak, after the other magic-less checks and before `ti::detect_weak` | The scanner's DER rules accept a certificate at offset 0 and only `0x00`/`0xFF` bytes follow |
| PEM | Strong, before the text hex formats | The text, after an optional UTF-8 BOM and whitespace, opens with `-----BEGIN CERTIFICATE-----`; then every non-whitespace byte must belong to a `CERTIFICATE` block whose contents parse |

- A damaged PEM file is a format error (`X.509 parse error: ...`), not raw
  text. Other PEM labels, explanatory text and `openssl x509 -text`
  output are rejected.
- Because the boundary is strong evidence, container members whose bytes
  open with it now count as recognized and are listed, even when the block
  is incomplete. Bundles that open with comments, such as certifi's
  `cacert.pem`, stay data files.
- TI X.509 boot images keep their TI format: `ti::detect_strong` runs
  first and requires TI's enterprise extensions and an image after the
  certificate.
- Metadata: `x509_certificate_count`; for one certificate `x509_subject`,
  `x509_issuer`, `x509_not_before`, `x509_not_after`, `x509_public_key`,
  `x509_signature_algorithm` and `x509_sha256`; for bundles
  `x509_certificate_<n>` lines with subject, issuer and SHA-256.
- PEM blocks become opaque members holding their DER bytes, transform
  `base64`, so the subfiles panel can open each certificate.

## Workbench

The **certificates** tab (key `6`) scans the selected file in the scan
worker as soon as it is selected, in 4 MiB windows that overlap by 2 MiB,
and shows the count on the tab. The tab lists certificates as a tree of
issuer links: roots (no link) first, each followed by the certificates that
link to it. Duplicates fold into their first occurrence with a `×N` badge,
and certificates reachable only through an issuer cycle are listed at the
top level. Selecting one shows its fields, its validity relative to this
computer's clock, every extension, the SHA-256 fingerprint and the regions
that contain it, for example
`ARM64 slice > __LINKEDIT > Mach-O code signature`. Actions: show the stored
bytes in hex, download DER or PEM, open the DER as a file (classified as
`x509`), and export the distinct certificates as one PEM file or the report
as JSON. The view says "signature not verified" for each certificate and
"name match" for each issuer link.

## Command line

`zrax certs FILE...` prints each certificate with its location, names,
validity, key, signature algorithm, fingerprint and links. `--format json`
adds `within`, the labels of the enclosing regions. `--dump DIR` writes
`cert_<index>.der` and `.pem`; `--tree` prints the issuer links.

## Bounds

| Bound | Value |
| --- | --- |
| Certificates per scan (`MAX_CERTIFICATES`) | 4096, then `truncated` and a note |
| DER certificate size (`MAX_CERTIFICATE_SIZE`) | 1 MiB |
| PEM block size (`MAX_PEM_BLOCK`) | 2 MiB |
| Window overlap (`WINDOW_OVERLAP`) | 2 MiB |

Each byte is searched a bounded number of times by the PEM finder, so a
flood of `BEGIN` markers takes linear time. DER candidates are rejected by
the length and tag checks before the full parser runs. Allocation is
bounded by the certificate limit times the size limits.

`Scan::push_window(window, base, report_len)` reports certificates that
start in `window[..report_len]`. A window that extends `WINDOW_OVERLAP` bytes
past its reported range contains every such certificate completely, so
consecutive windows produce the same report as `scan` over the whole input.
The browser streams files this way without a resident copy.

## Differences from cert-dump

| Area | cert-dump 3.0.1 | zrax |
| --- | --- | --- |
| PEM without `END` | Retries from `BEGIN + 1`: quadratic on a marker flood | Stops at the first unterminated `BEGIN`; nested `BEGIN` resolves to the innermost |
| DER lengths | Rejects only a leading zero octet; an inner `continue` does not skip bad candidates | Checked, minimal definite lengths of 1 to 4 octets |
| DER acceptance | Any prefix `x509-parser` accepts | Tag pre-filter, then exact consumption |
| Names | First CN, OU, O, L, ST, C and email only | Full DN in RDN order plus first CN |
| Chain links | Formatted DN strings; distinct names can merge | Encoded name bytes, then key identifiers |
| Root label | "ROOT/Self-Signed" | "self-issued"; signatures not checked |
| Validity | `--expired`/`--valid` use the clock | No clock in the library |
| RSA size | Bit length of the modulus | Same, from `x509-parser`'s parsed key |
| ML-DSA and ML-KEM sizes | Public-key byte counts or parameter-set numbers reported as bits | No bit size; the algorithm name carries the parameter set |
| Unknown OIDs | `unknown` | Dotted OID |
| Tree output | `truncate_dn` slices bytes and panics on non-ASCII names | Not ported; the CLI tree prints whole names |

## Assumption register

| ID | Assumption and dependent behavior | Falsification probe |
| --- | --- | --- |
| C1 | Real certificates use minimal DER lengths | Re-encode a fixture with a non-minimal outer length; it is not found, while `openssl x509 -inform DER` may still accept it |
| C2 | A certificate is at most 1 MiB | Build a certificate with a 1.5 MiB extension; it is skipped |
| C3 | Equal encoded names identify an issuer candidate | Two CAs with the same name and different keys: the AKI/SKI rule must pick the right one when present; without identifiers the lowest index is chosen and may be wrong |
| C4 | Base64 bodies contain only the alphabet, padding and whitespace | A body with RFC 7468 explanatory headers inside is rejected; cert-dump drops `-----` lines but not headers either |
| C5 | Windows that overlap by 2 MiB give whole-input results | `windowed_scans_equal_the_whole_input_scan` compares window sizes from 1 B to the whole input |

## Boundaries

- PKCS #7/CMS structures are not parsed; their certificates are found by
  the DER scan. `-----BEGIN PKCS7-----` blocks are base64 and are not
  decoded.
- BER (indefinite or non-minimal lengths) and UTF-16 text are not scanned.
- Certificates inside compressed or encrypted members are found only after
  opening the decoded member as its own file.
- `TRUSTED CERTIFICATE` and `X509 CERTIFICATE` PEM labels are not matched.
