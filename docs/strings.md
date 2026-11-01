# String extraction

`zrax::strings` lists printable runs in arbitrary bytes, in the manner of GNU
`strings`, extended to UTF-8 and UTF-16. Like certificate scanning it is
byte inspection: it does not feed the code model, does not change
classification and also runs on opaque members.

## Runs

All offsets and sizes are bytes in the scanned buffer; `chars` counts
characters (Unicode scalars).

| Encoding | ID | A run consists of |
| --- | --- | --- |
| ASCII | `ascii` | Bytes `0x20`-`0x7E` and tab (`0x09`) |
| UTF-8 | `utf8` | ASCII as above plus well-formed UTF-8 sequences of non-control scalars; at least one multibyte scalar |
| UTF-16LE | `utf16le` | Little-endian code units `0x0009`, `0x0020`-`0x007E`, `0x00A0`-`0x00FF` |
| UTF-16BE | `utf16be` | The same code units, big-endian |

- A run is reported when it has at least `min_chars` characters (default 4,
  as in GNU `strings`; accepted range 3 to 255).
- With ASCII and UTF-8 both enabled, a run is `utf8` if it contains a
  multibyte scalar and `ascii` otherwise. With UTF-8 disabled, a non-ASCII
  byte ends an ASCII run; with ASCII disabled, pure-ASCII runs are not
  reported.
- UTF-8 well-formedness follows Unicode 15.0, section 3.9, Table 3-7:
  overlong forms, surrogates and lead bytes above `0xF4` end a run, as do
  C0 and C1 controls other than tab. A sequence cut off by the end of the
  input is not part of the run.
- UTF-16 parity is absolute: a unit starts at an even or an odd file offset,
  and both parities are scanned. A UTF-16LE run preceded by `0x00` also
  reads as a UTF-16BE run one byte earlier. Both are reported when both
  encodings are enabled, which is why UTF-16BE is off by default.
- A UTF-16 run can absorb a preceding character: an ASCII byte followed by
  `0x00` at the same parity is a valid UTF-16LE unit, so a C string's last
  character can prefix a wide string that follows it. GNU `strings -el`
  behaves the same way.
- Text keeps the first 4096 characters (`MAX_TEXT_CHARS`); `clipped` marks a
  longer run, whose `size` and `chars` still cover the whole run.

Output is ordered by `(offset, encoding)` with encodings in the table order.

## Tags

Tags are lexical pattern matches on the stored text. They say what the
characters look like, not how the program uses them.

| Tag | Rule |
| --- | --- |
| `url` | `scheme://` followed by a non-whitespace character; the scheme starts with a letter, has at least two characters and consists of letters, digits, `+`, `.` and `-` |
| `email` | A non-empty local part of letters, digits and `._%+-`, then `@`, then at least two dot-separated labels whose last label is two or more letters |
| `ipv4` | A maximal token of digits and dots (one trailing dot allowed) that is exactly four groups of one to three digits, each at most 255. Four-part version numbers match too |
| `path` | `/a/b` at the start of the text or after whitespace or one of `" ' = ( : ,`, with segment characters letters, digits and `._-~+@`; or `X:\a`; or `\\host\` |
| `uuid` | `8-4-4-4-12` hexadecimal groups not adjacent to further hex digits |
| `format` | `%`, optional flags `-+ #0'`, width (`*` or digits), precision (`.` then `*` or digits), length (`hh ll I64 I32 h l j z t L q`) and a conversion from `diouxXeEfFgGaAcspn@`; `%%` is not a conversion |
| `digest` | A maximal hexadecimal run of 32, 40, 64 or 128 digits in one letter case, containing at least one decimal digit and one letter |
| `mangled` | The whole text starts with `_Z` or `__Z` followed by a digit or uppercase letter (Itanium), or starts with `?` and contains `@@` (MSVC) |
| `pem` | `-----BEGIN ` followed by an uppercase label and `-----` |

## Streaming and bounds

`Scanner::push(chunk, out)` consumes consecutive chunks of any size and
appends each string once no open run can start before it: closed runs are
held until the minimum start offset of the open runs passes them.
`finish` closes every run. The result does not depend on chunk boundaries;
the tests compare every two-chunk split of a mixed sample and pseudo-random
chunk sizes over 1 MiB of noise against one-pass extraction.

Per open run the scanner keeps at most 4096 characters of text, and there
are at most five open runs (one byte run, four UTF-16 runners). Closed runs
wait in a buffer until the watermark passes them; a consumer bounds the
total by count. `extract(data, options, limit)` keeps the first `limit`
strings and sets `truncated` when there were more. Time is linear in the
input; each string is tagged once, linearly in its stored text.

## Workbench

The **strings** tab (key `5`) runs in a separate scan worker
(`web/scan-worker.js`), so the analysis worker stays free for hex and map
requests:

```text
File --4 MiB slices--> StringScan (WASM) --rows--> StringIndex (worker)
                                                      |
       strings tab <--one query result, then pages of 256 rows--+
```

- The worker reads the file through `File.slice`, so it keeps no resident
  copy; rows appear while the scan runs. The index is columnar (offsets,
  sizes, lengths, packed flags, text) and holds at most 1,000,000 strings or
  128 Mi characters of text; past either limit the scan stops and the
  status line says so. Indexes for the three most recently viewed files are
  kept.
- A query filters by search text (substring, case-insensitive unless
  **Aa** is on, or a JavaScript regular expression with **.***), minimum
  length, scope (whole file, hex selection or one region) and the encoding
  and tag chips, then sorts by any column with scan order as the tie-break.
  Chip counts cover the rows that pass the text, length and scope
  conditions, ignoring the chips themselves. Filtering yields every 50,000
  rows, and a newer query supersedes an older one.
- A regular expression with catastrophic backtracking can block the worker
  inside one test, so it sends nothing at all. While a query is pending,
  every worker message re-arms a watchdog; after 4 s of silence the page
  replaces the worker, says so, rebuilds the index and does not replay that
  search until it is edited.
- Lowering the minimum length below the scanned floor, or enabling an
  encoding that was not scanned, starts a new scan; raising the length or
  disabling an encoding only filters.
- The region column is the smallest region (see
  [labelled regions](subfile-inspection.md#labelled-regions)) that contains
  the whole string.
- The grid renders only the visible rows. Lists taller than 8 million CSS
  pixels scroll proportionally, because browsers cap element heights.
- Search text, chips and scope are kept per file in the session; minimum
  length, encodings, sort and the two toggles are stored under
  `isawb.strings.v1`.
- Exports (TXT, CSV, JSON) contain the current view in its current order.

Filtering costs `O(n)` per query plus the cost of the pattern; sorting
costs `O(k log k)` for `k` matches. Region lookup builds elementary
intervals from the `p` region boundaries once per index, `O(p * r)` for `r`
regions, and then costs `O(log p)` per string.

## Command line

`zrax strings FILE...` prints one string per line (`-t o|d|x` adds the
offset), or CSV/JSON with `--format`. `-n` sets the minimum length,
`-e` the encodings and `--tag` keeps only tagged strings. The CLI has no
string limit; it holds the input in memory.

## Assumption register

| ID | Assumption and dependent behavior | Falsification probe |
| --- | --- | --- |
| S1 | UTF-16 text in binaries is mostly Latin-1 | Extract from a binary with CJK resources; those strings are missing by design |
| S2 | Reporting both twins of a zero-led UTF-16 run is better than guessing a byte order | Enable both orders on a Windows PE; twins appear one byte apart |
| S3 | Four characters is a useful default floor | Compare row counts at 4 and 6 on a large firmware image |
| S4 | Chunked and one-pass scans agree | `every_two_chunk_split_gives_the_whole_input_result` and `random_chunk_sizes_give_the_whole_input_result_on_noise` |

## Boundaries

- UTF-16 surrogate pairs and code units above U+00FF, UTF-32, EBCDIC and
  other code pages are not scanned (the hex view can still decode EBCDIC
  and CP437).
- Strings inside compressed or encrypted members are found only after
  opening the decoded member.
- Tags are not validated against the program's use of the string.
