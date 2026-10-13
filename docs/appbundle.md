# Application bundles

`src/formats/appbundle.rs` and its submodules parse three ways of packaging
an application's files for a runtime into the shared container model
([compressed streams and the container model](compressed-streams.md)):
PyInstaller archives (CArchive, also called PKG), Electron ASAR archives
and .NET single-file bundles. None of them names a CPU, so every container
leaves its target open; members are classified from their own bytes.

## Implemented layouts

| JSON format ID | Layout | Members | Primary source |
| --- | --- | --- | --- |
| `pyinstaller` | Entry data from offset 0, a table of contents (TOC), then an 88-byte cookie (`MEI\x0C\x0B\x0A\x0B\x0E`, package length, TOC offset and length, Python version, Python library name) that ends the archive | Binaries (`b`), data files (`x`), zip files (`Z`) and nested archives (`a`) in a recognized format, zlib-decoded when flagged; Python scripts (`s`), the PYZ archive (`z`) and splash resources (`l`) as opaque | PyInstaller [v6.22.3](https://github.com/pyinstaller/pyinstaller/tree/ecd7993d65c43b254f4e3f718e36d5b4a70a3ed5) `bootloader/src/pyi_archive.h`, `bootloader/src/pyi_archive.c`, `PyInstaller/archive/readers.py`, `PyInstaller/archive/writers.py`, `PyInstaller/building/api.py`; [v4.10](https://github.com/pyinstaller/pyinstaller/tree/669313ba4c5c1403ebeb335c35cb68c8c6ba5dd4) and [v3.6](https://github.com/pyinstaller/pyinstaller/tree/6d4cce1f8eb80c0bf49d35876d28daa55a05800f) `PyInstaller/archive/writers.py` |
| `asar` | A Chromium Pickle holding `header_size`, a Pickle holding the JSON directory tree, then the file data | Stored files in a recognized format (native Node modules, executables) | electron/asar [v4.3.1](https://github.com/electron/asar/tree/02c5b08ef8186bf5fd49ed1274ef8cd242ab196f) `README.md` ("Format"), `src/disk.ts`, `src/pickle.ts`, `src/integrity.ts`; Electron [v38.0.0](https://github.com/electron/electron/tree/79433861fe10e4f7841153461fd3778b400a4c0b) `shell/common/asar/archive.cc` |
| `dotnetbundle` | Files appended to an apphost, then a header (version, file count, bundle ID, `deps.json` and `runtimeconfig.json` locations, flags) and one entry per file; the header offset sits in the apphost's 40-byte bundle marker | Assemblies, native binaries, symbol and other files in a recognized format, raw-DEFLATE-decoded when compressed; configuration files are named in notes | dotnet/runtime [v10.0.0](https://github.com/dotnet/runtime/tree/60629d14374c56f1cb51819049ad1fa529307f8d) `src/native/corehost/apphost/bundle_marker.cpp`, `src/native/corehost/bundle/header.{h,cpp}`, `file_entry.{h,cpp}`, `file_type.h`, `reader.cpp`, `manifest.cpp`, `src/installer/managed/Microsoft.NET.HostModel/Bundle/Bundler.cs`, `Manifest.cs`, `FileEntry.cs`, `FileType.cs`, `TargetInfo.cs` |

The design document `docs/design/features/single-file/bundle-format.md`
does not exist at the .NET pin; the source files are the primary source.

### Integration: standalone files and bundles inside executables

An ASAR archive is a file of its own (`app.asar`) and is a strong format.
A PyInstaller archive is a file of its own only in a build directory
(`build/<name>/PKG-00.pkg`) or when side-loaded next to its executable
(`api.py` `EXE.assemble`, `append_pkg` off); `appbundle::detect` recognizes
it only when its cookie ends the input and the cookie's package length is
the input's length. Everywhere else the archive is inside an executable:
appended to a PE, stored in the ELF section `pydata` (`objcopy
--add-section`), or appended to a Mach-O and followed by its re-done code
signature. A .NET bundle always lives in its apphost (ELF, PE or Mach-O).

`detect_format` checks ELF, PE and Mach-O first, so a host executable keeps
its own format, ISA and metadata; nothing here changes how a host is
classified (tests compare hosts with and without an archive appended).
`appbundle::detect_embedded` finds a bundle inside a host: the .NET
marker with a nonzero header offset and a valid header, or the last
PyInstaller cookie whose archive starts after offset 0 and whose TOC ends
at the cookie. `appbundle::parse_container` (or `container::parse` with
`Kind::AppBundle`) then parses it with member offsets in the host file.

`lib.rs` has no mechanism that lists a container inside an executable
(FatELF and fat Mach-O are their own formats; nothing reads PE overlays or
appended data). Listing the members on the host's result needs a hook in
`classify_depth`, after the `parse_detected` result for
`DetectedFormat::Elf`, `Pe` and `MachO` is final and while `depth <
MAX_NESTING`:

```rust
if let Some(layout) = formats::appbundle::detect_embedded(data) {
    let kind = formats::container::Kind::AppBundle(layout);
    match formats::container::parse(data, kind) {
        Ok(bundle) => {
            let outcome = classify_container(&bundle, options, depth)?;
            slices.extend(outcome.slices);
            notes.extend(outcome.notes);
            metadata.extend(outcome.metadata);
        }
        Err(e) => notes.push(Note::warning(format!("{}: {e}", layout.label()))),
    }
}
```

The host's `result` stays as it is. The hook should also limit the host's
extension scan (`code_payload`) to the bytes before the bundle, which hold
the host's code. A universal Mach-O host would need the hook per slice
(see Known boundaries). This change was not made here.

### PyInstaller archive

All integers big-endian (`readers.py` `'!8sIIII64s'` and `'!IIIIBc'`).

| Structure | Field | Size | Meaning |
| --- | --- | --- | --- |
| Cookie | magic | 8 | `4D 45 49 0C 0B 0A 0B 0E` |
| | `pkg_length` | 4 | Archive length, cookie included; archive start = cookie end - `pkg_length` |
| | `toc_offset` | 4 | TOC position from the archive start |
| | `toc_length` | 4 | TOC length; every writer puts the TOC right before the cookie, so `toc_offset + toc_length + 88 = pkg_length` |
| | `python_version` | 4 | `major * 100 + minor` (v4.10, v6.22.3: 312 for 3.12); `major * 10 + minor` in v3.6 (36) |
| | `python_libname` | 64 | NUL-padded Python library name; `readers.py` rejects an empty one |
| TOC entry | `entry_length` | 4 | Whole entry, name included; a multiple of 16 in v3.6 to v6.22.3 |
| | `offset` | 4 | Data position from the archive start |
| | `length` | 4 | Stored length |
| | `uncompressed_length` | 4 | Length after decompression; equal to `length` when stored |
| | `compression_flag` | 1 | 1: zlib (RFC 1950); 0: stored |
| | `typecode` | 1 | `b`, `x`, `Z`, `a`, `z`, `m`, `M`, `s`, `l`, `o`, `d`, `n` (`pyi_archive.h`, `api.py` `PKG.xformdict`) |
| | `name` | rest | UTF-8, NUL-terminated and NUL-padded |

The cookie is found as the bootloader finds it (`pyi_archive.c`
`_pyi_archive_find_pkg_cookie_offset`, a back-to-front scan of the whole
file): the last occurrence of the magic. Option entries (`o`) are listed
in a note, dependency (`d`) and symbolic link (`n`) entries are counted.
Bootstrap modules (`m`, `M`: PyInstaller's own loader modules) are
counted, not listed. Scripts and the PYZ archive (the application's
modules) are opaque children: their marshalled bytecode has no ISA here.
The binary whose name is the cookie's Python library is listed first,
then the other members in TOC order, so the interpreter names the
archive's primary ISA.

### Electron ASAR archive

All integers little-endian (Chromium `Pickle`).

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 4 | Size pickle payload size: 4 |
| 4 | 4 | `header_size`: size of the header pickle |
| 8 | 4 | Header pickle payload size: `header_size - 4` |
| 12 | 4 | JSON string length |
| 16 | length | JSON header, zero-padded to 4 bytes: `header_size = 8 + align4(length)` |
| `8 + header_size` | | File data; each file's `offset` counts from here |

The JSON tree (`disk.ts` `validateHeader`): the root and each directory
are `{"files": {...}}`; a file has `size` (an integer), `offset` (a
decimal string) unless `unpacked` is true (the file is then in
`<archive>.asar.unpacked`), and optional `executable` and `integrity`
(`algorithm` `SHA256`, `hash` of the whole file, `blockSize`, `blocks`); a
link is `{"link": path}`. Names may not contain `/` or `\` or be `.` or
`..`. Members are the stored files in offset order (then path order).

### .NET single-file bundle

All integers little-endian.

| Structure | Field | Size | Since | Meaning |
| --- | --- | --- | --- | --- |
| Marker (in the apphost) | header offset | 8 | | 0 in an apphost that is not a bundle |
| | signature | 32 | | `8B 12 02 B9 ... B3 6A AE`, the SHA-256 of `.net core bundle\n`; the first occurrence in the file is the marker (`Bundler.cs` `IsBundle`) |
| Header | major, minor version | 4 + 4 | 1 | 6.0 (.NET 6 and later), 2.0 (.NET 5), 1.0 (.NET Core 3) per `TargetInfo.cs`; minor is always 0 |
| | file count | 4 | 1 | Signed; must be > 0 |
| | bundle ID | 1-2 + n | 1 | String: a 7-bit-encoded length of at most two bytes, never 0, then UTF-8 |
| | `deps.json` location | 8 + 8 | 2 | Offset and size; 0 when absent |
| | `runtimeconfig.json` location | 8 + 8 | 2 | Offset and size |
| | flags | 8 | 2 | Bit 0: .NET Core 3 compatibility mode |
| Entry | offset | 8 | 1 | File offset (the bundle stream starts with the apphost) |
| | size | 8 | 1 | Decoded size |
| | compressed size | 8 | 6 | 0 when stored; raw DEFLATE otherwise |
| | type | 1 | 1 | 0 unknown, 1 assembly, 2 native binary, 3 `deps.json`, 4 `runtimeconfig.json`, 5 symbols |
| | relative path | 1-2 + n | 1 | String |

The field order of an entry is the code's (`FileEntry.Write`,
`file_entry.cpp` `read`); the comment at the top of `FileEntry.cs` lists
another order and "version 3+" for the compressed size, which the code
contradicts. Members are listed in manifest order.

## Wire units and byte order

All offsets and sizes are bytes. PyInstaller fields are big-endian, ASAR
and .NET fields little-endian; none of them describes the code's byte
order. PyInstaller offsets count from the archive start, ASAR offsets from
the end of the header pickle, .NET offsets from the start of the file.
Member offsets in children, slices and notes are file offsets of the
stored bytes in the input; decoded members carry their codec (`zlib`,
`DEFLATE`) and decoded size.

## Validation and resource bounds

- PyInstaller: the cookie must be 88 bytes inside the input; the package
  length must fit before the cookie's end; the TOC must end at the cookie;
  the library name must be present; each TOC entry must be at least 18
  bytes and inside the TOC; each entry's data must lie before the TOC; a
  stored entry's two lengths must agree. Any failure is a parse error.
- ASAR: the size pickle payload must be 4, the header pickle payload
  `header_size - 4`, and the string length must fill the header pickle with
  at most 3 padding bytes; the header pickle must fit in the input; the
  JSON must parse (serde_json, which stops at 128 levels of nesting; the
  walk also stops at 64 directory levels) and every entry must be a valid
  directory, file, unpacked file or link; every stored file must end inside
  the input (64-bit sums). Any failure is a parse error.
- .NET: the marker's header offset must be positive and the header inside
  the input; the version must be 1.0, 2.0 or 6.0; the file count must be
  positive and fit the bytes after the header (at least 19 bytes per entry,
  27 from version 6) before anything is allocated; each entry needs a
  positive offset, non-negative sizes, a type below 6 and a valid path, and
  its stored bytes must lie between the end of the marker and the header.
  Any failure is a parse error.
- Members: at most `MAX_COMPONENTS` (4096) children; at most `MAX_PAYLOAD`
  (64 MiB) decoded per member and `MAX_EXTRACTED` (256 MiB) per bundle;
  the first 4 KiB of a member (decoded with `compressed::decode_prefix`
  when compressed) must be a recognized format before it is decoded and
  checked whole (a nested PyInstaller archive is checked whole: its cookie
  is at the end). A member that does not decode to its declared size is
  named in a note and skipped. What is left out is counted in notes.
- ASAR integrity hashes are computed over at most 256 MiB of file data.

## Evidence and verification

- PyInstaller: zlib members carry an Adler-32 that the decoder verifies
  for every decoded member; nothing else in the format is checked.
- ASAR: the SHA-256 `hash` of every stored file with `algorithm` `SHA256`
  is verified (up to 256 MiB) and mismatches are listed; block hashes are
  not verified; the header hash that Electron checks
  (`ElectronAsarIntegrity`) is outside the archive and not verified.
- .NET: the bundle ID is checked against the deterministic ID
  (`Manifest.GenerateDeterministicId`: base64url of the SHA-256 over each
  file's SHA-256 in manifest order, first 12 characters), which covers
  every file's contents. A mismatch is reported without a claim of
  corruption, since an ID may have been chosen another way. The
  `deps.json` and `runtimeconfig.json` locations in the version 2 header
  are checked against their manifest entries.
- Python versions, library names, Electron metadata and .NET target
  frameworks are not ISA evidence; no container names a target.

## Assumption register

| Assumption | Falsification probe |
| --- | --- |
| The last occurrence of the PyInstaller magic is the archive's cookie (the bootloader's rule) | An executable whose signature or section headers after the archive contain the 8-byte magic |
| Every PyInstaller writer puts the TOC right before the cookie | A real archive (any version) whose `toc_offset + toc_length + 88` differs from `pkg_length`; the two real macOS executables checked agree |
| Python version codes 20-39 are `major * 10 + minor` and 300-399 `major * 100 + minor` | An archive from PyInstaller 4.0-4.x with a code below 100 |
| Only flags 0 and 1 occur in TOC entries | An entry with another flag; such members are reported as not decoded |
| A standalone CArchive starts with a zlib stream or other bytes no earlier format claims | A PKG whose first entry is stored and starts with an ELF, PE or ZIP magic; it would be reported as that format |
| ASAR writers write `header_size = 8 + align4(length)` and a root object whose first key is `files` | An ASAR from another writer (Rust or Python asar libraries) with extra padding or another first key; it would not be recognized |
| The first .NET bundle signature in the file is the apphost's marker | A bundle whose host is preceded by another file holding the signature with a nonzero offset |
| .NET file offsets count from the start of the input | A universal (fat) Mach-O apphost, whose offsets count from its slice |
| The .NET 1.0 layout is the pinned managed writer's (no version 2 fields, no compressed size) | A bundle written by a .NET Core 3.x SDK (UNCONFIRMED: none was available) |

## Known boundaries

- Members of bundles inside executables are not listed on the host's
  result: that needs the `lib.rs` hook above. `detect_format` never returns
  `dotnetbundle`, and returns `pyinstaller` only for standalone archives.
- PyInstaller 2.0 and older (24-byte cookie without the library name) are
  not implemented. The PYZ archive's `marshal` TOC and bytecode, and the
  side-load signature (`MEI\x0D\x0B\x0A\x0B\x0E`) that marks an executable
  whose PKG is a separate file, are not parsed. Dependencies and links are
  not followed.
- ASAR unpacked files live outside the archive and are not read; links are
  not followed; block hashes are not verified.
- .NET bundles in universal Mach-O apphosts (offsets relative to the slice,
  `reader.h` `offset_in_FAT_universal_binary`) are not supported.
- Python bytecode has no `Isa` variant; scripts and PYZ archives are opaque.

## Verification

On 2026-10-13 (macOS 27.2 AArch64, rustc 1.100.0-nightly), `tests/appbundle.rs`
(23 tests) passed, including every-prefix parse sweeps and single-byte
mutation sweeps of a PyInstaller archive, the ASAR fixture and a .NET
bundle, as did the 10 module unit tests; `cargo test --all-features
--locked` passed 2,448 tests with 6 ignored. After `./build-web.sh`,
`web/tests/appbundle.test.mjs` (4 tests) passed through `/pkg/`, `/dist/`,
`/web/index.html` and `/dist/index.html`, and the whole browser suite
passed 280 tests with 4 skipped (the D10 and RX113 firmware tests, whose
firmware is not in the repository).

With `IDA_INPUT_DIR` set to IDA Pro's test inputs, 44,372 files up to 64 MiB
were checked: none is a bundle by `detect` or `detect_embedded`, and 40 ELF,
PE and Mach-O inputs with a synthetic PyInstaller archive appended kept
their format and ISA while the archive was found. With
`APPBUNDLE_SAMPLE_DIR` set to this Mac's own files (read in place, not
committed), these parsed:

| Sample | Result |
| --- | --- |
| Two PyInstaller 6 executables (Mach-O, Python 3.13, archive followed by a code signature) | 39 and 45 members examined, 3 listed each; host classified as Mach-O |
| A PyInstaller onedir executable (Python 3.12) | 9 scripts and the PYZ archive listed as opaque; host classified as Mach-O |
| A framework-dependent .NET 10 bundle written by `dotnet publish` (SDK 10.0.400, `osx-arm64`) | Version 6.0, 3 files; bundle ID matches the contents |
| A self-contained, compressed .NET 10 bundle (same SDK, `EnableCompressionInSingleFile`) | 175 files, 173 DEFLATE-compressed assemblies decoded and listed; bundle ID matches |
| Five Electron ASAR archives (`app.asar` and `default_app.asar`, 11 to 915 stored files) | Every SHA-256 file hash verified; native modules listed where present |

PyInstaller archives are not generated by a tool here (PyInstaller is not
installed); `.NET` bundles of versions 1.0 and 2.0, Windows and Linux
apphosts, and PyInstaller archives for Windows and Linux are tested only
with synthetic fixtures, not verified against real files.

After integration on the same day, the native suite passed 2,624 tests
with 6 ignored, and IDA's corpus (4,621 files) classified as before.
