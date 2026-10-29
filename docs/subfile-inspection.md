# Subfile inspection

The workbench opens container children and load sections as independent files.
Classification, entropy, hex, selections, downloads and JSON use that file's
own bytes. The immediate parent remains in the queue and in the breadcrumb.
This applies to IMG4/IM4P, FTAB, UARP, ZIP/tar/CPIO, ar and the other formats
represented by the shared container model.

```text
firmware.uarp
  +-- FTAB
  |     +-- krnl.im4p
  |           +-- krnl (decoded bytes, offset 0 in its own workbench)
  +-- TMAP (opaque: hex and entropy)
```

## Workflow

1. Load a container and open its **subfiles** panel.
2. Select **open <member>**. The new entry is indented below its parent and
   has its own cursor and map viewport. Reopening that member selects the
   existing entry.
3. Use any workbench tab. A decoded member's hex view shows decoded bytes;
   the parent panel continues to show stored byte coordinates and transform.
4. Select a breadcrumb to return to a container. Removing a container also
   removes its open descendants; unrelated uploaded files remain.

For custom Image4 decryption, enter the plaintext AES key and IV in the
inline panel and open the resulting **decrypted payload**. Custom material
is editable even when the file contains encoded keybags; select an encoded
entry separately to inspect its read-only bytes. Those bytes are not
unwrapped payload keys. Use explicit CBC or CTR for raw code that automatic
structural recognition cannot validate. The result is attached to the original file.
A replacement successful trial removes the previous decrypted result and
its descendants. Invalid or incomplete material reports an inline status
without changing the original file.

## Coordinates and native API

`inspection::subfiles(data)` lists descriptors in deterministic order:
children first, then load sections. Each index identifies the same parser
output for these exact immutable parent bytes. `extract_subfile(data, index)`
reparses the parent through the same validated decoder and returns the chosen
member's actual data, rather than slicing the stored range for a transformed
member.

| Descriptor | Meaning |
| --- | --- |
| `index` | Identity within this parent's enumeration; names need not be unique |
| `label` | Untrusted role or member path, escaped before HTML interpolation |
| `offset` | Stored byte offset in the immediate parent |
| `stored_size` | Stored bytes in the immediate parent |
| `size` | Member bytes after the parser's transform |
| `transform` | Transform already applied, when present |
| `opaque` | Metadata, ciphertext or other content excluded from ISA analysis |
| `available` | Whether opening fits the 64 MiB per-member limit |

The new file starts at byte offset zero. A descendant's offsets are relative
to its immediate parent, never accumulated across compression or encryption.
Opening opaque content constructs an opaque workbench engine: byte inspection
remains available, while architecture classification reports that ISA analysis
was not applied. No ciphertext or metadata enters the code model by reopening
an opaque member.

The worker protocol carries member indices and transferable byte buffers.
Request IDs and file membership are checked before publishing results. A
selection change or removal cancels pending interactive requests; stale
decryption results do not replace the current material's result. Key and IV
are never echoed in worker responses or log messages.

## Archives

Classification retains its existing recognized-member policy. The separate
inspection enumeration includes ordinary data files in ZIP, tar and CPIO,
subject to the same checksum, decoder and extraction bounds. Encrypted ZIP
members are available as opaque stored bytes; ZIP decryption is not implemented.
Unsupported compression methods can still be omitted with the parser's notes.
The ar inspector lists ordinary members after the ar parser resolves names.

No generic extraction is inferred from arbitrary classification slices:
legacy format paths outside the shared container model and ar are not yet
enumerated. A dyld image child contains the validated header/load-command
range supplied by that parser, not a reconstructed standalone dylib.

## Bounds and assumptions

Inspection lists at most 4096 entries, returns at most 64 MiB for one opened
member, and permits six levels of interactive child navigation. Parent
parsers retain their own aggregate extraction and nesting limits. Members
are decoded again when opened rather than caching every child's bytes in
resident WASM memory. Listing and extraction cost the parent parser's work;
returning a chosen member adds `O(size)` copying, bounded to 64 MiB. The
browser retains explicitly opened files until removal or clearing.

| ID | Assumption and dependent result | Falsification probe |
| --- | --- | --- |
| S1 | Parent bytes are immutable while an index is used | Extract the same index repeatedly and compare exact bytes |
| S2 | A transformed member cannot be reconstructed by its stored slice alone | Compare LZFSE IM4P extraction against the original Mach-O fixture |
| S3 | Opaque classification policy survives opening | Open an encrypted ZIP member; it must support hex without an ISA result |
| S4 | Labels are not unique identities | Open duplicate-name members by index and retain separate entries |
| S5 | Ancestors own their open descendants | Remove a root and check that descendants disappear while another root remains |
| S6 | Interactive results depend on current request identity | Change material or remove a file while a decryption request is pending; stale results must not create a current result |

| Impact | Adjacent pattern or boundary |
| --- | --- |
| High | Treating stored offsets as decoded coordinates would show the wrong bytes; extraction returns parser-owned transformed data |
| High | Opaque policy is explicit engine state, so manual opening cannot accidentally classify ciphertext |
| Medium | Duplicate tags and paths need index-based identity rather than name-based lookup |
| Medium | Each explicit open retains a browser file; removing a container releases its descendants' application references |

## Validation

Native tests compare exact extracted bytes, stored coordinates, invalid
indices, ordinary archive data and opaque encrypted ZIP content. Browser
tests exercise source and packaged WASM/pages, nested FTAB/IM4P navigation,
the full workbench, inline decryption, read-only keybags and removal.

The archive classification path was compared against base commit `d23b145`
on 2026-10-29: 129,101 inputs over 17 committed fixtures (each full file,
every truncation and each single-byte `0x00`, `0xFF` or bit-flip mutation).
Hashes covered parser `Debug`, exact errors and detection payload JSON;
all matched. The temporary snapshot test was removed after comparison.
This proves equivalence for those inputs, not for every possible archive.
