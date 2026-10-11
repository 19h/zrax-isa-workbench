# AOR AR-DV10 D10 support

The native classifier and browser WASM recognize D10 firmware, validate its
records and CRC, decode CPU XOR encoding when indicated, and classify CPU and
nonempty DSP code records independently. The workbench displays component
labels and retains file coordinates for the original bytes in entropy/hex views.
JSON exports retain the component slices. FPGA records, empty DSP slots and
companion records remain visible in metadata.

## Format and algorithms

All lengths and offsets below are in bytes (B); 1 B = 8 bits. Record address and
length fields are unsigned 32-bit big-endian integers. The checksum trailer is
an unsigned 16-bit little-endian integer.

| Field | Length | Meaning |
| --- | ---: | --- |
| Revision/build header | 16 B | Observed pattern: four decimal digits, uppercase release letter, five spaces, six decimal build digits |
| Record component ID | 1 B | 0 FPGA; 1-4 DSP; 5 CPU |
| Record block ID | 1 B | 0 or 1 |
| Record flash address | 4 B | Destination address supplied by the container |
| Record payload length | 4 B | Stored payload length |
| Record payload | Declared length | Bytes belonging to this record |
| Final CRC16 | 2 B | CRC over every preceding byte, including headers and encoded payloads |

The parser accepts record reordering and zero-length records. Both CPU records
must exist. Duplicate/out-of-range IDs, truncated fields or payloads, flash
ranges beyond the 32-bit address space, missing CPU records, short vectors and
CRC mismatches produce errors. Invalid recognized D10 containers do not fall
back to classifying their combined bytes as raw machine code.

CRC recurrence, with dimensionless unsigned integers:

```text
crc = 0xffff
for each byte b:
    crc = table[(crc XOR b) AND 0xff] XOR (crc >> 8)
result = crc XOR 0xffff
```

The table is independently generated using reflected polynomial 0x8408.
`123456789` produces 0x906e, matching the supplied reference implementation.
Checksum calculation is O(N) time and O(1) auxiliary space for N file bytes.
Record validation uses at most twelve borrowed payloads and a fixed ID bitmap.

Encoding is selected solely by CPU block 5:1 byte 0x7f equalling zero. The
128-byte XOR key is generated as follows; additions are modulo 256:

```text
state = 0
for i = 0..127:
    state = (state + ASCII("AOR!")[i mod 4] + i) mod 256
    key[i] = state
CPU code[i] = stored code[i] XOR key[i mod 128]
CPU vectors[128+i] = stored vectors[128+i] XOR key[i], i = 0..127
```

The vector prefix and bytes after offset 255 remain unchanged. Encoded vector
records must contain at least 256 B; plaintext vector records require 128 B.
Decoding costs O(C + V) time/space for C CPU code bytes and V vector bytes when
requested. Plaintext payloads are borrowed without a code/vector copy. ISA
model scanning retains the configured byte budget for each component;
extensions are detected on that component's decoded code. Candidates describe
the CPU decision. Each nonempty DSP block 0 receives its own contained slice.
Inconclusive records retain an unknown ISA rather than receiving an assumed RX
or Blackfin label. Slice offsets/sizes always refer to stored file bytes.

## Requested fixture

`/Users/int/Downloads/2504B.D10` contains these twelve records:

| Component/block | Payload offset | Flash address | Payload size (B) | Code classification |
| --- | ---: | ---: | ---: | --- |
| FPGA 0:0 | 0x1A | 0x00200000 | 239247 | FPGA data |
| FPGA 0:1 | 0x3A6B3 | 0x0027FFEA | 22 | Companion data |
| DSP 1:0 | 0x3A6D3 | 0x00100000 | 126096 | Blackfin, 32-bit, little-endian |
| DSP 1:1 | 0x5936D | 0x0013FFEA | 22 | Companion data |
| DSP 2:0 | 0x5938D | 0x00140000 | 126736 | Blackfin, 32-bit, little-endian |
| DSP 2:1 | 0x782A7 | 0x0017FFEA | 22 | Companion data |
| DSP 3:0 | 0x782C7 | 0x00180000 | 0 | Empty |
| DSP 3:1 | 0x782D1 | 0x001BFFEA | 0 | Empty |
| DSP 4:0 | 0x782DB | 0x001C0000 | 0 | Empty |
| DSP 4:1 | 0x782E5 | 0x001FFFEA | 0 | Empty |
| CPU 5:0 | 0x782EF | 0x00380100 | 487936 | Renesas RX, 32-bit, little-endian |
| CPU 5:1 | 0xEF4F9 | 0x003FFF80 | 128 | CPU vectors |

Size check: 16 B + 12 * 10 B + 980209 B + 2 B = 980347 B. Trailer CRC is
0x91bd. The stored CPU is plaintext. The RX/Blackfin conclusions are code-model
results, independently consistent with the colleague's component attribution;
the D10 headers themselves do not declare an ISA or a processor model number.

## Assumption register and falsification probes

| ID | Assumption / dependent behavior | Stress test or falsification probe |
| --- | --- | --- |
| A1 | Automatic detection uses the observed revision/build pattern and an initial valid component/block ID. Recognition of other D10 header conventions is unknown. | Verified on 2504B and official 2205A; reject revision-like ordinary text. A file with a different header convention falsifies coverage beyond these revisions. |
| A2 | Component 5 blocks 0/1 mean CPU code/vectors; sections 1-4 block 0 contain DSP images. Component mapping depends on the supplied extractor and colleague's description. | CPU and DSP classifier inputs are separated; a synthetic DSP with x86-64 code is labelled x86-64 rather than forced Blackfin. Real 2504B independently produces RX plus two Blackfin results. |
| A3 | Byte 0x7f and the supplied key/vector rule select CPU decoding. No date-based encoding assumption is made. | Plaintext 2205A/2504B, independently keyed synthetic records, and a controlled encoded 2504B variant match the Python extractor. A real vendor-encrypted release has not been tested. |
| A4 | DSP/FPGA block 1 companion data is metadata, and the CPU vector record is excluded from code classification. | Preserve all record bytes, offsets and addresses; inspect a future release for executable companion records before extending this routing. |
| A5 | The existing model can classify extracted code but does not identify a physical CPU part number. | Compare raw extracted CPU/DSP decisions with container decisions; retain unknown ISA for zero/non-code CPU records and expose per-DSP failures. |

## Bounded findings

- High impact: a single aggregate D10 model input mixes FPGA bitstream, DSP
  instructions and CPU instructions, potentially returning the wrong ISA.
  Component-isolated classification resolves that ambiguity.
- High impact: CRC and record validation occur before CPU decoding. Corruption
  and malicious length declarations cannot silently select a raw fallback for
  recognized containers.
- Medium impact: CRC detects inconsistent bytes but provides no authenticity
  guarantee; no signature-verification claim is made.
- Medium impact: encoded CPU classification and stored entropy/hex coordinates
  describe different byte representations. Explicit encoding metadata and
  component offsets preserve that distinction.
- Low impact: repeated Blackfin images are separate labelled slices, while the
  file summary lists each ISA family once.

## Provenance and verification

Primary format/decoding reference: the user-supplied
`/Users/int/Downloads/DV10_firmware_extractor.py`, attributed in its header to
c1, v2.0. SHA-256:
`34be1138cd825ccb137c46302ae91a9a7922afb3efd549d9278fdb7e4064e45c`.
This implementation uses the observed format and independently generated CRC
table, rather than importing the Python program into the browser.

[AOR's official firmware page](https://www.aorusa.com/support/firmware_ar-dv10.html)
identifies D10 as AR-DV10 firmware. The additional 2205A fixture came from the
[official 2205A download](https://www.aor.tokyo/support/firmware_ar-dv10_v2205A.html).
Firmware bytes are external fixtures; repository regression fixtures are
synthetic.

| Fixture | SHA-256 |
| --- | --- |
| Supplied 2504B | d6740dfd8c402d9213104bac6c301fdd8e55d080d16e9742e5ba65fdfd34c8b4 |
| Official 2205A | 7537843e06cd34c39454b23c668c1b4226e95af41d9683ea8fd0e6b4a5b3b526 |
| Controlled encoded 2504B variant | 511c997e637ac3fd0bfeb3463595ce35622602a32f59a4243ce7f40209aa7b82 |

Reproducible checks:

The completed controlled run passed 310 library/kernel tests and 13 synthetic
D10 regressions (five existing library tests remained ignored). The explicit
reference test was run separately on all three listed fixtures: every one of
their twelve decoded records matched the supplied Python parser byte-for-byte.
All 34 browser tests passed, including the real 2504B fixture on the packaged
page. Native human/JSON output and a 1440*1000 px Chromium visual inspection
also confirmed the labelled RX and Blackfin results. Packaged asset revision:
`d103fd96ec636478`.

```sh
cargo test --no-default-features --features wasm --lib --test d10
./build-web.sh
cd web
D10_FIXTURE=/Users/int/Downloads/2504B.D10 npm test
```

For byte-for-byte differential checks, import the supplied Python module, parse
the chosen file with `FirmwareParser`, and write each decoded record to
`D10_REFERENCE_DIR/<component>-<block>.bin`. Then, from the classifier root:

```sh
D10_FIXTURE=/path/to/file.D10 D10_REFERENCE_DIR=/path/to/reference-records \
  cargo test --no-default-features --test d10 \
  supplied_extractor_matches_every_component_byte -- --ignored --nocapture
```

The controlled encoded fixture uses the original component bytes, XOR-encoded
CPU code, and a vector prefix of 127 bytes 0xff followed by the zero marker;
the original 128-byte vectors form the encoded tail. Its vector address is
reduced by 128 B and the outer CRC is recomputed. It is a test transformation,
not a claim about a vendor-distributed encoded release.

QG1: no normative conclusions. QG2: A1-A5 bound assumptions and probes.
QG3: recognition, CRC, all records, decoding, isolated CPU/DSP classification,
CLI JSON/human output and source/packaged workbench paths are covered.
QG4: byte/bit units, field ordering and the fixture size equation are explicit.
QG5: truncation, duplicate/invalid IDs, address bounds, record reordering,
missing/short vectors, non-code CPU data, encoding and disabled extensions are
tested. QG6: supplied source and fixture hashes anchor provenance; extracted
bytes are compared to the reference parser. QG7: findings above are bounded by
impact and the tested revisions.
