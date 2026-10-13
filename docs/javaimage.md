# Java runtime images

`src/formats/javaimage.rs` and its submodules (`jimage.rs`, `resource.rs`,
`jmod.rs`) parse jimage files (the `lib/modules` file of a JDK or of a
jlink runtime image) and JMOD files into the shared container model
([compressed streams and the container model](compressed-streams.md)).
Neither format names a processor: the container result has an unknown ISA
with confidence 0, and the ISA comes from the members. Class files start
with `0xCAFEBABE`, and the Java class parser reports them as JVM bytecode;
other resources in a recognized format (an ELF file, for example) are
classified from their own bytes.

Primary sources, all OpenJDK tag
[`jdk-21+35`](https://github.com/openjdk/jdk/tree/jdk-21%2B35) (JDK 21 GA):

- jimage layout: `src/java.base/share/native/libjimage/imageFile.hpp`
  (header, index, perfect hash, location attributes, strings) and
  `imageFile.cpp` (`ImageFileReader::open`, `ImageStrings::find`,
  `ImageLocation::set_data`, `get_resource`), and the Java reader in
  `src/java.base/share/classes/jdk/internal/jimage/` (`ImageHeader.java`,
  `ImageLocation.java`, `BasicImageReader.java`, `ImageStringsReader.java`).
- Compressed resources: `imageDecompressor.hpp`/`.cpp` (native) and
  `jdk/internal/jimage/decompressor/` (`Decompressor.java`,
  `CompressedResourceHeader.java`, `ZipDecompressor.java`,
  `StringSharingDecompressor.java`, `CompressIndexes.java`,
  `ResourceDecompressorRepository.java`); `ZIP_InflateFully` in
  `src/java.base/share/native/libzip/zip_util.c`.
- The writer, for what readers leave open:
  `src/jdk.jlink/share/classes/jdk/tools/jlink/internal/`
  (`BasicImageWriter.java`, `ImageLocationWriter.java`,
  `ImageStringsWriter.java`, `PerfectHashBuilder.java`,
  `ImageFileCreator.java`, `ImageResourcesTree.java`,
  `ResourcePoolManager.java`, `plugins/ZipPlugin.java`,
  `plugins/StringSharingPlugin.java`, `plugins/DefaultCompressPlugin.java`).
- JMOD: `src/java.base/share/classes/jdk/internal/jmod/JmodFile.java` and
  `src/jdk.jlink/share/classes/jdk/tools/jmod/JmodOutputStream.java`.

## Implemented layouts

| JSON format ID | Layout | Recognition | Components | Primary source |
| --- | --- | --- | --- | --- |
| `jimage` | 28-byte header (magic, version `major << 16 \| minor`, flags, resource count, table length, locations size, strings size), redirect and offsets tables, location attribute streams, strings, resources; both byte orders | Strong: magic `0xCAFEDADA` in either byte order (`DA DA FE CA` little-endian, `CA FE DA DA` big-endian) and major version 1; checked right before the magic-bearing compressed streams | Resources in a recognized format, labelled with their full name (`/java.base/java/lang/Object.class`), in file order | `imageFile.hpp`, `ImageHeader.java`, `BasicImageReader.java` |
| `jimage` (stored resources) | `COMPRESSED` attribute 0: the `UNCOMPRESSED` bytes at index size + `OFFSET` | — | Borrowed at their stored offset | `ImageFileReader::get_resource` |
| `jimage` (`zip`) | 29-byte layer header, then a zlib stream (RFC 1950) that must decode to the header's size, Adler-32 verified | — | Decoded; transform `jimage zip`; stored offset is the layer header | `ZipDecompressor.java`, `ZIP_InflateFully`, `ZipPlugin.java` |
| `jimage` (`compact-cp`) | 29-byte layer header, then a class file whose UTF-8 constants were moved to the string table (`--compress=1`): externalized strings (tag 23) and descriptors (tag 25, object types rebuilt from package and class strings) restored, other entries copied | — | Decoded; transform `jimage compact-cp` (`jimage zip and compact-cp` for both layers) | `StringSharingDecompressor.java`, `SharedStringDecompressor`, `CompressIndexes.java` |
| `jimage` (directory entries) | `/modules`, `/packages` and the paths below them, and the root directory listing jlink writes after the last resource | — | Index data: counted, never examined | `ImageResourcesTree.java` |
| `jmod` | `JM`, version byte pair, then a ZIP archive to the end of the file | Strong: `JM 01 00` followed by a ZIP local file header at 0x4 | One child, the ZIP archive at 0x4, which the ZIP parser lists | `JmodFile.java`, `JmodOutputStream.java` |

The JSON `format.variant_name` is `jimage (little-endian)`,
`jimage (big-endian)` or `JMOD`. jimage notes give the version, byte order,
resource count, table length and where the resources start; the
perfect-hash result; the directory entries and the root listing; the
modules (first eight names); how many resources are compressed and how many
were decoded with each decompressor; how many were listed; and every limit
reached or resource not decoded. jimage metadata: `jimage_version`,
`jimage_resource_count` (header), `jimage_table_length`,
`jimage_index_size`, `jimage_resources` (locations other than directory
entries), `jimage_directory_entries`, `jimage_compressed_resources`,
`jimage_modules`, and the generated `jimage_image_size` and
`jimage_component_<n>`. JMOD metadata: `jmod_version`,
`jmod_archive_offset`.

## Wire units and byte order

All sizes and offsets are bytes. A jimage is written in the byte order of
the platform jlink targets (`--endian`): the header, both tables, the u32
words of the directory entries and every compressed-resource layer header
use it. Location attribute values are always most significant byte first,
and class files are big-endian as always. The index byte order does not
name an ISA and is reported only as the layout. Resource offsets
(`ATTRIBUTE_OFFSET`) count from the end of the index; child and slice
offsets are file offsets. The regions are not aligned: the writer's
`ImageStream.align(2)` pads `(size - 1) & 3` bytes, which is not an
alignment.

A full name is `/module/` (when the module string offset is nonzero),
`parent/` (when the parent offset is nonzero), the base, and `.extension`
(when the extension offset is nonzero), as `ImageLocation.getFullName`
builds it. The perfect hash is `h = seed; h = h * 0x01000193 ^ byte` over
the name's bytes, masked to 31 bits; the redirect entry for
`hash(name, 0x01000193) % table_length` is 0 (absent), `-1 - slot`, or a
seed that rehashes the name to its slot. Strings are modified UTF-8 and the
hash covers the stored bytes, which is what `ImageStringsReader` hashes.

A JMOD's ZIP offsets count from file offset 4: `JmodOutputStream` writes
the 4-byte header to the underlying stream after creating its
`ZipOutputStream`, so the archive from 0x4 is self-consistent.

## Validation and resource bounds

- Header: magic in the layout's byte order, version exactly 1.0 (both
  readers' rule; another minor version is an `Unsupported jimage version`
  error, another major version is not recognized). The index (28 B + 8 B per
  slot + locations + strings, computed in 64 bits) must fit in the file.
- Every nonzero slot: its location offset lies in the attribute region;
  attribute kinds are 0-7 and each appears at most once (the writer emits
  each once, so a stream is at most 64 B); value bytes lie in the region;
  string offsets lie in the string region and end with NUL within 4096 B
  (`IMAGE_MAX_PATH`); the full name is at most 4096 B; the redirect table
  leads back to the slot; the stored range lies in the file. Any failure is
  a parse error.
- Names built during the walk are capped at 64 MiB in total (our limit; the
  28,738 resource names of the JDK 21 image take 1.7 MiB).
- After the last stored range only the root directory listing (the
  location offsets of `/modules` and `/packages`) and padding (`0x00`/`0xFF`)
  may follow.
- A header resource count that differs from the number of locations is
  noted, not rejected; nonzero header flags are noted (none is defined).
- Compressed resources: at most 4 layers; each layer's payload must be the
  rest of the content (as `ResourcePoolManager.newCompressedResource`
  writes it; the two readers disagree about any other size); each layer's
  output is at most 64 MiB and charged to the 256 MiB per-image extraction
  budget before it is decoded; the result must have the location's
  `UNCOMPRESSED` size. A resource that fails any of this is counted in a
  note, not an error; one that names another decompressor is counted and
  its name listed.
- `compact-cp`: every read is bounds-checked; output may not grow past the
  layer's declared size; compressed integers with a zero length field and
  descriptors without type indexes (never written by jlink, and the readers
  disagree about them) are invalid; tags above 20 are invalid.
- Listing: resources are examined in file order, and only those whose
  first 4 KiB and then whole contents are a recognized format are listed,
  at most 4096 (`MAX_COMPONENTS`); the rest are counted in a note.
- JMOD: `JmodFile.checkMagic`'s rule (major above 1, or 1 with a minor above
  0, is unsupported); a ZIP local file header must follow at 0x4. Damage in
  the archive surfaces when the ZIP child is classified (the JMOD then has
  an unknown ISA and a note).

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| J1 | The index byte order describes the target platform, not the code | `sample-be.jimage` and a `jlink --endian big` image list the same JVM class files as the little-endian images |
| J2 | Every location of a valid image is found through the redirect table (the writer builds the table from every location) | The OpenJDK 17, 21 and 26, Oracle JDK 25 and GraalVM 25 `lib/modules` files on 2026-10-13: every location verified; `header_and_index_damage_is_reported` |
| J3 | A location's attribute stream holds each kind at most once (`ImageLocation.compress`) | The same real images parse; a stream with a repeated kind is rejected |
| J4 | The bytes after the last resource are the root directory listing jlink writes (`ImageResourcesTree.computeContent` writes the root node's entries, which no location names) | Every real image above ends with the 8 B listing; `every_truncation_of_an_image_is_an_error` |
| J5 | A layer's payload is the rest of the resource (`newCompressedResource`) | `--compress=zip-6` and `--compress=1` images of `java.base` decode |
| J6 | `compact-cp` output equals what the JDK readers return | `java.base` images built with `--compress=1` and with `--compress=zip-6`: the 4096 listed classes match the uncompressed image byte for byte; the fixtures' SHA-256 match `DumpImage.java` |
| J7 | The `/modules` and `/packages` entries are index data (`ImageResourcesTree`: u32 tables of location offsets and module-name string offsets) | Their content is never classified; their count is in a note |
| J8 | A JMOD's ZIP archive is self-consistent from offset 4 (`JmodOutputStream`) | `sample.jmod` and the JDK 21 `java.base.jmod` (19,773,228 B) parse as ZIP from 0x4 |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Images with more than 4096 recognized resources (every JDK image) | The first 4096 in file order are listed (in the JDK images examined, every `module-info.class` comes first, then the modules' resources in module name order); the rest are counted |
| Header flags | Reported when nonzero; no flag is defined |
| The layer header's last-layer byte | Not checked; neither reader reads it |
| Decompressor configuration strings | Not read; neither registered decompressor uses one |
| Decompressors other than `zip` and `compact-cp` | Not decoded; counted and named in a note |
| `compact-cp` tag 17 (`CONSTANT_Dynamic`) | Copied without data, as both readers' size tables say; not verified against a class with such entries |
| `compact-cp` tags 19 and 20 (`CONSTANT_Module`, `CONSTANT_Package`) | Two bytes each, from the Java reader's table (the native table stops at 18) |
| JMOD members | Listed by the ZIP parser in the ZIP child's own classification; the JMOD result shows the archive as one slice |
| CDS archives (`classes.jsa`), `jrt-fs.jar`, `ct.sym` | Other formats; not covered here (`jrt-fs.jar` is a ZIP) |
| jimage versions other than 1.0 | Major 1 with another minor: `Unsupported jimage version` error; other majors: not recognized |

## Verification

On 2026-10-13 (macOS AArch64, rustc 1.100.0-nightly `f248f4038`):
`tests/javaimage.rs` (19 tests) and the 15 unit tests in
`src/formats/javaimage.rs` and `src/formats/javaimage/` passed. Two of the
integration tests read external images from `JIMAGE_REFERENCE`,
`JIMAGE_COMPRESSED_REFERENCE` and `JIMAGE_PLAIN_REFERENCE` and skip
without them; they were run with the Homebrew OpenJDK 21.0.12.1
`lib/modules` (140,709,251 B, 31,024 locations, 28,738 resources in 69
modules, the counts `jimage list` reports) and with `jlink --add-modules
java.base` images built by that JDK with `--compress=zip-6`,
`--compress=1`, `--endian big` and no compression. The committed fixtures
(`tests/fixtures/javaimage/README.md`) were written by the JDK 21 jimage
writer and `jmod` from a synthetic module and cover both byte orders,
`zip` and `compact-cp`; the tests compare decoded resources with the stored
ones and with the SHA-256 the JDK reader produced, build synthetic images
from the documented layout (perfect hash with seeds, stacked layers,
failing streams, 4099 resources), damage header and index fields, parse
every prefix of every fixture, and mutate every byte of every fixture
(`0x00`, `0xFF`, each bit flip) through the parser, and every index byte
through the whole classifier. The OpenJDK 17.0.20.1 and 26.0.2.1, Oracle
JDK 25.0.1 and GraalVM 25.0.4 `lib/modules` files and the JDK 21
`java.base.jmod` were also classified once outside the tests (every index
verified; JMOD primary ISA JVM). `web/tests/javaimage.test.mjs` (4 tests)
passed through `/pkg/` and `/dist/` and in both workbench pages.

After integration with the partition table, FAT, ISO 9660 and console disc
families on the same day, `cargo test --all-features --locked` passed 1,710
tests with 6 ignored; the Oracle JDK 25 and GraalVM 25 `lib/modules` files
passed `reference_image_parses_with_a_verified_index`; and IDA's test
corpus (4,621 files, none a jimage or JMOD) classified as before.

Not verified: images written by jlink before JDK 21 or for other platforms
than macOS AArch64 (except the `--endian big` image), `compact-cp` classes
with `CONSTANT_Dynamic` entries, decoded resources beyond the first 4096
listed per image, and JMOD files with `bin/`, `conf/`, `include/`,
`legal/` or `man/` sections other than through the ZIP parser.
