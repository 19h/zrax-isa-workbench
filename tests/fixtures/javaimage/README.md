# Java runtime image fixtures

Small jimage files and a JMOD for `tests/javaimage.rs` and
`web/tests/javaimage.test.mjs`, written by the JDK's own tools from a
synthetic module. `generate.sh` rebuilds all five files.

## Contents

The module `zrax.sample` (`src/zrax.sample/`) is synthetic:

| Resource | Contents |
| --- | --- |
| `module-info.class` | compiled from `src/zrax.sample/module-info.java` |
| `zrax/sample/Hello.class` | compiled from `src/zrax.sample/zrax/sample/Hello.java`, a class whose constant pool holds names, descriptors with object types, a string, integer, float, long and double constants, method handles and an invokedynamic call site |
| `zrax/sample/payload.elf` | `tests/fixtures/compressed/payload.elf`: a 256 B ELF64 header for x86-64 with no code |
| `zrax/sample/readme.txt` | 58 B of ASCII text, not a recognized format |

| File | Writer | Layout |
| --- | --- | --- |
| `sample-le.jimage` | `GenerateImages.java`: jdk.jlink `ImageFileCreator.create` with no plugins | little-endian index, every resource stored |
| `sample-be.jimage` | the same, `ByteOrder.BIG_ENDIAN` | big-endian index (jlink `--endian big`), every resource stored |
| `sample-zip.jimage` | the same with `DefaultCompressPlugin` configured as `--compress=zip-6` | every resource in a `zip` (zlib) layer |
| `sample-compact-cp.jimage` | the same with `--compress=1` (string sharing, deprecated in JDK 21) | the two class files in a `compact-cp` layer, the other resources stored |
| `sample.jmod` | `jmod create --class-path <classes> --libs <libs> --date 2026-01-01T00:00:00Z` | `JM` 1.0 and a ZIP archive: `classes/...` and `lib/payload.elf` |

`GenerateImages.java` drives the JDK's jimage writer directly
(`ImageFileCreator`, `BasicImageWriter`, `ImagePluginStack` with resource
pool validation off) so the images hold only the synthetic module: jlink
itself always adds `java.base`, which is neither small nor ours to
redistribute. Every image therefore has the layout jlink writes, including
the `/modules` and `/packages` directory entries and the 8 B root directory
listing after the last resource.

## Generator and commands

Generated on 2026-10-13 on macOS AArch64 with Homebrew OpenJDK 21.0.12.1
(`javac 21.0.12.1`, `jmod 21.0.12.1`, `openjdk version "21.0.12.1"
2026-08-18`). From the repository root:

```sh
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home \
  tests/fixtures/javaimage/generate.sh
```

The script compiles the module with `javac --release 21 -g:none`, copies
the two non-class resources next to the classes, runs `GenerateImages.java`
(with `--add-exports` for the jdk.jlink internals) and `jmod create`.
Running it twice on 2026-10-13 produced identical files.

`DumpImage.java` reads an image with the JDK's reader
(`jdk.internal.jimage.ImageReader.open(path, byteOrder)`) and prints every
location with its offset, sizes and the SHA-256 of the resource as the
reader returns it (decompressed):

```sh
java --add-exports java.base/jdk.internal.jimage=ALL-UNNAMED \
  tests/fixtures/javaimage/DumpImage.java tests/fixtures/javaimage/sample-be.jimage big
```

On 2026-10-13 it listed the same 11 locations for all four images, and the
same resource hashes, among them `Hello.class`
`121b756f9b3a1134441a6c164b129e0bb507ac9f97af6840092e9ef4fcaf2393` and
`module-info.class`
`cb9a24c6f73207c62e7ab8c18cae502301cc8075593d6b1da9be01f6837e5153`.
`jimage list --verbose` (JDK 21.0.12.1) lists the three little-endian
images; it opens images in the host byte order only.

## Sizes and SHA-256

| File | Size (B) | SHA-256 |
| --- | --- | --- |
| `sample-le.jimage` | 1908 | `6aac7b08eda5a09ccff90be54c5e56893e081e746eade525f5fa40f5d5712565` |
| `sample-be.jimage` | 1908 | `475aeffc56a6d7e3e6166ad6d2b2ece060ba757d3f213f0e5c3d2de3143b90bf` |
| `sample-zip.jimage` | 1368 | `96bd709e383442190c8ff2f97580fa22a99592da8c81b20f6b6eb19ad4b4cf34` |
| `sample-compact-cp.jimage` | 1871 | `756961ab4ccb3b97b6e963bfd17ed641dc8840ebb3b2cf8ff9ae4fb3d11974a7` |
| `sample.jmod` | 1584 | `04ec42927f65a9472afef86d21c412621cddecbe0084800954ab2212fdae8c94` |
