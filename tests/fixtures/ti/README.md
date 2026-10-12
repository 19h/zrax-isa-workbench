# TI-generated fixture provenance

These fixtures contain synthetic four-byte core payloads (`01 02 03 04`),
not vendor application code or the supplied RX113 firmware. Generated on
2026-10-12 with Node.js, Python and OpenSSL.

| Fixture | Size (B) | SHA-256 |
| --- | --- | --- |
| `vendor.appimage` | 128 | `57f6121fcec76a6866525b27065d50603f1773eed0ae9920660f93cf95c8e061` |
| `vendor.mcelf` | 364 | `814e3e810245c4ec8850f833bda3afb7b228d86b2ff725c5ee35159463e6b1e5` |
| `vendor.mcelf_xip` | 216 | `2c498077d2d56b15417744e3aa6c3d251089332a948455a6c055758d350ccdf7` |
| `vendor.signed` | 1269 | `9c665b8d3671868e1cd532822f90619e95b50d343de7ec600ac97c63238c440d` |

Sources:

- MCU+ [multicoreImageGen.js](https://github.com/TexasInstruments/mcupsdk-core/blob/next/tools/boot/multicoreImageGen/multicoreImageGen.js), downloaded SHA-256
  `04c74f65130fc2f15a23c85bfbc18df3d8223e7e65463e0f39c4a8851b8fe7cb`.
- [multicore-elf](https://github.com/TexasInstruments/multicore-elf/tree/c43c01bfac3a44998f772d204de58b4038b8ffc8), revision
  `c43c01bfac3a44998f772d204de58b4038b8ffc8`.
- K3 [appimage_x509_cert_gen.py](https://github.com/TexasInstruments/mcupsdk-core-k3/blob/k3_main/tools/boot/signing/appimage_x509_cert_gen.py), downloaded SHA-256
  `3b52bdde452f7ebdfcbf9ebdb680b1365e7dd73120d2538248a830708ced8edc`.

Prepare each input RPRC as the little-endian 32-bit words
`43525052, entry, 0, 1, 1, entry, 0, 4, 0, 0`, then append the four payload
bytes. Use entries `0x1000` and `0x2000`. Prepare ELF32 inputs with `EM_ARM`,
`ET_EXEC`, a single `PT_LOAD` at file offset 84, the same entry/destination
addresses, size 4 and flags 5. The ELF has a 52-byte header and a 32-byte
program header; no section table. The declared ELF machine value is a test
input, not a prediction about the arbitrary payload bytes.

Commands (run in a temporary directory with these downloaded TI tools):

```sh
node multicoreImageGen.js -i 55 -o vendor.appimage core0.rprc@4 core1.rprc@14
python genimage.py --core-img=4:core0.elf --core-img=14:core1.elf --output=vendor.mcelf --xip=None
openssl genrsa -out fixture-key.pem 2048
python appimage_x509_cert_gen.py --bin vendor.appimage --key fixture-key.pem --cert fixture-cert.der --output vendor.signed --core r5_cl0_c0 --enc n --loadaddr 70000000
```

The ELF tool generates both `vendor.mcelf` and `vendor.mcelf_xip`; the latter
contains only notes because the input addresses are outside the XIP range.
`construct==2.10.70` and `pyelftools==0.31` were used with the host cryptography
package. Keys are generated only to create test certificates and are not stored
in this repository. Certificate dates, signatures, keys and the ELF final random
string vary on regeneration, so byte-identical reproduction is not expected.
The checked-in hashes identify the frozen artifacts tested here. The parser
validates structure and reports authentication as unverified.
