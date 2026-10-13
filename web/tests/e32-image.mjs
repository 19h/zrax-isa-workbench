// Hand-built Symbian E32 image files for the browser tests, written from the documented V header layout
// (Symbian Foundation kernelhwsrv commit 0c3208650587ac0230aed8a74e9bddb5288023eb,
// userlibandfileserver/fileserver/inc/f32image.h). The UID checksum and the header CRC are computed here, bit by bit.

export const EXECUTABLE_UID = 0x1000007a;
export const APP_UID2 = 0x100039ce;
export const CPU_X86 = 0x1000;
export const CPU_ARM_V5 = 0x2001;
export const COMPRESSION_NONE = 0;
export const COMPRESSION_DEFLATE = 0x101f7afc;

// iFlags: EABI (0x08), EKA2 entry point (0x20), V header format (0x02000000), ELF-derived imports (0x10000000).
export const ARM_EKA2_V_FLAGS = 0x1200002a;
// iFlags of a non-ARM image: only the V header format; no ABI or entry point type bits.
export const V_FLAGS = 0x02000000;

// sizeof(E32ImageHeaderV) with an empty export description: also iCodeOffset.
export const V_HEADER_SIZE = 0x9c;
const HEADER_CRC = 0x14;
const IMAGE_CRC_INITIALISER = 0xc90fdaa2;

// Mem::Crc: CRC-16, polynomial 0x1021, register 0, most significant bit first, no final XOR.
function crc16(bytes) {
  let crc = 0;
  for (const byte of bytes) {
    crc ^= byte << 8;
    for (let bit = 0; bit < 8; bit++) {
      crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
    }
  }
  return crc;
}

// TCheckedUid::Check: CRC-16 of the odd UID bytes in the high half, of the even bytes in the low half.
export function uidChecksum(uids) {
  const even = Buffer.from(uids.filter((_, i) => i % 2 === 0));
  const odd = Buffer.from(uids.filter((_, i) => i % 2 === 1));
  return ((crc16(odd) << 16) | crc16(even)) >>> 0;
}

// Mem::Crc32 over the header with iHeaderCrc set to KImageCrcInitialiser: reflected polynomial 0xEDB88320,
// register 0, no final XOR.
export function headerCrc(header) {
  const bytes = Buffer.from(header);
  bytes.writeUInt32LE(IMAGE_CRC_INITIALISER, HEADER_CRC);
  let crc = 0;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) {
      crc = crc & 1 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1;
    }
  }
  return crc >>> 0;
}

// A V image: the 0x9C-byte header, then the code part (iCodeSize = iTextSize, linked at 0x8000, entry offset 0), or
// `stored` compressed bytes for a `codeSize`-byte code part when `compression` is set. Fields: UIDs (0x0-0x8),
// UID checksum (0xC), 'EPOC' (0x10), header CRC (0x14), module version 10.0 (0x18), compression (0x1C), tools
// version 2.1 build 549 (0x20), flags (0x2C), sizes, heap 4 KiB-1 MiB, stack 8 KiB, bases, offsets (0x30-0x74),
// priority 350 and the CPU (0x78, 0x7A), uncompressed size (0x7C), secure ID = UID3, vendor ID, capabilities
// (0x80-0x8C), no exception descriptor, export description type 0 of 0 B (0x98).
export function e32Image({ uid3, code = Buffer.alloc(0), cpu = CPU_ARM_V5, flags = ARM_EKA2_V_FLAGS,
  compression = COMPRESSION_NONE, stored = null, codeSize = code.length }) {
  const header = Buffer.alloc(V_HEADER_SIZE);
  header.writeUInt32LE(EXECUTABLE_UID, 0x00);
  header.writeUInt32LE(APP_UID2, 0x04);
  header.writeUInt32LE(uid3, 0x08);
  header.write('EPOC', 0x10, 'latin1');
  header.writeUInt32LE(0x000a0000, 0x18);
  header.writeUInt32LE(compression, 0x1c);
  header.writeUInt8(2, 0x20);
  header.writeUInt8(1, 0x21);
  header.writeUInt16LE(549, 0x22);
  header.writeUInt32LE(flags, 0x2c);
  header.writeUInt32LE(codeSize, 0x30);
  header.writeUInt32LE(0x1000, 0x38);
  header.writeUInt32LE(0x100000, 0x3c);
  header.writeUInt32LE(0x2000, 0x40);
  header.writeUInt32LE(0x8000, 0x4c);
  header.writeUInt32LE(0x400000, 0x50);
  header.writeUInt32LE(codeSize, 0x60);
  header.writeUInt32LE(V_HEADER_SIZE, 0x64);
  header.writeUInt16LE(350, 0x78);
  header.writeUInt16LE(cpu, 0x7a);
  header.writeUInt32LE(codeSize, 0x7c);
  header.writeUInt32LE(uid3, 0x80);
  header.writeUInt32LE(0x70000001, 0x84);
  header.writeUInt32LE(0x000fffff, 0x88);
  header.writeUInt32LE(uidChecksum([...header.subarray(0, 12)]), 0x0c);
  header.writeUInt32LE(headerCrc(header), HEADER_CRC);
  return Buffer.concat([header, stored ?? code]);
}
