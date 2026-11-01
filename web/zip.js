// Stored (uncompressed) ZIP archives built in the browser, so several files
// download as one. Layout from PKWARE APPNOTE.TXT 6.3.10: local file headers
// (section 4.3.7), the central directory (4.3.12) and its end record
// (4.3.16). Names are UTF-8 (general purpose bit 11, section 4.4.4). Without
// ZIP64 an archive holds at most 65,535 entries and 4 GiB.

const LOCAL_FILE_HEADER = 0x0403_4b50;
const CENTRAL_FILE_HEADER = 0x0201_4b50;
const END_OF_CENTRAL_DIRECTORY = 0x0605_4b50;
const LOCAL_HEADER_SIZE = 30;
const CENTRAL_HEADER_SIZE = 46;
const END_RECORD_SIZE = 22;
// Version 2.0, host MS-DOS: external attributes 0 mean an ordinary file.
const VERSION = 20;
const FLAG_UTF8_NAMES = 0x0800;
const METHOD_STORED = 0;
const MAX_ENTRIES = 0xffff;
const MAX_OFFSET = 0xffff_ffff;
const MAX_NAME_BYTES = 0xffff;
const DOS_EPOCH_YEAR = 1980;
const DOS_LAST_YEAR = 2107;

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb8_8320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

/** CRC-32 (ISO 3309, reflected polynomial 0xEDB88320) of `bytes`. */
export function crc32(bytes) {
  let crc = 0xffff_ffff;
  for (const byte of bytes) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffff_ffff) >>> 0;
}

/** MS-DOS time and date fields (section 4.4.6) for a local time. */
function dosTimestamp(date) {
  const year = Math.min(Math.max(date.getFullYear(), DOS_EPOCH_YEAR), DOS_LAST_YEAR);
  const time = (date.getHours() << 11) | (date.getMinutes() << 5) | Math.floor(date.getSeconds() / 2);
  const day = ((year - DOS_EPOCH_YEAR) << 9) | ((date.getMonth() + 1) << 5) | date.getDate();
  return { time, day };
}

/** Fields shared by the local and central headers, from the version needed onwards. */
function writeCommonFields(view, at, entry, timestamp) {
  view.setUint16(at, VERSION, true);
  view.setUint16(at + 2, FLAG_UTF8_NAMES, true);
  view.setUint16(at + 4, METHOD_STORED, true);
  view.setUint16(at + 6, timestamp.time, true);
  view.setUint16(at + 8, timestamp.day, true);
  view.setUint32(at + 10, entry.crc, true);
  view.setUint32(at + 14, entry.size, true);
  view.setUint32(at + 18, entry.size, true);
  view.setUint16(at + 22, entry.name.length, true);
}

function localHeader(entry, timestamp) {
  const view = new DataView(new ArrayBuffer(LOCAL_HEADER_SIZE));
  view.setUint32(0, LOCAL_FILE_HEADER, true);
  writeCommonFields(view, 4, entry, timestamp);
  // Extra field length at 28 stays 0.
  return view;
}

function centralHeader(entry, timestamp) {
  const view = new DataView(new ArrayBuffer(CENTRAL_HEADER_SIZE));
  view.setUint32(0, CENTRAL_FILE_HEADER, true);
  view.setUint16(4, VERSION, true);
  writeCommonFields(view, 6, entry, timestamp);
  // Extra, comment, disk number, internal and external attributes stay 0.
  view.setUint32(42, entry.offset, true);
  return view;
}

function endRecord(count, directorySize, directoryOffset) {
  const view = new DataView(new ArrayBuffer(END_RECORD_SIZE));
  view.setUint32(0, END_OF_CENTRAL_DIRECTORY, true);
  view.setUint16(8, count, true);
  view.setUint16(10, count, true);
  view.setUint32(12, directorySize, true);
  view.setUint32(16, directoryOffset, true);
  return view;
}

/**
 * A ZIP archive of `files` (`{ name, bytes }`, names unique) stored without
 * compression, with `modified` as every entry's local time.
 *
 * Throws when the archive would need ZIP64.
 */
export function zipArchive(files, modified = new Date()) {
  if (files.length > MAX_ENTRIES) throw new Error(`Too many files for a ZIP archive: ${files.length}`);
  const encoder = new TextEncoder();
  const timestamp = dosTimestamp(modified);
  const parts = [];
  const entries = [];
  let offset = 0;
  for (const file of files) {
    const name = encoder.encode(file.name);
    if (name.length > MAX_NAME_BYTES) throw new Error(`File name too long for a ZIP archive: ${file.name}`);
    const entry = { name, size: file.bytes.length, crc: crc32(file.bytes), offset };
    offset += LOCAL_HEADER_SIZE + name.length + file.bytes.length;
    if (offset > MAX_OFFSET) throw new Error('Files too large for a ZIP archive without ZIP64');
    entries.push(entry);
    parts.push(localHeader(entry, timestamp), name, file.bytes);
  }
  const directoryOffset = offset;
  for (const entry of entries) {
    parts.push(centralHeader(entry, timestamp), entry.name);
    offset += CENTRAL_HEADER_SIZE + entry.name.length;
  }
  if (offset > MAX_OFFSET) throw new Error('Files too large for a ZIP archive without ZIP64');
  parts.push(endRecord(entries.length, offset - directoryOffset, directoryOffset));
  return new Blob(parts, { type: 'application/zip' });
}
