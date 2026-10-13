import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { gunzipSync } from 'node:zlib';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup); after(teardown);

const fixture = async name => gunzipSync(await readFile(new URL(`../../tests/fixtures/macho/${name}`, import.meta.url)));

// loader.h constants (xnu-12377.121.6).
const MH_MAGIC_64 = 0xfeedfacf;
const CPU_TYPE_X86_64 = 0x01000007;
const CPU_TYPE_ARM64 = 0x0100000c;
const CPU_SUBTYPE_ARM64E = 2;
const MH_EXECUTE = 0x2;
const MH_KEXT_BUNDLE = 0xb;
const MH_FILESET = 0xc;
const MH_DYLIB_IN_CACHE = 0x80000000;
const LC_SEGMENT_64 = 0x19;
const LC_FILESET_ENTRY = 0x80000035;
const CODE = 0x80000400;
const VM_PROT_RX = 5;

// mach_header_64 (32 B, little-endian): magic, cputype, cpusubtype,
// filetype, ncmds, sizeofcmds, flags, reserved; then the load commands.
function machHeader(cpuType, cpuSubtype, fileType, flags, commands) {
  const body = Buffer.concat(commands);
  const header = Buffer.alloc(32);
  [MH_MAGIC_64, cpuType, cpuSubtype, fileType, commands.length, body.length, flags, 0]
    .forEach((value, i) => header.writeUInt32LE(value >>> 0, 4 * i));
  return Buffer.concat([header, body]);
}

// segment_command_64 (72 B) with one section_64 (80 B): segname, vmaddr,
// vmsize, fileoff, filesize, maxprot, initprot, nsects, flags; the section
// holds sectname "__text", segname, addr, size, offset and flags.
function textSegment(vmAddress, fileOffset, fileSize, textOffset, textSize) {
  const command = Buffer.alloc(72 + 80);
  command.writeUInt32LE(LC_SEGMENT_64, 0);
  command.writeUInt32LE(command.length, 4);
  command.write('__TEXT', 8, 'latin1');
  command.writeBigUInt64LE(vmAddress, 24);
  command.writeBigUInt64LE(BigInt(fileSize), 32);
  command.writeBigUInt64LE(BigInt(fileOffset), 40);
  command.writeBigUInt64LE(BigInt(fileSize), 48);
  command.writeUInt32LE(VM_PROT_RX, 56);
  command.writeUInt32LE(VM_PROT_RX, 60);
  command.writeUInt32LE(1, 64);
  const section = 72;
  command.write('__text', section, 'latin1');
  command.write('__TEXT', section + 16, 'latin1');
  command.writeBigUInt64LE(vmAddress + BigInt(textOffset - fileOffset), section + 32);
  command.writeBigUInt64LE(BigInt(textSize), section + 40);
  command.writeUInt32LE(textOffset, section + 48);
  command.writeUInt32LE(CODE >>> 0, section + 64);
  return command;
}

// fileset_entry_command (32 B): vmaddr, fileoff, entry_id offset (32),
// reserved; then the NUL-terminated ID padded to 8 bytes.
function filesetEntry(vmAddress, fileOffset, id) {
  const text = Buffer.alloc(Math.ceil((id.length + 1) / 8) * 8);
  text.write(id, 0, 'latin1');
  const command = Buffer.alloc(32);
  command.writeUInt32LE(LC_FILESET_ENTRY >>> 0, 0);
  command.writeUInt32LE(32 + text.length, 4);
  command.writeBigUInt64LE(vmAddress, 8);
  command.writeBigUInt64LE(BigInt(fileOffset), 16);
  command.writeUInt32LE(32, 24);
  return Buffer.concat([command, text]);
}

// An arm64 MH_FILESET of 0x9000 B listing com.apple.kernel (an arm64e
// MH_EXECUTE at 0x4000, __text of AArch64 `ret` at 0x5000) and
// com.example.driver (an x86-64 MH_KEXT_BUNDLE at 0x8000, __text of x86
// `ret` at 0x8800). Entry segments use the fileset's file offsets.
function fileset() {
  const file = Buffer.alloc(0x9000);
  machHeader(CPU_TYPE_ARM64, 0, MH_FILESET, 0, [
    filesetEntry(0xfffffff007004000n, 0x4000, 'com.apple.kernel'),
    filesetEntry(0xfffffff007008000n, 0x8000, 'com.example.driver'),
  ]).copy(file, 0);
  machHeader(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, MH_EXECUTE, MH_DYLIB_IN_CACHE, [
    textSegment(0xfffffff007004000n, 0x4000, 0x2000, 0x5000, 0x40),
  ]).copy(file, 0x4000);
  for (let at = 0x5000; at < 0x5040; at += 4) file.writeUInt32LE(0xd65f03c0, at);
  machHeader(CPU_TYPE_X86_64, 3, MH_KEXT_BUNDLE, MH_DYLIB_IN_CACHE, [
    textSegment(0xfffffff007008000n, 0x8000, 0x1000, 0x8800, 0x10),
  ]).copy(file, 0x8000);
  file.fill(0xc3, 0x8800, 0x8810);
  return file;
}

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`Mach-O load commands and fileset entries classify through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const inputs = [
      { name: 'fileset', bytes: [...fileset()] },
      { name: 'hello-arm64', bytes: [...await fixture('hello-arm64.gz')] },
    ];
    const payloads = await page.evaluate(async ({ module, inputs }) => {
      const wasm = await import(module);
      await wasm.default();
      return Object.fromEntries(inputs.map(f => [f.name, JSON.parse(wasm.classify(new Uint8Array(f.bytes)))]));
    }, { module, inputs });

    const kc = payloads.fileset;
    assert.ok(!kc.error, kc.error);
    assert.equal(kc.format.format, 'macho');
    assert.ok(Object.hasOwn(FORMAT_NAMES, 'macho'), 'macho has a display name');
    assert.equal(kc.primary.isa, 'a_arch64');
    const kernel = kc.slices.find(s => s.label === 'com.apple.kernel');
    const driver = kc.slices.find(s => s.label === 'com.example.driver');
    assert.equal(kernel.isa, 'a_arch64');
    assert.equal(kernel.offset, 0x4000);
    assert.equal(kernel.variant?.name, 'ARMv8.3+ (PAC)');
    assert.equal(driver.isa, 'x86_64');
    assert.equal(driver.offset, 0x8000);
    assert.ok(kc.notes.some(n => n.message === '2 fileset entries (LC_FILESET_ENTRY)'), JSON.stringify(kc.notes));
    const entry = kc.metadata.find(m => m.key?.custom === 'macho_fileset_entry_1');
    assert.equal(entry?.label, 'com.example.driver');

    const hello = payloads['hello-arm64'];
    assert.equal(hello.format.format, 'macho');
    assert.equal(hello.primary.isa, 'a_arch64');
    assert.ok(hello.notes.some(n => n.message === 'Platform macOS (LC_BUILD_VERSION); minimum OS 12.0; SDK 27.2'));
    assert.equal(hello.metadata.find(m => m.key?.custom === 'macho_platform')?.value, 'macOS');
    assert.ok(hello.notes.some(n => n.message.startsWith('Code signature present') && n.message.endsWith('not verified')));
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench lists fileset entries as slices in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    await page.locator('#fileinput').setInputFiles([{ name: 'kernelcache', buffer: fileset(), mimeType: 'application/octet-stream' }]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes('Mach-O'), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.deepEqual(p.slices.map(s => s.label), ['com.apple.kernel', 'com.example.driver']);
  });
}
