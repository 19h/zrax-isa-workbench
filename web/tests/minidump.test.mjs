import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

// Compiled x86-64 code from the repository's testbins.
const x86_64Code = () => readFile(new URL('../../testbins/x86_64_x86_64-unknown-linux-gnu_O0_call_nested.bin', import.meta.url));

// Microsoft minidumpapiset.h and winnt.h values.
const MINIDUMP_SIGNATURE = 0x504d444d;
const MINIDUMP_VERSION = 0xa793;
const THREAD_LIST_STREAM = 3;
const MODULE_LIST_STREAM = 4;
const MEMORY_LIST_STREAM = 5;
const SYSTEM_INFO_STREAM = 7;
const PROCESSOR_ARCHITECTURE_AMD64 = 9;
const MACHINE_AMD64 = 0x8664;

const HEADER_SIZE = 32;
const DIRECTORY_ENTRY_SIZE = 12;
const SYSTEM_INFO_SIZE = 56;
const THREAD_LIST_SIZE = 4 + 48;
const MODULE_LIST_SIZE = 4 + 108;
const MEMORY_LIST_SIZE = 4 + 2 * 16;

const APP_BASE = 0x140000000n;
const CODE_ADDRESS = APP_BASE + 0x1000n;
const STACK_ADDRESS = 0x9f0000n;
const CODE_LABEL = 'Memory at 0x140001000 (app.exe)';
const STACK_LABEL = 'Memory at 0x9F0000 (thread 0x1234 stack)';

// MINIDUMP_STRING: Length in bytes without the terminator, UTF-16LE units,
// a NUL unit.
function minidumpString(text) {
  const units = Buffer.from(text, 'utf16le');
  const string = Buffer.alloc(4 + units.length + 2);
  string.writeUInt32LE(units.length, 0);
  units.copy(string, 4);
  return string;
}

// An AMD64 minidump with one thread, one module (app.exe) and two memory
// ranges: x86-64 code inside app.exe, then the thread's stack. Layout:
// header, directory, system info, thread list, module list, memory list,
// the module name, the memory bytes. Returns the file and where each
// range is stored.
function minidump(code) {
  const streams = [
    [SYSTEM_INFO_STREAM, SYSTEM_INFO_SIZE],
    [THREAD_LIST_STREAM, THREAD_LIST_SIZE],
    [MODULE_LIST_STREAM, MODULE_LIST_SIZE],
    [MEMORY_LIST_STREAM, MEMORY_LIST_SIZE],
  ];
  const stack = Buffer.alloc(0x100, 0x11);
  const name = minidumpString('C:\\App\\app.exe');
  let offset = HEADER_SIZE + streams.length * DIRECTORY_ENTRY_SIZE;
  const rvas = {};
  for (const [type, size] of streams) {
    rvas[type] = offset;
    offset += size;
  }
  const nameRva = offset;
  const codeRva = nameRva + name.length;
  const stackRva = codeRva + code.length;
  const file = Buffer.alloc(stackRva + stack.length);
  // MINIDUMP_HEADER: Signature, Version, NumberOfStreams,
  // StreamDirectoryRva, CheckSum, TimeDateStamp, Flags.
  file.writeUInt32LE(MINIDUMP_SIGNATURE, 0);
  file.writeUInt32LE(MINIDUMP_VERSION, 4);
  file.writeUInt32LE(streams.length, 8);
  file.writeUInt32LE(HEADER_SIZE, 12);
  // MINIDUMP_DIRECTORY: StreamType, DataSize, Rva.
  streams.forEach(([type, size], i) => {
    const entry = HEADER_SIZE + i * DIRECTORY_ENTRY_SIZE;
    file.writeUInt32LE(type, entry);
    file.writeUInt32LE(size, entry + 4);
    file.writeUInt32LE(rvas[type], entry + 8);
  });
  // MINIDUMP_SYSTEM_INFO: ProcessorArchitecture (0), NumberOfProcessors
  // (6), MajorVersion (8), BuildNumber (0x10), PlatformId (0x14).
  const system = rvas[SYSTEM_INFO_STREAM];
  file.writeUInt16LE(PROCESSOR_ARCHITECTURE_AMD64, system);
  file.writeUInt8(4, system + 6);
  file.writeUInt32LE(10, system + 8);
  file.writeUInt32LE(19041, system + 0x10);
  file.writeUInt32LE(2, system + 0x14);
  // Thread list: count, then MINIDUMP_THREAD: ThreadId (0), Stack start
  // (0x18) and size (0x20).
  const threads = rvas[THREAD_LIST_STREAM];
  file.writeUInt32LE(1, threads);
  file.writeUInt32LE(0x1234, threads + 4);
  file.writeBigUInt64LE(STACK_ADDRESS, threads + 4 + 0x18);
  file.writeUInt32LE(0x1000, threads + 4 + 0x20);
  // Module list: count, then MINIDUMP_MODULE: BaseOfImage (0),
  // SizeOfImage (8), ModuleNameRva (0x14).
  const modules = rvas[MODULE_LIST_STREAM];
  file.writeUInt32LE(1, modules);
  file.writeBigUInt64LE(APP_BASE, modules + 4);
  file.writeUInt32LE(0x10000, modules + 4 + 8);
  file.writeUInt32LE(nameRva, modules + 4 + 0x14);
  // Memory list: count, then MINIDUMP_MEMORY_DESCRIPTOR:
  // StartOfMemoryRange, DataSize, Rva.
  const memory = rvas[MEMORY_LIST_STREAM];
  const ranges = [[CODE_ADDRESS, code.length, codeRva], [STACK_ADDRESS, stack.length, stackRva]];
  file.writeUInt32LE(ranges.length, memory);
  ranges.forEach(([address, size, rva], i) => {
    const descriptor = memory + 4 + i * 16;
    file.writeBigUInt64LE(address, descriptor);
    file.writeUInt32LE(size, descriptor + 8);
    file.writeUInt32LE(rva, descriptor + 12);
  });
  name.copy(file, nameRva);
  code.copy(file, codeRva);
  stack.copy(file, stackRva);
  return { file, codeRva, stackRva };
}

// A 64-bit kernel dump header (8 KiB): "PAGE" and "DU64", MachineImageType
// at 0x30, NumberProcessors at 0x34, BugCheckCode at 0x38, DumpType at
// 0xF98; then 4 KiB of physical memory.
function kernelDump() {
  const file = Buffer.alloc(0x3000);
  file.write('PAGEDU64', 0, 'latin1');
  file.writeUInt32LE(MACHINE_AMD64, 0x30);
  file.writeUInt32LE(2, 0x34);
  file.writeUInt32LE(0xd1, 0x38);
  file.writeUInt32LE(1, 0xf98);
  return file;
}

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`Windows minidumps and kernel dumps classify through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const code = await x86_64Code();
    const dump = minidump(code);
    const fixtures = [
      { name: 'app.dmp', bytes: [...dump.file] },
      { name: 'MEMORY.DMP', bytes: [...kernelDump()] },
    ];
    const payloads = await page.evaluate(async ({ module, fixtures }) => {
      const wasm = await import(module);
      await wasm.default();
      return Object.fromEntries(fixtures.map(f => [f.name, JSON.parse(wasm.classify(new Uint8Array(f.bytes)))]));
    }, { module, fixtures });
    for (const id of ['minidump', 'windowskerneldump']) {
      assert.ok(Object.hasOwn(FORMAT_NAMES, id), `${id} has a display name`);
    }

    const p = payloads['app.dmp'];
    assert.ok(!p.error, p.error);
    assert.equal(p.format.format, 'minidump');
    assert.equal(p.format.variant_name, 'MDMP, little-endian');
    assert.deepEqual([p.primary.isa, p.primary.bitwidth, p.primary.endianness], ['x86_64', 64, 'little']);
    const codeSlice = p.slices.find(s => s.label === CODE_LABEL);
    assert.ok(codeSlice, `${CODE_LABEL} slice`);
    assert.deepEqual([codeSlice.isa, codeSlice.offset, codeSlice.size], ['x86_64', dump.codeRva, code.length]);
    const stackSlice = p.slices.find(s => s.label === STACK_LABEL);
    assert.ok(stackSlice, `${STACK_LABEL} slice`);
    assert.deepEqual([stackSlice.isa, stackSlice.offset], [{ unknown: 0 }, dump.stackRva]);
    assert.ok(p.notes.some(n => n.message.startsWith('Processor architecture 9 (AMD64)')));

    const kernel = payloads['MEMORY.DMP'];
    assert.ok(!kernel.error, kernel.error);
    assert.equal(kernel.format.format, 'windowskerneldump');
    assert.equal(kernel.primary.isa, 'x86_64');
    const body = kernel.slices.find(s => s.label === 'Dump data after the header');
    assert.deepEqual([body?.offset, body?.size], [0x2000, 0x1000]);
    assert.ok(kernel.notes.some(n => n.message === 'Bug check 0x000000D1 (0x0, 0x0, 0x0, 0x0)'));
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names Windows minidumps in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const { file } = minidump(await x86_64Code());
    await page.locator('#fileinput').setInputFiles([{ name: 'app.dmp', buffer: file, mimeType: 'application/octet-stream' }]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes('Windows minidump'), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'x86_64');
    assert.ok(p.metadata.some(m => m.key?.custom === 'minidump_image_size' && m.value === file.length));
  });
}
