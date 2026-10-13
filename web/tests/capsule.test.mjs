import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
before(setup);
after(teardown);

const fixture = name => readFile(new URL(`../../tests/fixtures/uefi/${name}`, import.meta.url));

const CAPSULE_FLAGS_PERSIST_ACROSS_RESET = 0x0001_0000;
const IMAGE_FILE_MACHINE_ARM64 = 0xaa64;

// On-disk bytes of an EFI_GUID: Data1, Data2 and Data3 little-endian, then
// Data4 in order.
function guid(data1, data2, data3, data4) {
  const out = Buffer.alloc(16);
  out.writeUInt32LE(data1, 0);
  out.writeUInt16LE(data2, 4);
  out.writeUInt16LE(data3, 6);
  Buffer.from(data4).copy(out, 8);
  return out;
}

const EFI_CAPSULE_GUID = guid(0x3b6686bd, 0x0d76, 0x4030, [0xb7, 0x0e, 0xb5, 0x51, 0x9e, 0x2f, 0xc5, 0xa0]);
const FMP_CAPSULE_GUID = guid(0x6dcbd5ed, 0xe82d, 0x4c44, [0xbd, 0xa1, 0x71, 0x94, 0x19, 0x9a, 0xd9, 0x2a]);
const PAYLOAD_TYPE_ID = guid(0x5a1e7e57, 0, 0x4000, [0x80, 0, 0, 0, 0, 0, 0, 0xc1]);

// EFI_CAPSULE_HEADER: CapsuleGuid, HeaderSize 0x20, Flags, CapsuleImageSize
// (header plus body), zero fill to 0x20, then the body.
function capsule(capsuleGuid, flags, body) {
  const header = Buffer.alloc(0x20);
  capsuleGuid.copy(header, 0);
  header.writeUInt32LE(0x20, 0x10);
  header.writeUInt32LE(flags, 0x14);
  header.writeUInt32LE(0x20 + body.length, 0x18);
  return Buffer.concat([header, body]);
}

// EFI_FIRMWARE_MANAGEMENT_CAPSULE_IMAGE_HEADER version 3: Version,
// UpdateImageTypeId, UpdateImageIndex 1 and three reserved bytes,
// UpdateImageSize, UpdateVendorCodeSize 0, UpdateHardwareInstance 0,
// ImageCapsuleSupport 0; then an EDK2 FMP_PAYLOAD_HEADER ('MSS1', 16,
// FwVersion 2, LowestSupportedVersion 1) and the firmware image.
function payloadItem(image) {
  const payloadHeader = Buffer.alloc(16);
  payloadHeader.write('MSS1', 0, 'latin1');
  payloadHeader.writeUInt32LE(16, 4);
  payloadHeader.writeUInt32LE(2, 8);
  payloadHeader.writeUInt32LE(1, 12);
  const updateImage = Buffer.concat([payloadHeader, image]);
  const header = Buffer.alloc(48);
  header.writeUInt32LE(3, 0);
  PAYLOAD_TYPE_ID.copy(header, 4);
  header[0x14] = 1;
  header.writeUInt32LE(updateImage.length, 0x18);
  return Buffer.concat([header, updateImage]);
}

// FMP capsule body: Version 1, EmbeddedDriverCount, PayloadItemCount, the
// ItemOffsetList (u64, from the body start), the drivers, the payloads.
function fmpBody(drivers, payloads) {
  const items = [...drivers, ...payloads];
  const header = Buffer.alloc(8 + 8 * items.length);
  header.writeUInt32LE(1, 0);
  header.writeUInt16LE(drivers.length, 4);
  header.writeUInt16LE(payloads.length, 6);
  let offset = header.length;
  items.forEach((item, i) => {
    header.writeBigUInt64LE(BigInt(offset), 8 + 8 * i);
    offset += item.length;
  });
  return Buffer.concat([header, ...items]);
}

// The minimal x86-64 PE32+ image of pe32-sections.bin (after its 4-byte
// section header) with Machine (PE offset 0x44) set to AArch64.
async function arm64Driver() {
  const image = Buffer.from((await fixture('pe32-sections.bin')).subarray(4, 0x1b0));
  image.writeUInt16LE(IMAGE_FILE_MACHINE_ARM64, 0x44);
  return image;
}

const sliceIsas = payload => Object.fromEntries(payload.slices.map(s => [s.label, s.isa]));

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`UEFI capsules classify their bodies, payloads and drivers through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const volume = await fixture('sample.fd');
    const efi = capsule(EFI_CAPSULE_GUID, CAPSULE_FLAGS_PERSIST_ACROSS_RESET, volume);
    const fmp = capsule(FMP_CAPSULE_GUID, 0, fmpBody([await arm64Driver()], [payloadItem(volume)]));
    const fixtures = [{ bytes: [...efi] }, { bytes: [...fmp] }];
    const payloads = await page.evaluate(async ({ module, fixtures }) => {
      const wasm = await import(module);
      await wasm.default();
      return fixtures.map(f => JSON.parse(wasm.classify(new Uint8Array(f.bytes))));
    }, { module, fixtures });
    const [efiPayload, fmpPayload] = payloads;
    for (const p of payloads) {
      assert.ok(!p.error, p.error);
      assert.equal(p.format.format, 'ueficapsule');
      assert.ok(Object.hasOwn(FORMAT_NAMES, p.format.format), `${p.format.format} has a display name`);
    }

    assert.equal(efiPayload.primary.isa, 'x86_64');
    const body = efiPayload.slices.find(s => s.label === 'Capsule body');
    assert.deepEqual([body.offset, body.size, body.isa], [0x20, volume.length, 'x86_64']);

    // The payload's firmware volume names the ISA, not the AArch64 driver.
    assert.equal(fmpPayload.primary.isa, 'x86_64');
    const isas = sliceIsas(fmpPayload);
    assert.equal(isas['Payload 1 (5A1E7E57-0000-4000-8000-0000000000C1)'], 'x86_64');
    assert.equal(isas['Embedded driver 1'], 'a_arch64');
    const payload = fmpPayload.slices.find(s => s.label.startsWith('Payload 1'));
    // The 0x20 B capsule header, the 8 B FMP header, two 8 B item offsets,
    // the 0x1AC B driver, the 48 B image header and the 16 B payload header.
    assert.equal(payload.offset, 0x20 + 8 + 16 + 0x1ac + 48 + 16);
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names UEFI capsules in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const buffer = capsule(EFI_CAPSULE_GUID, CAPSULE_FLAGS_PERSIST_ACROSS_RESET, await fixture('sample.fd'));
    await page.locator('#fileinput').setInputFiles([{ name: 'firmware.cap', buffer, mimeType: 'application/octet-stream' }]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.ueficapsule), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.format.format, 'ueficapsule');
    assert.ok(p.metadata.some(m => m.key?.custom === 'capsule_guid' && m.value === '3B6686BD-0D76-4030-B70E-B5519E2FC5A0'));
  });
}
