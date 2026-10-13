import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { FORMAT_NAMES } from '../format.js';
import { e32Image, CPU_X86, COMPRESSION_DEFLATE, V_FLAGS, V_HEADER_SIZE } from './e32-image.mjs';
before(setup);
after(teardown);

// Compiled little-endian 32-bit Arm code from the repository's testbins.
const ARM_CODE = '../../testbins/arm32_arm-unknown-linux-gnueabi_O0_call_nested.bin';
const armCode = () => readFile(new URL(ARM_CODE, import.meta.url));

const UID3 = 0xa0001234;

// Three V images: ARMv5 code, an x86 image (no ABI or entry point bits), and an ARM image whose 512 B code part is
// stored as 64 B of Symbian deflate data.
async function fixtures() {
  const arm = e32Image({ uid3: UID3, code: await armCode() });
  const x86 = e32Image({ uid3: UID3, code: Buffer.alloc(64), cpu: CPU_X86, flags: V_FLAGS });
  const stored = Buffer.from(Array.from({ length: 64 }, (_, i) => (i * 37 + 11) & 0xff));
  const compressed = e32Image({ uid3: UID3, compression: COMPRESSION_DEFLATE, stored, codeSize: 512 });
  return { arm, x86, compressed };
}

for (const module of ['/pkg/zrax.js', '/dist/zrax.js']) {
  test(`Symbian E32 images take their ISA from the CPU identifier through ${module}`, async t => {
    const page = await openPage(t);
    await page.goto(baseUrl + '/web/index.html');
    const images = await fixtures();
    const payloads = await page.evaluate(async ({ module, inputs }) => {
      const wasm = await import(module);
      await wasm.default();
      return inputs.map(bytes => JSON.parse(wasm.classify(new Uint8Array(bytes))));
    }, { module, inputs: [[...images.arm], [...images.x86], [...images.compressed]] });
    const [arm, x86, compressed] = payloads;
    assert.ok(Object.hasOwn(FORMAT_NAMES, 'epoc'), 'epoc has a display name');
    for (const p of payloads) {
      assert.ok(!p.error, p.error);
      assert.equal(p.format.format, 'epoc');
      assert.ok(p.notes.some(n => / UID checksum 0x[0-9A-F]{8} matches$/.test(n.message)));
      assert.ok(p.notes.some(n => /^Header CRC-32 0x[0-9A-F]{8} matches \(over 156 B\)$/.test(n.message)));
    }

    assert.deepEqual([arm.primary.isa, arm.primary.bitwidth, arm.primary.endianness], ['arm', 32, 'little']);
    assert.equal(arm.primary.variant?.name, 'ARMv5');
    assert.ok(arm.notes.some(n => n.message === 'CPU 0x2001 (ECpuArmV5): 32-bit little-endian ARM'));
    assert.ok(arm.metadata.some(m => m.key?.custom === 'epoc_header_format' && m.value === 'V'));

    assert.deepEqual([x86.primary.isa, x86.primary.bitwidth], ['x86', 32]);
    assert.equal(x86.primary.variant?.name, 'x86');

    assert.equal(compressed.primary.isa, 'arm');
    assert.equal(compressed.slices.length, 1);
    const contents = compressed.slices.find(s => s.label === 'Compressed contents');
    assert.ok(contents, 'compressed contents slice');
    assert.deepEqual([contents.offset, contents.size], [V_HEADER_SIZE, 64]);
    assert.ok(compressed.notes.some(n => n.message.startsWith('Contents compressed with Symbian deflate (0x101F7AFC)')));
  });
}

for (const path of ['/web/index.html', '/dist/index.html']) {
  test(`the workbench names Symbian E32 images in ${path}`, async t => {
    const page = await openPage(t);
    await load(page, path);
    const { arm } = await fixtures();
    await page.locator('#fileinput').setInputFiles([{ name: 'hello.exe', buffer: arm, mimeType: 'application/octet-stream' }]);
    await finished(page, 1);
    await selectEntry(page, 0);
    const content = await page.locator('#classification-content').textContent();
    assert.ok(content.includes(FORMAT_NAMES.epoc), content);
    await page.getByRole('tab', { name: 'json', exact: true }).click();
    const p = JSON.parse(await page.locator('#jsonRaw').textContent());
    assert.equal(p.primary.isa, 'arm');
    assert.ok(p.metadata.some(m => m.key?.custom === 'epoc_image_size' && m.value === arm.length));
  });
}
