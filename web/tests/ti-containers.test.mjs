import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { before, after, test } from 'node:test';
import { setup, teardown, openPage, load, finished, selectEntry, baseUrl } from './helpers.mjs';
import { fmtFormatName, isaName } from '../format.js';
before(setup); after(teardown);

function words(values) { const b = Buffer.alloc(values.length * 4); values.forEach((v,i) => b.writeUInt32LE(v >>> 0,i*4)); return b; }
const rprc = entry => Buffer.concat([words([0x43525052,entry,0,1,1,entry,0,4,0,0]),Buffer.from([1,2,3,4])]);
const a=rprc(0x1000), b=rprc(0x2000), size=128+a.length+b.length;
const header=Buffer.alloc(128); words([0x5254534d,2,37,0,0,size,
  1,0x35510000,128,0,0,a.length,0,0,1,0xd5510000,128+a.length,0,0,b.length,0,0,0,0x444e454d]).copy(header);
const radar=Buffer.concat([header,a,b]);
const vendor = async name => readFile(new URL(`../../tests/fixtures/ti/${name}`,import.meta.url));
const boot=Buffer.from('08aa00000000000000000000000000000000003f00000001003f000012340000','hex');
function oad() {
  const v=Buffer.alloc(64,255);v.write('CC26x2R1');v.writeUInt32LE(64,24);v.writeUInt32LE(0x1000,28);v.writeUInt16LE(44,40);
  v[18]=1;v[44]=1;v.writeUInt32LE(20,48);v.writeUInt32LE(0x1000,52);v.fill(0x12,56);return v;
}
function tek(type,address,bytes) {
  const data=`8${address.toString(16).padStart(8,'0')}${bytes.toString('hex')}`.toUpperCase();
  const prefix=`${(data.length+5).toString(16).padStart(2,'0')}${type}`.toUpperCase();
  const checksum=[...prefix+data].reduce((n,c)=>n+parseInt(c,16),0)&255;
  return `%${prefix}${checksum.toString(16).padStart(2,'0')}${data}\n`;
}
async function matrix() {
  const mcuboot=Buffer.alloc(36);mcuboot.writeUInt32LE(0x96f3b83d);mcuboot.writeUInt16LE(32,8);mcuboot.writeUInt32LE(4,12);mcuboot.writeUInt32LE(4,16);
  const fip=Buffer.alloc(96+a.length);fip.writeUInt32LE(0xaa640001);fip.writeUInt32LE(12345678,4);
  fip.set(Buffer.from('d6d0eea7fcead54b97829934f234b6e4','hex'),16);fip.writeBigUInt64LE(96n,32);fip.writeBigUInt64LE(BigInt(a.length),40);fip.writeBigUInt64LE(BigInt(fip.length),72);a.copy(fip,96);
  const body='90000B1234*567';const sum=[...body].reduce((n,c)=>n+c.charCodeAt(0),0);
  return [
    ['tiboot',boot],['tiais',words([0x41504954,0x58535906,0x1000])],['tirprc',a],['timulticore',await vendor('vendor.appimage')],
    ['timcelf',await vendor('vendor.mcelf')],['tiimage',Buffer.concat([words([16,0x80000000]),Buffer.alloc(16,0x42)])],
    ['tioad',oad()],['tix509',await vendor('vendor.signed')],['tiasciihex',Buffer.from(`\x02${[...boot].map(b=>b.toString(16).padStart(2,'0')).join(' ')}\x03`)],
    ['titagged',Buffer.from(`KfixtureF\n${body}${((-sum)&65535).toString(16).padStart(4,'0').toUpperCase()}F\n:\n`)],
    ['titekhex',Buffer.from(tek(6,0x1000,Buffer.from([1,2,3]))+tek(8,0x1000,Buffer.alloc(0)))],
    ['mcuboot',mcuboot],['fip',fip],['tidata',Buffer.from('1651 1 800 1 2\n0x1234\n0x5678\n')],
  ];
}
for (const module of ['/pkg/zrax.js','/dist/zrax.js']) {
  test(`all additional TI/shared format IDs survive WASM serialization from ${module}`,async t=>{
    const page=await openPage(t);await page.goto(baseUrl+'/web/index.html');
    const fixtures=(await matrix()).map(([format,bytes])=>({format,bytes:[...bytes]}));
    const payloads=await page.evaluate(async ({module,fixtures})=>{
      const wasm=await import(module);await wasm.default();
      return fixtures.map(f=>JSON.parse(wasm.classify(new Uint8Array(f.bytes))));
    },{module,fixtures});
    for (let i=0;i<fixtures.length;i++) {
      const p=payloads[i];assert.ok(!p.error,`${fixtures[i].format}: ${p.error}`);assert.equal(p.format.format,fixtures[i].format);
      assert.notEqual(fmtFormatName(p.format.format),p.format.format.toUpperCase());
      if (['mcuboot','tidata'].includes(fixtures[i].format)) {assert.deepEqual(p.primary.isa,{unknown:0});assert.deepEqual(p.candidates,[]);}
    }
    assert.equal(payloads[0].primary.isa,'ti_c28x');assert.equal(payloads[8].primary.isa,'ti_c28x');
    const malformed=await page.evaluate(async module=>{const w=await import(module);return JSON.parse(w.classify(new Uint8Array([84,73,80,65])));},module);
    assert.match(malformed.error,/TI container parse error/);
  });
}
for (const path of ['/web/index.html','/dist/index.html','/web/classic/index.html','/dist/classic/index.html']) {
  test(`radar roles and TI-generated wrappers display component metadata in ${path}`,async t=>{
    const page=await openPage(t);const classic=path.includes('/classic/');
    if (classic) {await page.goto(baseUrl+path);await page.waitForFunction(()=>document.getElementById('version').textContent.startsWith('v'));}
    else await load(page,path);
    const files=[['radar.bin',radar],['signed.bin',await vendor('vendor.signed')],['multicore.elf',await vendor('vendor.mcelf')]];
    await page.locator('#fileinput').setInputFiles(files.map(([name,buffer])=>({name,buffer,mimeType:'application/octet-stream'})));
    await finished(page,3);
    for (let i=0;i<files.length;i++) {
      await selectEntry(page,i);const content=page.locator(classic?'#results':'#classification-content');
      assert.match(await content.textContent(),new RegExp(['TI Multicore Appimage','TI X.509 Boot Image','TI Multicore ELF'][i].replaceAll('.','\\.')));
      if (classic) await page.getByRole('button',{name:'Raw JSON'}).click();else await page.getByRole('tab',{name:'json',exact:true}).click();
      const p=JSON.parse(await page.locator('#jsonRaw').textContent());
      if (i===0) {assert.equal(p.primary.isa,'arm');assert.deepEqual(p.slices.map(s=>s.isa),['arm','ti_c6000']);assert.equal(p.slices[1].offset,172);assert.deepEqual(p.candidates,[]);}
      else if (i===1) {assert.equal(p.slices[0].label,'Boot image');assert.ok(p.notes.some(n=>n.message.includes('not authenticated')));}
      else {assert.deepEqual(p.slices.map(s=>s.label),['Core 4 code segment','Core 14 code segment']);assert.ok(p.metadata.some(m=>m.label==='Core 14 code segment'));}
    }
    assert.equal(isaName('ti_c5400'),'TI C54x');
  });
}
