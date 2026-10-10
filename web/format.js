function esc(s) {
  if (s == null) return '';
  const entities = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  return String(s).replace(/[&<>"']/g, c => entities[c]);
}

function fmtSize(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1073741824) return `${(n / 1048576).toFixed(2)} MiB`;
  return `${(n / 1073741824).toFixed(2)} GiB`;
}

const ISA_NAMES = {
  x86: 'x86', x86_64: 'x86-64', arm: 'ARM', aarch64: 'AArch64', a_arch64: 'AArch64',
  risc_v32: 'RISC-V 32', risc_v64: 'RISC-V 64', risc_v128: 'RISC-V 128',
  mips: 'MIPS', mips64: 'MIPS64', ppc: 'PowerPC', ppc64: 'PowerPC 64',
  s390: 'S/390', s390x: 'z/Architecture', sparc: 'SPARC', sparc64: 'SPARC64',
  m68k: 'Motorola 68K', cold_fire: 'ColdFire', sh: 'SuperH', sh4: 'SH-4',
  ia64: 'Itanium', alpha: 'Alpha', parisc: 'PA-RISC',
  loong_arch32: 'LoongArch 32', loong_arch64: 'LoongArch 64',
  hexagon: 'Hexagon', arc: 'ARC', arc_compact: 'ARC Compact', arc_compact2: 'ARCv2 Compact',
  xtensa: 'Xtensa', micro_blaze: 'MicroBlaze', nios2: 'Nios II', open_risc: 'OpenRISC',
  lanai: 'Lanai', csky: 'C-SKY', v850: 'V850', rh850: 'RH850',
  k78k0r: '78K0R', rx: 'RX',
  ti_c6000: 'TI C6000', ti_c2000: 'TI C2000', ti_c28x: 'TI C28x', ti_c5500: 'TI C5500', ti_pru: 'TI PRU',
  blackfin: 'Blackfin', sharc: 'SHARC',
  avr: 'AVR', avr32: 'AVR32', msp430: 'MSP430', pic: 'PIC', stm8: 'STM8',
  tricore: 'TriCore', hcs12: 'HCS12', s12z: 'S12Z', hc11: '68HC11', c166: 'C166', rl78: 'RL78',
  amd_gpu: 'AMD GPU', cuda: 'CUDA', bpf: 'BPF',
  i860: 'i860', i960: 'i960', vax: 'VAX', pdp11: 'PDP-11',
  z80: 'Z80', mcs6502: '6502',
  wasm: 'WebAssembly', jvm: 'JVM', dalvik: 'Dalvik',
  ppc_vle: 'PowerPC VLE', cell_spu: 'Cell SPU',
};

function isaName(tag) {
  if (typeof tag === 'object') {
    const id = tag.unknown ?? tag.Unknown;
    if (id != null) return `Unknown (0x${Number(id).toString(16).toUpperCase()})`;
    return JSON.stringify(tag);
  }
  return ISA_NAMES[tag] || String(tag).replace(/_/g, ' ');
}

function fmtEndian(e) {
  if (e === 'little') return 'Little-endian';
  if (e === 'big') return 'Big-endian';
  if (e === 'bi_endian') return 'Bi-endian';
  return String(e);
}

function fmtSource(s) {
  const m = { file_format: 'File format', heuristic: 'Heuristic', combined: 'Combined', user_specified: 'User specified' };
  return m[s] || String(s);
}

const FORMAT_NAMES = {
  elf: 'ELF', pe: 'PE', mach_o: 'Mach-O', macho: 'Mach-O', mach_o_fat: 'Mach-O Fat', machofat: 'Mach-O Fat',
  coff: 'COFF', xcoff: 'XCOFF', ecoff: 'ECOFF',
  ols: 'OLS Project', epr: 'EPR Dump', sgo: 'SGO', vbf: 'VBF', frf: 'FRF', bcf: 'BCF', sox: 'SOX',
  d10: 'AOR D10', raw: 'Raw Binary',
  aout: 'a.out', plan9_aout: 'Plan 9 a.out', plan9aout: 'Plan 9 a.out', minix_aout: 'Minix a.out', minixaout: 'Minix a.out',
  mz: 'MZ/DOS', ne: 'NE', le: 'LE', lx: 'LX', com: 'COM', omf: 'OMF', pef: 'PEF',
  intel_hex: 'Intel HEX', intelhex: 'Intel HEX', srec: 'S-record', ti_txt: 'TI-TXT', titxt: 'TI-TXT',
  bflt: 'bFLT', dxe: 'DXE', goff: 'GOFF', mvs_load: 'MVS Load', mvsload: 'MVS Load', som: 'SOM',
  rsx11: 'RSX-11', vms: 'VMS',
};

function fmtFormatName(f) { return FORMAT_NAMES[f] || String(f).toUpperCase(); }

function fmtFormat(fmt) {
  let s = fmtFormatName(fmt.format);
  if (fmt.variant_name) s += ` (${fmt.variant_name})`;
  return s;
}

function fmtVariant(v) {
  if (!v) return '';
  let s = v.name || '';
  if (v.profile) s += ` / ${v.profile}`;
  if (v.abi) s += ` [${v.abi}]`;
  return s;
}

function fmtMetaValue(m) {
  const v = m.value;
  if (typeof v === 'number') {
    const hexKeys = ['entry_point', 'flags', 'raw_machine'];
    if (hexKeys.includes(m.key)) return '0x' + v.toString(16).toUpperCase();
    return v.toLocaleString();
  }
  if (typeof v === 'string') return v;
  return JSON.stringify(v);
}

function fmtCat(c) {
  const m = {
    simd: 'SIMD', crypto: 'Crypto', atomic: 'Atomic', floating_point: 'FP',
    bit_manip: 'Bit manip', virtualization: 'Virt', security: 'Security',
    transactional: 'Transactional', machine_learning: 'ML',
    compressed: 'Compressed', system: 'System', other: 'Other',
  };
  return m[c] || String(c);
}

function fmtExtSrc(s) {
  const m = { code_pattern: 'code pattern', format_attribute: 'format attr', variant_implied: 'variant implied' };
  return m[s] || String(s);
}

export { esc, fmtSize, isaName, fmtEndian, fmtSource, fmtFormatName, fmtFormat, fmtVariant, fmtMetaValue, fmtCat, fmtExtSrc };
