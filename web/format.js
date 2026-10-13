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
  ti_c6000: 'TI C6000', ti_c2000: 'TI C2000', ti_c28x: 'TI C28x', ti_c5500: 'TI C55x', ti_c5400: 'TI C54x', ti_pru: 'TI PRU',
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
  if (e === 'biendian' || e === 'bi_endian') return 'Bi-endian';
  return String(e);
}

// Short byte-order word for compact rows: 'little', 'big' or 'bi-endian'.
const fmtEndianShort = e => (e === 'biendian' || e === 'bi_endian' ? 'bi-endian' : String(e));

function fmtSource(s) {
  const m = { file_format: 'File format', heuristic: 'Heuristic', combined: 'Combined', user_specified: 'User specified' };
  return m[s] || String(s);
}

const FORMAT_NAMES = {
  elf: 'ELF', pe: 'PE', mach_o: 'Mach-O', macho: 'Mach-O', mach_o_fat: 'Mach-O Fat', machofat: 'Mach-O Fat',
  coff: 'COFF', xcoff: 'XCOFF', ecoff: 'ECOFF',
  ols: 'OLS Project', epr: 'EPR Dump', sgo: 'SGO', vbf: 'VBF', frf: 'FRF', bcf: 'BCF', sox: 'SOX',
  d10: 'AOR D10', tic55xboot: 'TI C55x Boot Table', raw: 'Raw Binary',
  tiboot: 'TI ROM Boot Table', tiais: 'TI AIS', tirprc: 'TI RPRC',
  timulticore: 'TI Multicore Appimage', timcelf: 'TI Multicore ELF', tiimage: 'TI GP ROM Image',
  tioad: 'TI OAD', tix509: 'TI X.509 Boot Image', tiasciihex: 'TI ASCII Hex',
  titagged: 'TI SDSMAC Tagged', titekhex: 'Extended Tektronix', mcuboot: 'MCUboot',
  fip: 'TF-A Firmware Image Package', tidata: 'CCS GO DSP Data',
  aout: 'a.out', plan9_aout: 'Plan 9 a.out', plan9aout: 'Plan 9 a.out', minix_aout: 'Minix a.out', minixaout: 'Minix a.out',
  mz: 'MZ/DOS', ne: 'NE', le: 'LE', lx: 'LX', com: 'COM', omf: 'OMF', pef: 'PEF',
  intel_hex: 'Intel HEX', intelhex: 'Intel HEX', srec: 'S-record', ti_txt: 'TI-TXT', titxt: 'TI-TXT',
  bflt: 'bFLT', dxe: 'DXE', zimage: 'Linux Kernel Image', uimage: 'U-Boot uImage', fit: 'U-Boot FIT', dtb: 'Device Tree Blob', goff: 'GOFF', mvs_load: 'MVS Load', mvsload: 'MVS Load', som: 'SOM',
  rsx11: 'RSX-11', vms: 'VMS',
  gzip: 'gzip', zlib: 'zlib', xz: 'xz', lzma: 'LZMA', lz4: 'LZ4', zstd: 'Zstandard', bzip2: 'bzip2',
  lzop: 'lzop', lzfse: 'LZFSE', lzss: 'Apple LZSS',
  tds: 'TDS', aof: 'AOF/AXF', epoc: 'EPOC', espfirmware: 'ESP Firmware', palmpdb: 'Palm PDB/PRC', amigahunk: 'Amiga Hunk',
  os9: 'OS-9', snesspc: 'SNES SPC', tmobj: 'TriMedia TMObj', dsplod: 'Motorola DSP LOD', ieee695: 'IEEE-695',
  wasm: 'WebAssembly', javaclass: 'Java Class', dex: 'DEX', odex: 'ODEX', vdex: 'VDEX', art: 'ART', llvmbc: 'LLVM Bitcode',
  fatelf: 'FatELF', archive: 'ar Archive', windowslib: 'Windows .lib', xbe: 'XBE', xex: 'XEX', selfps3: 'PS3 SELF',
  selfps4: 'PS4 SELF', selfps5: 'PS5 SELF', nso: 'NSO', nro: 'NRO', dol: 'DOL', rel: 'REL',
  odx: 'ASAM ODX', hondarwd: 'Honda RWD', toyotacuw: 'Toyota CUW', mercedescff: 'Mercedes CFF',
  nsf: 'NES Sound Format', sid: 'C64 SID Tune', gbs: 'Game Boy Sound System',
  blackfinldr: 'Blackfin LDR', pcioptionrom: 'Option ROM', huaweiupdate: 'Huawei UPDATE.APP',
  zxtape: 'ZX Spectrum Tape',
  xilinxbit: 'Xilinx bitstream', latticebitstream: 'Lattice bitstream', intelfpga: 'Intel FPGA configuration',
  uf2: 'UF2', dfuse: 'STM32 DfuSe', gbl: 'Silicon Labs GBL', cyacd: 'Cypress CYACD',
  allwinneregon: 'Allwinner eGON', rockchipimage: 'Rockchip image', mediatekpreloader: 'MediaTek preloader', qualcommmbn: 'Qualcomm MBN',
  genesisrom: 'Mega Drive ROM', psxexe: 'PS-X EXE', dreamcastip: 'Dreamcast IP.BIN', wiiurpx: 'Wii U RPX/RPL', n3dsncch: '3DS NCCH', n3ds3dsx: '3DSX', psppbp: 'PSP PBP',
  img4: 'Apple IMG4', im4p: 'Apple IM4P', dyldcache: 'dyld shared cache',
  androidboot: 'Android boot image', androidvendorboot: 'Android vendor_boot image', androidsparse: 'Android sparse image', androidota: 'Android OTA payload', androidbootloader: 'Android bootloader pack',
  xilinxbootbin: 'Xilinx BOOT.BIN', imximage: 'NXP i.MX Image', nxpsb: 'NXP Secure Binary',
  ndsrom: 'Nintendo DS ROM', gbarom: 'Game Boy Advance ROM', gbrom: 'Game Boy ROM', nesrom: 'NES ROM', snesrom: 'SNES ROM', n64rom: 'Nintendo 64 ROM',
  zip: 'ZIP', tar: 'tar', cpio: 'CPIO',
  squashfs: 'SquashFS', cramfs: 'CramFS', romfs: 'romfs',
  ubi: 'UBI', ubifs: 'UBIFS', jffs2: 'JFFS2',
  ext: 'ext filesystem',
  uefifv: 'UEFI Firmware Volume', uefite: 'UEFI TE Image', intelifd: 'Intel Flash Descriptor',
  fmap: 'Chromium FMAP', cbfs: 'coreboot CBFS',
  trx: 'Broadcom TRX', netgearchk: 'Netgear CHK', seama: 'D-Link SEAMA', tplink: 'TP-Link firmware',
  espflash: 'ESP flash dump',
  qnxifs: 'QNX IFS',
  winceimage: 'Windows CE image',
  psf: 'PSF', hes: 'HES', kss: 'KSS', sap: 'SAP', aytune: 'AY tune', sndh: 'SNDH', packice: 'Pack-Ice',
  intelmicrocode: 'Intel microcode', amdmicrocode: 'AMD microcode', intelme: 'Intel ME firmware', amdpsp: 'AMD PSP firmware',
  opteeimage: 'OP-TEE image', amlogicupgrade: 'Amlogic burning image', allwinnerimage: 'Allwinner IMAGEWTY', bareboximage: 'barebox image', img3: 'Apple Img3', apple8900: 'Apple 8900',
  smsrom: 'Master System ROM', sega32xrom: 'Sega 32X ROM', saturnip: 'Saturn IP.BIN', segacdip: 'Sega CD system area', msxrom: 'MSX ROM', lynxrom: 'Atari Lynx ROM', atari7800rom: 'Atari 7800 ROM', c64crt: 'C64 cartridge', ataristprg: 'Atari ST program', zxsnapshot: 'ZX Spectrum snapshot', wonderswanrom: 'WonderSwan ROM', ngprom: 'Neo Geo Pocket ROM',
  androidsuper: 'Android super image', androiddtbo: 'Android DTBO image', androidvbmeta: 'AVB vbmeta image', erofs: 'EROFS',
  mbr: 'MBR partition table', gpt: 'GPT partition table', applepartitionmap: 'Apple Partition Map',
  fat: 'FAT filesystem', exfat: 'exFAT filesystem',
  iso9660: 'ISO 9660',
  gamecubedisc: 'GameCube disc', wiidisc: 'Wii disc', xboxdvd: 'Xbox DVD (XDVDFS)',
  jimage: 'Java jimage', jmod: 'JMOD',
  dfusuffix: 'USB DFU file', silabsebl: 'Silicon Labs EBL', nordicinitpacket: 'Nordic DFU init packet',
  minidump: 'Windows minidump', windowskerneldump: 'Windows kernel dump',
  netwarenlm: 'NetWare NLM',
  geosgeode: 'PC/GEOS geode',
  psyqobject: 'PsyQ object',
  armaif: 'ARM AIF',
  symbiansis: 'Symbian SIS package',
  ueficapsule: 'UEFI capsule',
  qcow2: 'QCOW2 disk image', vmdk: 'VMDK disk image', vhd: 'VHD disk image', vhdx: 'VHDX disk image', vdi: 'VDI disk image',
  gcz: 'GCZ disc image', ciso: 'CISO disc image', wbfs: 'WBFS image', cso: 'CSO disc image',
  d64: 'D64 disk image', d71: 'D71 disk image', d81: 'D81 disk image', t64: 'T64 tape image',
  adf: 'Amiga disk image (ADF)', amigahdf: 'Amiga hard disk image',
  atr: 'Atari ATR disk image', atarixex: 'Atari binary load file',
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

export { esc, fmtSize, isaName, fmtEndian, fmtEndianShort, fmtSource, fmtFormatName, fmtFormat, fmtVariant, fmtMetaValue, fmtCat, fmtExtSrc, FORMAT_NAMES };
