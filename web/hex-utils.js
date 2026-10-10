export const hx = (n, width = 8) => Math.trunc(n).toString(16).toUpperCase().padStart(width, '0');
const ENC = [['ascii', 'ascii'], ['latin1', 'latin-1'], ['cp437', 'cp437 (dos)'], ['ebcdic', 'ebcdic (cp037)'], ['utf16le', 'utf-16le'], ['utf16be', 'utf-16be']];
const CP437_LO = Array.from('·☺☻♥♦♣♠•◘○◙♂♀♪♫☼►◄↕‼¶§▬↨↑↓→←∟↔▲▼');
const CP437_HI = Array.from('ÇüéâäàåçêëèïîìÄÅ' + 'ÉæÆôöòûùÿÖÜ¢£¥₧ƒ' + 'áíóúñÑªº¿⌐¬½¼¡«»' + '░▒▓│┤╡╢╖╕╣║╗╝╜╛┐' + '└┴┬├─┼╞╟╚╔╩╦╠═╬╧' + '╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀' + 'αßΓπΣσµτΦΘΩδ∞φε∩' + '≡±≥≤⌠⌡÷≈°∙·√ⁿ²■\u00A0');
const EBC = ["\u0000", "\u0001", "\u0002", "\u0003", "\u009c", "\t", "\u0086", "\u007f", "\u0097", "\u008d", "\u008e", "\u000b", "\f", "\r", "\u000e", "\u000f", "\u0010", "\u0011", "\u0012", "\u0013", "\u009d", "\u0085", "\b", "\u0087", "\u0018", "\u0019", "\u0092", "\u008f", "\u001c", "\u001d", "\u001e", "\u001f", "\u0080", "\u0081", "\u0082", "\u0083", "\u0084", "\n", "\u0017", "\u001b", "\u0088", "\u0089", "\u008a", "\u008b", "\u008c", "\u0005", "\u0006", "\u0007", "\u0090", "\u0091", "\u0016", "\u0093", "\u0094", "\u0095", "\u0096", "\u0004", "\u0098", "\u0099", "\u009a", "\u009b", "\u0014", "\u0015", "\u009e", "\u001a", " ", "\u00a0", "\u00e2", "\u00e4", "\u00e0", "\u00e1", "\u00e3", "\u00e5", "\u00e7", "\u00f1", "\u00a2", ".", "<", "(", "+", "|", "&", "\u00e9", "\u00ea", "\u00eb", "\u00e8", "\u00ed", "\u00ee", "\u00ef", "\u00ec", "\u00df", "!", "$", "*", ")", ";", "\u00ac", "-", "/", "\u00c2", "\u00c4", "\u00c0", "\u00c1", "\u00c3", "\u00c5", "\u00c7", "\u00d1", "\u00a6", ",", "%", "_", ">", "?", "\u00f8", "\u00c9", "\u00ca", "\u00cb", "\u00c8", "\u00cd", "\u00ce", "\u00cf", "\u00cc", "`", ":", "#", "@", "'", "=", "\"", "\u00d8", "a", "b", "c", "d", "e", "f", "g", "h", "i", "\u00ab", "\u00bb", "\u00f0", "\u00fd", "\u00fe", "\u00b1", "\u00b0", "j", "k", "l", "m", "n", "o", "p", "q", "r", "\u00aa", "\u00ba", "\u00e6", "\u00b8", "\u00c6", "\u00a4", "\u00b5", "~", "s", "t", "u", "v", "w", "x", "y", "z", "\u00a1", "\u00bf", "\u00d0", "\u00dd", "\u00de", "\u00ae", "^", "\u00a3", "\u00a5", "\u00b7", "\u00a9", "\u00a7", "\u00b6", "\u00bc", "\u00bd", "\u00be", "[", "]", "\u00af", "\u00a8", "\u00b4", "\u00d7", "{", "A", "B", "C", "D", "E", "F", "G", "H", "I", "\u00ad", "\u00f4", "\u00f6", "\u00f2", "\u00f3", "\u00f5", "}", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "\u00b9", "\u00fb", "\u00fc", "\u00f9", "\u00fa", "\u00ff", "\\", "\u00f7", "S", "T", "U", "V", "W", "X", "Y", "Z", "\u00b2", "\u00d4", "\u00d6", "\u00d2", "\u00d3", "\u00d5", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "\u00b3", "\u00db", "\u00dc", "\u00d9", "\u00da", "\u009f"];
// returns [glyph, kind]: 2 printable, 1 control/box glyph, 0 not representable
function encChar(enc, v) {
  if (enc === 'ebcdic') { const c = EBC[v], p = c.codePointAt(0); return p >= 32 && !(p >= 127 && p < 160) ? [c, 2] : ['.', 0]; }
  if (v >= 32 && v < 127) return [String.fromCharCode(v), 2];
  if (enc === 'latin1' && v >= 0xA0) return [String.fromCharCode(v), 2];
  if (enc === 'cp437') { if (v === 0) return ['.', 0]; if (v < 32) return [CP437_LO[v], 1]; if (v === 127) return ['⌂', 1]; return [CP437_HI[v - 128] || '.', v >= 0xB0 && v < 0xE0 ? 1 : 2]; }
  return ['.', 0];
}
function parseGoto(str, cur, size) {
  let t = String(str).trim().toLowerCase().replace(/[_\s]/g, ''); if (!t) return null;
  let rel = 0; if (t[0] === '+' || t[0] === '-') { rel = t[0] === '+' ? 1 : -1; t = t.slice(1); }
  let v;
  if (/^\d+(\.\d+)?%$/.test(t)) v = Math.floor(parseFloat(t) / 100 * (size - 1));
  else if (/^0x[0-9a-f]+$/.test(t)) v = parseInt(t.slice(2), 16);
  else if (/^[0-9a-f]+h$/.test(t)) v = parseInt(t.slice(0, -1), 16);
  else if (/^\d+$/.test(t)) v = parseInt(t, 10);
  else if (/^[0-9a-f]+$/.test(t)) v = parseInt(t, 16);
  else return null;
  return rel ? cur + rel * v : v;
}
const fmtF = (x, p) => Number.isNaN(x) ? 'NaN' : !isFinite(x) ? (x > 0 ? '+inf' : '-inf') : x === 0 ? (Object.is(x, -0) ? '-0' : '0') : (Math.abs(x) >= 1e-4 && Math.abs(x) < 1e10 ? String(+x.toPrecision(p)) : x.toExponential(p > 7 ? 10 : 5));
const unixT = u => u >= 315532800 && u <= 2208988800 ? new Date(u * 1000).toISOString().slice(0, 19).replace('T', ' ') + 'Z' : '— (out of range)';
function utf8At(b) {
  for (let L = 1; L <= Math.min(4, b.length); L++) {
    try { const t = new TextDecoder('utf-8', { fatal: true }).decode(b.subarray(0, L)); if (t) { const cp = t.codePointAt(0); return cp < 0x20 || cp === 0x7F ? `U+${hx(cp, 4)} control` : `${t}  U+${hx(cp, 4)} · ${L} byte${L > 1 ? 's' : ''}`; } } catch (e) {}
  }
  return 'invalid sequence';
}

export { ENC, encChar, parseGoto, fmtF, unixT, utf8At };
