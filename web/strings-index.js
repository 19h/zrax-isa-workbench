// Columnar store, filters, sorting, region lookup and export for the strings
// tab. Pure module: no DOM, so the scan worker and Node tests share it.

// Bits of the packed per-string flags word.
const ENCODING_MASK = 0x3;
const CLIPPED = 0x4;
const TAG_SHIFT = 8;

// Regions recorded per elementary interval; deeper nesting is not listed.
const MAX_REGION_DEPTH = 64;

export const SORT_KEYS = ['offset', 'region', 'encoding', 'chars', 'size', 'tags', 'text'];

/** Count of set bits in a 16-bit tag mask. */
function bitCount(value) {
  let count = 0;
  for (let rest = value; rest; rest &= rest - 1) count++;
  return count;
}

/** Grow a typed array to at least `size` elements, keeping its contents. */
function grown(array, size) {
  if (array.length >= size) return array;
  const next = new array.constructor(Math.max(size, array.length * 2, 1024));
  next.set(array);
  return next;
}

/**
 * Strings of one file in scan order (by offset, then encoding). Rows come
 * from the WASM scanner as `[offset, size, chars, encoding, tags, clipped,
 * text]`; `encoding` indexes `encodingIds` and `tags` holds tag bits.
 */
export class StringIndex {
  constructor(encodingIds, tagIds) {
    this.encodingIds = encodingIds;
    this.tagIds = tagIds;
    this.length = 0;
    this.textChars = 0;
    this.offsets = new Float64Array(0);
    this.sizes = new Float64Array(0);
    this.chars = new Float64Array(0);
    this.flags = new Uint32Array(0);
    this.texts = [];
    this.lowered = [];
    this.regionOf = null;
    this.regions = [];
  }

  /** Append scanner rows; at most `limit` strings are kept in total. */
  append(rows, limit = Infinity) {
    const room = Math.max(0, Math.min(rows.length, limit - this.length));
    const size = this.length + room;
    this.offsets = grown(this.offsets, size);
    this.sizes = grown(this.sizes, size);
    this.chars = grown(this.chars, size);
    this.flags = grown(this.flags, size);
    for (let i = 0; i < room; i++) {
      const [offset, bytes, chars, encoding, tags, clipped, text] = rows[i];
      const at = this.length + i;
      this.offsets[at] = offset;
      this.sizes[at] = bytes;
      this.chars[at] = chars;
      this.flags[at] = (encoding & ENCODING_MASK) | (clipped ? CLIPPED : 0) | (tags << TAG_SHIFT);
      this.texts.push(text);
      this.textChars += text.length;
    }
    this.length = size;
    this.regionOf = null;
    return room;
  }

  encoding(i) {
    return this.flags[i] & ENCODING_MASK;
  }

  tags(i) {
    return this.flags[i] >>> TAG_SHIFT;
  }

  clipped(i) {
    return (this.flags[i] & CLIPPED) !== 0;
  }

  lower(i) {
    let text = this.lowered[i];
    if (text === undefined) {
      text = this.texts[i].toLowerCase();
      this.lowered[i] = text;
    }
    return text;
  }

  /** The row as an object for the grid and the inspector. */
  row(i) {
    return {
      index: i,
      offset: this.offsets[i],
      size: this.sizes[i],
      chars: this.chars[i],
      encoding: this.encodingIds[this.encoding(i)],
      tags: this.tagIds.filter(([bit]) => this.tags(i) & bit).map(([, id]) => id),
      clipped: this.clipped(i),
      text: this.texts[i],
      region: this.region(i),
    };
  }

  /**
   * Use `regions` (sorted by offset, enclosing first, as the engine reports
   * them) for region lookups. Each string gets the smallest region that
   * contains all of its bytes.
   */
  setRegions(regions) {
    this.regions = regions || [];
    this.regionOf = null;
  }

  region(i) {
    if (!this.regions.length) return -1;
    if (!this.regionOf || this.regionOf.length < this.length) this.regionOf = this.locateRegions();
    return this.regionOf[i];
  }

  /**
   * Innermost containing region per string. Region boundaries split the
   * file into elementary intervals; each interval lists the regions that
   * cover it, smallest first, so a lookup is a binary search plus a short
   * walk. Time O(p * r + n log p) for p boundaries, r regions, n strings.
   */
  locateRegions() {
    const regions = this.regions;
    const points = [...new Set(regions.flatMap(r => [r.offset, r.offset + r.size]))].sort((a, b) => a - b);
    const covering = [];
    for (let k = 0; k + 1 < points.length; k++) {
      const start = points[k];
      const end = points[k + 1];
      const list = [];
      for (let r = 0; r < regions.length && list.length < MAX_REGION_DEPTH; r++) {
        if (regions[r].offset <= start && regions[r].offset + regions[r].size >= end) list.push(r);
      }
      list.sort((a, b) => regions[a].size - regions[b].size);
      covering.push(list);
    }
    const result = new Int32Array(this.length).fill(-1);
    for (let i = 0; i < this.length; i++) {
      const start = this.offsets[i];
      const end = start + this.sizes[i];
      let low = 0;
      let high = points.length - 2;
      let found = -1;
      while (low <= high) {
        const middle = (low + high) >> 1;
        if (points[middle] <= start) {
          found = middle;
          low = middle + 1;
        } else {
          high = middle - 1;
        }
      }
      if (found < 0 || found >= covering.length) continue;
      const match = covering[found].find(r => regions[r].offset + regions[r].size >= end);
      if (match !== undefined) result[i] = match;
    }
    return result;
  }
}

/**
 * A predicate for one query, or an `error` message for an invalid regular
 * expression. The predicate tests `base` conditions (text, length, scope)
 * and the facet chips separately, so counts can ignore the chips.
 */
export function compileQuery(spec) {
  const search = spec.search || '';
  let matchesText = () => true;
  if (search && spec.regex) {
    let pattern;
    try {
      // No `u` flag: it rejects common identity escapes such as `\-`.
      pattern = new RegExp(search, spec.caseSensitive ? '' : 'i');
    } catch (error) {
      return { error: `Invalid regular expression: ${error.message}` };
    }
    matchesText = (index, i) => pattern.test(index.texts[i]);
  } else if (search && spec.caseSensitive) {
    matchesText = (index, i) => index.texts[i].includes(search);
  } else if (search) {
    const needle = search.toLowerCase();
    matchesText = (index, i) => index.lower(i).includes(needle);
  }
  const minChars = spec.minChars || 0;
  const range = spec.range || null;
  const region = Number.isInteger(spec.region) ? spec.region : -1;
  const base = (index, i) => {
    if (index.chars[i] < minChars) return false;
    if (range && (index.offsets[i] < range.start || index.offsets[i] + index.sizes[i] > range.end)) return false;
    if (region >= 0 && !regionContains(index, region, i)) return false;
    return matchesText(index, i);
  };
  const encodings = spec.encodings ?? 0xf;
  const tags = spec.tags || 0;
  const facets = (index, i) => {
    if (!(encodings & (1 << index.encoding(i)))) return false;
    return !tags || (index.tags(i) & tags) !== 0;
  };
  return { base, facets };
}

function regionContains(index, region, i) {
  const r = index.regions[region];
  return Boolean(r) && index.offsets[i] >= r.offset && index.offsets[i] + index.sizes[i] <= r.offset + r.size;
}

/**
 * Filter rows `from` to `to` (exclusive) into `matches`, updating facet
 * `counts` ({ encodings: number[], tags: Map<bit, number> }) for rows that
 * pass the base conditions. Callers run this in slices and yield between.
 */
export function filterRange(index, query, from, to, matches, counts) {
  for (let i = from; i < to; i++) {
    if (!query.base(index, i)) continue;
    counts.encodings[index.encoding(i)]++;
    const tags = index.tags(i);
    for (const [bit] of index.tagIds) if (tags & bit) counts.tags.set(bit, (counts.tags.get(bit) || 0) + 1);
    if (query.facets(index, i)) matches.push(i);
  }
}

export function emptyCounts(index) {
  return { encodings: index.encodingIds.map(() => 0), tags: new Map(index.tagIds.map(([bit]) => [bit, 0])) };
}

/** Sort matching row indices; ties keep scan order (offset, encoding). */
export function sortView(index, view, sort) {
  const direction = sort?.dir === 'desc' ? -1 : 1;
  const key = sort?.key || 'offset';
  if (key === 'offset') return direction === 1 ? view : view.reverse();
  const label = i => index.regions[index.region(i)]?.label || '';
  const compare = {
    region: (a, b) => label(a).localeCompare(label(b)),
    encoding: (a, b) => index.encoding(a) - index.encoding(b),
    chars: (a, b) => index.chars[a] - index.chars[b],
    size: (a, b) => index.sizes[a] - index.sizes[b],
    tags: (a, b) => bitCount(index.tags(a)) - bitCount(index.tags(b)) || index.tags(a) - index.tags(b),
    text: (a, b) => (index.texts[a] < index.texts[b] ? -1 : index.texts[a] > index.texts[b] ? 1 : 0),
  }[key];
  if (!compare) return view;
  return view.sort((a, b) => direction * compare(a, b) || a - b);
}

/** A CSV field, quoted when it contains a quote, comma or line break. */
export function csvField(value) {
  const text = String(value ?? '');
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

/** Export parts for a Blob: `txt` (one text per line), `csv` or `json`. */
export function exportParts(index, view, format) {
  const parts = [];
  if (format === 'csv') parts.push('offset,size,chars,encoding,tags,clipped,region,text\r\n');
  if (format === 'json') parts.push('[');
  view.forEach((i, position) => {
    const row = index.row(i);
    const region = index.regions[row.region]?.label || '';
    if (format === 'txt') {
      parts.push(`${row.text}\n`);
    } else if (format === 'csv') {
      const fields = [row.offset, row.size, row.chars, row.encoding, row.tags.join(';'), row.clipped, region, row.text];
      parts.push(`${fields.map(csvField).join(',')}\r\n`);
    } else {
      const record = {
        offset: row.offset,
        size: row.size,
        chars: row.chars,
        encoding: row.encoding,
        tags: row.tags,
        clipped: row.clipped,
        region: region || null,
        text: row.text,
      };
      parts.push(`${position ? ',' : ''}\n${JSON.stringify(record)}`);
    }
  });
  if (format === 'json') parts.push('\n]\n');
  return parts;
}
