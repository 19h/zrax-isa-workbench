/* Synthetic, freestanding C used only to produce realistic machine code for
 * the transform tests. Compiled by generate.sh; not part of the crate. */
typedef unsigned int u32;
typedef unsigned char u8;

static u32 table[256];

void crc_init(void) {
    for (u32 i = 0; i < 256; i++) {
        u32 c = i;
        for (int k = 0; k < 8; k++)
            c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
        table[i] = c;
    }
}

u32 crc32(const u8 *p, u32 n) {
    u32 c = 0xFFFFFFFFu;
    while (n--)
        c = table[(c ^ *p++) & 0xFF] ^ (c >> 8);
    return ~c;
}

static void swap(int *a, int *b) { int t = *a; *a = *b; *b = t; }

void quicksort(int *v, int lo, int hi) {
    while (lo < hi) {
        int p = v[(lo + hi) / 2], i = lo, j = hi;
        while (i <= j) {
            while (v[i] < p) i++;
            while (v[j] > p) j--;
            if (i <= j) swap(&v[i++], &v[j--]);
        }
        if (j - lo < hi - i) { quicksort(v, lo, j); lo = i; }
        else { quicksort(v, i, hi); hi = j; }
    }
}

u32 str_len(const char *s) { const char *p = s; while (*p) p++; return (u32)(p - s); }

int str_cmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (u8)*a - (u8)*b;
}

char *utoa(u32 v, char *buf, u32 base) {
    char tmp[33]; int n = 0;
    do { u32 d = v % base; tmp[n++] = (char)(d < 10 ? '0' + d : 'a' + d - 10); v /= base; } while (v);
    for (int i = 0; i < n; i++) buf[i] = tmp[n - 1 - i];
    buf[n] = 0;
    return buf;
}

static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

u32 base64_encode(const u8 *in, u32 n, char *out) {
    u32 o = 0;
    for (u32 i = 0; i < n; i += 3) {
        u32 v = in[i] << 16 | (i + 1 < n ? in[i + 1] << 8 : 0) | (i + 2 < n ? in[i + 2] : 0);
        out[o++] = b64[(v >> 18) & 63];
        out[o++] = b64[(v >> 12) & 63];
        out[o++] = i + 1 < n ? b64[(v >> 6) & 63] : '=';
        out[o++] = i + 2 < n ? b64[v & 63] : '=';
    }
    out[o] = 0;
    return o;
}

void matmul(const int *a, const int *b, int *c, int n) {
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++) {
            int s = 0;
            for (int k = 0; k < n; k++) s += a[i * n + k] * b[k * n + j];
            c[i * n + j] = s;
        }
}

enum { OP_PUSH, OP_ADD, OP_SUB, OP_MUL, OP_JZ, OP_JMP, OP_DUP, OP_HALT };

int run_vm(const int *code, int *stack) {
    int pc = 0, sp = 0;
    for (;;) {
        switch (code[pc++]) {
        case OP_PUSH: stack[sp++] = code[pc++]; break;
        case OP_ADD: sp--; stack[sp - 1] += stack[sp]; break;
        case OP_SUB: sp--; stack[sp - 1] -= stack[sp]; break;
        case OP_MUL: sp--; stack[sp - 1] *= stack[sp]; break;
        case OP_JZ: { int t = code[pc++]; if (!stack[--sp]) pc = t; break; }
        case OP_JMP: pc = code[pc]; break;
        case OP_DUP: stack[sp] = stack[sp - 1]; sp++; break;
        default: return sp ? stack[sp - 1] : 0;
        }
    }
}

struct entry { u32 key; u32 value; struct entry *next; };
static struct entry pool[64];
static struct entry *buckets[16];
static u32 used;

int map_put(u32 key, u32 value) {
    u32 h = (key * 2654435761u) >> 28;
    for (struct entry *e = buckets[h]; e; e = e->next)
        if (e->key == key) { e->value = value; return 0; }
    if (used >= 64) return -1;
    struct entry *e = &pool[used++];
    e->key = key; e->value = value; e->next = buckets[h]; buckets[h] = e;
    return 1;
}

int map_get(u32 key, u32 *value) {
    u32 h = (key * 2654435761u) >> 28;
    for (struct entry *e = buckets[h]; e; e = e->next)
        if (e->key == key) { *value = e->value; return 1; }
    return 0;
}

u32 isqrt(u32 x) {
    u32 r = 0, bit = 1u << 30;
    while (bit > x) bit >>= 2;
    while (bit) {
        if (x >= r + bit) { x -= r + bit; r = (r >> 1) + bit; } else r >>= 1;
        bit >>= 2;
    }
    return r;
}

void memmove_bytes(u8 *d, const u8 *s, u32 n) {
    if (d < s) while (n--) *d++ = *s++;
    else { d += n; s += n; while (n--) *--d = *--s; }
}

u32 fib(u32 n) { u32 a = 0, b = 1; while (n--) { u32 t = a + b; a = b; b = t; } return a; }

int parse_int(const char *s, int *out) {
    int sign = 1, v = 0, any = 0;
    while (*s == ' ' || *s == '\t') s++;
    if (*s == '-') { sign = -1; s++; } else if (*s == '+') s++;
    while (*s >= '0' && *s <= '9') { v = v * 10 + (*s++ - '0'); any = 1; }
    *out = v * sign;
    return any;
}
