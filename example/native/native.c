#include <stdint.h>
#include <sys/types.h>

#define MODE_URL        1
#define MODE_RAW        2
#define MODE_AVX2       4
#define MODE_JSON       8

#define as_m32v(v)      (*(uint32_t *)(v))
#define as_m64v(v)      (*(uint64_t *)(v))
#define always_inline   inline __attribute__((always_inline))

struct slice_t {
    char * buf;
    size_t len;
    size_t cap;
};

/** Exported Functions **/

void    b64encode(struct slice_t *out, const struct slice_t *src, int mode);
ssize_t b64decode(struct slice_t *out, const char *src, size_t nb, int mode);

/** Encoder Helper Functions **/

static const char TabEncodeCharsetStd[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char TabEncodeCharsetURL[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** Function Implementations **/

void b64encode(struct slice_t *out, const struct slice_t *src, int mode) {
    char *       ob = out->buf + out->len;
    char *       op = out->buf + out->len;
    const char * ip = src->buf;
    const char * ie = src->buf + src->len;
    const char * st = TabEncodeCharsetStd;

    /* check for empty string */
    if (src->len == 0) {
        return;
    }

    /* check for URL encoding */
    if (mode & MODE_URL) {
        st = TabEncodeCharsetURL;
    }

    /* handle the remaining bytes with scalar code (with 4 bytes load) */
    while (ip <= ie - 4) {
        uint32_t v0 = __builtin_bswap32(*(const uint32_t *)ip);
        uint8_t  v1 = (v0 >> 26) & 0x3f;
        uint8_t  v2 = (v0 >> 20) & 0x3f;
        uint8_t  v3 = (v0 >> 14) & 0x3f;
        uint8_t  v4 = (v0 >>  8) & 0x3f;

        /* encode the characters, and move to next block */
        ip += 3;
        *op++ = st[v1];
        *op++ = st[v2];
        *op++ = st[v3];
        *op++ = st[v4];
    }

    /* load the last bytes */
    size_t   dp = ie - ip;
    uint32_t v0 = (uint32_t)(uint8_t)ip[0] << 16;

#define B2 v0 |= (uint32_t)(uint8_t)ip[2]
#define B1 v0 |= (uint32_t)(uint8_t)ip[1] << 8

#define R4 *op++ = st[(v0 >>  0) & 0x3f]
#define R3 *op++ = st[(v0 >>  6) & 0x3f]
#define R2 *op++ = st[(v0 >> 12) & 0x3f]
#define R1 *op++ = st[(v0 >> 18) & 0x3f]

#define NB { out->len += op - ob; }
#define PD { if ((mode & MODE_RAW) == 0) { *op++ = '='; } }

    /* encode the last few bytes */
    switch (dp) {
        case 3  : B2; B1; R1; R2; R3; R4; NB; break;
        case 2  :     B1; R1; R2; R3; PD; NB; break;
        case 1  :         R1; R2; PD; PD; NB; break;
        default :                         NB; break;
    }

#undef PD
#undef NB
#undef R1
#undef R2
#undef R3
#undef R4
#undef B1
#undef B2
}

/** Decoder Helper Functions **/

static const uint8_t VecDecodeCharsetStd[256] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,   62, 0xff, 0xff, 0xff,   63,
      52,   53,   54,   55,   56,   57,   58,   59,   60,   61, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff,    0,    1,    2,    3,    4,    5,    6,    7,    8,    9,   10,   11,   12,   13,   14,
      15,   16,   17,   18,   19,   20,   21,   22,   23,   24,   25, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff,   26,   27,   28,   29,   30,   31,   32,   33,   34,   35,   36,   37,   38,   39,   40,
      41,   42,   43,   44,   45,   46,   47,   48,   49,   50,   51, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static const uint8_t VecDecodeCharsetURL[256] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,   62, 0xff, 0xff,
      52,   53,   54,   55,   56,   57,   58,   59,   60,   61, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff,    0,    1,    2,    3,    4,    5,    6,    7,    8,    9,   10,   11,   12,   13,   14,
      15,   16,   17,   18,   19,   20,   21,   22,   23,   24,   25, 0xff, 0xff, 0xff, 0xff,   63,
    0xff,   26,   27,   28,   29,   30,   31,   32,   33,   34,   35,   36,   37,   38,   39,   40,
      41,   42,   43,   44,   45,   46,   47,   48,   49,   50,   51, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

#define ALL_01h     (~0ul / 255)
#define ALL_7fh     (ALL_01h * 127)
#define ALL_80h     (ALL_01h * 128)

static always_inline uint32_t hasless(uint32_t x, uint8_t n) {
    return (x - ALL_01h * n) & ~x & ALL_80h;
}

static always_inline uint32_t hasmore(uint32_t x, uint8_t n) {
    return (x + ALL_01h * (127 - n) | x) & ALL_80h;
}

static always_inline uint32_t hasbetween(uint32_t x, uint8_t m, uint8_t n) {
    return (ALL_01h * (127 + n) - (x & ALL_7fh) & ~x & (x & ALL_7fh) + ALL_01h * (127 - m)) & ALL_80h;
}

#undef ALL_01h
#undef ALL_7fh
#undef ALL_80h

static always_inline char unhex16_is(const uint8_t *s) {
    uint32_t v = *(uint32_t *)s;
    return !(hasless(v, '0') || hasmore(v, 'f') || hasbetween(v, '9', 'A') || hasbetween(v, 'F', 'a'));
}

static always_inline uint32_t unhex16_fast(const uint8_t *s) {
    uint32_t a = __builtin_bswap32(*(uint32_t *)s);
    uint32_t b = 9 * ((~a & 0x10101010) >> 4) + (a & 0x0f0f0f0f);
    uint32_t c = (b >> 4) | b;
    uint32_t d = ((c >> 8) & 0xff00) | (c & 0x00ff);
    return d;
}

static always_inline uint8_t unescape_asc(const uint8_t * ie, const uint8_t ** ipp) {
    const uint8_t * ee = (*ipp) + 1;
    uint32_t ch = 0xff;
    /* check eof */
    if (ee > ie) {
        return 0xff;
    }
    switch (ee[-1]) {
        case 'r': ch = '\r'; break;
        case 'n': ch = '\n'; break;
        case '/': ch = '/'; break;
        case 'u': /* neee more 4 bytes */
        if (ie - ee >= 4 && unhex16_is(ee)) {
            ch = unhex16_fast(ee);
            /* if not ascii, as 0xff */
            ch = ch < 128 ? ch : 0xff;
            ee += 4;
        }
        break;
    }
    *ipp = ee;
    return ch;
}

/* Return 0 if success, otherwise return the error position + 1 */
int64_t decode_block(
    const uint8_t *  ie,
    const uint8_t ** ipp,
    char **          opp,
    const uint8_t *  tab,
    int              mode
) {
    int      nb = 0;
    uint32_t v0 = 0;

    /* buffer pointers */
    char *          op = *opp;
    const uint8_t * ip = *ipp;
    uint8_t id = 0;
    uint8_t ch = 0;
    int pad = 0;

#define may_unescape() { if (ch == '\\' && (mode & MODE_JSON)) ch = unescape_asc(ie, &ip); }
#define skip_newlines() { if (ch == '\r' || ch == '\n') continue; }

    /* load up to 4 characters */
    while (ip < ie && nb < 4) {
        ch = *ip++;
        may_unescape();
        skip_newlines();

        /* lookup the index, and check for invalid characters */
        if ((id = tab[ch]) == 0xff) {
            if ((mode & MODE_RAW) || ch != '=' || nb < 2) goto error;
            pad++; goto tail;
        }

        /* decode the character */
        v0 = (v0 << 6) | id;
        nb++;
    }

    if (nb == 0) {
        /* update the pointers */
        *ipp = ip;
        return 0;
    }

    /* check eof, MODE_STD need paddings */
    if (ip >= ie && nb != 4) {
        if (!(mode & MODE_RAW) || nb == 1) goto error;
    }

decode:
    v0 <<= 6 * (4 - nb);
    /* ends with eof or 4 characters, decode into output */
    switch (nb) {
        case 4: op[2] = (v0 >>  0) & 0xff;
        case 3: op[1] = (v0 >>  8) & 0xff;
        case 2: op[0] = (v0 >> 16) & 0xff;
    }

    /* update the pointers */
    *ipp = ip;
    *opp = op + nb - 1;
    return 0;

tail:
    /* loop for more paddings */
    while (ip < ie) {
        ch = *ip++;
        may_unescape();
        skip_newlines();
        if (ch != '=') goto error;
        if (++pad + nb > 4) goto error;
    }
    goto decode;
#undef may_unescape
#undef skip_newlines

error:
    /* update eof error position */
    if (ip == ie) ip++;
    return ip - *ipp;
}

ssize_t b64decode(struct slice_t *out, const char *src, size_t nb, int mode) {
    int64_t dv;
    const uint8_t *st = VecDecodeCharsetStd;

    /* check for empty input */
    if (nb == 0) {
        return 0;
    }

    /* output buffer */
    char *ob = out->buf + out->len;
    char *op = out->buf + out->len;
    char *oe = out->buf + out->cap;

    /* input buffer */
    const uint8_t *ib = (const uint8_t *)src;
    const uint8_t *ip = (const uint8_t *)src;
    const uint8_t *ie = (const uint8_t *)src + nb;

    /* check for URL encoding */
    if (mode & MODE_URL) {
        st = VecDecodeCharsetURL;
    }

    /* handle the remaining bytes with scalar code (8 byte loop) */
    while (ip <= ie - 8 && op <= oe - 8) {
        uint8_t v0 = st[ip[0]];
        uint8_t v1 = st[ip[1]];
        uint8_t v2 = st[ip[2]];
        uint8_t v3 = st[ip[3]];
        uint8_t v4 = st[ip[4]];
        uint8_t v5 = st[ip[5]];
        uint8_t v6 = st[ip[6]];
        uint8_t v7 = st[ip[7]];

        /* check for invalid bytes */
        if ((v0 | v1 | v2 | v3 | v4 | v5 | v6 | v7) == 0xff) {
            if ((dv = decode_block(ie, &ip, &op, st, mode)) != 0) {
                return ib - ip - dv;
            } else {
                continue;
            }
        }

        /* construct the characters */
        uint64_t vv = __builtin_bswap64(
            ((uint64_t)v0 << 58) |
            ((uint64_t)v1 << 52) |
            ((uint64_t)v2 << 46) |
            ((uint64_t)v3 << 40) |
            ((uint64_t)v4 << 34) |
            ((uint64_t)v5 << 28) |
            ((uint64_t)v6 << 22) |
            ((uint64_t)v7 << 16)
        );

        /* store the result, and move to next block */
        as_m64v(op) = vv;
        ip += 8;
        op += 6;
    }

    /* handle the remaining bytes with scalar code (4 byte loop) */
    while (ip <= ie - 4 && op <= oe - 4) {
        uint8_t v0 = st[ip[0]];
        uint8_t v1 = st[ip[1]];
        uint8_t v2 = st[ip[2]];
        uint8_t v3 = st[ip[3]];

        /* check for invalid bytes */
        if ((v0 | v1 | v2 | v3) == 0xff) {
            if ((dv = decode_block(ie, &ip, &op, st, mode)) != 0) {
                return ib - ip - dv;
            } else {
                continue;
            }
        }

        /* construct the characters */
        uint32_t vv = __builtin_bswap32(
            ((uint32_t)v0 << 26) |
            ((uint32_t)v1 << 20) |
            ((uint32_t)v2 << 14) |
            ((uint32_t)v3 <<  8)
        );

        /* store the result, and move to next block */
        as_m32v(op) = vv;
        ip += 4;
        op += 3;
    }

    /* decode the last few bytes */
    while (ip < ie) {
        if ((dv = decode_block(ie, &ip, &op, st, mode)) != 0) {
            return ib - ip - dv;
        }
    }

    /* update the result length */
    out->len += op - ob;
    return op - ob;
}

#define ETAG        -1
#define EEOF        -2
#define ESTACK      -3
#define MAX_STACK   1024

#define T_bool      2
#define T_i8        3
#define T_double    4
#define T_i16       6
#define T_i32       8
#define T_i64       10
#define T_string    11
#define T_struct    12
#define T_map       13
#define T_set       14
#define T_list      15
#define T_map_pair  0xff

typedef struct {
    uint8_t  t;
    uint8_t  k;
    uint8_t  v;
    uint32_t n;
} skipbuf_t;

static const char WireTags[256] = {
    [T_bool  ] = 1,
    [T_i8    ] = 1,
    [T_double] = 1,
    [T_i16   ] = 1,
    [T_i32   ] = 1,
    [T_i64   ] = 1,
    [T_string] = 1,
    [T_struct] = 1,
    [T_map   ] = 1,
    [T_set   ] = 1,
    [T_list  ] = 1,
};

static const int8_t SkipSizeFixed[256] = {
    [T_bool  ] = 1,
    [T_i8    ] = 1,
    [T_double] = 8,
    [T_i16   ] = 2,
    [T_i32   ] = 4,
    [T_i64   ] = 8,
};

static inline int64_t u32be(const char *s) {
    return __builtin_bswap32(*(const uint32_t *)s);
}

static inline char stpop(skipbuf_t *s, int64_t *p) {
    if (s[*p].n == 0) {
        (*p)--;
        return 1;
    } else {
        s[*p].n--;
        return 0;
    }
}

static inline char stadd(skipbuf_t *s, int64_t *p, uint8_t t) {
    if (++*p >= MAX_STACK) {
        return 0;
    } else {
        s[*p].t = t;
        s[*p].n = 0;
        return 1;
    }
}

static inline void mvbuf(const char **s, int64_t *n, int64_t *r, int64_t nb) {
    *n -= nb;
    *r += nb;
    *s += nb;
}

int64_t do_skip(skipbuf_t *st, const char *s, int64_t n, uint8_t t) {
    int64_t nb;
    int64_t rv = 0;
    int64_t sp = 0;

    /* initialize the stack */
    st->n = 0;
    st->t = t;

    /* run until drain */
    while (sp >= 0) {
        switch (st[sp].t) {
            default: {
                return ETAG;
            }

            /* simple fixed types */
            case T_bool   :
            case T_i8     :
            case T_double :
            case T_i16    :
            case T_i32    :
            case T_i64    : {
                if ((nb = SkipSizeFixed[st[sp].t]) > n) {
                    return EEOF;
                } else {
                    stpop(st, &sp);
                    mvbuf(&s, &n, &rv, nb);
                    break;
                }
            }

            /* strings & binaries */
            case T_string: {
                if (n < 4) {
                    return EEOF;
                } else if ((nb = u32be(s) + 4) > n) {
                    return EEOF;
                } else {
                    stpop(st, &sp);
                    mvbuf(&s, &n, &rv, nb);
                    break;
                }
            }

            /* structs */
            case T_struct: {
                int64_t nf;
                uint8_t vt;

                /* must have at least 1 byte */
                if (n < 1) {
                    return EEOF;
                }

                /* check for end of tag */
                if ((vt = *s) == 0) {
                    stpop(st, &sp);
                    mvbuf(&s, &n, &rv, 1);
                    continue;
                }

                /* check for tag value */
                if (!(WireTags[vt])) {
                    return ETAG;
                }

                /* fast-path for primitive fields */
                if ((nf = SkipSizeFixed[vt]) != 0) {
                    if (n < nf + 3) {
                        return EEOF;
                    } else {
                        mvbuf(&s, &n, &rv, nf + 3);
                        continue;
                    }
                }

                /* must have more than 3 bytes (fields cannot have a size of zero), also skip the field ID cause we don't care */
                if (n <= 3) {
                    return EEOF;
                } else if (!stadd(st, &sp, vt)) {
                    return ESTACK;
                } else {
                    mvbuf(&s, &n, &rv, 3);
                    break;
                }
            }

            /* maps */
            case T_map: {
                int64_t np;
                uint8_t kt;
                uint8_t vt;

                /* must have at least 6 bytes */
                if (n < 6) {
                    return EEOF;
                }

                /* get the element type and count */
                kt = s[0];
                vt = s[1];
                np = u32be(s + 2);

                /* check for tag value */
                if (!(WireTags[kt] && WireTags[vt])) {
                    return ETAG;
                }

                /* empty map */
                if (np == 0) {
                    stpop(st, &sp);
                    mvbuf(&s, &n, &rv, 6);
                    continue;
                }

                /* check for fixed key and value */
                int64_t nk = SkipSizeFixed[kt];
                int64_t nv = SkipSizeFixed[vt];

                /* fast path for fixed key and value */
                if (nk != 0 && nv != 0) {
                    if ((nb = np * (nk + nv) + 6) > n) {
                        return EEOF;
                    } else {
                        stpop(st, &sp);
                        mvbuf(&s, &n, &rv, nb);
                        continue;
                    }
                }

                /* set to parse the map pairs */
                st[sp].k = kt;
                st[sp].v = vt;
                st[sp].t = T_map_pair;
                st[sp].n = np * 2 - 1;
                mvbuf(&s, &n, &rv, 6);
                break;
            }

            /* map pairs */
            case T_map_pair: {
                uint8_t kt = st[sp].k;
                uint8_t vt = st[sp].v;

                /* there are keys pending */
                if (!stpop(st, &sp) && (st[sp].n & 1) == 0) {
                    vt = kt;
                }

                /* push the element onto stack */
                if (stadd(st, &sp, vt)) {
                    break;
                } else {
                    return ESTACK;
                }
            }

            /* sets and lists */
            case T_set  :
            case T_list : {
                int64_t nv;
                int64_t nt;
                uint8_t et;

                /* must have at least 5 bytes */
                if (n < 5) {
                    return EEOF;
                }

                /* get the element type and count */
                et = s[0];
                nv = u32be(s + 1);

                /* check for tag value */
                if (!(WireTags[et])) {
                    return ETAG;
                }

                /* empty sequence */
                if (nv == 0) {
                    stpop(st, &sp);
                    mvbuf(&s, &n, &rv, 5);
                    continue;
                }

                /* fast path for fixed types */
                if ((nt = SkipSizeFixed[et]) != 0) {
                    if ((nb = nv * nt + 5) > n) {
                        return EEOF;
                    } else {
                        stpop(st, &sp);
                        mvbuf(&s, &n, &rv, nb);
                        continue;
                    }
                }

                /* set to parse the elements */
                st[sp].t = et;
                st[sp].n = nv - 1;
                mvbuf(&s, &n, &rv, 5);
                break;
            }
        }
    }

    /* all done */
    return rv;
}