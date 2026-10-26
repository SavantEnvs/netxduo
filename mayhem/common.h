/* Shared helpers for the NetX Crypto fuzz harnesses (standalone crypto build, no ThreadX). */
#ifndef MAYHEM_COMMON_H
#define MAYHEM_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "nx_crypto.h"

#define N_ELEMS(a) (sizeof(a) / sizeof((a)[0]))

typedef struct { const uint8_t *p; size_t left; } rd_t;

static inline uint8_t rd_u8(rd_t *r) {
    if (r->left == 0) return 0;
    r->left--;
    return *r->p++;
}

static inline const uint8_t *rd_bytes(rd_t *r, size_t want, size_t *got) {
    const uint8_t *q = r->p;
    if (want > r->left) want = r->left;
    r->p += want;
    r->left -= want;
    *got = want;
    return q;
}

/* Exact-size heap copy so ASan sees any read or write past what the library was told it owns. */
static inline uint8_t *dup_exact(const uint8_t *src, size_t n) {
    uint8_t *q = (uint8_t *)malloc(n ? n : 1);
    if (n) memcpy(q, src, n);
    return q;
}

/* Like dup_exact but with `slack` extra readable bytes. */
static inline uint8_t *dup_slack(const uint8_t *src, size_t n, size_t slack) {
    uint8_t *q = (uint8_t *)calloc(n + slack ? n + slack : 1, 1);
    if (n) memcpy(q, src, n);
    return q;
}

#endif
