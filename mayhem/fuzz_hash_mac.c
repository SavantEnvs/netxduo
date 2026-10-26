/* Hashes, HMACs and AES-XCBC-MAC through the generic NX_CRYPTO_METHOD interface.
   Checks one-shot vs. initialize/update/calculate agreement. */
#include "common.h"

extern NX_CRYPTO_METHOD crypto_method_md5, crypto_method_sha1, crypto_method_sha224,
    crypto_method_sha256, crypto_method_sha384, crypto_method_sha512,
    crypto_method_sha512_224, crypto_method_sha512_256, crypto_method_hmac_md5,
    crypto_method_hmac_sha1, crypto_method_hmac_sha224, crypto_method_hmac_sha256,
    crypto_method_hmac_sha384, crypto_method_hmac_sha512, crypto_method_hmac_sha512_224,
    crypto_method_hmac_sha512_256, crypto_method_aes_xcbc_mac_96;

typedef struct { NX_CRYPTO_METHOD *m; int keyed; int fixed_key_bytes; } entry_t;

static entry_t table[] = {
    {&crypto_method_md5, 0, 0},          {&crypto_method_sha1, 0, 0},
    {&crypto_method_sha224, 0, 0},       {&crypto_method_sha256, 0, 0},
    {&crypto_method_sha384, 0, 0},       {&crypto_method_sha512, 0, 0},
    {&crypto_method_sha512_224, 0, 0},   {&crypto_method_sha512_256, 0, 0},
    {&crypto_method_hmac_md5, 1, 0},     {&crypto_method_hmac_sha1, 1, 0},
    {&crypto_method_hmac_sha224, 1, 0},  {&crypto_method_hmac_sha256, 1, 0},
    {&crypto_method_hmac_sha384, 1, 0},  {&crypto_method_hmac_sha512, 1, 0},
    {&crypto_method_hmac_sha512_224, 1, 0}, {&crypto_method_hmac_sha512_256, 1, 0},
    {&crypto_method_aes_xcbc_mac_96, 1, 16},
};

#define OUT_BYTES 64

static UINT run(NX_CRYPTO_METHOD *m, UINT op, UCHAR *key, UINT key_bits, UCHAR *in, ULONG in_len,
                UCHAR *out, ULONG out_len, VOID *md, ULONG md_size) {
    return m->nx_crypto_operation(op, NX_CRYPTO_NULL, m, key, key_bits, in, in_len, NX_CRYPTO_NULL,
                                  out, out_len, md, md_size, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return -1;
    rd_t r = {data, size};
    entry_t *e = &table[rd_u8(&r) % N_ELEMS(table)];
    uint8_t split_sel = rd_u8(&r);
    size_t klen = rd_u8(&r);
    if (e->fixed_key_bytes) klen = e->fixed_key_bytes;
    if (!e->keyed) klen = 0;
    size_t kgot;
    const uint8_t *kraw = rd_bytes(&r, klen, &kgot);
    if (kgot < klen) return -1;
    size_t dlen = r.left;
    UCHAR *key = e->keyed ? dup_exact(kraw, klen) : NULL;
    UCHAR *in = dup_exact(r.p, dlen);
    UINT key_bits = (UINT)(klen * 8);
    ULONG md_size = e->m->nx_crypto_metadata_area_size;
    VOID *md = malloc(md_size);

    UCHAR *out1 = (UCHAR *)calloc(OUT_BYTES, 1);
    UCHAR *out2 = (UCHAR *)calloc(OUT_BYTES, 1);
    UINT s1, s2 = NX_CRYPTO_SUCCESS;

    if (e->m->nx_crypto_init) e->m->nx_crypto_init(e->m, key, key_bits, NX_CRYPTO_NULL, md, md_size);
    s1 = run(e->m, NX_CRYPTO_AUTHENTICATE, key, key_bits, in, (ULONG)dlen, out1, OUT_BYTES, md, md_size);

    /* XCBC-MAC has no incremental interface: every operation code runs the whole MAC. */
    if (e->fixed_key_bytes) goto done;

    size_t cut = dlen ? split_sel % (dlen + 1) : 0;
    if (e->m->nx_crypto_init) e->m->nx_crypto_init(e->m, key, key_bits, NX_CRYPTO_NULL, md, md_size);
    s2 = run(e->m, NX_CRYPTO_HASH_INITIALIZE, key, key_bits, NULL, 0, NULL, 0, md, md_size);
    if (s2 == NX_CRYPTO_SUCCESS)
        s2 = run(e->m, NX_CRYPTO_HASH_UPDATE, NULL, 0, in, (ULONG)cut, NULL, 0, md, md_size);
    if (s2 == NX_CRYPTO_SUCCESS)
        s2 = run(e->m, NX_CRYPTO_HASH_UPDATE, NULL, 0, in + cut, (ULONG)(dlen - cut), NULL, 0, md, md_size);
    if (s2 == NX_CRYPTO_SUCCESS)
        s2 = run(e->m, NX_CRYPTO_HASH_CALCULATE, NULL, 0, NULL, 0, out2, OUT_BYTES, md, md_size);

    if (s1 == NX_CRYPTO_SUCCESS && s2 == NX_CRYPTO_SUCCESS && memcmp(out1, out2, OUT_BYTES) != 0)
        abort();

done:
    if (e->m->nx_crypto_cleanup) e->m->nx_crypto_cleanup(md);
    free(out1); free(out2); free(md); free(in); free(key);
    return 0;
}
