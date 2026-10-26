/* AES-CBC / AES-CCM / AES-GCM / DES / 3DES through the generic NX_CRYPTO_METHOD interface.
   Encrypts the fuzz plaintext, decrypts it back and requires the round trip to be lossless;
   also feeds the raw fuzz bytes to the decrypt path as forged ciphertext+tag. */
#include "common.h"

extern NX_CRYPTO_METHOD crypto_method_aes_cbc_128, crypto_method_aes_cbc_192, crypto_method_aes_cbc_256,
    crypto_method_aes_ccm_8, crypto_method_aes_ccm_16, crypto_method_aes_128_gcm_16,
    crypto_method_aes_256_gcm_16, crypto_method_des, crypto_method_3des;

typedef enum { CBC, CCM, GCM, DES_ } kind_t;
typedef struct { NX_CRYPTO_METHOD *m; kind_t k; unsigned key_bytes; unsigned iv_bytes; unsigned tag; } entry_t;

static entry_t table[] = {
    {&crypto_method_aes_cbc_128, CBC, 16, 16, 0}, {&crypto_method_aes_cbc_192, CBC, 24, 16, 0},
    {&crypto_method_aes_cbc_256, CBC, 32, 16, 0}, {&crypto_method_aes_ccm_8, CCM, 16, 16, 8},
    {&crypto_method_aes_ccm_16, CCM, 16, 16, 16}, {&crypto_method_aes_128_gcm_16, GCM, 16, 16, 16},
    {&crypto_method_aes_256_gcm_16, GCM, 32, 16, 16}, {&crypto_method_des, DES_, 8, 8, 0},
    {&crypto_method_3des, DES_, 24, 8, 0},
};

static UINT op(NX_CRYPTO_METHOD *m, UINT o, UCHAR *key, UINT kbits, UCHAR *in, ULONG inlen, UCHAR *iv, UCHAR *out,
               ULONG outlen, VOID *md, ULONG mdsz) {
    return m->nx_crypto_operation(o, NX_CRYPTO_NULL, m, key, kbits, in, inlen, iv, out, outlen, md, mdsz,
                                  NX_CRYPTO_NULL, NX_CRYPTO_NULL);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) return -1;
    rd_t r = {data, size};
    entry_t *e = &table[rd_u8(&r) % N_ELEMS(table)];
    uint8_t flags = rd_u8(&r);
    size_t aad_len = e->k == CBC || e->k == DES_ ? 0 : rd_u8(&r) % 64;
    unsigned ivlen_sel = rd_u8(&r);
    size_t got;
    const uint8_t *kraw = rd_bytes(&r, e->key_bytes, &got);
    if (got < e->key_bytes) return -1;
    const uint8_t *ivraw = rd_bytes(&r, e->iv_bytes, &got);
    if (got < e->iv_bytes) return -1;
    const uint8_t *aadraw = rd_bytes(&r, aad_len, &got);
    aad_len = got;
    size_t plen = r.left;
    if (e->k == CBC || e->k == DES_) plen -= plen % e->m->nx_crypto_block_size_in_bytes;

    UCHAR *key = dup_exact(kraw, e->key_bytes);
    UCHAR *iv = dup_exact(ivraw, e->iv_bytes);
    UCHAR *iv2 = dup_exact(ivraw, e->iv_bytes);
    UCHAR *aad = dup_exact(aadraw, aad_len);
    /* The GCM tail block XOR reads a full 16-byte block from the final partial input block (an over-read upstream
       tolerates because real callers pass packet buffers); give GCM inputs one block of slack to keep that known
       behaviour from masking everything else. */
    size_t slack = e->k == GCM ? 16 : 0;
    UCHAR *pt = dup_slack(r.p, plen, slack);
    if (e->k == GCM) { iv[0] = (UCHAR)(ivlen_sel % 16); iv2[0] = iv[0]; }
    if (e->k == CCM) { iv[0] = (UCHAR)(7 + ivlen_sel % 7); iv2[0] = iv[0]; }

    ULONG mdsz = e->m->nx_crypto_metadata_area_size;
    VOID *md = calloc(1, mdsz);
    UINT kbits = e->key_bytes * 8;

    if (e->m->nx_crypto_init(e->m, key, kbits, NX_CRYPTO_NULL, md, mdsz) == NX_CRYPTO_SUCCESS) {
        size_t ctlen = plen + e->tag;
        UCHAR *ct = (UCHAR *)calloc(ctlen + slack + 1, 1);
        UCHAR *back = (UCHAR *)calloc(plen ? plen : 1, 1);
        UINT s1, s2 = NX_CRYPTO_SUCCESS;

        if (e->k != CBC && e->k != DES_)
            op(e->m, NX_CRYPTO_SET_ADDITIONAL_DATA, key, kbits, aad, (ULONG)aad_len, NULL, NULL, 0, md, mdsz);
        s1 = op(e->m, NX_CRYPTO_ENCRYPT, key, kbits, pt, (ULONG)plen, iv, ct, (ULONG)ctlen, md, mdsz);
        if (s1 == NX_CRYPTO_SUCCESS) {
            if (e->k != CBC && e->k != DES_)
                op(e->m, NX_CRYPTO_SET_ADDITIONAL_DATA, key, kbits, aad, (ULONG)aad_len, NULL, NULL, 0, md, mdsz);
            s2 = op(e->m, NX_CRYPTO_DECRYPT, key, kbits, ct, (ULONG)ctlen, iv2, back, (ULONG)plen, md, mdsz);
            if (s2 == NX_CRYPTO_SUCCESS && memcmp(back, pt, plen) != 0) abort();
            /* A flipped ciphertext/tag bit must not authenticate. */
            if ((e->k == CCM || e->k == GCM) && ctlen && (flags & 1)) {
                ct[(flags >> 1) % ctlen] ^= (UCHAR)(1u << ((flags >> 4) & 7));
                memcpy(iv2, ivraw, e->iv_bytes);
                iv2[0] = iv[0];
                op(e->m, NX_CRYPTO_SET_ADDITIONAL_DATA, key, kbits, aad, (ULONG)aad_len, NULL, NULL, 0, md, mdsz);
                if (op(e->m, NX_CRYPTO_DECRYPT, key, kbits, ct, (ULONG)ctlen, iv2, back, (ULONG)plen, md, mdsz) ==
                    NX_CRYPTO_SUCCESS)
                    abort();
            }
        }

        /* Raw fuzz bytes as ciphertext (forged input) into the decrypt path. */
        {
            size_t rl = plen + (e->tag && (flags & 2) ? e->tag : 0);
            UCHAR *forged = dup_slack(r.p, rl <= r.left ? rl : r.left, slack);
            size_t fl = rl <= r.left ? rl : r.left;
            if (e->k == CBC || e->k == DES_) fl -= fl % e->m->nx_crypto_block_size_in_bytes;
            UCHAR *dst = (UCHAR *)calloc(fl ? fl : 1, 1);
            memcpy(iv2, ivraw, e->iv_bytes);
            iv2[0] = iv[0];
            if (e->k != CBC && e->k != DES_)
                op(e->m, NX_CRYPTO_SET_ADDITIONAL_DATA, key, kbits, aad, (ULONG)aad_len, NULL, NULL, 0, md, mdsz);
            op(e->m, NX_CRYPTO_DECRYPT, key, kbits, forged, (ULONG)fl, iv2, dst, (ULONG)fl, md, mdsz);
            free(dst); free(forged);
        }
        free(ct); free(back);
    }
    if (e->m->nx_crypto_cleanup) e->m->nx_crypto_cleanup(md);
    free(md); free(pt); free(aad); free(iv2); free(iv); free(key);
    return 0;
}
