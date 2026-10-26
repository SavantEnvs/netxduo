/* HKDF-Extract / HKDF-Expand (RFC 5869) through the generic NX_CRYPTO_METHOD interface and the direct API. */
#include "common.h"
#include "nx_crypto_hkdf.h"

extern NX_CRYPTO_METHOD crypto_method_hkdf, crypto_method_md5, crypto_method_sha1, crypto_method_sha256,
    crypto_method_sha384, crypto_method_sha512, crypto_method_hmac_md5, crypto_method_hmac_sha1,
    crypto_method_hmac_sha256, crypto_method_hmac_sha384, crypto_method_hmac_sha512;

static NX_CRYPTO_METHOD *hashes[] = {&crypto_method_md5, &crypto_method_sha1, &crypto_method_sha256,
                                     &crypto_method_sha384, &crypto_method_sha512};
static NX_CRYPTO_METHOD *hmacs[] = {&crypto_method_hmac_md5, &crypto_method_hmac_sha1, &crypto_method_hmac_sha256,
                                    &crypto_method_hmac_sha384, &crypto_method_hmac_sha512};

#define OUT_MAX 16400

static UINT op(NX_CRYPTO_METHOD *m, UINT o, UCHAR *key, UINT kbits, UCHAR *in, ULONG inlen, UCHAR *out, ULONG outlen,
               VOID *md, ULONG mdsz) {
    return crypto_method_hkdf.nx_crypto_operation(o, NX_CRYPTO_NULL, m, key, kbits, in, inlen, NX_CRYPTO_NULL, out,
                                                  outlen, md, mdsz, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 6) return -1;
    rd_t r = {data, size};
    uint8_t sel = rd_u8(&r);
    size_t hi = sel % N_ELEMS(hashes);
    int mismatch_pair = (sel & 0x80) != 0; /* occasionally pair a hash with a different HMAC */
    size_t mi = mismatch_pair ? (rd_u8(&r) % N_ELEMS(hmacs)) : hi;
    uint16_t want = (uint16_t)(rd_u8(&r) | (rd_u8(&r) << 8));
    size_t outlen = want >= 0xFFF0 ? OUT_MAX : want % 700; /* mostly small; rarely beyond the 255*HashLen limit */
    size_t slen = rd_u8(&r), ilen = rd_u8(&r), nlen = rd_u8(&r);
    size_t got;
    const uint8_t *s = rd_bytes(&r, slen, &got); slen = got;
    const uint8_t *k = rd_bytes(&r, ilen, &got); ilen = got;
    const uint8_t *n = rd_bytes(&r, nlen, &got); nlen = got;
    const uint8_t *prk = r.p;
    size_t prklen = r.left > 80 ? 80 : r.left;

    UCHAR *salt = dup_exact(s, slen), *ikm = dup_exact(k, ilen), *info = dup_exact(n, nlen);
    UCHAR *out = (UCHAR *)malloc(outlen ? outlen : 1);
    UCHAR *pk = dup_exact(prk, prklen);
    UCHAR *prk_out = (UCHAR *)malloc(128);

    ULONG mdsz = sizeof(NX_CRYPTO_HKDF);
    NX_CRYPTO_HKDF *md = (NX_CRYPTO_HKDF *)calloc(1, mdsz);

    crypto_method_hkdf.nx_crypto_init(&crypto_method_hkdf, ikm, (UINT)(ilen * 8), NX_CRYPTO_NULL, md, mdsz);
    op(hashes[hi], NX_CRYPTO_HKDF_SET_HASH, NULL, 0, NULL, 0, NULL, 0, md, mdsz);
    op(hmacs[mi], NX_CRYPTO_HKDF_SET_HMAC, NULL, 0, NULL, 0, NULL, 0, md, mdsz);
    UINT st = op(&crypto_method_hkdf, NX_CRYPTO_HKDF_EXTRACT, salt, (UINT)(slen * 8), ikm, (ULONG)ilen, prk_out, 128, md, mdsz);
    if (st == NX_CRYPTO_SUCCESS)
        op(&crypto_method_hkdf, NX_CRYPTO_HKDF_EXPAND, info, (UINT)(nlen * 8), NULL, 0, out, (ULONG)outlen, md, mdsz);
    /* Expand from an externally supplied PRK. */
    op(&crypto_method_hkdf, NX_CRYPTO_HKDF_SET_PRK, pk, (UINT)(prklen * 8), NULL, 0, NULL, 0, md, mdsz);
    op(&crypto_method_hkdf, NX_CRYPTO_HKDF_EXPAND, info, (UINT)(nlen * 8), NULL, 0, out, (ULONG)outlen, md, mdsz);
    crypto_method_hkdf.nx_crypto_cleanup(md);

    free(md); free(prk_out); free(pk); free(out); free(info); free(ikm); free(salt);
    return 0;
}
