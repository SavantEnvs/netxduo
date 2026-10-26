/* RSA public/private operation, PKCS#1 v1.5 verify and RSASSA-PSS verify with attacker-chosen moduli,
   exponents, messages and signatures. */
#include "common.h"
#include "nx_crypto_rsa.h"
#include "nx_crypto_pkcs1_v1.5.h"

extern NX_CRYPTO_METHOD crypto_method_rsa, crypto_method_pkcs1, crypto_method_md5, crypto_method_sha1,
    crypto_method_sha224, crypto_method_sha256, crypto_method_sha384, crypto_method_sha512;

static NX_CRYPTO_METHOD *hashes[] = {&crypto_method_md5, &crypto_method_sha1, &crypto_method_sha224,
                                     &crypto_method_sha256, &crypto_method_sha384, &crypto_method_sha512};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) return -1;
    rd_t r = {data, size};
    uint8_t mode = rd_u8(&r) % 3;
    NX_CRYPTO_METHOD *hm = hashes[rd_u8(&r) % N_ELEMS(hashes)];
    size_t got;

    if (mode == 0) { /* raw RSA through the method interface, optional CRT primes */
        size_t modlen = 1 + (rd_u8(&r) | (rd_u8(&r) << 8)) % 520;
        size_t explen = 1 + rd_u8(&r) % modlen;
        size_t inlen = rd_u8(&r) % (modlen + 1);
        int crt = rd_u8(&r) & 1;
        size_t plen = crt ? 1 + rd_u8(&r) % (modlen / 2 + 1) : 0, qlen = plen;
        const uint8_t *m = rd_bytes(&r, modlen, &got); modlen = got;
        const uint8_t *e = rd_bytes(&r, explen, &got); explen = got;
        const uint8_t *in = rd_bytes(&r, inlen, &got); inlen = got;
        const uint8_t *p = rd_bytes(&r, plen, &got); plen = got;
        const uint8_t *q = rd_bytes(&r, qlen, &got); qlen = got;
        if (!modlen || !explen) return -1;
        UCHAR *mod = dup_exact(m, modlen), *exp = dup_exact(e, explen), *inb = dup_exact(in, inlen);
        UCHAR *pp = dup_exact(p, plen), *qq = dup_exact(q, qlen);
        UCHAR *out = (UCHAR *)calloc(modlen, 1);
        NX_CRYPTO_RSA *ctx = (NX_CRYPTO_RSA *)calloc(1, sizeof(*ctx));
        if (crypto_method_rsa.nx_crypto_init(&crypto_method_rsa, mod, (UINT)(modlen * 8), NX_CRYPTO_NULL, ctx,
                                             sizeof(*ctx)) == NX_CRYPTO_SUCCESS) {
            if (crt && plen && qlen) {
                crypto_method_rsa.nx_crypto_operation(NX_CRYPTO_SET_PRIME_P, NX_CRYPTO_NULL, &crypto_method_rsa, NULL,
                                                      0, pp, (ULONG)plen, NULL, NULL, 0, ctx, sizeof(*ctx), NULL, NULL);
                crypto_method_rsa.nx_crypto_operation(NX_CRYPTO_SET_PRIME_Q, NX_CRYPTO_NULL, &crypto_method_rsa, NULL,
                                                      0, qq, (ULONG)qlen, NULL, NULL, 0, ctx, sizeof(*ctx), NULL, NULL);
            }
            crypto_method_rsa.nx_crypto_operation(NX_CRYPTO_DECRYPT, NX_CRYPTO_NULL, &crypto_method_rsa, exp,
                                                  (UINT)(explen * 8), inb, (ULONG)inlen, NULL, out, (ULONG)modlen,
                                                  ctx, sizeof(*ctx), NULL, NULL);
        }
        if (crypto_method_rsa.nx_crypto_cleanup) crypto_method_rsa.nx_crypto_cleanup(ctx);
        free(ctx); free(out); free(qq); free(pp); free(inb); free(exp); free(mod);
    } else if (mode == 1) { /* PKCS#1 v1.5 verify via the method interface */
        size_t modlen = 1 + (rd_u8(&r) | (rd_u8(&r) << 8)) % 520;
        size_t explen = 1 + rd_u8(&r) % 8;
        size_t msglen = rd_u8(&r) % 100;
        size_t siglen = rd_u8(&r) & 1 ? modlen : rd_u8(&r) % (modlen + 1);
        const uint8_t *m = rd_bytes(&r, modlen, &got); modlen = got;
        const uint8_t *e = rd_bytes(&r, explen, &got); explen = got;
        const uint8_t *msg = rd_bytes(&r, msglen, &got); msglen = got;
        const uint8_t *sg = rd_bytes(&r, siglen, &got); siglen = got;
        if (!modlen || !explen) return -1;
        if (siglen > modlen) siglen = modlen;
        UCHAR *mod = dup_exact(m, modlen), *exp = dup_exact(e, explen), *mb = dup_exact(msg, msglen);
        UCHAR *sig = dup_exact(sg, siglen);
        NX_CRYPTO_PKCS1 *ctx = (NX_CRYPTO_PKCS1 *)calloc(1, sizeof(*ctx));
        NX_CRYPTO_RSA *rsa = (NX_CRYPTO_RSA *)calloc(1, sizeof(*rsa));
        VOID *hmd = calloc(1, hm->nx_crypto_metadata_area_size);
        NX_CRYPTO_PKCS1_OPTIONS opt = {&crypto_method_rsa, rsa, sizeof(*rsa), hm, hmd,
                                       (UINT)hm->nx_crypto_metadata_area_size};
        if (crypto_method_pkcs1.nx_crypto_operation(NX_CRYPTO_SET_ADDITIONAL_DATA, NX_CRYPTO_NULL,
                                                    &crypto_method_pkcs1, mod, (UINT)(modlen * 8), (UCHAR *)&opt,
                                                    sizeof(opt), NULL, NULL, 0, ctx, sizeof(*ctx), NULL, NULL) ==
            NX_CRYPTO_SUCCESS)
            crypto_method_pkcs1.nx_crypto_operation(NX_CRYPTO_VERIFY, NX_CRYPTO_NULL, &crypto_method_pkcs1, exp,
                                                    (UINT)(explen * 8), mb, (ULONG)msglen, NULL, sig, (ULONG)siglen,
                                                    ctx, sizeof(*ctx), NULL, NULL);
        free(hmd); free(rsa); free(ctx); free(sig); free(mb); free(exp); free(mod);
    } else { /* RSASSA-PSS verify (RFC 8017 9.1.2, salt length == hash length) */
        UINT hlen = hm->nx_crypto_ICV_size_in_bits >> 3;
        UINT em_bits = 1 + (rd_u8(&r) | (rd_u8(&r) << 8)) % 4200;
        UINT em_len = (em_bits + 7) >> 3;
        const uint8_t *h = rd_bytes(&r, hlen, &got);
        if (got < hlen) return -1;
        const uint8_t *e = rd_bytes(&r, em_len, &got);
        UCHAR *hash = dup_exact(h, hlen);
        UCHAR *em = dup_exact(e, got);
        if (got < em_len) { free(em); em = (UCHAR *)calloc(em_len, 1); memcpy(em, e, got); }
        UINT db_len = em_len > hlen + 1 ? em_len - hlen - 1 : 0;
        UINT scratch_len = db_len + hlen;
        UCHAR *scratch = (UCHAR *)calloc(scratch_len ? scratch_len : 1, 1);
        VOID *hmd = calloc(1, hm->nx_crypto_metadata_area_size);
        _nx_crypto_rsa_pss_verify(hash, hlen, em, em_bits, hm, hmd, hm->nx_crypto_metadata_area_size, scratch,
                                  scratch_len);
        free(hmd); free(scratch); free(em); free(hash);
    }
    return 0;
}
