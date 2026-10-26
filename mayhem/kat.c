/* Known-answer probe: prints lowercase hex for fixed vectors from FIPS 180/197 and RFC 4231/5869.
   mayhem/test.sh compares the output in bash, so a neutered binary cannot pass. */
#include <stdio.h>
#include "common.h"
#include "nx_crypto_hkdf.h"

extern NX_CRYPTO_METHOD crypto_method_md5, crypto_method_sha256, crypto_method_hmac_sha256,
    crypto_method_hkdf, crypto_method_aes_cbc_128;

static void hex(const char *label, const UCHAR *p, size_t n) {
    printf("%s=", label);
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\n");
}

static UINT run(NX_CRYPTO_METHOD *m, UINT o, NX_CRYPTO_METHOD *aux, UCHAR *key, UINT kbits, UCHAR *in, ULONG inlen,
                UCHAR *iv, UCHAR *out, ULONG outlen, VOID *md, ULONG mdsz) {
    return m->nx_crypto_operation(o, NX_CRYPTO_NULL, aux, key, kbits, in, inlen, iv, out, outlen, md, mdsz,
                                  NX_CRYPTO_NULL, NX_CRYPTO_NULL);
}

static void digest(const char *label, NX_CRYPTO_METHOD *m, UCHAR *key, UINT kbits, const char *msg) {
    UCHAR out[64] = {0};
    ULONG mdsz = m->nx_crypto_metadata_area_size;
    VOID *md = calloc(1, mdsz);
    if (m->nx_crypto_init) m->nx_crypto_init(m, key, kbits, NX_CRYPTO_NULL, md, mdsz);
    UINT st = run(m, NX_CRYPTO_AUTHENTICATE, m, key, kbits, (UCHAR *)msg, (ULONG)strlen(msg), NULL, out, 64, md, mdsz);
    printf("%s_status=%u\n", label, st);
    hex(label, out, m->nx_crypto_ICV_size_in_bits / 8);
    if (m->nx_crypto_cleanup) m->nx_crypto_cleanup(md);
    free(md);
}

int main(void) {
    digest("md5_abc", &crypto_method_md5, NULL, 0, "abc");
    digest("sha256_abc", &crypto_method_sha256, NULL, 0, "abc");
    digest("hmac_sha256_jefe", &crypto_method_hmac_sha256, (UCHAR *)"Jefe", 32, "what do ya want for nothing?");

    /* FIPS-197 C.1: AES-128 ECB == CBC with a zero IV for one block. */
    UCHAR key[16], pt[16], iv[16] = {0}, ct[16] = {0};
    for (int i = 0; i < 16; i++) { key[i] = (UCHAR)i; pt[i] = (UCHAR)(i * 0x11); }
    ULONG mdsz = crypto_method_aes_cbc_128.nx_crypto_metadata_area_size;
    VOID *md = calloc(1, mdsz);
    crypto_method_aes_cbc_128.nx_crypto_init(&crypto_method_aes_cbc_128, key, 128, NX_CRYPTO_NULL, md, mdsz);
    UINT st = run(&crypto_method_aes_cbc_128, NX_CRYPTO_ENCRYPT, &crypto_method_aes_cbc_128, key, 128, pt, 16, iv, ct, 16, md, mdsz);
    printf("aes128_status=%u\n", st);
    hex("aes128_fips197", ct, 16);
    free(md);

    /* RFC 5869 A.1 */
    UCHAR ikm[22], salt[13], info[10], prk[64] = {0}, okm[42] = {0};
    memset(ikm, 0x0b, sizeof ikm);
    for (int i = 0; i < 13; i++) salt[i] = (UCHAR)i;
    for (int i = 0; i < 10; i++) info[i] = (UCHAR)(0xf0 + i);
    NX_CRYPTO_HKDF *hk = (NX_CRYPTO_HKDF *)calloc(1, sizeof(NX_CRYPTO_HKDF));
    ULONG hsz = sizeof(NX_CRYPTO_HKDF);
    crypto_method_hkdf.nx_crypto_init(&crypto_method_hkdf, ikm, sizeof ikm * 8, NX_CRYPTO_NULL, hk, hsz);
    run(&crypto_method_hkdf, NX_CRYPTO_HKDF_SET_HASH, &crypto_method_sha256, NULL, 0, NULL, 0, NULL, NULL, 0, hk, hsz);
    run(&crypto_method_hkdf, NX_CRYPTO_HKDF_SET_HMAC, &crypto_method_hmac_sha256, NULL, 0, NULL, 0, NULL, NULL, 0, hk, hsz);
    st = run(&crypto_method_hkdf, NX_CRYPTO_HKDF_EXTRACT, &crypto_method_hkdf, salt, sizeof salt * 8, ikm, sizeof ikm, NULL, prk, 64, hk, hsz);
    printf("hkdf_extract_status=%u\n", st);
    hex("hkdf_prk", prk, 32);
    st = run(&crypto_method_hkdf, NX_CRYPTO_HKDF_EXPAND, &crypto_method_hkdf, info, sizeof info * 8, NULL, 0, NULL, okm, sizeof okm, hk, hsz);
    printf("hkdf_expand_status=%u\n", st);
    hex("hkdf_okm", okm, sizeof okm);
    crypto_method_hkdf.nx_crypto_cleanup(hk);
    free(hk);
    return 0;
}
