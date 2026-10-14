/*
 * 生成 SM4-GCM KAT 向量（tests/vectors/sm4/gcm.json）。
 *
 * GCM 是标准 AEAD（NIST SP 800-38D），套在 SM4（GB/T 32907-2016）的 128-bit
 * 分组上。GmSSL 与 OpenSSL 都遵循同一规范，结果必须一致；本机没有 gmssl
 * 命令，但 OpenSSL 3.6.3 提供 `SM4-GCM`（OID 1.2.156.10197.1.104.8），故用它
 * 作为权威 C 实现的行为锚（与 sm2 目录下 generate-gmssl-vector.c 同一套路）。
 *
 * 注意：Node 的 `node:crypto` 不提供 sm4-gcm，无法沿用 tests/sm4.spec.ts 里
 * 那套 oracle 对比，GCM 只能靠这里的离线向量。
 *
 * 编译（macOS + Homebrew OpenSSL）：
 *
 *   clang -I /opt/homebrew/include -L /opt/homebrew/lib \
 *     -o /tmp/gcmvec tests/vectors/sm4/generate-openssl-vector.c -lcrypto
 *
 * 运行：`/tmp/gcmvec tests/vectors/sm4/gcm.json`（省略参数则写到 stdout）。
 */
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

static FILE *out;

static int hex2bin(const char *h, unsigned char *o) {
    int n = (int)(strlen(h) / 2);
    for (int i = 0; i < n; i++) {
        unsigned v = 0;
        sscanf(h + 2 * i, "%2x", &v);
        o[i] = (unsigned char)v;
    }
    return n;
}

/* 12 字节 IV（96-bit，标准优化路径）。 */
#define IV12 "000000000000000000000000"
/* 16 字节 IV（非 96-bit，走 GHASH 派生 J0）。 */
#define IV16 "00000000000000000000000000000000"
#define KEY "0123456789abcdeffedcba9876543210"

static int first = 1;

static void run(const char *name, const char *ivhex, const char *aadhex,
                const char *pthex) {
    unsigned char key[16], iv[64], aad[256], pt[256], ct[256], tag[16];
    hex2bin(KEY, key);
    int ivlen = hex2bin(ivhex, iv);
    int aadlen = hex2bin(aadhex, aad);
    int ptlen = hex2bin(pthex, pt);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    /* 该 OpenSSL 的 evp.h 没有 EVP_sm4_gcm()，走 provider 的 fetch 接口。 */
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "SM4-GCM", NULL);
    if (!cipher) {
        fprintf(stderr, "SM4-GCM not available\n");
        return;
    }
    int len = 0, outlen = 0;
    EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivlen, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    if (aadlen > 0)
        EVP_EncryptUpdate(ctx, NULL, &len, aad, aadlen);
    EVP_EncryptUpdate(ctx, ct, &len, pt, ptlen);
    outlen = len;
    EVP_EncryptFinal_ex(ctx, ct + outlen, &len);
    outlen += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);

    if (!first)
        fprintf(out, ",\n");
    first = 0;
    fprintf(out,
            "    { \"name\": \"%s\", \"iv\": \"%s\", \"aad\": \"%s\", "
            "\"pt\": \"%s\", \"ct\": \"",
            name, ivhex, aadhex, pthex);
    for (int i = 0; i < outlen; i++)
        fprintf(out, "%02x", ct[i]);
    fprintf(out, "\", \"tag\": \"");
    for (int i = 0; i < 16; i++)
        fprintf(out, "%02x", tag[i]);
    fprintf(out, "\" }");
}

int main(int argc, char **argv) {
    out = stdout;
    if (argc > 1) {
        out = fopen(argv[1], "w");
        if (!out) {
            fprintf(stderr, "cannot open %s\n", argv[1]);
            return 1;
        }
    }

    fprintf(out, "{\n");
    fprintf(out,
            "  \"_source\": \"OpenSSL 3.6.3 EVP_sm4_gcm()，由 "
            "tests/vectors/sm4/generate-openssl-vector.c 生成\",\n");
    fprintf(out,
            "  \"_note\": \"GCM per NIST SP 800-38D + SM4 per GB/T "
            "32907-2016；tag 固定 16 字节。按 OID 1.2.156.10197.1.104.8，与 "
            "GmSSL 的 SM4-GCM 等价。\",\n");
    fprintf(out, "  \"key\": \"%s\",\n", KEY);
    fprintf(out, "  \"cases\": [\n");

    run("iv12-aad16-pt16", IV12,
        "a3b1bac656aa3350677d9197b27022dc", "00112233445566778899aabbccddeeff");
    run("iv12-aad0-pt16", IV12, "",
        "00112233445566778899aabbccddeeff");
    run("iv12-aad20-pt20", IV12, "deadbeefcafebabefeedface1234567890abcd",
        "00112233445566778899aabbccddeeff00112233");
    run("iv12-aad0-pt0", IV12, "", "");
    run("iv16-aad16-pt32", IV16, "a3b1bac656aa3350677d9197b27022dc",
        "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f");

    fprintf(out, "\n  ]\n}\n");

    if (out != stdout)
        fclose(out);
    return 0;
}
