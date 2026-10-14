/*
 * 生成 SM2 密钥交换 KAT 向量（tests/vectors/sm2/keyexchange.json）。
 *
 * 依赖 GmSSL 3.3 源码（github.com/guanzhi/GmSSL）。在该源码根目录编译：
 *
 *   clang -I include -O1 -o gmkexvec <此文件> \
 *     src/sm2_exch.c src/sm2_enc.c src/sm2_key.c src/sm2_sign.c \
 *     src/sm2_z256.c src/sm2_z256_table.c src/sm3.c src/hex.c \
 *     -ffunction-sections -Wl,-dead_strip
 *
 * 运行输出 RA/RB/ZA/ZB/U/SA/SB/K。注意：GmSSL 本身不含官方（GB/T 32918.3
 * 附录 A）固定向量——它的 tests/sm2_exchtest.c 是随机自洽；此程序用固定输入
 * 生成确定性样本，作为权威 C 实现的行为锚。
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <gmssl/sm2.h>
#include <gmssl/sm2_z256.h>

static void ph(const char *label, const uint8_t *b, size_t n) {
    printf("%s=", label);
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

int main(void) {
    const char *dA_hex = "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8";
    const char *dB_hex = "7a3d1c2b9e4f5061728394a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f";
    const char *rA_hex = "0000000000000000000000000000000000000000000000000000000000000003";
    const char *rB_hex = "0000000000000000000000000000000000000000000000000000000000000005";
    const char *ida = "Alice", *idb = "Bob";

    SM2_KEY a, b, ra, rb;
    sm2_z256_t dA, dB, rAv, rBv;
    sm2_z256_from_hex(dA, dA_hex);
    sm2_z256_from_hex(dB, dB_hex);
    sm2_z256_from_hex(rAv, rA_hex);
    sm2_z256_from_hex(rBv, rB_hex);
    if (sm2_key_set_private_key(&a, dA) != 1) { printf("set a fail\n"); return 1; }
    if (sm2_key_set_private_key(&b, dB) != 1) { printf("set b fail\n"); return 1; }
    if (sm2_key_set_private_key(&ra, rAv) != 1) { printf("set ra fail\n"); return 1; }
    if (sm2_key_set_private_key(&rb, rBv) != 1) { printf("set rb fail\n"); return 1; }

    uint8_t ra_oct[65], rb_oct[65];
    sm2_z256_point_to_uncompressed_octets(&ra.public_key, ra_oct);
    sm2_z256_point_to_uncompressed_octets(&rb.public_key, rb_oct);

    uint8_t ua[65], ska[32], sa[32], sb[32];
    if (sm2_key_exchange(1, &a, ida, strlen(ida), &b, idb, strlen(idb), &ra, rb_oct, ua, 32, ska) != 1) { printf("exchange A fail\n"); return 1; }
    if (sm2_key_exchange_compute_confirm(1, &a, ida, strlen(ida), &b, idb, strlen(idb), &ra, rb_oct, ua, sa) != 1) { printf("confirm A fail\n"); return 1; }
    if (sm2_key_exchange_compute_confirm(0, &b, idb, strlen(idb), &a, ida, strlen(ida), &rb, ra_oct, ua, sb) != 1) { printf("confirm B fail\n"); return 1; }

    uint8_t za[32], zb[32];
    sm2_compute_z(za, &a.public_key, ida, strlen(ida));
    sm2_compute_z(zb, &b.public_key, idb, strlen(idb));

    ph("RA", ra_oct, 65);
    ph("RB", rb_oct, 65);
    ph("ZA", za, 32);
    ph("ZB", zb, 32);
    ph("U", ua, 65);
    ph("SA", sa, 32);
    ph("SB", sb, 32);
    ph("K", ska, 32);
    return 0;
}
