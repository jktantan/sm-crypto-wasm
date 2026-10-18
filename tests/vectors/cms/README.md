# CMS 测试向量

固定样本由 **OpenSSL 3.5.5** 生成，CI 不依赖 OpenSSL 动态生成。

生成命令（在 `tests/vectors/cms/` 下执行）：

```bash
printf 'hello 国密 CMS' > data.bin
printf 'hello ber' > data-ber.bin

# attached（内容内嵌）
openssl cms -sign -in data.bin \
  -signer ../x509/root-ca.pem -inkey ../x509/root-ca.key \
  -outform DER -md sm3 -binary -nodetach -out ossl-attached.der

# detached（内容外置）
openssl cms -sign -in data.bin \
  -signer ../x509/root-ca.pem -inkey ../x509/root-ca.key \
  -outform DER -md sm3 -binary -out ossl-detached.der

# BER indefinite-length（-stream）
openssl cms -sign -in data-ber.bin \
  -signer ../x509/root-ca.pem -inkey ../x509/root-ca.key \
  -outform DER -md sm3 -binary -nodetach -stream \
  -out ossl-ber-indefinite.der
```

| 文件 | 说明 |
|---|---|
| `data.bin` | detached / attached 的原始内容（UTF-8，无换行） |
| `data-ber.bin` | BER 样本的原始内容 |
| `ossl-attached.der` | OpenSSL 生成的 attached SignedData |
| `ossl-detached.der` | OpenSSL 生成的 detached SignedData |
| `ossl-ber-indefinite.der` | OpenSSL `-stream` 生成的 BER indefinite-length SignedData |

签名者证书为 `tests/vectors/x509/root-ca.pem`（其私钥仅用于测试）。
OpenSSL 未指定 `-sigopt distid`，因此签名使用空 SM2 用户标识；本库验签默认
先试空标识，再回退 GM/T 默认标识。
