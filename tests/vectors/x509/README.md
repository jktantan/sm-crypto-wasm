# X.509 测试向量

固定样本，CI **不依赖** OpenSSL 动态生成。当前样本由 **OpenSSL 3.5.5** 生成：

```bash
bash tests/vectors/x509/generate.sh
```

`generate.sh` 使用固定序列号与固定有效期（`-set_serial` / `-not_before` / `-not_after`），
因此除签名随机性外，字段与结构可重复。私钥仅用于测试，**不得**用于任何真实用途。

## 文件

| 文件 | 说明 |
|---|---|
| `root-ca.pem/.der/.key` | SM2 自签根 CA（v3，`CA:TRUE, pathlen:2`，`keyCertSign,cRLSign`，SKI/AKI） |
| `intermediate-ca.pem/.der/.key` | SM2 中间 CA，由根 CA 签发（`pathlen:0`） |
| `leaf-server.pem/.der/.key` | SM2 终端证书：SAN `DNS:server.example.test`、`DNS:alt.example.test`、`IP:127.0.0.1`、`IP:2001:db8::1`，EKU `serverAuth` |
| `leaf-sign.pem/.der/.key` | SM2 签名证书（`digitalSignature,nonRepudiation`，EKU `emailProtection`） |
| `leaf-enc.pem/.der/.key` | SM2 加密证书（`keyEncipherment,dataEncipherment`） |
| `expired.pem/.der/.key` | 已过期（2020-01-01 .. 2021-01-01） |
| `future.pem/.der/.key` | 尚未生效（2030-01-01 .. 2031-01-01） |
| `rsa.pem/.der/.key` | RSA 自签负例：可解析字段，但本库不支持验签 |

有效期基线：

- 根 CA / 中间 CA：2024-01-01 .. 2034-01-01
- 终端证书：2024-01-01 .. 2030-01-01

## 重新生成

```bash
# 需要 OpenSSL 3.x 且支持 SM2：
openssl ecparam -list_curves | grep SM2

bash tests/vectors/x509/generate.sh
```
