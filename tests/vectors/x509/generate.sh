#!/usr/bin/env bash
#
# 重新生成 tests/vectors/x509/ 下的证书样本。
#
# 环境：OpenSSL 3.5.5（必须支持 SM2；`openssl ecparam -list_curves | grep SM2`）。
# 生成结果是确定性输入（固定序列号与有效期），除签名随机性外字段完全一致。
# 私钥仅用于测试，**不要**用于任何真实用途。
set -euo pipefail
cd "$(dirname "$0")"

# Windows Git Bash 会把 `/C=CN/...` 当作路径重写，导致 -subj 解析失败。
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

OPENSSL=${OPENSSL:-openssl}
"$OPENSSL" version

rm -f ./*.pem ./*.der ./*.key ./*.csr ./*.srl

# 固定时间窗口（当前测试基线：2026 年）。
NB="20240101000000Z"
NA="20340101000000Z"
LEAF_NA="20300101000000Z"
EXPIRED_NB="20200101000000Z"
EXPIRED_NA="20210101000000Z"
FUTURE_NB="20300101000000Z"
FUTURE_NA="20310101000000Z"

extfile() {
  local name=$1
  shift
  printf '%s\n' "$@" > "$name"
}

# ---------- 自签根 CA ----------
"$OPENSSL" req -x509 -newkey sm2 -nodes \
  -keyout root-ca.key -out root-ca.pem \
  -subj "/C=CN/O=SM Crypto Test/OU=PKI/CN=SM Crypto Root CA" \
  -set_serial 0x1001 -not_before "$NB" -not_after "$NA" \
  -sigopt distid:1234567812345678 \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:2" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" \
  -addext "authorityKeyIdentifier=keyid:always"

# ---------- 中间 CA ----------
"$OPENSSL" genpkey -algorithm SM2 -out intermediate-ca.key
"$OPENSSL" req -new -key intermediate-ca.key \
  -subj "/C=CN/O=SM Crypto Test/OU=PKI/CN=SM Crypto Intermediate CA" \
  -out intermediate-ca.csr
extfile intermediate.ext \
  "basicConstraints=critical,CA:TRUE,pathlen:0" \
  "keyUsage=critical,keyCertSign,cRLSign" \
  "subjectKeyIdentifier=hash" \
  "authorityKeyIdentifier=keyid,issuer"
"$OPENSSL" x509 -req -in intermediate-ca.csr \
  -CA root-ca.pem -CAkey root-ca.key -set_serial 0x1002 \
  -not_before "$NB" -not_after "$NA" \
  -sigopt distid:1234567812345678 \
  -extfile intermediate.ext -out intermediate-ca.pem

# ---------- 终端证书：服务端 ----------
"$OPENSSL" genpkey -algorithm SM2 -out leaf-server.key
"$OPENSSL" req -new -key leaf-server.key \
  -subj "/C=CN/O=SM Crypto Test/OU=Servers/CN=server.example.test" \
  -out leaf-server.csr
extfile leaf-server.ext \
  "basicConstraints=critical,CA:FALSE" \
  "keyUsage=critical,digitalSignature,keyEncipherment" \
  "extendedKeyUsage=serverAuth" \
  "subjectAltName=DNS:server.example.test,DNS:alt.example.test,IP:127.0.0.1,IP:2001:db8::1" \
  "subjectKeyIdentifier=hash" \
  "authorityKeyIdentifier=keyid,issuer"
"$OPENSSL" x509 -req -in leaf-server.csr \
  -CA intermediate-ca.pem -CAkey intermediate-ca.key -set_serial 0x1003 \
  -not_before "$NB" -not_after "$LEAF_NA" \
  -sigopt distid:1234567812345678 \
  -extfile leaf-server.ext -out leaf-server.pem

# ---------- 双证书：签名证书 ----------
"$OPENSSL" genpkey -algorithm SM2 -out leaf-sign.key
"$OPENSSL" req -new -key leaf-sign.key \
  -subj "/C=CN/O=SM Crypto Test/OU=Signing/CN=SM Crypto Signing Cert" \
  -out leaf-sign.csr
extfile leaf-sign.ext \
  "basicConstraints=critical,CA:FALSE" \
  "keyUsage=critical,digitalSignature,nonRepudiation" \
  "extendedKeyUsage=emailProtection" \
  "subjectKeyIdentifier=hash" \
  "authorityKeyIdentifier=keyid,issuer"
"$OPENSSL" x509 -req -in leaf-sign.csr \
  -CA intermediate-ca.pem -CAkey intermediate-ca.key -set_serial 0x1004 \
  -not_before "$NB" -not_after "$LEAF_NA" \
  -sigopt distid:1234567812345678 \
  -extfile leaf-sign.ext -out leaf-sign.pem

# ---------- 双证书：加密证书 ----------
"$OPENSSL" genpkey -algorithm SM2 -out leaf-enc.key
"$OPENSSL" req -new -key leaf-enc.key \
  -subj "/C=CN/O=SM Crypto Test/OU=Encryption/CN=SM Crypto Encryption Cert" \
  -out leaf-enc.csr
extfile leaf-enc.ext \
  "basicConstraints=critical,CA:FALSE" \
  "keyUsage=critical,keyEncipherment,dataEncipherment" \
  "subjectKeyIdentifier=hash" \
  "authorityKeyIdentifier=keyid,issuer"
"$OPENSSL" x509 -req -in leaf-enc.csr \
  -CA intermediate-ca.pem -CAkey intermediate-ca.key -set_serial 0x1005 \
  -not_before "$NB" -not_after "$LEAF_NA" \
  -sigopt distid:1234567812345678 \
  -extfile leaf-enc.ext -out leaf-enc.pem

# ---------- 过期证书 ----------
"$OPENSSL" genpkey -algorithm SM2 -out expired.key
"$OPENSSL" req -new -key expired.key \
  -subj "/C=CN/O=SM Crypto Test/CN=Expired Cert" -out expired.csr
extfile expired.ext \
  "basicConstraints=critical,CA:FALSE" \
  "keyUsage=critical,digitalSignature" \
  "subjectKeyIdentifier=hash" \
  "authorityKeyIdentifier=keyid,issuer"
"$OPENSSL" x509 -req -in expired.csr \
  -CA root-ca.pem -CAkey root-ca.key -set_serial 0x1006 \
  -not_before "$EXPIRED_NB" -not_after "$EXPIRED_NA" \
  -sigopt distid:1234567812345678 \
  -extfile expired.ext -out expired.pem

# ---------- 尚未生效证书 ----------
"$OPENSSL" genpkey -algorithm SM2 -out future.key
"$OPENSSL" req -new -key future.key \
  -subj "/C=CN/O=SM Crypto Test/CN=Future Cert" -out future.csr
extfile future.ext \
  "basicConstraints=critical,CA:FALSE" \
  "keyUsage=critical,digitalSignature" \
  "subjectKeyIdentifier=hash" \
  "authorityKeyIdentifier=keyid,issuer"
"$OPENSSL" x509 -req -in future.csr \
  -CA root-ca.pem -CAkey root-ca.key -set_serial 0x1007 \
  -not_before "$FUTURE_NB" -not_after "$FUTURE_NA" \
  -sigopt distid:1234567812345678 \
  -extfile future.ext -out future.pem

# ---------- OpenSSL 默认用户标识（空 ID）自签，兼容性样本 ----------
# 不加 -sigopt distid，OpenSSL 的 X.509 路径使用空标识。
"$OPENSSL" req -x509 -newkey sm2 -nodes \
  -keyout root-ca-openssl-default.key -out root-ca-openssl-default.pem \
  -subj "/C=CN/O=SM Crypto Test/CN=OpenSSL Default ID CA" \
  -set_serial 0x1008 -not_before "$NB" -not_after "$NA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# ---------- RSA 自签（负例：可解析，但不支持验签） ----------
"$OPENSSL" req -x509 -newkey rsa:2048 -nodes \
  -keyout rsa.key -out rsa.pem \
  -subj "/C=CN/O=SM Crypto Test/CN=RSA Test Cert" \
  -set_serial 0x2001 -not_before "$NB" -not_after "$NA" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment"

# ---------- DER 副本 ----------
for name in root-ca intermediate-ca leaf-server leaf-sign leaf-enc expired future root-ca-openssl-default rsa; do
  "$OPENSSL" x509 -in "$name.pem" -outform DER -out "$name.der"
done

# 清理中间文件。
rm -f ./*.csr ./*.srl ./*.ext

ls -l
