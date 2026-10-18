# CMS SignedData

`sm-crypto-wasm/cms` provides CMS SignedData signing and verification with SM2:

- detached (default) and attached modes;
- builds the `contentType` / `messageDigest` / `signingTime` signed attributes;
- verifies over the **original DER bytes** of `signedAttrs`, never re-encoding;
- accepts BER indefinite-length input;
- returns structured failure reasons.

Only SignedData is implemented — no EnvelopedData or RFC 3161 timestamps, and
**no trust-chain building**. Certificate validity, usage and CRL/OCSP checks are
the caller's responsibility.

## Signing

```ts
import { cms, sm2, sm3 } from 'sm-crypto-wasm';

await sm2.ensureLoaded();
await sm3.ensureLoaded();

const signed = cms.signData({
  data: 'message',                // strings are encoded as UTF-8 (not hex/base64)
  privateKey: privateKeyPem,
  certificate: certificatePem,    // signer certificate
  certificates: [caPem],          // optional extra chain certificates
  detached: true,                 // default
  signingTime: new Date(),        // default now; false to omit
});

signed.der;     // Uint8Array
signed.pem;     // -----BEGIN CMS-----
signed.base64;
```

The signer identifier is `issuerAndSerialNumber`, taken from the signer certificate.

## Verification

```ts
const result = cms.verifySignedData(signed.der, {
  detachedData: 'message',
  certificates: [extraPem],       // optional extra candidates
});

result.valid;                     // true only if every signer is valid
result.signers[0]?.valid;
result.signers[0]?.certificate;
result.signers[0]?.signingTime;
result.signers[0]?.errorCode;
result.signers[0]?.error;
```

`errorCode`:

| Value | Meaning |
| --- | --- |
| `NO_CERTIFICATE` | the signer certificate is neither embedded nor supplied |
| `DIGEST_MISMATCH` | `messageDigest` / `contentType` does not match the content |
| `SIGNATURE_INVALID` | malformed signature value or failed SM2 verification |
| `UNSUPPORTED_ALGORITHM` | digest/signature algorithm is not SM3 / SM3withSM2 |
| `MALFORMED` | malformed CMS, or detached mode without `detachedData` |

Completely unparseable input returns a `MALFORMED` result instead of throwing;
environment errors such as unloaded wasm still throw.

## Input formats

`verifySignedData` / `parseSignedData` accept:

- PEM (`-----BEGIN CMS-----` or `-----BEGIN PKCS7-----`);
- base64 / hex;
- DER or BER bytes.

## User id

CMS signing uses the **empty** SM2 user id by default, matching OpenSSL's CMS
path. For the GM/T default id:

```ts
import { DEFAULT_SM2_USER_ID } from 'sm-crypto-wasm/x509';

cms.signData({ data, privateKey, certificate, userID: DEFAULT_SM2_USER_ID });
cms.verifySignedData(der, { detachedData: data, userID: DEFAULT_SM2_USER_ID });
```

When `userID` is omitted during verification, the empty id is tried first and
the GM/T default second.

## Security boundaries

- verifies only that the signature matches the content — **not that the
  certificate is trusted**; callers must perform chain / policy / validity checks;
- certificate usage is not checked;
- `signData` neither generates nor manages private keys.
