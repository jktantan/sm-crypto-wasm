/**
 * 旧 ASN.1 入口（兼容层）。
 *
 * 实现已迁移到 `src/asn1/`（DER/BER 通用层）。本文件只保留历史导出名，
 * 使 `src/pem/*` 与既有测试无需改动：
 *
 * - `parseDer` → `src/asn1/decode.ts`
 * - `encodeDer` → `src/asn1/encode.ts` 的 `encode`
 * - `asn1Int` / `asn1Octets` / `asn1Oid` / `asn1Null` / `asn1Seq` → 对应构造器
 * - `encodeOid` / `decodeOid` / `asn1IntValue` → OID 与 INTEGER 解码
 *
 * spec/plan 对应：X.509/CMS plan 阶段 0「迁移」。
 */

export {
  decodeOid,
  encode as encodeDer,
  encodeOid,
  integer as asn1Int,
  nullValue as asn1Null,
  octetString as asn1Octets,
  oid as asn1Oid,
  parseDer,
  readInteger as asn1IntValue,
  seq as asn1Seq,
} from '../asn1/index.js';
export { Asn1Error, type Asn1Node } from '../asn1/types.js';
