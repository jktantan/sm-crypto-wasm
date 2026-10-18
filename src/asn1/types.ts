/**
 * ASN.1 通用类型与常量（DER/BER 子集）。
 *
 * 与旧 `src/pem/asn1.ts` 的关系：
 * - 旧实现只覆盖 PKCS#8 用到的最小类型，且不保留 `constructed` 位；
 * - 本层是 X.509 / CMS / WebCrypto 共用的通用基础设施，覆盖
 *   BOOLEAN、SET、字符串、时间、context/application/private 标签等。
 *
 * 设计要点：
 * - 每个节点保留 `raw`（含 tag + length + value 的原始切片），X.509 的 TBS
 *   与 CMS 的 `signedAttrs` 验签必须对原始字节做摘要，不能重新编码；
 * - `raw` 是对输入缓冲的**视图**（不拷贝），调用方不应假定其生命周期；
 *   需要长期持有时自行 `slice()`；
 * - 解析错误统一为 `Asn1Error`；上层（X.509/CMS）负责转换为各自的错误类型。
 */

/** ASN.1 标签类别。 */
export type Asn1Class = 0 | 1 | 2 | 3;

/** ASN.1 标签类别常量。 */
export const Asn1Class = {
  Universal: 0,
  Application: 1,
  ContextSpecific: 2,
  Private: 3,
} as const;

/** UNIVERSAL 类常用标签编号。 */
export const UniversalTag = {
  EndOfContent: 0,
  Boolean: 1,
  Integer: 2,
  BitString: 3,
  OctetString: 4,
  Null: 5,
  ObjectIdentifier: 6,
  Enumerated: 10,
  Utf8String: 12,
  Sequence: 16,
  Set: 17,
  NumericString: 18,
  PrintableString: 19,
  TeletexString: 20,
  VideotexString: 21,
  Ia5String: 22,
  UtcTime: 23,
  GeneralizedTime: 24,
  UniversalString: 28,
  BmpString: 30,
} as const;

/** ASN.1 节点。 */
export interface Asn1Node {
  /** 标签类别：UNIVERSAL=0、APPLICATION=1、CONTEXT=2、PRIVATE=3。 */
  readonly cls: Asn1Class;
  /** 标签编号（高 tag number 已展开为数值，不含 0x1f 标志位）。 */
  readonly tag: number;
  /** 是否为 constructed 编码。 */
  readonly constructed: boolean;
  /** 是否使用 BER indefinite-length（`0x80` + EOC）。DER 节点恒为 false。 */
  readonly indefinite: boolean;
  /** 内容字节数（indefinite 时为实际内容长度，不含 EOC）。 */
  readonly length: number;
  /** primitive 的 value；constructed 为子节点编码拼接后的内容字节。 */
  readonly value: Uint8Array;
  /** constructed 节点的子节点；primitive 为 `undefined`。 */
  readonly children?: readonly Asn1Node[];
  /** 节点原始字节（含 tag + length + value；indefinite 时含 EOC）。 */
  readonly raw: Uint8Array;
}

/** ASN.1 解析/编码错误。 */
export class Asn1Error extends Error {
  override readonly name = 'Asn1Error';
}

/** 判断节点是否为指定 UNIVERSAL 类型。 */
export function isUniversal(node: Asn1Node, tag: number): boolean {
  return node.cls === Asn1Class.Universal && node.tag === tag;
}

/** 断言节点为指定 UNIVERSAL 类型，否则抛 `Asn1Error`。 */
export function expectUniversal(node: Asn1Node | undefined, tag: number, what: string): Asn1Node {
  if (node === undefined) {
    throw new Asn1Error(`${what}: missing element (expected tag ${tag})`);
  }
  if (!isUniversal(node, tag)) {
    throw new Asn1Error(
      `${what}: expected UNIVERSAL tag ${tag}, got class ${node.cls} tag ${node.tag}`,
    );
  }
  return node;
}

/** 断言节点为 constructed SEQUENCE 并返回子节点。 */
export function expectSequence(node: Asn1Node | undefined, what: string): readonly Asn1Node[] {
  const seq = expectUniversal(node, UniversalTag.Sequence, what);
  if (!seq.children) {
    throw new Asn1Error(`${what}: SEQUENCE is not constructed`);
  }
  return seq.children;
}
