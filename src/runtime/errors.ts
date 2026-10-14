/**
 * 统一错误类型层级（error hierarchy）。
 *
 * 设计要点：
 * - **所有库语义错误都是 `SmCryptoError` 的子类**；调用方可用
 *   `err instanceof SmCryptoError` 一次判定"是不是这个库因其输入而拒绝"。
 * - 按"用户修复路径"分两支：
 *   - 密钥支 `InvalidKeyError`：密钥 / 标量输入的格式、长度、曲线合法性有问题。
 *     （`InvalidPublicKeyError` 是其子类。）
 *   - 密文支 `CiphertextError`：密文 / 签名 / 协议消息的结构或校验有问题。
 *     - `InvalidCiphertextError`：结构不对（长度、版本字节、ASN.1、点编码）。
 *     - `DecryptionError`：结构合法但校验不通过（C3 SM3 / GCM tag / C3 HMAC）。
 * - **只有"参数根本不是密码学对象"才用宿主原生类型**：类型不对抛 `TypeError`，
 *   数值越界（长度上限、计数器为负等）抛 `RangeError`，不包装为 `SmCryptoError`。
 *
 * spec/plan 对应：plan Task 2、Review Focus #3/#4；spec §6 API、§9 安全姿态。
 */

/** 库根错误。所有自定义错误都派生自它。 */
export class SmCryptoError extends Error {
  /** 错误名，便于跨语言/跨进程识别错误类型。 */
  override readonly name: string = 'SmCryptoError';

  constructor(message: string, options?: { cause?: unknown }) {
    super(message);
    if (options?.cause !== undefined) {
      (this as { cause?: unknown }).cause = options.cause;
    }
  }
}

/** 密钥无效：解析失败、OID 不支持、点不在曲线上、长度不对等。 */
export class InvalidKeyError extends SmCryptoError {
  override readonly name: string = 'InvalidKeyError';
}

/** 公钥无效：不在曲线上、坐标越界、或为无穷远点。 */
export class InvalidPublicKeyError extends InvalidKeyError {
  override readonly name = 'InvalidPublicKeyError';
}

/** 密文支的基类：密文 / 签名 / 协议消息相关失败的共同祖先。 */
export class CiphertextError extends SmCryptoError {
  override readonly name: string = 'CiphertextError';
}

/** 密文无效：长度、版本字节、ASN.1 结构、点编码不符合规范。 */
export class InvalidCiphertextError extends CiphertextError {
  override readonly name = 'InvalidCiphertextError';
}

/** 解密失败：密文结构合法但解密结果与预期 MAC / SM3 不一致。 */
export class DecryptionError extends CiphertextError {
  override readonly name = 'DecryptionError';
}

/** 算法尚未实现（仅在 stub 阶段出现）。提示用户等待后续版本。 */
export class NotImplementedError extends SmCryptoError {
  override readonly name = 'NotImplementedError';
}

/**
 * 类型守卫：`err` 是不是本库的 SmCryptoError（含子类）。
 *
 * @param err 任意异常。
 */
export function isSmCryptoError(err: unknown): err is SmCryptoError {
  return err instanceof SmCryptoError;
}
