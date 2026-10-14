/**
 * 统一错误类型层级（error hierarchy）。
 *
 * 设计要点：
 * - 所有公开 API 抛出的错误都是 `SmCryptoError` 或其子类的实例；
 *   调用方可用 `err instanceof SmError` 一次判定是不是这个库出的错。
 * - 子类按"用户修复路径"细分：
 *   - `InvalidKeyError`：密钥格式错（坏 PEM / 坏 OID / 偏曲线点等）。
 *   - `InvalidCiphertextError`：密文结构错（C1/C3 长度不对 / 坏 ASN.1）。
 *   - `DecryptionError`：解密失败（解出的明文 C3 SM3 校验不过 / 私钥错）。
 *   - `NotImplementedError`：算法尚未实现（仅 stub 阶段出现）。
 *   - `TypeError` / `RangeError`：保留宿主原生类型，**不**包装为 SmCryptoError。
 *
 * spec/plan 对应：plan Task 2；spec §6 API、§9 安全姿态。
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

/** 密文无效：长度、版本字节、ASN.1 结构不符合规范。 */
export class InvalidCiphertextError extends SmCryptoError {
  override readonly name = 'InvalidCiphertextError';
}

/** 解密失败：密文结构合法但解密结果与预期 MAC/SM3 不一致。 */
export class DecryptionError extends SmCryptoError {
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
