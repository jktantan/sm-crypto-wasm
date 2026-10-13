/**
 * SM9 算法 OID 常量与按 OID 调度解析的辅助函数。
 *
 * spec/plan 对应：plan Task 4；spec §12.1 Q3。
 *
 * 主私钥 / 主公钥 / 用户私钥 / 用户公钥都使用同一 SM9 算法 OID；
 * 区别在于私钥文件里包不包含用户标识 hash 与 KGC 主私钥派生信息。
 * 本文件只定义**算法层** OID 调度，高层 key 类型在 `src/sm9/` 与
 * `src/sm2/` 的 pem 模块中定义。
 */

export const SM9_OID = '1.2.156.10197.1.100';
