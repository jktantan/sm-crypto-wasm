# 安全策略 / Security Policy

## 支持的版本 / Supported versions

当前维护安全修复的版本 / Versions currently receiving security fixes:

| 版本 / Version | 支持 / Supported |
|---|---|
| 0.7.x | ✅ |
| < 0.7 | ❌ |

## 报告漏洞 / Reporting a vulnerability

请**不要**通过公开 Issue 报告安全漏洞。请使用 GitHub Security Advisories：
Please **do not** report security vulnerabilities through public issues. Use GitHub Security Advisories:

<https://github.com/jktantan/sm-crypto-wasm/security/advisories/new>

报告中请尽量包含 / Please include as much of the following as possible:

- 受影响的版本或提交 / affected version or commit;
- 复现步骤或最小 PoC / reproduction steps or a minimal PoC;
- 影响范围（机密性 / 完整性 / 可用性）/ impact (confidentiality / integrity / availability);
- 是否涉及密钥、随机数、WASM 内存安全等 / whether keys, random number generation,
  or WASM memory safety are involved.

## 范围 / Scope

本项目实现 SM2 / SM3 / SM4 / SM9 / ZUC 以及 X.509 / CMS / WebCrypto 子集。
This project implements SM2 / SM3 / SM4 / SM9 / ZUC and subsets of X.509 / CMS / WebCrypto.

以下情况通常不视为本库漏洞 / The following are generally not considered vulnerabilities in this library:

- 调用方自行管理密钥、IV 或计数器时的误用 /
  misuse by callers who manage keys, IVs, or counters themselves;
- 宿主无法提供 `crypto.getRandomValues` 的安全上下文问题 /
  security-context issues where the host cannot provide `crypto.getRandomValues`;
- README / 文档中未声明支持的运行时 /
  runtimes not declared as supported in the README or documentation;
- 第三方打包器或运行时自身的缺陷 /
  defects in third-party bundlers or runtimes.

## 披露 / Disclosure

确认问题后，维护者会在 GitHub Security Advisory 中协调修复与披露；
修复发布后会在对应的 Release Notes 中说明。

After a report is confirmed, maintainers will coordinate the fix and disclosure in a
GitHub Security Advisory. Once the fix is released, it will be described in the
corresponding Release Notes.
