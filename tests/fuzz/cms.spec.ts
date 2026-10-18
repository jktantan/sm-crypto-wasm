/**
 * CMS 解析器 fuzz（plan「测试与向量策略」）。
 *
 * - `parseSignedData`：随机字节只能抛 `CmsError`；
 * - `verifySignedData`：随机字节必须返回 `valid=false`（MALFORMED），不能抛错。
 */
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { CmsError, parseSignedData, verifySignedData } from '@/cms';

describe('CMS parser fuzz', () => {
  it('parseSignedData only throws CmsError', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 4096 }), (bytes) => {
        try {
          parseSignedData(new Uint8Array(bytes));
        } catch (err) {
          expect(err).toBeInstanceOf(CmsError);
        }
      }),
      { numRuns: 200 },
    );
  });

  it('verifySignedData returns MALFORMED instead of throwing', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 4096 }), (bytes) => {
        const result = verifySignedData(new Uint8Array(bytes));
        expect(result.valid).toBe(false);
        if (result.signers.length > 0) {
          expect(result.signers[0]?.errorCode).toBe('MALFORMED');
        }
      }),
      { numRuns: 200 },
    );
  });
});
