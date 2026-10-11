import { expect } from "vitest";

import { KmsSignerError } from "../../src/errors/index.js";
import type { KmsSignerErrorCode } from "../../src/errors/index.js";

/** Asserts that `fn` throws a {@link KmsSignerError} with `code`. */
export function expectCode(fn: () => unknown, code: KmsSignerErrorCode): void {
    try {
        fn();
    } catch (e) {
        expect(e).toBeInstanceOf(KmsSignerError);
        expect((e as KmsSignerError).code).toBe(code);
        return;
    }
    throw new Error(`expected KmsSignerError ${code}`);
}

/** Asserts that `promise` rejects with a {@link KmsSignerError} with `code`. */
export async function expectCodeAsync(
    promise: Promise<unknown>,
    code: KmsSignerErrorCode,
): Promise<KmsSignerError> {
    const err = await promise.then(
        () => undefined,
        (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(KmsSignerError);
    expect((err as KmsSignerError).code).toBe(code);
    return err as KmsSignerError;
}
