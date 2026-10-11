import { expect } from "vitest";

import { RemoteSignerError } from "../../src/errors/index.js";
import type { RemoteSignerErrorCode } from "../../src/errors/index.js";

/** Asserts that `fn` throws a {@link RemoteSignerError} with `code`. */
export function expectCode(
    fn: () => unknown,
    code: RemoteSignerErrorCode,
): void {
    try {
        fn();
    } catch (e) {
        expect(e).toBeInstanceOf(RemoteSignerError);
        expect((e as RemoteSignerError).code).toBe(code);
        return;
    }
    throw new Error(`expected RemoteSignerError ${code}`);
}

/** Asserts that `promise` rejects with a {@link RemoteSignerError} with `code`. */
export async function expectCodeAsync(
    promise: Promise<unknown>,
    code: RemoteSignerErrorCode,
): Promise<RemoteSignerError> {
    const err = await promise.then(
        () => undefined,
        (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(RemoteSignerError);
    expect((err as RemoteSignerError).code).toBe(code);
    return err as RemoteSignerError;
}
