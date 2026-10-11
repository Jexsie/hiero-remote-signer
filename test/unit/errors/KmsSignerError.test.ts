import { describe, expect, it } from "vitest";

import {
    KmsSignerError,
    KmsSignerErrorCodes,
} from "../../../src/errors/index.js";

describe("KmsSignerError", () => {
    it("carries its code, message and name", () => {
        const error = new KmsSignerError(
            KmsSignerErrorCodes.UnsupportedKey,
            "bad key",
        );
        expect(error.code).toBe("UNSUPPORTED_KEY");
        expect(error.message).toBe("bad key");
        expect(error.name).toBe("KmsSignerError");
        expect(error.cause).toBeUndefined();
    });

    it("keeps the original error as cause", () => {
        const cause = new Error("original");
        const error = new KmsSignerError(
            KmsSignerErrorCodes.KmsRequestFailed,
            "wrapped",
            { cause },
        );
        expect(error.cause).toBe(cause);
    });

    it("is instanceof Error", () => {
        const error = new KmsSignerError(
            KmsSignerErrorCodes.MalformedDer,
            "test",
        );
        expect(error).toBeInstanceOf(Error);
        expect(error).toBeInstanceOf(KmsSignerError);
    });
});
