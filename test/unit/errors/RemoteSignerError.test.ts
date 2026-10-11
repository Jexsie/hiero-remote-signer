import { describe, expect, it } from "vitest";

import {
    RemoteSignerError,
    RemoteSignerErrorCodes,
} from "../../../src/errors/index.js";

describe("RemoteSignerError", () => {
    it("carries its code, message and name", () => {
        const error = new RemoteSignerError(
            RemoteSignerErrorCodes.UnsupportedKey,
            "bad key",
        );
        expect(error.code).toBe("UNSUPPORTED_KEY");
        expect(error.message).toBe("bad key");
        expect(error.name).toBe("RemoteSignerError");
        expect(error.cause).toBeUndefined();
    });

    it("keeps the original error as cause", () => {
        const cause = new Error("original");
        const error = new RemoteSignerError(
            RemoteSignerErrorCodes.BackendRequestFailed,
            "wrapped",
            { cause },
        );
        expect(error.cause).toBe(cause);
    });

    it("is instanceof Error", () => {
        const error = new RemoteSignerError(
            RemoteSignerErrorCodes.MalformedDer,
            "test",
        );
        expect(error).toBeInstanceOf(Error);
        expect(error).toBeInstanceOf(RemoteSignerError);
    });
});
