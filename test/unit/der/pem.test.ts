import { describe, expect, it } from "vitest";

import { pemToDer } from "../../../src/der/index.js";
import { RemoteSignerErrorCodes } from "../../../src/errors/index.js";
import { expectCode } from "../../utils/assertions.js";
import { generateKeyMaterial } from "../../utils/key-material.js";

describe("pemToDer", () => {
    it("decodes a PUBLIC KEY block to the SubjectPublicKeyInfo DER", () => {
        const key = generateKeyMaterial("secp256k1");
        expect(pemToDer(key.pem)).toEqual(key.spki);
    });

    it("rejects a block with another label", () => {
        expectCode(
            () =>
                pemToDer(
                    "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----",
                ),
            RemoteSignerErrorCodes.MalformedDer,
        );
    });

    it("rejects input without a PEM block", () => {
        expectCode(
            () => pemToDer("not pem"),
            RemoteSignerErrorCodes.MalformedDer,
        );
    });
});
