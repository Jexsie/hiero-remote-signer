import { describe, expect, it } from "vitest";
import { secp256k1 } from "@noble/curves/secp256k1.js";

import { compressSecp256k1Point, parseSpki } from "../../../src/der/index.js";
import { RemoteSignerErrorCodes } from "../../../src/errors/index.js";
import { expectCode } from "../../utils/assertions.js";
import { makeKey } from "../../utils/fake-kms.js";

describe("parseSpki", () => {
    it("extracts a compressed secp256k1 point that matches the private key", () => {
        const key = makeKey("ECC_SECG_P256K1");
        const parsed = parseSpki(key.spki);
        expect(parsed.keyType).toBe("ECDSA_SECP256K1");
        expect(parsed.publicKey).toEqual(
            secp256k1.getPublicKey(key.privateKey, true),
        );
    });

    it("extracts a 32-byte Ed25519 key", () => {
        const parsed = parseSpki(makeKey("ECC_NIST_EDWARDS25519").spki);
        expect(parsed.keyType).toBe("ED25519");
        expect(parsed.publicKey.length).toBe(32);
    });

    it("rejects P-256, which Hiero does not verify", () => {
        expectCode(
            () => parseSpki(makeKey("ECC_NIST_P256").spki),
            RemoteSignerErrorCodes.UnsupportedKey,
        );
    });

    it("rejects RSA keys", () => {
        expectCode(
            () => parseSpki(makeKey("RSA_2048").spki),
            RemoteSignerErrorCodes.UnsupportedKey,
        );
    });

    it("rejects truncated and padded input", () => {
        const spki = makeKey("ECC_SECG_P256K1").spki;
        expectCode(
            () => parseSpki(spki.subarray(0, spki.length - 1)),
            RemoteSignerErrorCodes.MalformedDer,
        );
        expectCode(
            () => parseSpki(new Uint8Array([...spki, 0])),
            RemoteSignerErrorCodes.MalformedDer,
        );
    });
});

describe("compressSecp256k1Point", () => {
    const priv = secp256k1.utils.randomSecretKey();

    it("compresses an uncompressed point", () => {
        const uncompressed = secp256k1.getPublicKey(priv, false);
        expect(compressSecp256k1Point(uncompressed)).toEqual(
            secp256k1.getPublicKey(priv, true),
        );
    });

    it("returns a copy of an already compressed point", () => {
        const compressed = secp256k1.getPublicKey(priv, true);
        const out = compressSecp256k1Point(compressed);
        expect(out).toEqual(compressed);
        expect(out).not.toBe(compressed);
    });

    it("rejects other encodings", () => {
        expectCode(
            () => compressSecp256k1Point(new Uint8Array(64)),
            RemoteSignerErrorCodes.MalformedDer,
        );
    });
});

describe("parseSpki structural checks", () => {
    it("rejects a BIT STRING with unused bits", () => {
        const spki = new Uint8Array(makeKey("ECC_NIST_EDWARDS25519").spki);
        // Ed25519 SPKI: 30 2a 30 05 06 03 2b 65 70 03 21 00 <32 bytes>
        spki[11] = 0x01;
        expectCode(() => parseSpki(spki), RemoteSignerErrorCodes.MalformedDer);
    });

    it("rejects an Ed25519 key that is not 32 bytes", () => {
        const spki = new Uint8Array([
            0x30, 0x0c, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x03,
            0x00, 0x01, 0x02,
        ]);
        expectCode(() => parseSpki(spki), RemoteSignerErrorCodes.MalformedDer);
    });
});
