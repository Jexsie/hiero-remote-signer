import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { PublicKey } from "@hiero-ledger/sdk";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";

import {
    derSignatureToCompact,
    normalizeCompactSignature,
} from "../../../src/der/index.js";
import { SECP256K1_N } from "../../../src/der/signature.js";
import {
    RemoteSignerError,
    RemoteSignerErrorCodes,
} from "../../../src/errors/index.js";
import { expectCode } from "../../utils/assertions.js";

const HALF_N = SECP256K1_N >> 1n;

function sValue(compact: Uint8Array): bigint {
    return BigInt("0x" + Buffer.from(compact.subarray(32)).toString("hex"));
}

describe("derSignatureToCompact", () => {
    const priv = secp256k1.utils.randomSecretKey();
    const pub = PublicKey.fromBytesECDSA(secp256k1.getPublicKey(priv, true));

    function derSign(message: Uint8Array, highS: boolean): Uint8Array {
        const compact = secp256k1.sign(keccak_256(message), priv, {
            prehash: false,
            lowS: true,
        });
        let sig = secp256k1.Signature.fromBytes(compact, "compact");
        if (highS) sig = new secp256k1.Signature(sig.r, SECP256K1_N - sig.s);
        return sig.toBytes("der");
    }

    it("passes a low-S signature through unchanged", () => {
        const msg = randomBytes(100);
        const out = derSignatureToCompact(derSign(msg, false));
        expect(sValue(out) <= HALF_N).toBe(true);
        expect(pub.verify(msg, out)).toBe(true);
    });

    it("normalizes high-S, which the Hiero SDK would otherwise reject", () => {
        const msg = randomBytes(100);
        const der = derSign(msg, true);

        // Demonstrates the failure this library prevents.
        const naive = secp256k1.Signature.fromBytes(der, "der").toBytes(
            "compact",
        );
        expect(sValue(naive) > HALF_N).toBe(true);
        expect(pub.verify(msg, naive)).toBe(false);

        const out = derSignatureToCompact(der);
        expect(sValue(out) <= HALF_N).toBe(true);
        expect(pub.verify(msg, out)).toBe(true);
    });

    it("left-pads short scalars and strips the DER sign byte", () => {
        // r = 1 (one byte), s = n - 1 (33 bytes with leading 0x00, high-S).
        const sBytes = Buffer.from(
            (SECP256K1_N - 1n).toString(16).padStart(64, "0"),
            "hex",
        );
        const der = new Uint8Array([
            0x30,
            3 + 2 + 33,
            0x02,
            0x01,
            0x01,
            0x02,
            33,
            0x00,
            ...sBytes,
        ]);
        const out = derSignatureToCompact(der);
        expect(out.length).toBe(64);
        expect(out[31]).toBe(1);
        expect(sValue(out)).toBe(1n); // n - (n - 1)
    });

    it("rejects zero, negative and out-of-range scalars", () => {
        const zero = new Uint8Array([0x30, 6, 0x02, 1, 0x00, 0x02, 1, 0x01]);
        const negative = new Uint8Array([
            0x30, 6, 0x02, 1, 0x80, 0x02, 1, 0x01,
        ]);
        const nBytes = Buffer.from(SECP256K1_N.toString(16), "hex");
        const tooBig = new Uint8Array([
            0x30,
            3 + 2 + 33,
            0x02,
            0x01,
            0x01,
            0x02,
            33,
            0x00,
            ...nBytes,
        ]);
        expectCode(
            () => derSignatureToCompact(zero),
            RemoteSignerErrorCodes.MalformedSignature,
        );
        expectCode(
            () => derSignatureToCompact(negative),
            RemoteSignerErrorCodes.MalformedSignature,
        );
        expectCode(
            () => derSignatureToCompact(tooBig),
            RemoteSignerErrorCodes.MalformedSignature,
        );
    });

    it("only ever throws RemoteSignerError on mutated input", () => {
        const base = derSign(randomBytes(64), false);
        for (let i = 0; i < 2000; i++) {
            const mutated = new Uint8Array(base);
            const flips = 1 + (i % 3);
            for (let f = 0; f < flips; f++) {
                mutated[Math.floor(Math.random() * mutated.length)] =
                    Math.floor(Math.random() * 256);
            }
            try {
                const out = derSignatureToCompact(mutated);
                expect(out.length).toBe(64);
            } catch (e) {
                expect(e).toBeInstanceOf(RemoteSignerError);
            }
        }
    });
});

describe("normalizeCompactSignature", () => {
    const priv = secp256k1.utils.randomSecretKey();
    const pub = PublicKey.fromBytesECDSA(secp256k1.getPublicKey(priv, true));

    function compactSign(message: Uint8Array, highS: boolean): Uint8Array {
        const sig = secp256k1.Signature.fromBytes(
            secp256k1.sign(keccak_256(message), priv, {
                prehash: false,
                lowS: true,
            }),
            "compact",
        );
        return (
            highS ? new secp256k1.Signature(sig.r, SECP256K1_N - sig.s) : sig
        ).toBytes("compact");
    }

    it("passes a low-S signature through unchanged", () => {
        const msg = randomBytes(100);
        const sig = compactSign(msg, false);
        expect(normalizeCompactSignature(sig)).toEqual(sig);
    });

    it("normalizes high-S so the Hiero SDK accepts it", () => {
        const msg = randomBytes(100);
        const sig = compactSign(msg, true);
        expect(pub.verify(msg, sig)).toBe(false);

        const out = normalizeCompactSignature(sig);
        expect(sValue(out) <= HALF_N).toBe(true);
        expect(pub.verify(msg, out)).toBe(true);
    });

    it("rejects wrong lengths and out-of-range scalars", () => {
        expectCode(
            () => normalizeCompactSignature(new Uint8Array(63)),
            RemoteSignerErrorCodes.MalformedSignature,
        );
        const zeroR = new Uint8Array(64);
        zeroR[63] = 1;
        expectCode(
            () => normalizeCompactSignature(zeroR),
            RemoteSignerErrorCodes.MalformedSignature,
        );
        const bigS = new Uint8Array(64);
        bigS[31] = 1;
        bigS.set(Buffer.from(SECP256K1_N.toString(16), "hex"), 32);
        expectCode(
            () => normalizeCompactSignature(bigS),
            RemoteSignerErrorCodes.MalformedSignature,
        );
    });
});
