import { KmsSignerError, KmsSignerErrorCodes } from "../errors/index.js";
import { DerTag, expectTag, readTlv } from "./tlv.js";

/** Order of the secp256k1 group. */
export const SECP256K1_N =
    0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const SECP256K1_HALF_N = SECP256K1_N >> 1n;

/**
 * Converts a DER-encoded ECDSA signature (as returned by every major KMS) to
 * the 64-byte `r || s` form that Hiero expects in a SignaturePair.
 *
 * `s` is normalized to the lower half of the curve order. KMS services return
 * a high `s` for roughly half of all signatures, and the Hiero SDK rejects
 * those during verification, so normalization is required for correctness.
 * Both forms are mathematically valid signatures, so this does not weaken
 * anything.
 */
export function derSignatureToCompact(der: Uint8Array): Uint8Array {
    const seq = readTlv(der, 0);
    expectTag(seq, DerTag.Sequence, "ECDSA-Sig-Value SEQUENCE");
    if (seq.end !== der.length) {
        throw new KmsSignerError(
            KmsSignerErrorCodes.MalformedSignature,
            "trailing bytes after signature",
        );
    }
    const r = readScalar(seq.value, 0, "r");
    const s = readScalar(seq.value, r.end, "s");
    if (s.end !== seq.value.length) {
        throw new KmsSignerError(
            KmsSignerErrorCodes.MalformedSignature,
            "unexpected elements in signature",
        );
    }

    const lowS = s.value > SECP256K1_HALF_N ? SECP256K1_N - s.value : s.value;
    const out = new Uint8Array(64);
    out.set(bigIntTo32Bytes(r.value), 0);
    out.set(bigIntTo32Bytes(lowS), 32);
    return out;
}

/** Reads a DER INTEGER that must be a positive value in [1, n-1]. */
function readScalar(
    seq: Uint8Array,
    offset: number,
    name: string,
): { value: bigint; end: number } {
    const tlv = readTlv(seq, offset);
    expectTag(tlv, DerTag.Integer, `${name} INTEGER`);
    if (tlv.value.length === 0 || tlv.value.length > 33) {
        throw new KmsSignerError(
            KmsSignerErrorCodes.MalformedSignature,
            `${name} has invalid length ${tlv.value.length}`,
        );
    }
    if (tlv.value[0]! & 0x80) {
        throw new KmsSignerError(
            KmsSignerErrorCodes.MalformedSignature,
            `${name} is negative`,
        );
    }
    const value = bytesToBigInt(tlv.value);
    if (value === 0n || value >= SECP256K1_N) {
        throw new KmsSignerError(
            KmsSignerErrorCodes.MalformedSignature,
            `${name} is out of range`,
        );
    }
    return { value, end: tlv.end };
}

function bytesToBigInt(bytes: Uint8Array): bigint {
    let n = 0n;
    for (const b of bytes) n = (n << 8n) | BigInt(b);
    return n;
}

function bigIntTo32Bytes(n: bigint): Uint8Array {
    const out = new Uint8Array(32);
    for (let i = 31; i >= 0; i--) {
        out[i] = Number(n & 0xffn);
        n >>= 8n;
    }
    return out;
}
