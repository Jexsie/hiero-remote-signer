import { RemoteSignerError, RemoteSignerErrorCodes } from "../errors/index.js";
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
        throw new RemoteSignerError(
            RemoteSignerErrorCodes.MalformedSignature,
            "trailing bytes after signature",
        );
    }
    const r = readScalar(seq.value, 0, "r");
    const s = readScalar(seq.value, r.end, "s");
    if (s.end !== seq.value.length) {
        throw new RemoteSignerError(
            RemoteSignerErrorCodes.MalformedSignature,
            "unexpected elements in signature",
        );
    }

    return toLowSCompact(r.value, s.value);
}

/**
 * Validates a 64-byte `r || s` ECDSA signature (the JWS form, RFC 7518) and
 * returns it with `s` normalized to the lower half of the curve order, as
 * Hiero requires. See {@link derSignatureToCompact} for why.
 */
export function normalizeCompactSignature(compact: Uint8Array): Uint8Array {
    if (compact.length !== 64) {
        throw new RemoteSignerError(
            RemoteSignerErrorCodes.MalformedSignature,
            `expected a 64-byte r || s signature, got ${compact.length} bytes`,
        );
    }
    const r = checkScalar(bytesToBigInt(compact.subarray(0, 32)), "r");
    const s = checkScalar(bytesToBigInt(compact.subarray(32)), "s");
    return toLowSCompact(r, s);
}

function toLowSCompact(r: bigint, s: bigint): Uint8Array {
    const lowS = s > SECP256K1_HALF_N ? SECP256K1_N - s : s;
    const out = new Uint8Array(64);
    out.set(bigIntTo32Bytes(r), 0);
    out.set(bigIntTo32Bytes(lowS), 32);
    return out;
}

/** Throws unless `value` is in [1, n-1]. */
function checkScalar(value: bigint, name: string): bigint {
    if (value === 0n || value >= SECP256K1_N) {
        throw new RemoteSignerError(
            RemoteSignerErrorCodes.MalformedSignature,
            `${name} is out of range`,
        );
    }
    return value;
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
        throw new RemoteSignerError(
            RemoteSignerErrorCodes.MalformedSignature,
            `${name} has invalid length ${tlv.value.length}`,
        );
    }
    if (tlv.value[0]! & 0x80) {
        throw new RemoteSignerError(
            RemoteSignerErrorCodes.MalformedSignature,
            `${name} is negative`,
        );
    }
    return { value: checkScalar(bytesToBigInt(tlv.value), name), end: tlv.end };
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
