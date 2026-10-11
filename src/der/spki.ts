import { RemoteSignerError, RemoteSignerErrorCodes } from "../errors/index.js";
import { DerTag, decodeOid, expectTag, readTlv } from "./tlv.js";

/** Object identifiers used in SubjectPublicKeyInfo structures. */
export const OID = {
    ecPublicKey: "1.2.840.10045.2.1",
    secp256k1: "1.3.132.0.10",
    ed25519: "1.3.101.112",
} as const;

export type SpkiKey =
    | {
          keyType: "ECDSA_SECP256K1";
          /** 33-byte compressed point */
          publicKey: Uint8Array;
      }
    | {
          keyType: "ED25519";
          /** 32 bytes */
          publicKey: Uint8Array;
      };

/**
 * Parses a DER-encoded SubjectPublicKeyInfo (RFC 5280), which is the format
 * cloud KMS services return from their "get public key" operations.
 *
 * Only secp256k1 and Ed25519 keys are accepted, because those are the only key
 * types Hiero networks verify. secp256k1 points are returned compressed, which
 * is the form Hiero stores in account keys.
 */
export function parseSpki(der: Uint8Array): SpkiKey {
    const outer = readTlv(der, 0);
    expectTag(outer, DerTag.Sequence, "SubjectPublicKeyInfo SEQUENCE");
    if (outer.end !== der.length) {
        throw new RemoteSignerError(
            RemoteSignerErrorCodes.MalformedDer,
            "trailing bytes after SubjectPublicKeyInfo",
        );
    }

    const algorithm = readTlv(outer.value, 0);
    expectTag(algorithm, DerTag.Sequence, "AlgorithmIdentifier SEQUENCE");
    const bitString = readTlv(outer.value, algorithm.end);
    expectTag(bitString, DerTag.BitString, "subjectPublicKey BIT STRING");

    if (bitString.value[0] !== 0x00) {
        throw new RemoteSignerError(
            RemoteSignerErrorCodes.MalformedDer,
            "BIT STRING has unused bits",
        );
    }
    const keyBytes = bitString.value.subarray(1);

    const algOid = readTlv(algorithm.value, 0);
    expectTag(algOid, DerTag.ObjectIdentifier, "algorithm OID");
    const algorithmOid = decodeOid(algOid.value);

    if (algorithmOid === OID.ed25519) {
        if (keyBytes.length !== 32) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.MalformedDer,
                `Ed25519 key must be 32 bytes, got ${keyBytes.length}`,
            );
        }
        return { keyType: "ED25519", publicKey: new Uint8Array(keyBytes) };
    }

    if (algorithmOid === OID.ecPublicKey) {
        const curve = readTlv(algorithm.value, algOid.end);
        expectTag(curve, DerTag.ObjectIdentifier, "named curve OID");
        const curveOid = decodeOid(curve.value);
        if (curveOid !== OID.secp256k1) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.UnsupportedKey,
                `EC curve ${curveOid} is not secp256k1; Hiero networks only verify secp256k1 ECDSA keys`,
            );
        }
        return {
            keyType: "ECDSA_SECP256K1",
            publicKey: compressSecp256k1Point(keyBytes),
        };
    }

    throw new RemoteSignerError(
        RemoteSignerErrorCodes.UnsupportedKey,
        `public key algorithm ${algorithmOid} is not supported`,
    );
}

/** Converts an SEC1 point (compressed or uncompressed) to its 33-byte compressed form. */
export function compressSecp256k1Point(point: Uint8Array): Uint8Array {
    if (point.length === 33 && (point[0] === 0x02 || point[0] === 0x03)) {
        return new Uint8Array(point);
    }
    if (point.length !== 65 || point[0] !== 0x04) {
        throw new RemoteSignerError(
            RemoteSignerErrorCodes.MalformedDer,
            "invalid secp256k1 public key point encoding",
        );
    }
    const out = new Uint8Array(33);
    out[0] = (point[64]! & 1) === 0 ? 0x02 : 0x03;
    out.set(point.subarray(1, 33), 1);
    return out;
}
