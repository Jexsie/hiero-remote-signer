import { randomUUID } from "node:crypto";

import { crc32c } from "../../src/gcp/crc32c.js";
import type { GcpKmsClient } from "../../src/gcp/index.js";
import {
    generateKeyMaterial,
    signEd25519,
    signSecp256k1Digest,
} from "./key-material.js";
import type { KeyCurve, SignBehaviour } from "./key-material.js";

export type GcpAlgorithm =
    | "EC_SIGN_SECP256K1_SHA256"
    | "EC_SIGN_ED25519"
    | "EC_SIGN_P256_SHA256"
    | "RSA_SIGN_PSS_2048_SHA256";

/** Faults in the integrity fields of an AsymmetricSign response. */
export type GcpIntegrityFault =
    "none" | "signature-crc" | "unverified-request" | "wrong-name";

export interface FakeGcpKey {
    name: string;
    algorithm: GcpAlgorithm;
    pem: string;
    privateKey: Uint8Array;
    behaviour: SignBehaviour;
    fault: GcpIntegrityFault;
}

const CURVES: Record<GcpAlgorithm, KeyCurve> = {
    EC_SIGN_SECP256K1_SHA256: "secp256k1",
    EC_SIGN_ED25519: "ed25519",
    EC_SIGN_P256_SHA256: "p256",
    RSA_SIGN_PSS_2048_SHA256: "rsa",
};

export function makeGcpKey(
    algorithm: GcpAlgorithm,
    overrides: Partial<FakeGcpKey> = {},
): FakeGcpKey {
    const { pem, privateKey } = generateKeyMaterial(CURVES[algorithm]);
    return {
        name:
            `projects/test/locations/global/keyRings/hiero/cryptoKeys/` +
            `${randomUUID().slice(0, 8)}/cryptoKeyVersions/1`,
        algorithm,
        pem,
        privateKey,
        behaviour: "normal",
        fault: "none",
        ...overrides,
    };
}

/** gRPC-style error, as thrown by the Cloud KMS client. */
class GrpcError extends Error {
    constructor(
        readonly code: number,
        message: string,
    ) {
        super(message);
        this.name = "GrpcError";
    }
}

const INVALID_ARGUMENT = 3;
const NOT_FOUND = 5;

interface SignRequest {
    name?: string | null;
    digest?: {
        sha256?: Uint8Array | null;
        sha384?: Uint8Array | null;
        sha512?: Uint8Array | null;
    } | null;
    digestCrc32c?: { value?: unknown } | null;
    data?: Uint8Array | null;
    dataCrc32c?: { value?: unknown } | null;
}

/**
 * A fake Cloud KMS client for the given keys. It enforces the parts of the
 * AsymmetricSign contract that matter for Hiero signing, including CRC32C
 * request verification, so a signer that sends the wrong field, digest size
 * or checksum fails here as it would against Cloud KMS. 64-bit checksum
 * values are returned as strings, as the real client may.
 */
export function createFakeGcpKms(keys: FakeGcpKey[]) {
    const calls: { method: string; request: SignRequest }[] = [];

    const find = (name: string | null | undefined) => {
        const key = keys.find((k) => k.name === name);
        if (!key) throw new GrpcError(NOT_FOUND, `${name} not found`);
        return key;
    };
    const checksum = (value: unknown, bytes: Uint8Array) => {
        if (value != null && Number(String(value)) !== crc32c(bytes)) {
            throw new GrpcError(INVALID_ARGUMENT, "checksum mismatch");
        }
        return value != null;
    };

    const fake = {
        calls,
        async getPublicKey(request: { name?: string | null }) {
            calls.push({ method: "getPublicKey", request });
            const key = find(request.name);
            return [
                {
                    name: key.name,
                    pem: key.pem,
                    pemCrc32c: {
                        value: String(
                            crc32c(new TextEncoder().encode(key.pem)),
                        ),
                    },
                    algorithm: key.algorithm,
                    protectionLevel:
                        key.algorithm === "EC_SIGN_SECP256K1_SHA256"
                            ? "HSM"
                            : "SOFTWARE",
                },
            ];
        },
        async asymmetricSign(request: SignRequest) {
            calls.push({ method: "asymmetricSign", request });
            const key = find(request.name);
            const digest = request.digest;
            if (digest && request.data) {
                throw new GrpcError(
                    INVALID_ARGUMENT,
                    "digest and data cannot both be set",
                );
            }

            let signature: Uint8Array;
            let verifiedDigestCrc32c = false;
            let verifiedDataCrc32c = false;
            if (key.algorithm === "EC_SIGN_SECP256K1_SHA256") {
                const sha256 = digest?.sha256;
                if (!sha256 || sha256.length !== 32) {
                    throw new GrpcError(
                        INVALID_ARGUMENT,
                        "EC_SIGN_SECP256K1_SHA256 requires a 32-byte sha256 digest",
                    );
                }
                verifiedDigestCrc32c = checksum(
                    request.digestCrc32c?.value,
                    sha256,
                );
                signature = signSecp256k1Digest(
                    sha256,
                    key.privateKey,
                    key.behaviour,
                );
            } else if (key.algorithm === "EC_SIGN_ED25519") {
                if (!request.data || digest) {
                    throw new GrpcError(
                        INVALID_ARGUMENT,
                        "EC_SIGN_ED25519 requires data, not a digest",
                    );
                }
                verifiedDataCrc32c = checksum(
                    request.dataCrc32c?.value,
                    request.data,
                );
                signature = signEd25519(
                    request.data,
                    key.privateKey,
                    key.behaviour,
                );
            } else {
                throw new GrpcError(
                    INVALID_ARGUMENT,
                    "test KMS cannot sign with this key",
                );
            }

            return [
                {
                    name:
                        key.fault === "wrong-name" ? `${key.name}0` : key.name,
                    signature: Buffer.from(signature),
                    signatureCrc32c: {
                        // `>>> 0` keeps the XOR result an unsigned 32-bit value.
                        value: String(
                            (crc32c(signature) ^
                                (key.fault === "signature-crc" ? 1 : 0)) >>>
                                0,
                        ),
                    },
                    verifiedDigestCrc32c:
                        key.fault !== "unverified-request" &&
                        verifiedDigestCrc32c,
                    verifiedDataCrc32c:
                        key.fault !== "unverified-request" &&
                        verifiedDataCrc32c,
                },
            ];
        },
    };

    return { fake, client: fake as unknown as GcpKmsClient };
}
