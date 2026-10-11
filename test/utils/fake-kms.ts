import { randomUUID } from "node:crypto";
import {
    GetPublicKeyCommand,
    KMSClient,
    SignCommand,
} from "@aws-sdk/client-kms";
import { mockClient } from "aws-sdk-client-mock";

import {
    generateKeyMaterial,
    signEd25519,
    signSecp256k1Digest,
} from "./key-material.js";
import type { KeyCurve, SignBehaviour } from "./key-material.js";

export type { SignBehaviour } from "./key-material.js";

export type FakeKeySpec =
    "ECC_SECG_P256K1" | "ECC_NIST_EDWARDS25519" | "ECC_NIST_P256" | "RSA_2048";

export interface FakeKey {
    keyId: string;
    arn: string;
    alias: string;
    spec: FakeKeySpec;
    spki: Uint8Array;
    /** Raw private scalar (secp256k1) or seed (Ed25519). Test-only. */
    privateKey: Uint8Array;
    keyUsage: "SIGN_VERIFY" | "ENCRYPT_DECRYPT";
    behaviour: SignBehaviour;
}

const CURVES: Record<FakeKeySpec, KeyCurve> = {
    ECC_SECG_P256K1: "secp256k1",
    ECC_NIST_EDWARDS25519: "ed25519",
    ECC_NIST_P256: "p256",
    RSA_2048: "rsa",
};

export function makeKey(
    spec: FakeKeySpec,
    overrides: Partial<FakeKey> = {},
): FakeKey {
    const keyId = randomUUID();
    const { spki, privateKey } = generateKeyMaterial(CURVES[spec]);

    return {
        keyId,
        arn: `arn:aws:kms:eu-central-1:111122223333:key/${keyId}`,
        alias: `alias/test-${keyId.slice(0, 8)}`,
        spec,
        spki,
        privateKey,
        keyUsage: "SIGN_VERIFY",
        behaviour: "normal",
        ...overrides,
    };
}

const ALGORITHMS: Record<FakeKeySpec, string[]> = {
    ECC_SECG_P256K1: ["ECDSA_SHA_256"],
    ECC_NIST_EDWARDS25519: ["ED25519_SHA_512", "ED25519_PH_SHA_512"],
    ECC_NIST_P256: ["ECDSA_SHA_256"],
    RSA_2048: ["RSASSA_PSS_SHA_256"],
};

class KmsError extends Error {
    constructor(name: string, message: string) {
        super(message);
        this.name = name;
    }
}

/**
 * Installs a mock on KMSClient that behaves like AWS KMS for the given keys.
 * It enforces the parts of the Sign contract that matter for Hiero signing,
 * so a signer that sends the wrong message type, algorithm or digest length
 * fails here exactly as it would against AWS.
 */
export function installFakeKms(keys: FakeKey[]) {
    const mock = mockClient(KMSClient);
    const find = (id: string | undefined) => {
        const key = keys.find(
            (k) => id === k.keyId || id === k.arn || id === k.alias,
        );
        if (!key)
            throw new KmsError(
                "NotFoundException",
                `Key '${id}' does not exist`,
            );
        return key;
    };

    mock.on(GetPublicKeyCommand).callsFake((input) => {
        const key = find(input.KeyId);
        return {
            KeyId: key.arn,
            KeySpec: key.spec,
            KeyUsage: key.keyUsage,
            PublicKey: key.spki,
            SigningAlgorithms:
                key.keyUsage === "SIGN_VERIFY"
                    ? ALGORITHMS[key.spec]
                    : undefined,
        };
    });

    mock.on(SignCommand).callsFake((input) => {
        const key = find(input.KeyId);
        const message = input.Message as Uint8Array;
        if (!ALGORITHMS[key.spec].includes(input.SigningAlgorithm!)) {
            throw new KmsError(
                "InvalidKeyUsageException",
                "algorithm not valid for key",
            );
        }

        let signature: Uint8Array;
        if (key.spec === "ECC_SECG_P256K1") {
            if (input.MessageType !== "DIGEST" || message.length !== 32) {
                // Without DIGEST, real KMS would SHA-256 the message, producing a
                // signature over the wrong hash. Fail loudly instead.
                throw new KmsError(
                    "ValidationException",
                    "test KMS requires a 32-byte DIGEST",
                );
            }
            signature = signSecp256k1Digest(
                message,
                key.privateKey,
                key.behaviour,
            );
        } else if (key.spec === "ECC_NIST_EDWARDS25519") {
            if (
                input.MessageType !== "RAW" ||
                input.SigningAlgorithm !== "ED25519_SHA_512"
            ) {
                throw new KmsError(
                    "ValidationException",
                    "test KMS requires RAW + ED25519_SHA_512",
                );
            }
            if (message.length > 4096) {
                throw new KmsError(
                    "ValidationException",
                    "Message exceeds 4096 bytes",
                );
            }
            signature = signEd25519(message, key.privateKey, key.behaviour);
        } else {
            throw new KmsError(
                "UnsupportedOperationException",
                "test KMS cannot sign with this key",
            );
        }

        return {
            KeyId: key.arn,
            Signature: signature,
            SigningAlgorithm: input.SigningAlgorithm,
        };
    });

    return mock;
}
