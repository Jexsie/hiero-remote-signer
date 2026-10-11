import { generateKeyPairSync, randomUUID } from "node:crypto";
import {
    GetPublicKeyCommand,
    KMSClient,
    SignCommand,
} from "@aws-sdk/client-kms";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { mockClient } from "aws-sdk-client-mock";

export type FakeKeySpec =
    "ECC_SECG_P256K1" | "ECC_NIST_EDWARDS25519" | "ECC_NIST_P256" | "RSA_2048";

/** Controls how the fake KMS misbehaves, to exercise the signer's defences. */
export type SignBehaviour = "normal" | "always-high-s" | "corrupt";

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

const N = secp256k1.Point.CURVE().n;

function b64urlToBytes(s: string): Uint8Array {
    return new Uint8Array(Buffer.from(s, "base64url"));
}

export function makeKey(
    spec: FakeKeySpec,
    overrides: Partial<FakeKey> = {},
): FakeKey {
    const keyId = randomUUID();
    let spki: Uint8Array;
    let privateKey: Uint8Array = new Uint8Array();

    if (spec === "ECC_SECG_P256K1" || spec === "ECC_NIST_P256") {
        const pair = generateKeyPairSync("ec", {
            namedCurve: spec === "ECC_SECG_P256K1" ? "secp256k1" : "prime256v1",
        });
        spki = new Uint8Array(
            pair.publicKey.export({ type: "spki", format: "der" }),
        );
        privateKey = b64urlToBytes(
            pair.privateKey.export({ format: "jwk" }).d!,
        );
    } else if (spec === "ECC_NIST_EDWARDS25519") {
        const pair = generateKeyPairSync("ed25519");
        spki = new Uint8Array(
            pair.publicKey.export({ type: "spki", format: "der" }),
        );
        privateKey = b64urlToBytes(
            pair.privateKey.export({ format: "jwk" }).d!,
        );
    } else {
        const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
        spki = new Uint8Array(
            pair.publicKey.export({ type: "spki", format: "der" }),
        );
    }

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
            let sig = secp256k1.Signature.fromBytes(
                secp256k1.sign(message, key.privateKey, {
                    prehash: false,
                    lowS: true,
                }),
                "compact",
            );
            if (key.behaviour === "always-high-s") {
                sig = new secp256k1.Signature(sig.r, N - sig.s);
            }
            signature = sig.toBytes("der");
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
            signature = ed25519.sign(message, key.privateKey);
        } else {
            throw new KmsError(
                "UnsupportedOperationException",
                "test KMS cannot sign with this key",
            );
        }

        if (key.behaviour === "corrupt") {
            signature = new Uint8Array(signature);
            signature[signature.length - 1]! ^= 0x01;
        }
        return {
            KeyId: key.arn,
            Signature: signature,
            SigningAlgorithm: input.SigningAlgorithm,
        };
    });

    return mock;
}
