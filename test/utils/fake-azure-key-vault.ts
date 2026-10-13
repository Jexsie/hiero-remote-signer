import { randomBytes } from "node:crypto";
import type { KeyVaultKey, SignResult } from "@azure/keyvault-keys";
import { secp256k1 } from "@noble/curves/secp256k1.js";

import { generateKeyMaterial, signSecp256k1Digest } from "./key-material.js";
import type { KeyCurve, SignBehaviour } from "./key-material.js";

/** Key Vault curve names this fake can serve. */
export type AzureCurve = "P-256K" | "P-256";

/** How the fake encodes ECDSA signatures; Key Vault uses the JWS `r || s` form. */
export type AzureSignatureFormat = "jws" | "der";

export interface FakeAzureKey {
    name: string;
    version: string;
    curve: AzureCurve;
    kty: "EC" | "EC-HSM";
    x: Uint8Array;
    y: Uint8Array;
    privateKey: Uint8Array;
    enabled: boolean;
    keyOps: string[];
    behaviour: SignBehaviour;
    format: AzureSignatureFormat;
}

export const VAULT_URL = "https://hiero-test.vault.azure.net";

const CURVES: Record<AzureCurve, KeyCurve> = {
    "P-256K": "secp256k1",
    "P-256": "p256",
};

export function makeAzureKey(
    curve: AzureCurve = "P-256K",
    overrides: Partial<FakeAzureKey> = {},
): FakeAzureKey {
    const { publicJwk, privateKey } = generateKeyMaterial(CURVES[curve]);
    return {
        name: `hiero-${randomBytes(4).toString("hex")}`,
        version: randomBytes(16).toString("hex"),
        curve,
        kty: "EC-HSM",
        x: new Uint8Array(Buffer.from(publicJwk.x!, "base64url")),
        y: new Uint8Array(Buffer.from(publicJwk.y!, "base64url")),
        privateKey,
        enabled: true,
        keyOps: ["sign", "verify"],
        behaviour: "normal",
        format: "jws",
        ...overrides,
    };
}

export const keyIdOf = (key: FakeAzureKey) =>
    `${VAULT_URL}/keys/${key.name}/${key.version}`;

/** REST-style error, as thrown by the Key Vault clients. */
class RestError extends Error {
    constructor(
        readonly statusCode: number,
        readonly code: string,
        message: string,
    ) {
        super(message);
        this.name = "RestError";
    }
}

/**
 * Fake Key Vault clients for the given keys. They enforce the parts of the
 * contract that matter for Hiero signing: `getKey` resolves a missing version
 * to the latest, `sign` only signs a 32-byte digest with ES256K on a P-256K
 * key, and signatures come back in the JWS `r || s` form.
 */
export function createFakeKeyVault(keys: FakeAzureKey[]) {
    const signCalls: {
        keyId: string;
        algorithm: string;
        digest: Uint8Array;
    }[] = [];

    const keyClient = {
        async getKey(
            name: string,
            options?: { version?: string },
        ): Promise<KeyVaultKey> {
            const key = keys.find(
                (k) =>
                    k.name === name &&
                    (!options?.version || k.version === options.version),
            );
            if (!key) {
                throw new RestError(404, "KeyNotFound", `${name} not found`);
            }
            return {
                id: keyIdOf(key),
                name: key.name,
                keyType: key.kty,
                keyOperations: key.keyOps,
                key: {
                    kid: keyIdOf(key),
                    kty: key.kty,
                    crv: key.curve,
                    x: key.x,
                    y: key.y,
                    keyOps: key.keyOps,
                },
                properties: {
                    id: keyIdOf(key),
                    name: key.name,
                    vaultUrl: VAULT_URL,
                    version: key.version,
                    enabled: key.enabled,
                },
            };
        },
    };

    const cryptographyClientFor = (keyId: string) => ({
        async sign(algorithm: string, digest: Uint8Array): Promise<SignResult> {
            signCalls.push({ keyId, algorithm, digest });
            const key = keys.find((k) => keyIdOf(k) === keyId);
            if (!key) {
                throw new RestError(404, "KeyNotFound", `${keyId} not found`);
            }
            if (!key.enabled || !key.keyOps.includes("sign")) {
                throw new RestError(
                    403,
                    "Forbidden",
                    "operation not permitted",
                );
            }
            if (
                key.curve !== "P-256K" ||
                algorithm !== "ES256K" ||
                digest.length !== 32
            ) {
                throw new RestError(
                    400,
                    "BadParameter",
                    "ES256K requires a P-256K key and a 32-byte digest",
                );
            }
            const der = signSecp256k1Digest(
                digest,
                key.privateKey,
                key.behaviour,
            );
            return {
                keyID: keyId,
                algorithm,
                result:
                    key.format === "der" || key.behaviour === "corrupt"
                        ? der
                        : secp256k1.Signature.fromBytes(der, "der").toBytes(
                              "compact",
                          ),
            };
        },
    });

    return {
        signCalls,
        keyClient: keyClient,
        cryptographyClientFor: (keyId: string) => cryptographyClientFor(keyId),
    };
}
