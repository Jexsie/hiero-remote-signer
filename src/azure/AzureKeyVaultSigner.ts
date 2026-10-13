import {
    CryptographyClient,
    KeyClient,
    parseKeyVaultKeyIdentifier,
} from "@azure/keyvault-keys";
import { PublicKey } from "@hiero-ledger/sdk";
import { keccak_256 } from "@noble/hashes/sha3.js";

import {
    compressSecp256k1Point,
    derSignatureToCompact,
    normalizeCompactSignature,
} from "../der/index.js";
import { RemoteSignerError, RemoteSignerErrorCodes } from "../errors/index.js";
import type { HieroKeyType, HieroRemoteSigner } from "../types/index.js";
import type {
    AzureCryptographyClient,
    AzureKeyVaultSignerOptions,
    AzureTokenCredential,
} from "./AzureKeyVaultSignerOptions.js";

function requireCredential(
    credential: AzureTokenCredential | undefined,
): AzureTokenCredential {
    if (!credential) {
        throw new TypeError(
            "credential is required unless keyClient and cryptographyClient are both supplied",
        );
    }
    return credential;
}

/**
 * Signs Hiero transactions with an elliptic curve key stored in Azure Key
 * Vault or Azure Key Vault Managed HSM.
 *
 * Construct it with `AzureKeyVaultSigner.create()`, which fetches and
 * validates the public key once. The private key never leaves Key Vault.
 *
 * Only `EC` and `EC-HSM` keys on curve `P-256K` (secp256k1) are supported,
 * signed with `ES256K`. Key Vault has no Ed25519 keys.
 */
export class AzureKeyVaultSigner implements HieroRemoteSigner {
    readonly keyType: HieroKeyType = "ECDSA_SECP256K1";
    readonly publicKey: PublicKey;
    /**
     * Signs serialized TransactionBody bytes. A bound function, so it can be
     * passed to the SDK as `signer.sign`.
     */
    readonly sign: (bodyBytes: Uint8Array) => Promise<Uint8Array>;
    /** The versioned key identifier the signer is pinned to. */
    readonly keyId: string;

    readonly #client: AzureCryptographyClient;
    readonly #verify: boolean;

    private constructor(params: {
        client: AzureCryptographyClient;
        keyId: string;
        publicKey: PublicKey;
        verify: boolean;
    }) {
        this.#client = params.client;
        this.keyId = params.keyId;
        this.publicKey = params.publicKey;
        this.#verify = params.verify;
        this.sign = (bodyBytes) => this.#sign(bodyBytes);
    }

    /** Fetches the public key for `keyId` and validates that it can sign for Hiero. */
    static async create(
        options: AzureKeyVaultSignerOptions,
    ): Promise<AzureKeyVaultSigner> {
        const { vaultUrl, name, version } = parseKeyVaultKeyIdentifier(
            options.keyId,
        );
        const keyClient =
            options.keyClient ??
            new KeyClient(vaultUrl, requireCredential(options.credential));

        let key;
        try {
            key = await keyClient.getKey(name, { version });
        } catch (cause) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.BackendRequestFailed,
                `getKey failed for ${options.keyId}`,
                { cause },
            );
        }

        const jwk = key.key;
        if (
            !jwk ||
            (jwk.kty !== "EC" && jwk.kty !== "EC-HSM") ||
            jwk.crv !== "P-256K"
        ) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.UnsupportedKey,
                `Key Vault key ${jwk?.kty ?? "unknown"}/${jwk?.crv ?? "unknown"} is not ` +
                    `supported; use an EC or EC-HSM key on curve P-256K`,
            );
        }
        if (key.properties.enabled === false) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.KeyNotUsable,
                `Key Vault key ${options.keyId} is disabled`,
            );
        }
        if (key.keyOperations && !key.keyOperations.includes("sign")) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.KeyNotUsable,
                `Key Vault key ${options.keyId} does not permit the sign operation`,
            );
        }
        if (jwk.x?.length !== 32 || jwk.y?.length !== 32) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.MalformedDer,
                "Key Vault returned a P-256K key without 32-byte x and y coordinates",
            );
        }

        const point = new Uint8Array(65);
        point[0] = 0x04;
        point.set(jwk.x, 1);
        point.set(jwk.y, 33);
        // Rejects points that are not on secp256k1.
        const publicKey = PublicKey.fromBytesECDSA(
            compressSecp256k1Point(point),
        );

        const keyId = key.id ?? options.keyId;
        return new AzureKeyVaultSigner({
            client:
                options.cryptographyClient ??
                new CryptographyClient(
                    keyId,
                    requireCredential(options.credential),
                ),
            keyId,
            publicKey,
            verify: options.verifySignatures ?? true,
        });
    }

    /**
     * Signs serialized TransactionBody bytes.
     *
     * The message is hashed locally with Keccak-256, which is the digest
     * Hiero verifies, and Key Vault signs that digest with `ES256K`. Key Vault
     * only ever signs a supplied digest, so the SHA-256 in the algorithm name
     * is never applied.
     */
    async #sign(bodyBytes: Uint8Array): Promise<Uint8Array> {
        let result;
        try {
            result = await this.#client.sign("ES256K", keccak_256(bodyBytes));
        } catch (cause) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.BackendRequestFailed,
                `sign failed for ${this.keyId}`,
                { cause },
            );
        }

        if (!result.result || result.result.length === 0) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.SignatureInvalid,
                "Key Vault returned no signature",
            );
        }
        // Key Vault returns the JWS `r || s` form (RFC 7518); accept DER too.
        const raw = new Uint8Array(result.result);
        const signature =
            raw.length === 64
                ? normalizeCompactSignature(raw)
                : derSignatureToCompact(raw);

        if (this.#verify && !this.publicKey.verify(bodyBytes, signature)) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.SignatureInvalid,
                "Key Vault signature does not verify against the key's public key",
            );
        }
        return signature;
    }
}
