import type { CryptographyClient, KeyClient } from "@azure/keyvault-keys";

/** The parts of the Key Vault key client that {@link AzureKeyVaultSigner} calls. */
export type AzureKeyClient = Pick<KeyClient, "getKey">;

/** The parts of the Key Vault cryptography client that {@link AzureKeyVaultSigner} calls. */
export type AzureCryptographyClient = Pick<CryptographyClient, "sign">;

/** An Azure credential, such as `DefaultAzureCredential` from `@azure/identity`. */
export type AzureTokenCredential = ConstructorParameters<typeof KeyClient>[1];

/**
 * Options for {@link AzureKeyVaultSigner.create}.
 */
export interface AzureKeyVaultSignerOptions {
    /**
     * Key identifier, for example
     * `https://my-vault.vault.azure.net/keys/hiero-treasury/<version>` or a
     * Managed HSM key such as
     * `https://my-hsm.managedhsm.azure.net/keys/hiero-treasury/<version>`.
     * Include the version: without it the latest version is resolved once and
     * pinned, so a later rotation does not change the signing key silently.
     */
    keyId: string;
    /**
     * Credential used to create the clients that are not supplied below.
     * Required unless both `keyClient` and `cryptographyClient` are given.
     */
    credential?: AzureTokenCredential;
    /** An existing key client for the key's vault, used to read the public key. */
    keyClient?: AzureKeyClient;
    /** An existing cryptography client for the key version, used to sign. */
    cryptographyClient?: AzureCryptographyClient;
    /**
     * Verify every signature locally against the public key before returning
     * it. Defaults to `true`.
     */
    verifySignatures?: boolean;
}
