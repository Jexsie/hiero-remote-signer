import type { HieroRemoteSigner } from "hiero-remote-signer";

import { optional, required } from "./config.js";

const BACKENDS = ["aws", "gcp", "azure", "vault", "pkcs11"] as const;
export type Backend = (typeof BACKENDS)[number];

/** A remote signer plus the cleanup for the backend client behind it. */
export interface OpenSigner {
    backend: Backend;
    signer: HieroRemoteSigner;
    close(): Promise<void>;
}

export function backend(): Backend {
    const name = required("REMOTE_SIGNER_BACKEND").toLowerCase();
    if (!(BACKENDS as readonly string[]).includes(name)) {
        throw new Error(
            `REMOTE_SIGNER_BACKEND must be one of ${BACKENDS.join(", ")}, got ${name}`,
        );
    }
    return name as Backend;
}

/**
 * Opens the signer selected by REMOTE_SIGNER_BACKEND. Each backend is
 * imported on demand, so only its client library has to be installed.
 */
export async function openSigner(): Promise<OpenSigner> {
    const selected = backend();
    switch (selected) {
        case "aws": {
            const { KMSClient } = await import("@aws-sdk/client-kms");
            const { AwsKmsSigner } = await import("hiero-remote-signer/aws");
            // Region and credentials come from the standard AWS settings
            // (AWS_REGION, AWS_PROFILE, SSO, instance roles, ...).
            const client = new KMSClient({});
            try {
                const signer = await AwsKmsSigner.create({
                    keyId: required("AWS_KMS_KEY_ID"),
                    client,
                });
                return {
                    backend: selected,
                    signer,
                    close: async () => client.destroy(),
                };
            } catch (error) {
                client.destroy();
                throw error;
            }
        }
        case "gcp": {
            const { KeyManagementServiceClient } =
                await import("@google-cloud/kms");
            const { GcpKmsSigner } = await import("hiero-remote-signer/gcp");
            // Credentials come from Application Default Credentials.
            const client = new KeyManagementServiceClient();
            try {
                const signer = await GcpKmsSigner.create({
                    keyVersionName: required("GCP_KMS_KEY_VERSION"),
                    client,
                });
                return {
                    backend: selected,
                    signer,
                    close: () => client.close(),
                };
            } catch (error) {
                await client.close();
                throw error;
            }
        }
        case "azure": {
            const { DefaultAzureCredential } = await import("@azure/identity");
            const { AzureKeyVaultSigner } =
                await import("hiero-remote-signer/azure");
            // DefaultAzureCredential picks up `az login`, environment
            // variables or a managed identity.
            const signer = await AzureKeyVaultSigner.create({
                keyId: required("AZURE_KEY_VAULT_KEY_ID"),
                credential: new DefaultAzureCredential(),
            });
            return { backend: selected, signer, close: async () => {} };
        }
        case "vault": {
            const { VaultTransitSigner } =
                await import("hiero-remote-signer/vault");
            const signer = await VaultTransitSigner.create({
                address: required("VAULT_ADDR"),
                token: required("VAULT_TOKEN"),
                keyName: required("VAULT_TRANSIT_KEY"),
                mountPath: optional("VAULT_TRANSIT_MOUNT"),
                namespace: optional("VAULT_NAMESPACE"),
            });
            return { backend: selected, signer, close: async () => {} };
        }
        case "pkcs11": {
            const { Pkcs11Signer } = await import("hiero-remote-signer/pkcs11");
            const signer = await Pkcs11Signer.create({
                library: required("PKCS11_LIBRARY"),
                tokenLabel: required("PKCS11_TOKEN_LABEL"),
                pin: required("PKCS11_PIN"),
                keyLabel: required("PKCS11_KEY_LABEL"),
            });
            return { backend: selected, signer, close: () => signer.close() };
        }
    }
}

/** Runs `fn` with an open signer and always releases the backend client. */
export async function withSigner<T>(
    fn: (open: OpenSigner) => Promise<T>,
): Promise<T> {
    const open = await openSigner();
    try {
        return await fn(open);
    } finally {
        await open.close();
    }
}
