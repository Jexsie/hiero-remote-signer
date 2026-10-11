import type { KeyManagementServiceClient } from "@google-cloud/kms";

/** The parts of the Cloud KMS client that {@link GcpKmsSigner} calls. */
export type GcpKmsClient = Pick<
    KeyManagementServiceClient,
    "getPublicKey" | "asymmetricSign"
>;

/**
 * Options for {@link GcpKmsSigner.create}.
 */
export interface GcpKmsSignerOptions {
    /**
     * Full resource name of the key version, for example
     * `projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1`.
     */
    keyVersionName: string;
    /**
     * An existing Cloud KMS client. Supply one to share credentials and
     * connections with the rest of the application. When omitted a client is
     * created from `clientOptions`.
     */
    client?: GcpKmsClient;
    /** Options for the client created when `client` is omitted. */
    clientOptions?: ConstructorParameters<typeof KeyManagementServiceClient>[0];
    /**
     * Verify every signature locally against the public key before returning
     * it. Defaults to `true`.
     */
    verifySignatures?: boolean;
}
