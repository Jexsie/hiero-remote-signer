import type { KMSClient, KMSClientConfig } from "@aws-sdk/client-kms";

/**
 * Options for {@link AwsKmsSigner.create}.
 */
export interface AwsKmsSignerOptions {
    /** Key ID, key ARN, alias name (`alias/...`) or alias ARN. */
    keyId: string;
    /**
     * An existing KMS client. Supply one to share connection pools, credentials
     * and middleware with the rest of the application. When omitted a client
     * is created from `clientConfig`.
     */
    client?: KMSClient;
    /** Configuration for the KMS client created when `client` is omitted. */
    clientConfig?: KMSClientConfig;
    /**
     * Verify every signature locally against the KMS public key before
     * returning it. This costs one local signature verification and catches
     * a misconfigured key or a faulty KMS response before a transaction is
     * submitted. Defaults to `true`.
     */
    verifySignatures?: boolean;
    /** Grant tokens passed through to KMS, if the key is accessed via a grant. */
    grantTokens?: string[];
}
