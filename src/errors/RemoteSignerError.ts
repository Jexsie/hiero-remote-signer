/**
 * Machine-readable codes carried by every {@link RemoteSignerError}.
 */
export const RemoteSignerErrorCodes = {
    /** A DER structure returned by the KMS could not be parsed. */
    MalformedDer: "MALFORMED_DER",
    /** A DER signature was structurally valid but its scalars are invalid. */
    MalformedSignature: "MALFORMED_SIGNATURE",
    /** The KMS key uses an algorithm or curve that Hiero networks do not verify. */
    UnsupportedKey: "UNSUPPORTED_KEY",
    /** The KMS key exists but is not configured for signing. */
    KeyNotUsable: "KEY_NOT_USABLE",
    /** The message cannot be signed with this key type (for example, too large). */
    MessageRejected: "MESSAGE_REJECTED",
    /** The KMS returned no signature or a signature that does not verify. */
    SignatureInvalid: "SIGNATURE_INVALID",
    /** The call to the signing backend failed. The original error is attached as `cause`. */
    BackendRequestFailed: "BACKEND_REQUEST_FAILED",
} as const;

export type RemoteSignerErrorCode =
    (typeof RemoteSignerErrorCodes)[keyof typeof RemoteSignerErrorCodes];

/**
 * Error thrown by every signer and DER helper in this package.
 */
export class RemoteSignerError extends Error {
    /** Machine-readable error code */
    public readonly code: RemoteSignerErrorCode;

    constructor(
        code: RemoteSignerErrorCode,
        message: string,
        options?: { cause?: unknown },
    ) {
        super(message, options);
        this.name = "RemoteSignerError";
        this.code = code;
    }
}
