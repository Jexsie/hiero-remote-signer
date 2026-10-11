/**
 * Machine-readable codes carried by every {@link RemoteSignerError}.
 */
export const RemoteSignerErrorCodes = {
    /** A DER, PEM or JWK structure returned by the backend could not be parsed. */
    MalformedDer: "MALFORMED_DER",
    /** A DER signature was structurally valid but its scalars are invalid. */
    MalformedSignature: "MALFORMED_SIGNATURE",
    /** The backend key uses an algorithm or curve that Hiero networks do not verify. */
    UnsupportedKey: "UNSUPPORTED_KEY",
    /** The backend key exists but is not configured for signing. */
    KeyNotUsable: "KEY_NOT_USABLE",
    /** The message cannot be signed with this key type (for example, too large). */
    MessageRejected: "MESSAGE_REJECTED",
    /** The backend returned no signature or a signature that does not verify. */
    SignatureInvalid: "SIGNATURE_INVALID",
    /**
     * A backend response failed its transport integrity check, for example a
     * CRC32C mismatch. Discard the response; retrying the call is safe.
     */
    IntegrityCheckFailed: "INTEGRITY_CHECK_FAILED",
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
