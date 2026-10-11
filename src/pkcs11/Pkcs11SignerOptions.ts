import type { PKCS11 } from "pkcs11js";

/** The parts of a loaded `pkcs11js` module that {@link Pkcs11Signer} calls. */
export type Pkcs11Module = Pick<
    PKCS11,
    | "C_GetSlotList"
    | "C_GetTokenInfo"
    | "C_OpenSession"
    | "C_CloseSession"
    | "C_Login"
    | "C_FindObjectsInit"
    | "C_FindObjects"
    | "C_FindObjectsFinal"
    | "C_GetAttributeValue"
    | "C_SignInit"
    | "C_Sign"
>;

/**
 * Options for {@link Pkcs11Signer.create}. Supply either `library` or an
 * already initialized `pkcs11` module, and at least one of `keyLabel` and
 * `keyId`.
 */
export interface Pkcs11SignerOptions {
    /**
     * Path to the PKCS#11 module, for example
     * `/usr/lib/softhsm/libsofthsm2.so`. The signer loads and initializes it,
     * and finalizes it in `close()`.
     */
    library?: string;
    /**
     * An already loaded and initialized `pkcs11js` module, for sharing one
     * module between several signers. The caller remains responsible for
     * finalizing it.
     */
    pkcs11?: Pkcs11Module;
    /** Label of the token that holds the key. */
    tokenLabel: string;
    /** User PIN of the token. */
    pin: string;
    /** `CKA_LABEL` of the key pair. */
    keyLabel?: string;
    /** `CKA_ID` of the key pair. */
    keyId?: Uint8Array;
    /**
     * Verify every signature locally against the public key before returning
     * it. Defaults to `true`.
     */
    verifySignatures?: boolean;
}
