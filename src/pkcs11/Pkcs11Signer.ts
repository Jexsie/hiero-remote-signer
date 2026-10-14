import { PublicKey } from "@hiero-ledger/sdk";
import { keccak_256 } from "@noble/hashes/sha3.js";
import * as pkcs11js from "pkcs11js";

import {
    compressSecp256k1Point,
    derSignatureToCompact,
    normalizeCompactSignature,
} from "../der/index.js";
import { OID } from "../der/spki.js";
import { DerTag, decodeOid, readTlv } from "../der/tlv.js";
import { RemoteSignerError, RemoteSignerErrorCodes } from "../errors/index.js";
import { RemoteSigner } from "../signer/index.js";
import type { HieroKeyType } from "../types/index.js";
import type {
    Pkcs11Module,
    Pkcs11SignerOptions,
} from "./Pkcs11SignerOptions.js";

/**
 * PKCS#11 constants. Taken from the standard rather than `pkcs11js`, which
 * does not export the v3.0 EdDSA values.
 */
export const Pkcs11Constants = {
    CKA_CLASS: 0x0000,
    CKA_LABEL: 0x0003,
    CKA_ID: 0x0102,
    CKA_SIGN: 0x0108,
    CKA_EC_PARAMS: 0x0180,
    CKA_EC_POINT: 0x0181,
    CKO_PUBLIC_KEY: 2,
    CKO_PRIVATE_KEY: 3,
    CKU_USER: 1,
    CKF_SERIAL_SESSION: 0x0004,
    CKM_ECDSA: 0x1041,
    CKM_EDDSA: 0x1057,
    CKR_USER_ALREADY_LOGGED_IN: 0x0100,
    CKR_CRYPTOKI_ALREADY_INITIALIZED: 0x0191,
} as const;

const C = Pkcs11Constants;

/** Curve name some tokens put in CKA_EC_PARAMS for Ed25519 instead of the OID. */
const EDWARDS25519_NAME = "edwards25519";

function backendError(message: string, cause?: unknown): RemoteSignerError {
    return new RemoteSignerError(
        RemoteSignerErrorCodes.BackendRequestFailed,
        message,
        cause === undefined ? undefined : { cause },
    );
}

function errorCode(error: unknown): number | undefined {
    return (error as { code?: number } | null)?.code;
}

/** Maps `CKA_EC_PARAMS` (a named curve OID or PrintableString) to a Hiero key type. */
function keyTypeFromEcParams(params: Uint8Array): HieroKeyType {
    const tlv = readTlv(params, 0);
    if (tlv.tag === DerTag.ObjectIdentifier) {
        const oid = decodeOid(tlv.value);
        if (oid === OID.secp256k1) return "ECDSA_SECP256K1";
        if (oid === OID.ed25519) return "ED25519";
        throw new RemoteSignerError(
            RemoteSignerErrorCodes.UnsupportedKey,
            `curve ${oid} is not supported; use secp256k1 or Ed25519`,
        );
    }
    // PrintableString (0x13), used by tokens that predate PKCS#11 v3.0
    if (
        tlv.tag === 0x13 &&
        Buffer.from(tlv.value).toString("ascii") === EDWARDS25519_NAME
    ) {
        return "ED25519";
    }
    throw new RemoteSignerError(
        RemoteSignerErrorCodes.UnsupportedKey,
        "CKA_EC_PARAMS is not a supported named curve",
    );
}

/**
 * Unwraps `CKA_EC_POINT`. The standard encodes it as a DER OCTET STRING, but
 * some tokens return the raw point, so both are accepted.
 */
function decodeEcPoint(value: Uint8Array, rawLengths: number[]): Uint8Array {
    if (value[0] === DerTag.OctetString) {
        try {
            const tlv = readTlv(value, 0);
            if (
                tlv.end === value.length &&
                rawLengths.includes(tlv.value.length)
            ) {
                return tlv.value;
            }
        } catch {
            // Not DER; a raw point may also start with 0x04.
        }
    }
    if (rawLengths.includes(value.length)) return value;
    throw new RemoteSignerError(
        RemoteSignerErrorCodes.MalformedDer,
        `CKA_EC_POINT has unexpected length ${value.length}`,
    );
}

/**
 * Signs Hiero transactions with a key held in a hardware security module
 * (or any other token) through PKCS#11, using the `pkcs11js` binding.
 *
 * Construct it with `Pkcs11Signer.create()`, which opens a session, logs in,
 * finds the key pair and reads the public key once. Call `close()` when done.
 * The private key never leaves the token.
 *
 * Supported keys are EC keys on secp256k1 (signed with `CKM_ECDSA` over the
 * Keccak-256 digest) and Edwards keys on Ed25519 (signed with `CKM_EDDSA`
 * over the raw bytes, PKCS#11 v3.0). A session runs one operation at a time,
 * so concurrent `sign` calls are queued.
 */
export class Pkcs11Signer extends RemoteSigner {
    readonly keyType: HieroKeyType;
    readonly publicKey: PublicKey;
    /**
     * Signs serialized TransactionBody bytes. A bound function, so it can be
     * passed to the SDK as `signer.sign`.
     */
    readonly sign: (bodyBytes: Uint8Array) => Promise<Uint8Array>;

    readonly #module: Pkcs11Module;
    readonly #session: Buffer;
    readonly #privateKey: Buffer;
    readonly #verify: boolean;
    readonly #release: () => void;
    #queue: Promise<unknown> = Promise.resolve();
    #closed = false;

    private constructor(params: {
        module: Pkcs11Module;
        session: Buffer;
        privateKey: Buffer;
        keyType: HieroKeyType;
        publicKey: PublicKey;
        verify: boolean;
        release: () => void;
    }) {
        super();
        this.#module = params.module;
        this.#session = params.session;
        this.#privateKey = params.privateKey;
        this.keyType = params.keyType;
        this.publicKey = params.publicKey;
        this.#verify = params.verify;
        this.#release = params.release;
        this.sign = (bodyBytes) => this.#sign(bodyBytes);
    }

    /** Opens a session on the token, logs in and loads the key pair. */
    // async although PKCS#11 calls are synchronous, so failures reject the
    // returned promise like every other backend's create().
    // oxlint-disable-next-line typescript/require-await
    static async create(options: Pkcs11SignerOptions): Promise<Pkcs11Signer> {
        if (!options.keyLabel && !options.keyId) {
            throw new TypeError("keyLabel or keyId is required");
        }

        let owned: pkcs11js.PKCS11 | undefined;
        // Only finalize what this signer initialized: C_Finalize ends every
        // session the application has on the library.
        let initialized = false;
        let module: Pkcs11Module;
        if (options.pkcs11) {
            module = options.pkcs11;
        } else if (options.library) {
            owned = new pkcs11js.PKCS11();
            try {
                owned.load(options.library);
            } catch (cause) {
                throw backendError(
                    `loading PKCS#11 module ${options.library} failed`,
                    cause,
                );
            }
            try {
                owned.C_Initialize();
                initialized = true;
            } catch (cause) {
                if (errorCode(cause) !== C.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
                    owned.close();
                    throw backendError(
                        `initializing PKCS#11 module ${options.library} failed`,
                        cause,
                    );
                }
            }
            module = owned;
        } else {
            throw new TypeError("library or pkcs11 is required");
        }

        let session: Buffer | undefined;
        const release = () => {
            if (session) module.C_CloseSession(session);
            if (initialized) owned!.C_Finalize();
            owned?.close();
        };

        try {
            session = Pkcs11Signer.#openSession(module, options);
            const { privateKey, keyType, publicKey } = Pkcs11Signer.#loadKey(
                module,
                session,
                options,
            );
            return new Pkcs11Signer({
                module,
                session,
                privateKey,
                keyType,
                publicKey,
                verify: options.verifySignatures ?? true,
                release,
            });
        } catch (error) {
            release();
            throw error;
        }
    }

    static #openSession(
        module: Pkcs11Module,
        options: Pkcs11SignerOptions,
    ): Buffer {
        let slot: Buffer | undefined;
        try {
            slot = module
                .C_GetSlotList(true)
                .find(
                    (s) =>
                        module.C_GetTokenInfo(s).label.trim() ===
                        options.tokenLabel,
                );
        } catch (cause) {
            throw backendError("listing PKCS#11 slots failed", cause);
        }
        if (!slot) {
            throw backendError(
                `no PKCS#11 token labelled "${options.tokenLabel}"`,
            );
        }

        let session: Buffer;
        try {
            session = module.C_OpenSession(slot, C.CKF_SERIAL_SESSION);
        } catch (cause) {
            throw backendError("opening a PKCS#11 session failed", cause);
        }
        try {
            module.C_Login(session, C.CKU_USER, options.pin);
        } catch (cause) {
            // Login state is shared by all sessions of the application.
            if (errorCode(cause) !== C.CKR_USER_ALREADY_LOGGED_IN) {
                module.C_CloseSession(session);
                throw backendError("PKCS#11 login failed", cause);
            }
        }
        return session;
    }

    static #loadKey(
        module: Pkcs11Module,
        session: Buffer,
        options: Pkcs11SignerOptions,
    ): { privateKey: Buffer; keyType: HieroKeyType; publicKey: PublicKey } {
        const find = (objectClass: number): Buffer => {
            const template: pkcs11js.Template = [
                { type: C.CKA_CLASS, value: objectClass },
            ];
            if (options.keyLabel) {
                template.push({ type: C.CKA_LABEL, value: options.keyLabel });
            }
            if (options.keyId) {
                template.push({
                    type: C.CKA_ID,
                    value: Buffer.from(options.keyId),
                });
            }
            let handles: Buffer[];
            try {
                module.C_FindObjectsInit(session, template);
                handles = module.C_FindObjects(session, 2);
                module.C_FindObjectsFinal(session);
            } catch (cause) {
                throw backendError("searching the PKCS#11 token failed", cause);
            }
            const kind =
                objectClass === C.CKO_PRIVATE_KEY ? "private" : "public";
            if (handles.length !== 1) {
                throw new RemoteSignerError(
                    handles.length === 0
                        ? RemoteSignerErrorCodes.BackendRequestFailed
                        : RemoteSignerErrorCodes.KeyNotUsable,
                    handles.length === 0
                        ? `no ${kind} key matches the given label and ID`
                        : `more than one ${kind} key matches; set both keyLabel and keyId`,
                );
            }
            return handles[0]!;
        };
        const attributes = (handle: Buffer, types: number[]) => {
            try {
                return module
                    .C_GetAttributeValue(
                        session,
                        handle,
                        types.map((type) => ({ type })),
                    )
                    .map((attribute) => new Uint8Array(attribute.value));
            } catch (cause) {
                throw backendError(
                    "reading PKCS#11 key attributes failed",
                    cause,
                );
            }
        };

        const privateKey = find(C.CKO_PRIVATE_KEY);
        const [canSign] = attributes(privateKey, [C.CKA_SIGN]);
        if (!canSign?.some((b) => b !== 0)) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.KeyNotUsable,
                "the private key does not have CKA_SIGN set",
            );
        }

        const [params, point] = attributes(find(C.CKO_PUBLIC_KEY), [
            C.CKA_EC_PARAMS,
            C.CKA_EC_POINT,
        ]);
        const keyType = keyTypeFromEcParams(params!);
        const publicKey =
            keyType === "ED25519"
                ? PublicKey.fromBytesED25519(decodeEcPoint(point!, [32]))
                : PublicKey.fromBytesECDSA(
                      compressSecp256k1Point(decodeEcPoint(point!, [33, 65])),
                  );
        return { privateKey, keyType, publicKey };
    }

    /**
     * Signs serialized TransactionBody bytes.
     *
     * For ECDSA keys the message is hashed locally with Keccak-256, the digest
     * Hiero verifies, and signed with `CKM_ECDSA`, which signs a supplied
     * digest. For Ed25519 keys the raw bytes are signed with `CKM_EDDSA`.
     */
    #sign(bodyBytes: Uint8Array): Promise<Uint8Array> {
        const result = this.#queue.then(() => this.#signNow(bodyBytes));
        this.#queue = result.catch(() => undefined);
        return result;
    }

    async #signNow(bodyBytes: Uint8Array): Promise<Uint8Array> {
        if (this.#closed) {
            throw backendError("the PKCS#11 signer is closed");
        }
        const isEcdsa = this.keyType === "ECDSA_SECP256K1";
        const message = isEcdsa ? keccak_256(bodyBytes) : bodyBytes;

        let raw: Uint8Array;
        try {
            this.#module.C_SignInit(
                this.#session,
                { mechanism: isEcdsa ? C.CKM_ECDSA : C.CKM_EDDSA },
                this.#privateKey,
            );
            raw = await new Promise<Uint8Array>((resolve, reject) => {
                this.#module.C_Sign(
                    this.#session,
                    Buffer.from(message),
                    Buffer.alloc(256),
                    (error, data) =>
                        error ? reject(error) : resolve(new Uint8Array(data)),
                );
            });
        } catch (cause) {
            throw backendError("PKCS#11 sign failed", cause);
        }

        // CKM_ECDSA returns r || s; tolerate tokens that return DER.
        const signature = !isEcdsa
            ? raw
            : raw.length === 64
              ? normalizeCompactSignature(raw)
              : derSignatureToCompact(raw);
        if (signature.length !== 64) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.SignatureInvalid,
                `expected a 64-byte signature, got ${signature.length} bytes`,
            );
        }
        if (this.#verify && !this.publicKey.verify(bodyBytes, signature)) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.SignatureInvalid,
                "PKCS#11 signature does not verify against the key's public key",
            );
        }
        return signature;
    }

    /**
     * Waits for pending signatures, then closes the session. Finalizes the
     * PKCS#11 module if this signer loaded it.
     */
    async close(): Promise<void> {
        if (this.#closed) return;
        this.#closed = true;
        await this.#queue;
        this.#release();
    }
}
