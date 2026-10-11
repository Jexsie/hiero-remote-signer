import {
    GetPublicKeyCommand,
    KMSClient,
    SignCommand,
} from "@aws-sdk/client-kms";
import type { SigningAlgorithmSpec } from "@aws-sdk/client-kms";
import { PublicKey } from "@hiero-ledger/sdk";
import { keccak_256 } from "@noble/hashes/sha3.js";

import { derSignatureToCompact, parseSpki } from "../der/index.js";
import { RemoteSignerError, RemoteSignerErrorCodes } from "../errors/index.js";
import type { HieroKeyType, HieroRemoteSigner } from "../types/index.js";
import type { AwsKmsSignerOptions } from "./AwsKmsSignerOptions.js";

/**
 * AWS KMS accepts at most 4096 bytes in `Sign` with `MessageType: RAW`, which
 * Ed25519 requires. A transaction body larger than this cannot be signed with
 * an Ed25519 KMS key.
 */
export const AWS_KMS_MAX_RAW_MESSAGE_BYTES = 4096;

/** KMS key specs this signer accepts, mapped to the Hiero key type they produce. */
const KEY_SPECS: Record<
    string,
    { keyType: HieroKeyType; algorithm: SigningAlgorithmSpec }
> = {
    ECC_SECG_P256K1: { keyType: "ECDSA_SECP256K1", algorithm: "ECDSA_SHA_256" },
    ECC_NIST_EDWARDS25519: {
        keyType: "ED25519",
        algorithm: "ED25519_SHA_512",
    },
};

/**
 * Signs Hiero transactions with an asymmetric key stored in AWS KMS.
 *
 * Construct it with `AwsKmsSigner.create()`, which fetches and validates the
 * public key once. The private key never leaves KMS.
 *
 * Supported key specs are `ECC_SECG_P256K1` (Hiero ECDSA keys) and
 * `ECC_NIST_EDWARDS25519` (Hiero ED25519 keys).
 */
export class AwsKmsSigner implements HieroRemoteSigner {
    readonly keyType: HieroKeyType;
    readonly publicKey: PublicKey;
    /** The key ARN as reported by KMS, resolved from any alias. */
    readonly keyArn: string;

    readonly #client: KMSClient;
    readonly #algorithm: SigningAlgorithmSpec;
    readonly #verify: boolean;
    readonly #grantTokens: string[] | undefined;

    private constructor(params: {
        client: KMSClient;
        keyArn: string;
        keyType: HieroKeyType;
        algorithm: SigningAlgorithmSpec;
        publicKey: PublicKey;
        verify: boolean;
        grantTokens: string[] | undefined;
    }) {
        this.#client = params.client;
        this.keyArn = params.keyArn;
        this.keyType = params.keyType;
        this.#algorithm = params.algorithm;
        this.publicKey = params.publicKey;
        this.#verify = params.verify;
        this.#grantTokens = params.grantTokens;
        // Bind so `signer.sign` can be passed to the SDK as a bare function.
        this.sign = this.sign.bind(this);
    }

    /** Fetches the public key for `keyId` and validates that it can sign for Hiero. */
    static async create(options: AwsKmsSignerOptions): Promise<AwsKmsSigner> {
        const client =
            options.client ?? new KMSClient(options.clientConfig ?? {});

        let response;
        try {
            response = await client.send(
                new GetPublicKeyCommand({
                    KeyId: options.keyId,
                    GrantTokens: options.grantTokens,
                }),
            );
        } catch (cause) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.BackendRequestFailed,
                `GetPublicKey failed for ${options.keyId}`,
                { cause },
            );
        }

        const spec = response.KeySpec ? KEY_SPECS[response.KeySpec] : undefined;
        if (!spec) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.UnsupportedKey,
                `KMS key spec ${response.KeySpec ?? "unknown"} is not supported; ` +
                    `use ECC_SECG_P256K1 or ECC_NIST_EDWARDS25519`,
            );
        }
        if (response.KeyUsage !== "SIGN_VERIFY") {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.KeyNotUsable,
                `KMS key usage is ${response.KeyUsage ?? "unknown"}; SIGN_VERIFY is required`,
            );
        }
        if (
            response.SigningAlgorithms &&
            !response.SigningAlgorithms.includes(spec.algorithm)
        ) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.KeyNotUsable,
                `KMS key does not offer signing algorithm ${spec.algorithm}`,
            );
        }
        if (!response.PublicKey) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.MalformedDer,
                "GetPublicKey returned no public key",
            );
        }

        const parsed = parseSpki(response.PublicKey);
        if (parsed.keyType !== spec.keyType) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.UnsupportedKey,
                `KMS reported ${response.KeySpec} but returned a ${parsed.keyType} public key`,
            );
        }

        const publicKey =
            parsed.keyType === "ED25519"
                ? PublicKey.fromBytesED25519(parsed.publicKey)
                : PublicKey.fromBytesECDSA(parsed.publicKey);

        return new AwsKmsSigner({
            client,
            keyArn: response.KeyId ?? options.keyId,
            keyType: spec.keyType,
            algorithm: spec.algorithm,
            publicKey,
            verify: options.verifySignatures ?? true,
            grantTokens: options.grantTokens,
        });
    }

    /**
     * Signs serialized TransactionBody bytes.
     *
     * For ECDSA keys the message is hashed locally with Keccak-256, which is
     * the digest Hiero verifies, and KMS signs that digest (`MessageType:
     * DIGEST`). KMS does not offer Keccak itself, so it cannot hash the raw
     * message. For Ed25519 keys KMS signs the raw bytes (`MessageType: RAW`).
     */
    async sign(bodyBytes: Uint8Array): Promise<Uint8Array> {
        let message: Uint8Array;
        let messageType: "DIGEST" | "RAW";

        if (this.keyType === "ECDSA_SECP256K1") {
            message = keccak_256(bodyBytes);
            messageType = "DIGEST";
        } else {
            if (bodyBytes.length > AWS_KMS_MAX_RAW_MESSAGE_BYTES) {
                throw new RemoteSignerError(
                    RemoteSignerErrorCodes.MessageRejected,
                    `transaction body is ${bodyBytes.length} bytes; AWS KMS signs at most ` +
                        `${AWS_KMS_MAX_RAW_MESSAGE_BYTES} bytes with Ed25519. Use a secp256k1 key ` +
                        `or reduce the body size (for example, a smaller file chunk size).`,
                );
            }
            message = bodyBytes;
            messageType = "RAW";
        }

        let response;
        try {
            response = await this.#client.send(
                new SignCommand({
                    KeyId: this.keyArn,
                    Message: message,
                    MessageType: messageType,
                    SigningAlgorithm: this.#algorithm,
                    GrantTokens: this.#grantTokens,
                }),
            );
        } catch (cause) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.BackendRequestFailed,
                `Sign failed for ${this.keyArn}`,
                { cause },
            );
        }

        if (!response.Signature) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.SignatureInvalid,
                "KMS returned no signature",
            );
        }

        const signature =
            this.keyType === "ECDSA_SECP256K1"
                ? derSignatureToCompact(response.Signature)
                : new Uint8Array(response.Signature);

        if (signature.length !== 64) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.SignatureInvalid,
                `expected a 64-byte signature, got ${signature.length} bytes`,
            );
        }
        if (this.#verify && !this.publicKey.verify(bodyBytes, signature)) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.SignatureInvalid,
                "KMS signature does not verify against the key's public key",
            );
        }
        return signature;
    }
}
