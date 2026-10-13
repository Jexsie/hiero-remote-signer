import { KeyManagementServiceClient } from "@google-cloud/kms";
import type { protos } from "@google-cloud/kms";
import { PublicKey } from "@hiero-ledger/sdk";
import { keccak_256 } from "@noble/hashes/sha3.js";

import { derSignatureToCompact, parseSpki, pemToDer } from "../der/index.js";
import { RemoteSignerError, RemoteSignerErrorCodes } from "../errors/index.js";
import type { HieroKeyType, HieroRemoteSigner } from "../types/index.js";
import { crc32c } from "./crc32c.js";
import type {
    GcpKmsClient,
    GcpKmsSignerOptions,
} from "./GcpKmsSignerOptions.js";

type AsymmetricSignRequest = protos.google.cloud.kms.v1.IAsymmetricSignRequest;
type Int64Value = protos.google.protobuf.IInt64Value;

/** Cloud KMS algorithms this signer accepts, mapped to the Hiero key type they produce. */
const ALGORITHMS: Record<string, HieroKeyType> = {
    EC_SIGN_SECP256K1_SHA256: "ECDSA_SECP256K1",
    EC_SIGN_ED25519: "ED25519",
};

function checksumMatches(
    expected: Int64Value | null | undefined,
    bytes: Uint8Array,
): boolean {
    return (
        expected?.value == null ||
        Number(String(expected.value)) === crc32c(bytes)
    );
}

function toBytes(value: Uint8Array | string): Uint8Array {
    return typeof value === "string"
        ? new Uint8Array(Buffer.from(value, "base64"))
        : new Uint8Array(value);
}

/**
 * Signs Hiero transactions with an asymmetric key stored in Google Cloud KMS.
 *
 * Construct it with `GcpKmsSigner.create()`, which fetches and validates the
 * public key once. The private key never leaves Cloud KMS.
 *
 * Supported algorithms are `EC_SIGN_SECP256K1_SHA256` (Hiero ECDSA keys,
 * HSM protection level only) and `EC_SIGN_ED25519` (Hiero ED25519 keys,
 * software protection level only). Every request and response is checked
 * with CRC32C, as Cloud KMS recommends.
 */
export class GcpKmsSigner implements HieroRemoteSigner {
    readonly keyType: HieroKeyType;
    readonly publicKey: PublicKey;
    /**
     * Signs serialized TransactionBody bytes. A bound function, so it can be
     * passed to the SDK as `signer.sign`.
     */
    readonly sign: (bodyBytes: Uint8Array) => Promise<Uint8Array>;
    /** The key version resource name as reported by Cloud KMS. */
    readonly keyVersionName: string;

    readonly #client: GcpKmsClient;
    readonly #verify: boolean;

    private constructor(params: {
        client: GcpKmsClient;
        keyVersionName: string;
        keyType: HieroKeyType;
        publicKey: PublicKey;
        verify: boolean;
    }) {
        this.#client = params.client;
        this.keyVersionName = params.keyVersionName;
        this.keyType = params.keyType;
        this.publicKey = params.publicKey;
        this.#verify = params.verify;
        this.sign = (bodyBytes) => this.#sign(bodyBytes);
    }

    /** Fetches the public key for the key version and validates that it can sign for Hiero. */
    static async create(options: GcpKmsSignerOptions): Promise<GcpKmsSigner> {
        const client =
            options.client ??
            new KeyManagementServiceClient(options.clientOptions);
        const name = options.keyVersionName;

        let response;
        try {
            [response] = await client.getPublicKey({ name });
        } catch (cause) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.BackendRequestFailed,
                `GetPublicKey failed for ${name}`,
                { cause },
            );
        }

        const algorithm = String(response.algorithm ?? "unknown");
        const keyType = ALGORITHMS[algorithm];
        if (!keyType) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.UnsupportedKey,
                `Cloud KMS algorithm ${algorithm} is not supported; ` +
                    `use EC_SIGN_SECP256K1_SHA256 or EC_SIGN_ED25519`,
            );
        }
        if (!response.pem) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.MalformedDer,
                "GetPublicKey returned no public key",
            );
        }
        if (
            (response.name && response.name !== name) ||
            !checksumMatches(
                response.pemCrc32c,
                new TextEncoder().encode(response.pem),
            )
        ) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.IntegrityCheckFailed,
                `GetPublicKey response for ${name} failed integrity verification`,
            );
        }

        const parsed = parseSpki(pemToDer(response.pem));
        if (parsed.keyType !== keyType) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.UnsupportedKey,
                `Cloud KMS reported ${algorithm} but returned a ${parsed.keyType} public key`,
            );
        }

        const publicKey =
            parsed.keyType === "ED25519"
                ? PublicKey.fromBytesED25519(parsed.publicKey)
                : PublicKey.fromBytesECDSA(parsed.publicKey);

        return new GcpKmsSigner({
            client,
            keyVersionName: name,
            keyType,
            publicKey,
            verify: options.verifySignatures ?? true,
        });
    }

    /**
     * Signs serialized TransactionBody bytes.
     *
     * For ECDSA keys the message is hashed locally with Keccak-256, which is
     * the digest Hiero verifies, and Cloud KMS signs that digest. The digest
     * travels in the `sha256` field because that is the field the key
     * algorithm expects; Cloud KMS signs the 32 bytes as given. For Ed25519
     * keys Cloud KMS signs the raw bytes (PureEdDSA) passed in `data`.
     */
    async #sign(bodyBytes: Uint8Array): Promise<Uint8Array> {
        const name = this.keyVersionName;
        const isEcdsa = this.keyType === "ECDSA_SECP256K1";
        const message = isEcdsa ? keccak_256(bodyBytes) : bodyBytes;
        const request: AsymmetricSignRequest = isEcdsa
            ? {
                  name,
                  digest: { sha256: message },
                  digestCrc32c: { value: crc32c(message) },
              }
            : {
                  name,
                  data: message,
                  dataCrc32c: { value: crc32c(message) },
              };

        let response;
        try {
            [response] = await this.#client.asymmetricSign(request);
        } catch (cause) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.BackendRequestFailed,
                `AsymmetricSign failed for ${name}`,
                { cause },
            );
        }

        if (!response.signature) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.SignatureInvalid,
                "Cloud KMS returned no signature",
            );
        }
        const raw = toBytes(response.signature);
        const requestVerified = isEcdsa
            ? response.verifiedDigestCrc32c
            : response.verifiedDataCrc32c;
        if (
            !requestVerified ||
            response.name !== name ||
            !checksumMatches(response.signatureCrc32c, raw)
        ) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.IntegrityCheckFailed,
                `AsymmetricSign response for ${name} failed integrity verification`,
            );
        }

        const signature = isEcdsa ? derSignatureToCompact(raw) : raw;
        if (signature.length !== 64) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.SignatureInvalid,
                `expected a 64-byte signature, got ${signature.length} bytes`,
            );
        }
        if (this.#verify && !this.publicKey.verify(bodyBytes, signature)) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.SignatureInvalid,
                "Cloud KMS signature does not verify against the key's public key",
            );
        }
        return signature;
    }
}
