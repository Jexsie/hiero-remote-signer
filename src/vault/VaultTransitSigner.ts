import { PublicKey } from "@hiero-ledger/sdk";

import { parseSpki, pemToDer } from "../der/index.js";
import { RemoteSignerError, RemoteSignerErrorCodes } from "../errors/index.js";
import type { HieroKeyType, HieroRemoteSigner } from "../types/index.js";
import type {
    VaultToken,
    VaultTransitSignerOptions,
} from "./VaultTransitSignerOptions.js";

/** The fields of a transit key read that this signer uses. */
interface TransitKey {
    type?: string;
    derived?: boolean;
    supports_signing?: boolean;
    latest_version?: number;
    keys?: Record<string, { public_key?: string } | number>;
}

const SIGNATURE = /^vault:v(\d+):([A-Za-z0-9+/=]+)$/;

/** Minimal HTTP client for the two transit endpoints the signer calls. */
class TransitApi {
    readonly #baseUrl: string;
    readonly #token: VaultToken;
    readonly #namespace: string | undefined;
    readonly #fetch: typeof fetch;

    constructor(options: VaultTransitSignerOptions) {
        const mount = (options.mountPath ?? "transit").replace(
            /^\/+|\/+$/g,
            "",
        );
        this.#baseUrl = `${options.address.replace(/\/+$/, "")}/v1/${mount}`;
        this.#token = options.token;
        this.#namespace = options.namespace;
        this.#fetch = options.fetch ?? fetch;
    }

    readKey(name: string): Promise<TransitKey> {
        return this.#request("GET", `keys/${encodeURIComponent(name)}`);
    }

    sign(
        name: string,
        input: Uint8Array,
        keyVersion: number,
    ): Promise<{ signature?: string }> {
        return this.#request("POST", `sign/${encodeURIComponent(name)}`, {
            input: Buffer.from(input).toString("base64"),
            key_version: keyVersion,
        });
    }

    async #request<T>(method: string, path: string, body?: object): Promise<T> {
        const token =
            typeof this.#token === "function"
                ? await this.#token()
                : this.#token;
        const headers: Record<string, string> = { "X-Vault-Token": token };
        if (this.#namespace) headers["X-Vault-Namespace"] = this.#namespace;
        if (body) headers["Content-Type"] = "application/json";

        const response = await this.#fetch(`${this.#baseUrl}/${path}`, {
            method,
            headers,
            body: body ? JSON.stringify(body) : undefined,
        });
        const json = (await response.json().catch(() => ({}))) as {
            data?: T;
            errors?: string[];
        };
        if (!response.ok || !json.data) {
            throw new Error(
                `Vault returned ${response.status}` +
                    (json.errors?.length ? `: ${json.errors.join("; ")}` : ""),
            );
        }
        return json.data;
    }
}

/**
 * Signs Hiero transactions with an Ed25519 key in the HashiCorp Vault transit
 * secrets engine (or OpenBao, which shares its API).
 *
 * Construct it with `VaultTransitSigner.create()`, which reads and validates
 * the public key once. The private key never leaves Vault.
 *
 * Only `ed25519` keys are supported: transit has no secp256k1 keys. Derived
 * keys are rejected, because they need a per-request context.
 */
export class VaultTransitSigner implements HieroRemoteSigner {
    readonly keyType: HieroKeyType = "ED25519";
    readonly publicKey: PublicKey;
    /** Name of the transit key. */
    readonly keyName: string;
    /** The key version the signer is pinned to. */
    readonly keyVersion: number;

    readonly #api: TransitApi;
    readonly #verify: boolean;

    private constructor(params: {
        api: TransitApi;
        keyName: string;
        keyVersion: number;
        publicKey: PublicKey;
        verify: boolean;
    }) {
        this.#api = params.api;
        this.keyName = params.keyName;
        this.keyVersion = params.keyVersion;
        this.publicKey = params.publicKey;
        this.#verify = params.verify;
        // Bind so `signer.sign` can be passed to the SDK as a bare function.
        this.sign = this.sign.bind(this);
    }

    /** Reads the transit key and validates that it can sign for Hiero. */
    static async create(
        options: VaultTransitSignerOptions,
    ): Promise<VaultTransitSigner> {
        const api = new TransitApi(options);
        const name = options.keyName;

        let key;
        try {
            key = await api.readKey(name);
        } catch (cause) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.BackendRequestFailed,
                `reading transit key ${name} failed`,
                { cause },
            );
        }

        if (key.type !== "ed25519") {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.UnsupportedKey,
                `transit key type ${key.type ?? "unknown"} is not supported; ` +
                    `use an ed25519 key (transit has no secp256k1 keys)`,
            );
        }
        if (key.supports_signing === false || key.derived) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.KeyNotUsable,
                `transit key ${name} cannot sign without a context; ` +
                    `use a non-derived ed25519 key`,
            );
        }

        const keyVersion =
            options.keyVersion ??
            key.latest_version ??
            Math.max(0, ...Object.keys(key.keys ?? {}).map(Number));
        const entry = key.keys?.[String(keyVersion)];
        const encoded =
            typeof entry === "object" ? entry.public_key : undefined;
        if (!encoded) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.KeyNotUsable,
                `transit key ${name} has no public key for version ${keyVersion}`,
            );
        }

        return new VaultTransitSigner({
            api,
            keyName: name,
            keyVersion,
            publicKey: PublicKey.fromBytesED25519(decodePublicKey(encoded)),
            verify: options.verifySignatures ?? true,
        });
    }

    /**
     * Signs serialized TransactionBody bytes. Vault signs the raw bytes with
     * pure Ed25519, which is what Hiero verifies.
     */
    async sign(bodyBytes: Uint8Array): Promise<Uint8Array> {
        let response;
        try {
            response = await this.#api.sign(
                this.keyName,
                bodyBytes,
                this.keyVersion,
            );
        } catch (cause) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.BackendRequestFailed,
                `transit sign failed for ${this.keyName}`,
                { cause },
            );
        }

        const match = SIGNATURE.exec(response.signature ?? "");
        if (!match) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.SignatureInvalid,
                "Vault returned no signature or one in an unknown format",
            );
        }
        if (Number(match[1]) !== this.keyVersion) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.SignatureInvalid,
                `Vault signed with key version ${match[1]}, expected ${this.keyVersion}`,
            );
        }

        const signature = new Uint8Array(Buffer.from(match[2]!, "base64"));
        if (signature.length !== 64) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.SignatureInvalid,
                `expected a 64-byte signature, got ${signature.length} bytes`,
            );
        }
        if (this.#verify && !this.publicKey.verify(bodyBytes, signature)) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.SignatureInvalid,
                "Vault signature does not verify against the key's public key",
            );
        }
        return signature;
    }
}

/** Transit returns Ed25519 public keys as base64 of the raw 32 bytes; accept PEM too. */
function decodePublicKey(encoded: string): Uint8Array {
    if (encoded.includes("-----BEGIN")) {
        const parsed = parseSpki(pemToDer(encoded));
        if (parsed.keyType !== "ED25519") {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.UnsupportedKey,
                `transit returned a ${parsed.keyType} public key for an ed25519 key`,
            );
        }
        return parsed.publicKey;
    }
    const raw = new Uint8Array(Buffer.from(encoded, "base64"));
    if (raw.length !== 32) {
        throw new RemoteSignerError(
            RemoteSignerErrorCodes.MalformedDer,
            `Ed25519 public key must be 32 bytes, got ${raw.length}`,
        );
    }
    return raw;
}
