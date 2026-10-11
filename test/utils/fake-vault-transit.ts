import { randomBytes } from "node:crypto";

import { generateKeyMaterial, signEd25519 } from "./key-material.js";
import type { SignBehaviour } from "./key-material.js";

export type TransitKeyType = "ed25519" | "ecdsa-p256" | "rsa-2048";

export interface FakeTransitKey {
    name: string;
    type: TransitKeyType;
    derived: boolean;
    /** Version number to [public key (base64 or PEM), private seed]. */
    versions: Record<number, { publicKey: string; privateKey: Uint8Array }>;
    behaviour: SignBehaviour;
}

export const VAULT_ADDRESS = "https://vault.test:8200";
export const VAULT_TOKEN = "s.test-token";

function makeVersion(type: TransitKeyType) {
    const material = generateKeyMaterial(
        type === "ed25519" ? "ed25519" : "p256",
    );
    return {
        // Transit returns raw base64 for Ed25519 and PEM for ECDSA keys.
        publicKey:
            type === "ed25519"
                ? Buffer.from(material.publicJwk.x!, "base64url").toString(
                      "base64",
                  )
                : material.pem,
        privateKey: material.privateKey,
    };
}

export function makeTransitKey(
    type: TransitKeyType = "ed25519",
    overrides: Partial<FakeTransitKey> & { versionCount?: number } = {},
): FakeTransitKey {
    const { versionCount = 1, ...rest } = overrides;
    const versions: FakeTransitKey["versions"] = {};
    for (let v = 1; v <= versionCount; v++) versions[v] = makeVersion(type);
    return {
        name: `hiero-${randomBytes(4).toString("hex")}`,
        type,
        derived: false,
        versions,
        behaviour: "normal",
        ...rest,
    };
}

/**
 * A `fetch` that serves the transit endpoints the signer uses for the given
 * keys. It enforces the token header, base64 input and key versions, signs
 * with real Ed25519 keys, and returns errors in Vault's `{ errors: [...] }`
 * shape, so a signer that misuses the API fails here as it would against
 * Vault.
 */
export function createFakeVault(
    keys: FakeTransitKey[],
    options: { mountPath?: string; namespace?: string } = {},
) {
    const requests: { method: string; url: string; body?: unknown }[] = [];
    const prefix = `${VAULT_ADDRESS}/v1/${options.mountPath ?? "transit"}/`;

    const reply = (status: number, body: object) =>
        new Response(JSON.stringify(body), {
            status,
            headers: { "Content-Type": "application/json" },
        });
    const error = (status: number, message: string) =>
        reply(status, { errors: [message] });

    const fetchImpl = async (
        input: string | URL | Request,
        init?: RequestInit,
    ): Promise<Response> => {
        const url = String(input);
        const method = init?.method ?? "GET";
        const headers = new Headers(init?.headers);
        const body = init?.body ? JSON.parse(String(init.body)) : undefined;
        requests.push({ method, url, body });

        if (headers.get("X-Vault-Token") !== VAULT_TOKEN) {
            return error(403, "permission denied");
        }
        if (
            options.namespace &&
            headers.get("X-Vault-Namespace") !== options.namespace
        ) {
            return error(403, "permission denied");
        }
        if (!url.startsWith(prefix)) {
            return error(404, "no handler for route");
        }

        const [operation, encodedName] = url.slice(prefix.length).split("/");
        const key = keys.find(
            (k) => k.name === decodeURIComponent(encodedName ?? ""),
        );

        if (operation === "keys" && method === "GET") {
            if (!key) return error(404, "key not found");
            const versions = Object.keys(key.versions).map(Number);
            return reply(200, {
                data: {
                    name: key.name,
                    type: key.type,
                    derived: key.derived,
                    supports_signing: true,
                    latest_version: Math.max(...versions),
                    keys: Object.fromEntries(
                        versions.map((v) => [
                            v,
                            {
                                name: key.type,
                                creation_time: "2026-01-01T00:00:00Z",
                                public_key: key.versions[v]!.publicKey,
                            },
                        ]),
                    ),
                },
            });
        }

        if (operation === "sign" && method === "POST") {
            if (!key) return error(400, "signing key not found");
            if (key.derived) {
                return error(400, "missing 'context' for key derivation");
            }
            if (typeof body?.input !== "string") {
                return error(400, "missing input to process");
            }
            const latest = Math.max(...Object.keys(key.versions).map(Number));
            const version = body.key_version || latest;
            const material = key.versions[version];
            if (!material) return error(400, "invalid key version");
            if (key.type !== "ed25519") {
                return error(400, "test Vault only signs with ed25519 keys");
            }
            const input = new Uint8Array(Buffer.from(body.input, "base64"));
            const signature = signEd25519(
                input,
                material.privateKey,
                key.behaviour,
            );
            return reply(200, {
                data: {
                    signature: `vault:v${version}:${Buffer.from(signature).toString("base64")}`,
                    key_version: version,
                },
            });
        }

        return error(405, "unsupported operation");
    };

    return { requests, fetch: fetchImpl as typeof fetch };
}
