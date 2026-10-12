import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { AccountId, Client, PrivateKey } from "@hiero-ledger/sdk";

// Settings come from example/.env (copy .env.example) or the environment.
const envFile = fileURLToPath(new URL("../.env", import.meta.url));
if (existsSync(envFile)) process.loadEnvFile(envFile);

/** Networks the example runs against. Mainnet is left out on purpose. */
const NETWORKS = ["testnet", "previewnet"] as const;
export type Network = (typeof NETWORKS)[number];

export function required(name: string): string {
    const value = process.env[name]?.trim();
    if (!value) {
        throw new Error(`${name} is not set; see example/.env.example`);
    }
    return value;
}

export function optional(name: string): string | undefined {
    return process.env[name]?.trim() || undefined;
}

export function network(): Network {
    const name = optional("HIERO_NETWORK") ?? "testnet";
    if (!(NETWORKS as readonly string[]).includes(name)) {
        throw new Error(
            `HIERO_NETWORK must be ${NETWORKS.join(" or ")}, got ${name}`,
        );
    }
    return name as Network;
}

// Refuse an unsupported network before any script touches a key.
network();

/** A client for the configured network with no operator set yet. */
export function networkClient(): Client {
    return Client.forName(network());
}

/**
 * The funding account: your existing testnet account, with its private key
 * held locally. It only pays to create the remote-key account and for the
 * co-signed transfer.
 */
export function fundingAccount(): { id: AccountId; key: PrivateKey } {
    const id = AccountId.fromString(required("FUNDING_ACCOUNT_ID"));
    const raw = required("FUNDING_PRIVATE_KEY");
    const type = (optional("FUNDING_KEY_TYPE") ?? "ecdsa").toLowerCase();
    switch (type) {
        case "ecdsa":
            return { id, key: PrivateKey.fromStringECDSA(raw) };
        case "ed25519":
            return { id, key: PrivateKey.fromStringED25519(raw) };
        case "der":
            return { id, key: PrivateKey.fromStringDer(raw) };
        default:
            throw new Error(
                `FUNDING_KEY_TYPE must be ecdsa, ed25519 or der, got ${type}`,
            );
    }
}

/** The account created by `npm run create-account`, owned by the remote key. */
export function remoteAccountId(): AccountId {
    return AccountId.fromString(required("REMOTE_ACCOUNT_ID"));
}

export function hashscanAccount(id: AccountId | string): string {
    return `https://hashscan.io/${network()}/account/${id.toString()}`;
}
