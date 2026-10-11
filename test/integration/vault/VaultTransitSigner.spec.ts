/**
 * Tests against a real HashiCorp Vault (or OpenBao) server.
 *
 * The first suite needs only VAULT_ADDR and VAULT_TOKEN for a server where
 * the token may mount secrets engines, such as a dev server
 * (`vault server -dev`). It mounts transit, creates an ed25519 key and checks
 * every signature with the Hiero SDK. CI runs it against a Vault container.
 *
 * The second suite also needs the Hiero network variables (see
 * test/utils/live-network.ts) and runs the full account flow on a live network.
 */
import { randomUUID } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import {
    Client,
    Hbar,
    Status,
    TransactionId,
    TransferTransaction,
} from "@hiero-ledger/sdk";

import { VaultTransitSigner } from "../../../src/vault/index.js";
import {
    createAccountAndSpend,
    hieroNetworkConfigured,
} from "../../utils/live-network.js";

const address = process.env.VAULT_ADDR;
const token = process.env.VAULT_TOKEN;
const mountPath = process.env.VAULT_TRANSIT_MOUNT ?? "transit";
const vaultConfigured = Boolean(address && token);

async function vault(method: string, path: string, body?: object) {
    const response = await fetch(`${address}/v1/${path}`, {
        method,
        headers: {
            "X-Vault-Token": token!,
            "Content-Type": "application/json",
        },
        body: body ? JSON.stringify(body) : undefined,
    });
    if (!response.ok && response.status !== 400) {
        throw new Error(
            `${method} ${path}: ${response.status} ${await response.text()}`,
        );
    }
}

/** Creates a fresh ed25519 transit key and returns its name. */
async function createKey(): Promise<string> {
    const keyName = `hiero-${randomUUID().slice(0, 8)}`;
    await vault("POST", `${mountPath}/keys/${keyName}`, { type: "ed25519" });
    return keyName;
}

describe.skipIf(!vaultConfigured)("VaultTransitSigner on a real Vault", () => {
    beforeAll(async () => {
        // 400 means the mount already exists.
        await vault("POST", `sys/mounts/${mountPath}`, { type: "transit" });
    });

    const create = async (keyName: string) =>
        VaultTransitSigner.create({
            address: address!,
            token: token!,
            keyName,
            mountPath,
        });

    it("signs a frozen transaction for every node", async () => {
        const signer = await create(await createKey());
        const network = Client.forNetwork({
            "127.0.0.1:50211": "0.0.3",
            "127.0.0.1:50212": "0.0.4",
            "127.0.0.1:50213": "0.0.5",
        });

        const tx = new TransferTransaction()
            .addHbarTransfer("0.0.1234", Hbar.fromTinybars(-1000))
            .addHbarTransfer("0.0.1001", Hbar.fromTinybars(1000))
            .setTransactionId(TransactionId.generate("0.0.1234"))
            .freezeWith(network);
        await tx.signWith(signer.publicKey, signer.sign);

        expect(signer.publicKey.verifyTransaction(tx)).toBe(true);
        network.close();
    });

    it("keeps signing with the pinned version after a rotation", async () => {
        const keyName = await createKey();
        const signer = await create(keyName);
        await vault("POST", `${mountPath}/keys/${keyName}/rotate`);

        const body = new Uint8Array(64).fill(1);
        expect(signer.publicKey.verify(body, await signer.sign(body))).toBe(
            true,
        );
        expect((await create(keyName)).keyVersion).toBe(2);
    });
});

const networkConfigured =
    vaultConfigured &&
    hieroNetworkConfigured &&
    Boolean(process.env.VAULT_TRANSIT_KEY);

describe.skipIf(!networkConfigured)(
    "VaultTransitSigner on a live Hiero network",
    () => {
        it("creates an account owned by the transit key and spends from it", async () => {
            const signer = await VaultTransitSigner.create({
                address: address!,
                token: token!,
                keyName: process.env.VAULT_TRANSIT_KEY!,
                mountPath,
            });
            expect(await createAccountAndSpend(signer)).toBe(Status.Success);
        }, 120_000);
    },
);
