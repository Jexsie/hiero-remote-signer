import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import {
    Client,
    Hbar,
    PrivateKey,
    Transaction,
    TransactionId,
    TransferTransaction,
} from "@hiero-ledger/sdk";

import { setClientOperator } from "../../../src/client/index.js";
import { RemoteSignerErrorCodes } from "../../../src/errors/index.js";
import { VaultTransitSigner } from "../../../src/vault/index.js";
import type { VaultTransitSignerOptions } from "../../../src/vault/index.js";
import { expectCodeAsync } from "../../utils/assertions.js";
import {
    createFakeVault,
    makeTransitKey,
    VAULT_ADDRESS,
    VAULT_TOKEN,
} from "../../utils/fake-vault-transit.js";
import type { FakeTransitKey } from "../../utils/fake-vault-transit.js";

function setup(
    key: FakeTransitKey,
    overrides: Partial<VaultTransitSignerOptions> = {},
    vaultOptions: { mountPath?: string; namespace?: string } = {},
) {
    const vault = createFakeVault([key], vaultOptions);
    const create = (extra: Partial<VaultTransitSignerOptions> = {}) =>
        VaultTransitSigner.create({
            address: VAULT_ADDRESS,
            token: VAULT_TOKEN,
            keyName: key.name,
            fetch: vault.fetch,
            ...overrides,
            ...extra,
        });
    return { ...vault, create };
}

/** A fetch that answers every request with `status` and `body`. */
function respondWith(status: number, body: unknown): typeof fetch {
    return () =>
        Promise.resolve(
            new Response(
                typeof body === "string" ? body : JSON.stringify(body),
                { status },
            ),
        );
}

/** A fetch that serves `key` but answers sign requests with `data`. */
function signResponse(key: FakeTransitKey, data: object): typeof fetch {
    const vault = createFakeVault([key]);
    return (input, init) =>
        init?.method === "POST"
            ? Promise.resolve(Response.json({ data }))
            : vault.fetch(input, init);
}

function hieroClient(): Client {
    return Client.forNetwork({
        "127.0.0.1:50211": "0.0.3",
        "127.0.0.1:50212": "0.0.4",
        "127.0.0.1:50213": "0.0.5",
    });
}

const seedOf = (key: FakeTransitKey, version = 1) =>
    key.versions[version]!.privateKey;

describe("VaultTransitSigner.create", () => {
    it("derives the Hiero public key and pins the latest version", async () => {
        const key = makeTransitKey("ed25519", { versionCount: 3 });
        const signer = await setup(key).create();
        expect(signer.keyType).toBe("ED25519");
        expect(signer.keyVersion).toBe(3);
        expect(signer.publicKey.toStringRaw()).toBe(
            PrivateKey.fromBytesED25519(seedOf(key, 3)).publicKey.toStringRaw(),
        );
    });

    it("uses the requested key version", async () => {
        const key = makeTransitKey("ed25519", { versionCount: 2 });
        const vault = setup(key);
        const signer = await vault.create({ keyVersion: 1 });
        expect(signer.publicKey.toStringRaw()).toBe(
            PrivateKey.fromBytesED25519(seedOf(key, 1)).publicKey.toStringRaw(),
        );

        await signer.sign(randomBytes(32));
        expect(vault.requests.at(-1)!.body).toMatchObject({ key_version: 1 });
    });

    it("supports a custom mount path, namespace and token provider", async () => {
        const key = makeTransitKey();
        const signer = await setup(
            key,
            {
                mountPath: "/hiero-transit/",
                namespace: "team-a",
                address: `${VAULT_ADDRESS}/`,
                token: () => Promise.resolve(VAULT_TOKEN),
            },
            { mountPath: "hiero-transit", namespace: "team-a" },
        ).create();
        const body = randomBytes(32);
        expect(signer.publicKey.verify(body, await signer.sign(body))).toBe(
            true,
        );
    });

    it.each(["ecdsa-p256", "rsa-2048"] as const)(
        "rejects %s keys",
        async (type) => {
            await expectCodeAsync(
                setup(makeTransitKey(type)).create(),
                RemoteSignerErrorCodes.UnsupportedKey,
            );
        },
    );

    it("rejects derived keys", async () => {
        await expectCodeAsync(
            setup(makeTransitKey("ed25519", { derived: true })).create(),
            RemoteSignerErrorCodes.KeyNotUsable,
        );
    });

    it("rejects a key version that does not exist", async () => {
        await expectCodeAsync(
            setup(makeTransitKey()).create({ keyVersion: 7 }),
            RemoteSignerErrorCodes.KeyNotUsable,
        );
    });

    it("falls back to the highest version when latest_version is absent", async () => {
        const key = makeTransitKey();
        const publicKey = key.versions[1]!.publicKey;
        const signer = await VaultTransitSigner.create({
            address: VAULT_ADDRESS,
            token: VAULT_TOKEN,
            keyName: key.name,
            fetch: respondWith(200, {
                data: {
                    type: "ed25519",
                    keys: { "1": 1700000000, "2": { public_key: publicKey } },
                },
            }),
        });
        expect(signer.keyVersion).toBe(2);
    });

    it("accepts a PEM public key and rejects one of another type", async () => {
        const ed = PrivateKey.generateED25519();
        const pem = (der: string) =>
            `-----BEGIN PUBLIC KEY-----\n${Buffer.from(der, "hex").toString("base64")}\n-----END PUBLIC KEY-----`;
        const keyRead = (publicKey: string) =>
            respondWith(200, {
                data: {
                    type: "ed25519",
                    latest_version: 1,
                    keys: { "1": { public_key: publicKey } },
                },
            });

        const signer = await VaultTransitSigner.create({
            address: VAULT_ADDRESS,
            token: VAULT_TOKEN,
            keyName: "k",
            fetch: keyRead(pem(ed.publicKey.toStringDer())),
        });
        expect(signer.publicKey.toStringRaw()).toBe(ed.publicKey.toStringRaw());

        const p256 = makeTransitKey("ecdsa-p256").versions[1]!.publicKey;
        await expectCodeAsync(
            VaultTransitSigner.create({
                address: VAULT_ADDRESS,
                token: VAULT_TOKEN,
                keyName: "k",
                fetch: keyRead(p256),
            }),
            RemoteSignerErrorCodes.UnsupportedKey,
        );
    });

    it("rejects a raw public key that is not 32 bytes", async () => {
        await expectCodeAsync(
            VaultTransitSigner.create({
                address: VAULT_ADDRESS,
                token: VAULT_TOKEN,
                keyName: "k",
                fetch: respondWith(200, {
                    data: {
                        type: "ed25519",
                        latest_version: 1,
                        keys: { "1": { public_key: "AAAA" } },
                    },
                }),
            }),
            RemoteSignerErrorCodes.MalformedDer,
        );
    });

    it("wraps Vault errors and keeps the message as cause", async () => {
        const err = await expectCodeAsync(
            setup(makeTransitKey(), { token: "wrong" }).create(),
            RemoteSignerErrorCodes.BackendRequestFailed,
        );
        expect((err.cause as Error).message).toBe(
            "Vault returned 403: permission denied",
        );
    });

    it("wraps non-JSON error responses", async () => {
        const err = await expectCodeAsync(
            VaultTransitSigner.create({
                address: VAULT_ADDRESS,
                token: VAULT_TOKEN,
                keyName: "k",
                fetch: respondWith(502, "Bad Gateway"),
            }),
            RemoteSignerErrorCodes.BackendRequestFailed,
        );
        expect((err.cause as Error).message).toBe("Vault returned 502");
    });
});

describe("VaultTransitSigner.sign", () => {
    it("sends the raw body as base64 input and returns a valid signature", async () => {
        const key = makeTransitKey();
        const vault = setup(key);
        const signer = await vault.create();
        const body = randomBytes(8192);

        const sig = await signer.sign(body);

        const request = vault.requests.at(-1)!;
        expect(request.method).toBe("POST");
        expect(request.url).toBe(
            `${VAULT_ADDRESS}/v1/transit/sign/${key.name}`,
        );
        expect(request.body).toEqual({
            input: body.toString("base64"),
            key_version: 1,
        });
        expect(signer.publicKey.verify(body, sig)).toBe(true);
    });

    it("refuses to return a signature that does not verify", async () => {
        const signer = await setup(
            makeTransitKey("ed25519", { behaviour: "corrupt" }),
        ).create();
        await expectCodeAsync(
            signer.sign(randomBytes(64)),
            RemoteSignerErrorCodes.SignatureInvalid,
        );
    });

    it("skips local verification when disabled", async () => {
        const signer = await setup(
            makeTransitKey("ed25519", { behaviour: "corrupt" }),
        ).create({ verifySignatures: false });
        const body = randomBytes(64);
        expect(signer.publicKey.verify(body, await signer.sign(body))).toBe(
            false,
        );
    });

    it.each([
        ["no signature", {}],
        ["an unknown format", { signature: "not-a-vault-signature" }],
        ["another key version", { signature: `vault:v2:${"A".repeat(88)}` }],
        ["a short signature", { signature: "vault:v1:AAAA" }],
    ])("rejects a response with %s", async (_, data) => {
        const key = makeTransitKey();
        const signer = await VaultTransitSigner.create({
            address: VAULT_ADDRESS,
            token: VAULT_TOKEN,
            keyName: key.name,
            fetch: signResponse(key, data),
        });
        await expectCodeAsync(
            signer.sign(randomBytes(32)),
            RemoteSignerErrorCodes.SignatureInvalid,
        );
    });

    it("wraps sign failures", async () => {
        const key = makeTransitKey();
        const vault = createFakeVault([key]);
        let calls = 0;
        const signer = await VaultTransitSigner.create({
            address: VAULT_ADDRESS,
            token: VAULT_TOKEN,
            keyName: key.name,
            fetch: (input, init) =>
                calls++ === 0
                    ? vault.fetch(input, init)
                    : Promise.reject(new Error("connection refused")),
        });
        const err = await expectCodeAsync(
            signer.sign(randomBytes(32)),
            RemoteSignerErrorCodes.BackendRequestFailed,
        );
        expect((err.cause as Error).message).toBe("connection refused");
    });
});

describe("Hiero SDK integration (Vault transit)", () => {
    const transfer = (payer: string) =>
        new TransferTransaction()
            .addHbarTransfer(payer, Hbar.fromTinybars(-1000))
            .addHbarTransfer("0.0.1001", Hbar.fromTinybars(1000))
            .setTransactionId(TransactionId.generate(payer));

    it("signs every per-node body of a frozen transaction", async () => {
        const vault = setup(makeTransitKey());
        const signer = await vault.create();
        const network = hieroClient();

        const tx = transfer("0.0.1234").freezeWith(network);
        await tx.signWith(signer.publicKey, signer.sign);

        expect(signer.publicKey.verifyTransaction(tx)).toBe(true);
        expect(vault.requests.filter((r) => r.method === "POST")).toHaveLength(
            3,
        );
        const restored = Transaction.fromBytes(tx.toBytes());
        expect(signer.publicKey.verifyTransaction(restored)).toBe(true);
        network.close();
    });

    it("works as the client operator", async () => {
        const signer = await setup(makeTransitKey()).create();
        const network = hieroClient();
        setClientOperator(network, "0.0.1234", signer);

        const tx = transfer("0.0.1234").freezeWith(network);
        await tx.signWithOperator(network);
        expect(signer.publicKey.verifyTransaction(tx)).toBe(true);
        network.close();
    });
});
