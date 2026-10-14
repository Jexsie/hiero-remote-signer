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
import { keccak_256 } from "@noble/hashes/sha3.js";

import { AzureKeyVaultSigner } from "../../../src/azure/index.js";
import type {
    AzureCryptographyClient,
    AzureKeyClient,
} from "../../../src/azure/index.js";
import { RemoteSignerErrorCodes } from "../../../src/errors/index.js";
import { expectCodeAsync } from "../../utils/assertions.js";
import {
    createFakeKeyVault,
    keyIdOf,
    makeAzureKey,
    VAULT_URL,
} from "../../utils/fake-azure-key-vault.js";
import type { FakeAzureKey } from "../../utils/fake-azure-key-vault.js";

function setup(key: FakeAzureKey) {
    const vault = createFakeKeyVault([key]);
    const create = (verifySignatures?: boolean, keyId = keyIdOf(key)) =>
        AzureKeyVaultSigner.create({
            keyId,
            keyClient: vault.keyClient,
            cryptographyClient: vault.cryptographyClientFor(keyIdOf(key)),
            verifySignatures,
        });
    return { ...vault, create };
}

/** A key client whose getKey returns `key` verbatim. */
function keyClientReturning(key: object): AzureKeyClient {
    return { getKey: () => Promise.resolve(key) } as unknown as AzureKeyClient;
}

/** A cryptography client whose sign resolves to `result`. */
function signReturning(result: Uint8Array): AzureCryptographyClient {
    return {
        sign: () => Promise.resolve({ result, algorithm: "ES256K" }),
    };
}

function hieroClient(): Client {
    return Client.forNetwork({
        "127.0.0.1:50211": "0.0.3",
        "127.0.0.1:50212": "0.0.4",
        "127.0.0.1:50213": "0.0.5",
    });
}

describe("AzureKeyVaultSigner.create", () => {
    it("derives the Hiero public key from the JWK coordinates", async () => {
        const key = makeAzureKey();
        const signer = await setup(key).create();
        expect(signer.keyType).toBe("ECDSA_SECP256K1");
        expect(signer.keyId).toBe(keyIdOf(key));
        expect(signer.publicKey.toStringRaw()).toBe(
            PrivateKey.fromBytesECDSA(key.privateKey).publicKey.toStringRaw(),
        );
    });

    it("pins the latest version when the key ID has none", async () => {
        const key = makeAzureKey();
        const signer = await setup(key).create(
            true,
            `${VAULT_URL}/keys/${key.name}`,
        );
        expect(signer.keyId).toBe(keyIdOf(key));
    });

    it("rejects keys on other curves", async () => {
        await expectCodeAsync(
            setup(makeAzureKey("P-256")).create(),
            RemoteSignerErrorCodes.UnsupportedKey,
        );
    });

    it("rejects a response without key material", async () => {
        await expectCodeAsync(
            AzureKeyVaultSigner.create({
                keyId: `${VAULT_URL}/keys/k/v`,
                keyClient: keyClientReturning({ properties: {} }),
                cryptographyClient: signReturning(new Uint8Array(64)),
            }),
            RemoteSignerErrorCodes.UnsupportedKey,
        );
    });

    it("rejects disabled keys", async () => {
        await expectCodeAsync(
            setup(makeAzureKey("P-256K", { enabled: false })).create(),
            RemoteSignerErrorCodes.KeyNotUsable,
        );
    });

    it("rejects keys that do not permit signing", async () => {
        await expectCodeAsync(
            setup(makeAzureKey("P-256K", { keyOps: ["verify"] })).create(),
            RemoteSignerErrorCodes.KeyNotUsable,
        );
    });

    it("rejects coordinates of the wrong length", async () => {
        await expectCodeAsync(
            setup(makeAzureKey("P-256K", { x: new Uint8Array(31) })).create(),
            RemoteSignerErrorCodes.MalformedDer,
        );
    });

    it("rejects a point that is not on secp256k1", async () => {
        const key = makeAzureKey("P-256K", { y: new Uint8Array(32).fill(7) });
        await expectCodeAsync(
            setup(key).create(),
            RemoteSignerErrorCodes.MalformedDer,
        );
    });

    it("wraps Key Vault failures and keeps the original error as cause", async () => {
        const vault = createFakeKeyVault([]);
        const err = await expectCodeAsync(
            AzureKeyVaultSigner.create({
                keyId: `${VAULT_URL}/keys/missing/v1`,
                keyClient: vault.keyClient,
                cryptographyClient: vault.cryptographyClientFor("x"),
            }),
            RemoteSignerErrorCodes.BackendRequestFailed,
        );
        expect((err.cause as { statusCode: number }).statusCode).toBe(404);
    });

    it("creates the cryptography client from the credential", async () => {
        const key = makeAzureKey();
        const vault = createFakeKeyVault([key]);
        const signer = await AzureKeyVaultSigner.create({
            keyId: keyIdOf(key),
            keyClient: vault.keyClient,
            credential: {
                getToken: () => Promise.resolve(null),
            },
        });
        expect(signer.keyId).toBe(keyIdOf(key));
    });

    it("requires a credential when a client is missing", async () => {
        const vault = createFakeKeyVault([makeAzureKey()]);
        await expect(
            AzureKeyVaultSigner.create({
                keyId: `${VAULT_URL}/keys/k/v`,
                cryptographyClient: vault.cryptographyClientFor("x"),
            }),
        ).rejects.toThrow(TypeError);
    });
});

describe("AzureKeyVaultSigner.sign", () => {
    it("asks Key Vault to sign the Keccak-256 digest with ES256K", async () => {
        const key = makeAzureKey();
        const vault = setup(key);
        const signer = await vault.create();
        const body = randomBytes(300);

        const sig = await signer.sign(body);

        expect(vault.signCalls).toHaveLength(1);
        expect(vault.signCalls[0]!.algorithm).toBe("ES256K");
        expect(vault.signCalls[0]!.digest).toEqual(keccak_256(body));
        expect(sig.length).toBe(64);
        expect(signer.publicKey.verify(body, sig)).toBe(true);
    });

    it.each(["jws", "der"] as const)(
        "normalizes high-S signatures in %s form",
        async (format) => {
            const key = makeAzureKey("P-256K", {
                behaviour: "always-high-s",
                format,
            });
            const signer = await setup(key).create();
            for (let i = 0; i < 25; i++) {
                const body = randomBytes(50 + i);
                expect(
                    signer.publicKey.verify(body, await signer.sign(body)),
                ).toBe(true);
            }
        },
    );

    it("refuses to return a signature that does not verify", async () => {
        const key = makeAzureKey("P-256K", { behaviour: "corrupt" });
        const signer = await setup(key).create();
        await expectCodeAsync(
            signer.sign(randomBytes(64)),
            RemoteSignerErrorCodes.SignatureInvalid,
        );
    });

    it("skips local verification when disabled", async () => {
        const key = makeAzureKey("P-256K", { behaviour: "corrupt" });
        const signer = await setup(key).create(false);
        const body = randomBytes(64);
        expect(signer.publicKey.verify(body, await signer.sign(body))).toBe(
            false,
        );
    });

    it("rejects an empty signature", async () => {
        const key = makeAzureKey();
        const vault = createFakeKeyVault([key]);
        const signer = await AzureKeyVaultSigner.create({
            keyId: keyIdOf(key),
            keyClient: vault.keyClient,
            cryptographyClient: signReturning(new Uint8Array()),
        });
        await expectCodeAsync(
            signer.sign(randomBytes(32)),
            RemoteSignerErrorCodes.SignatureInvalid,
        );
    });

    it("wraps sign failures and keeps the original error as cause", async () => {
        const key = makeAzureKey();
        const vault = createFakeKeyVault([key]);
        const signer = await AzureKeyVaultSigner.create({
            keyId: keyIdOf(key),
            keyClient: vault.keyClient,
            cryptographyClient: {
                sign: () => Promise.reject(new Error("throttled")),
            },
        });
        const err = await expectCodeAsync(
            signer.sign(randomBytes(32)),
            RemoteSignerErrorCodes.BackendRequestFailed,
        );
        expect((err.cause as Error).message).toBe("throttled");
    });
});

describe("Hiero SDK integration (Azure Key Vault)", () => {
    const transfer = (payer: string) =>
        new TransferTransaction()
            .addHbarTransfer(payer, Hbar.fromTinybars(-1000))
            .addHbarTransfer("0.0.1001", Hbar.fromTinybars(1000))
            .setTransactionId(TransactionId.generate(payer));

    it("signs every per-node body of a frozen transaction", async () => {
        const key = makeAzureKey();
        const vault = setup(key);
        const signer = await vault.create();
        const network = hieroClient();

        const tx = transfer("0.0.1234").freezeWith(network);
        await tx.signWith(signer.publicKey, signer.sign);

        expect(signer.publicKey.verifyTransaction(tx)).toBe(true);
        expect(vault.signCalls).toHaveLength(3);
        const restored = Transaction.fromBytes(tx.toBytes());
        expect(signer.publicKey.verifyTransaction(restored)).toBe(true);
        network.close();
    });

    it("works as the client operator", async () => {
        const key = makeAzureKey();
        const signer = await setup(key).create();
        const network = hieroClient();
        signer.setClientOperator(network, "0.0.1234");

        const tx = transfer("0.0.1234").freezeWith(network);
        await tx.signWithOperator(network);
        expect(signer.publicKey.verifyTransaction(tx)).toBe(true);
        network.close();
    });
});
