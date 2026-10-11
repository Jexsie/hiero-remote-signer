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

import { setClientOperator } from "../../../src/client/index.js";
import { RemoteSignerErrorCodes } from "../../../src/errors/index.js";
import { crc32c } from "../../../src/gcp/crc32c.js";
import { GcpKmsSigner } from "../../../src/gcp/index.js";
import type { GcpKmsClient } from "../../../src/gcp/index.js";
import { expectCodeAsync } from "../../utils/assertions.js";
import { createFakeGcpKms, makeGcpKey } from "../../utils/fake-gcp-kms.js";
import type { FakeGcpKey, GcpAlgorithm } from "../../utils/fake-gcp-kms.js";

function setup(key: FakeGcpKey) {
    const kms = createFakeGcpKms([key]);
    const create = (verifySignatures?: boolean) =>
        GcpKmsSigner.create({
            keyVersionName: key.name,
            client: kms.client,
            verifySignatures,
        });
    return { ...kms, create };
}

/** A client whose getPublicKey returns `response` verbatim. */
function publicKeyClient(response: object): GcpKmsClient {
    return {
        getPublicKey: () => Promise.resolve([response]),
    } as unknown as GcpKmsClient;
}

/** A client that serves `key` but answers asymmetricSign with `response`. */
function signResponseClient(key: FakeGcpKey, response: object): GcpKmsClient {
    const { fake } = createFakeGcpKms([key]);
    return {
        getPublicKey: fake.getPublicKey,
        asymmetricSign: () => Promise.resolve([response]),
    } as unknown as GcpKmsClient;
}

/** An offline client for a three-node Hiero network. No network calls are made. */
function hieroClient(): Client {
    return Client.forNetwork({
        "127.0.0.1:50211": "0.0.3",
        "127.0.0.1:50212": "0.0.4",
        "127.0.0.1:50213": "0.0.5",
    });
}

describe("GcpKmsSigner.create", () => {
    it("derives the Hiero public key for a secp256k1 key", async () => {
        const key = makeGcpKey("EC_SIGN_SECP256K1_SHA256");
        const signer = await setup(key).create();
        expect(signer.keyType).toBe("ECDSA_SECP256K1");
        expect(signer.keyVersionName).toBe(key.name);
        expect(signer.publicKey.toStringRaw()).toBe(
            PrivateKey.fromBytesECDSA(key.privateKey).publicKey.toStringRaw(),
        );
    });

    it("derives the Hiero public key for an Ed25519 key", async () => {
        const key = makeGcpKey("EC_SIGN_ED25519");
        const signer = await setup(key).create();
        expect(signer.keyType).toBe("ED25519");
        expect(signer.publicKey.toStringRaw()).toBe(
            PrivateKey.fromBytesED25519(key.privateKey).publicKey.toStringRaw(),
        );
    });

    it.each(["EC_SIGN_P256_SHA256", "RSA_SIGN_PSS_2048_SHA256"] as const)(
        "rejects %s keys",
        async (algorithm: GcpAlgorithm) => {
            await expectCodeAsync(
                setup(makeGcpKey(algorithm)).create(),
                RemoteSignerErrorCodes.UnsupportedKey,
            );
        },
    );

    it("wraps Cloud KMS failures and keeps the original error as cause", async () => {
        const { client } = createFakeGcpKms([]);
        const err = await expectCodeAsync(
            GcpKmsSigner.create({ keyVersionName: "missing", client }),
            RemoteSignerErrorCodes.BackendRequestFailed,
        );
        expect((err.cause as { code: number }).code).toBe(5);
    });

    it("rejects a response without a public key", async () => {
        await expectCodeAsync(
            GcpKmsSigner.create({
                keyVersionName: "k",
                client: publicKeyClient({
                    name: "k",
                    algorithm: "EC_SIGN_ED25519",
                }),
            }),
            RemoteSignerErrorCodes.MalformedDer,
        );
    });

    it("rejects a response without an algorithm", async () => {
        await expectCodeAsync(
            GcpKmsSigner.create({
                keyVersionName: "k",
                client: publicKeyClient({ name: "k" }),
            }),
            RemoteSignerErrorCodes.UnsupportedKey,
        );
    });

    it("rejects a public key whose CRC32C does not match", async () => {
        const key = makeGcpKey("EC_SIGN_ED25519");
        await expectCodeAsync(
            GcpKmsSigner.create({
                keyVersionName: key.name,
                client: publicKeyClient({
                    name: key.name,
                    algorithm: key.algorithm,
                    pem: key.pem,
                    pemCrc32c: { value: "1" },
                }),
            }),
            RemoteSignerErrorCodes.IntegrityCheckFailed,
        );
    });

    it("rejects a public key for a different key version", async () => {
        const key = makeGcpKey("EC_SIGN_ED25519");
        await expectCodeAsync(
            GcpKmsSigner.create({
                keyVersionName: key.name,
                client: publicKeyClient({
                    name: `${key.name}0`,
                    algorithm: key.algorithm,
                    pem: key.pem,
                }),
            }),
            RemoteSignerErrorCodes.IntegrityCheckFailed,
        );
    });

    it("rejects a public key that does not match the reported algorithm", async () => {
        const ed25519 = makeGcpKey("EC_SIGN_ED25519");
        await expectCodeAsync(
            GcpKmsSigner.create({
                keyVersionName: "k",
                client: publicKeyClient({
                    algorithm: "EC_SIGN_SECP256K1_SHA256",
                    pem: ed25519.pem,
                }),
            }),
            RemoteSignerErrorCodes.UnsupportedKey,
        );
    });
});

describe("GcpKmsSigner.sign (ECDSA secp256k1)", () => {
    it("sends the Keccak-256 digest with its CRC32C, not the raw message", async () => {
        const key = makeGcpKey("EC_SIGN_SECP256K1_SHA256");
        const kms = setup(key);
        const signer = await kms.create();
        const body = randomBytes(300);

        const sig = await signer.sign(body);

        const request = kms.fake.calls.find(
            (c) => c.method === "asymmetricSign",
        )!.request;
        const digest = keccak_256(body);
        expect(request.name).toBe(key.name);
        expect(request.data).toBeUndefined();
        expect(request.digest?.sha256).toEqual(digest);
        expect(request.digestCrc32c?.value).toBe(crc32c(digest));
        expect(sig.length).toBe(64);
        expect(signer.publicKey.verify(body, sig)).toBe(true);
    });

    it("produces SDK-valid signatures even when Cloud KMS returns high-S", async () => {
        const key = makeGcpKey("EC_SIGN_SECP256K1_SHA256", {
            behaviour: "always-high-s",
        });
        const signer = await setup(key).create();
        for (let i = 0; i < 25; i++) {
            const body = randomBytes(50 + i);
            expect(signer.publicKey.verify(body, await signer.sign(body))).toBe(
                true,
            );
        }
    });

    it("refuses to return a signature that does not verify", async () => {
        const key = makeGcpKey("EC_SIGN_SECP256K1_SHA256", {
            behaviour: "corrupt",
        });
        const signer = await setup(key).create();
        await expectCodeAsync(
            signer.sign(randomBytes(64)),
            RemoteSignerErrorCodes.SignatureInvalid,
        );
    });

    it("skips local verification when disabled", async () => {
        const key = makeGcpKey("EC_SIGN_SECP256K1_SHA256", {
            behaviour: "corrupt",
        });
        const signer = await setup(key).create(false);
        const body = randomBytes(64);
        expect(signer.publicKey.verify(body, await signer.sign(body))).toBe(
            false,
        );
    });
});

describe("GcpKmsSigner.sign (Ed25519)", () => {
    it("sends the raw message with its CRC32C as data", async () => {
        const key = makeGcpKey("EC_SIGN_ED25519");
        const kms = setup(key);
        const signer = await kms.create();
        const body = randomBytes(8192);

        const sig = await signer.sign(body);

        const request = kms.fake.calls.find(
            (c) => c.method === "asymmetricSign",
        )!.request;
        expect(request.digest).toBeUndefined();
        expect(request.data).toEqual(body);
        expect(request.dataCrc32c?.value).toBe(crc32c(body));
        expect(signer.publicKey.verify(body, sig)).toBe(true);
    });

    it("accepts a base64 signature", async () => {
        const key = makeGcpKey("EC_SIGN_ED25519");
        const local = PrivateKey.fromBytesED25519(key.privateKey);
        const body = randomBytes(32);
        const signature = local.sign(body);
        const signer = await GcpKmsSigner.create({
            keyVersionName: key.name,
            client: signResponseClient(key, {
                name: key.name,
                signature: Buffer.from(signature).toString("base64"),
                verifiedDataCrc32c: true,
            }),
        });
        expect(await signer.sign(body)).toEqual(signature);
    });

    it("rejects a signature that is not 64 bytes", async () => {
        const key = makeGcpKey("EC_SIGN_ED25519");
        const signer = await GcpKmsSigner.create({
            keyVersionName: key.name,
            client: signResponseClient(key, {
                name: key.name,
                signature: new Uint8Array(63),
                verifiedDataCrc32c: true,
            }),
        });
        await expectCodeAsync(
            signer.sign(randomBytes(32)),
            RemoteSignerErrorCodes.SignatureInvalid,
        );
    });
});

describe("GcpKmsSigner integrity checks", () => {
    it.each(["signature-crc", "unverified-request", "wrong-name"] as const)(
        "discards a response with fault %s",
        async (fault) => {
            const key = makeGcpKey("EC_SIGN_SECP256K1_SHA256", { fault });
            const signer = await setup(key).create();
            await expectCodeAsync(
                signer.sign(randomBytes(32)),
                RemoteSignerErrorCodes.IntegrityCheckFailed,
            );
        },
    );

    it("wraps AsymmetricSign failures and keeps the original error as cause", async () => {
        const key = makeGcpKey("EC_SIGN_ED25519");
        const { fake } = createFakeGcpKms([key]);
        const signer = await GcpKmsSigner.create({
            keyVersionName: key.name,
            client: {
                getPublicKey: fake.getPublicKey,
                asymmetricSign: () => Promise.reject(new Error("unavailable")),
            } as unknown as GcpKmsClient,
        });
        const err = await expectCodeAsync(
            signer.sign(randomBytes(32)),
            RemoteSignerErrorCodes.BackendRequestFailed,
        );
        expect((err.cause as Error).message).toBe("unavailable");
    });

    it("rejects a response without a signature", async () => {
        const key = makeGcpKey("EC_SIGN_ED25519");
        const signer = await GcpKmsSigner.create({
            keyVersionName: key.name,
            client: signResponseClient(key, { name: key.name }),
        });
        await expectCodeAsync(
            signer.sign(randomBytes(32)),
            RemoteSignerErrorCodes.SignatureInvalid,
        );
    });
});

describe.each(["EC_SIGN_SECP256K1_SHA256", "EC_SIGN_ED25519"] as const)(
    "Hiero SDK integration (%s)",
    (algorithm) => {
        const transfer = (payer: string) =>
            new TransferTransaction()
                .addHbarTransfer(payer, Hbar.fromTinybars(-1000))
                .addHbarTransfer("0.0.1001", Hbar.fromTinybars(1000))
                .setTransactionId(TransactionId.generate(payer));

        it("signs every per-node body of a frozen transaction", async () => {
            const key = makeGcpKey(algorithm);
            const kms = setup(key);
            const signer = await kms.create();
            const network = hieroClient();

            const tx = transfer("0.0.1234").freezeWith(network);
            await tx.signWith(signer.publicKey, signer.sign);

            expect(signer.publicKey.verifyTransaction(tx)).toBe(true);
            expect(
                kms.fake.calls.filter((c) => c.method === "asymmetricSign"),
            ).toHaveLength(3);
            const restored = Transaction.fromBytes(tx.toBytes());
            expect(signer.publicKey.verifyTransaction(restored)).toBe(true);
            network.close();
        });

        it("works as the client operator", async () => {
            const key = makeGcpKey(algorithm);
            const signer = await setup(key).create();
            const network = hieroClient();
            setClientOperator(network, "0.0.1234", signer);

            const tx = transfer("0.0.1234").freezeWith(network);
            await tx.signWithOperator(network);
            expect(signer.publicKey.verifyTransaction(tx)).toBe(true);
            network.close();
        });
    },
);
