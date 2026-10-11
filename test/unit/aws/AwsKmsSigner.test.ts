import { afterEach, describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import {
    GetPublicKeyCommand,
    KMSClient,
    SignCommand,
} from "@aws-sdk/client-kms";
import {
    AccountId,
    Client,
    FileAppendTransaction,
    Hbar,
    PrivateKey,
    Transaction,
    TransactionId,
    TransferTransaction,
} from "@hiero-ledger/sdk";
import { keccak_256 } from "@noble/hashes/sha3.js";

import { AwsKmsSigner } from "../../../src/aws/index.js";
import { setClientOperator } from "../../../src/client/index.js";
import { RemoteSignerErrorCodes } from "../../../src/errors/index.js";
import { expectCodeAsync } from "../../utils/assertions.js";
import { installFakeKms, makeKey } from "../../utils/fake-kms.js";
import type { FakeKey } from "../../utils/fake-kms.js";

const client = () =>
    new KMSClient({
        region: "eu-central-1",
        credentials: { accessKeyId: "x", secretAccessKey: "x" },
    });

/** An offline client for a three-node Hiero network. No network calls are made. */
function hieroClient(): Client {
    return Client.forNetwork({
        "127.0.0.1:50211": "0.0.3",
        "127.0.0.1:50212": "0.0.4",
        "127.0.0.1:50213": "0.0.5",
    });
}

let mock: ReturnType<typeof installFakeKms> | undefined;
afterEach(() => mock?.restore());

function setup(...keys: FakeKey[]) {
    mock = installFakeKms(keys);
    return mock;
}

describe("AwsKmsSigner.create", () => {
    it("resolves an alias to the key ARN and derives the Hiero public key", async () => {
        const key = makeKey("ECC_SECG_P256K1");
        setup(key);
        const signer = await AwsKmsSigner.create({
            keyId: key.alias,
            client: client(),
        });
        expect(signer.keyArn).toBe(key.arn);
        expect(signer.keyType).toBe("ECDSA_SECP256K1");
        const expected = PrivateKey.fromBytesECDSA(key.privateKey).publicKey;
        expect(signer.publicKey.toStringRaw()).toBe(expected.toStringRaw());
    });

    it("supports Ed25519 keys", async () => {
        const key = makeKey("ECC_NIST_EDWARDS25519");
        setup(key);
        const signer = await AwsKmsSigner.create({
            keyId: key.keyId,
            client: client(),
        });
        expect(signer.keyType).toBe("ED25519");
        const expected = PrivateKey.fromBytesED25519(key.privateKey).publicKey;
        expect(signer.publicKey.toStringRaw()).toBe(expected.toStringRaw());
    });

    it.each(["ECC_NIST_P256", "RSA_2048"] as const)(
        "rejects %s keys",
        async (spec) => {
            const key = makeKey(spec);
            setup(key);
            await expectCodeAsync(
                AwsKmsSigner.create({ keyId: key.keyId, client: client() }),
                RemoteSignerErrorCodes.UnsupportedKey,
            );
        },
    );

    it("rejects keys that are not configured for signing", async () => {
        const key = makeKey("ECC_SECG_P256K1", { keyUsage: "ENCRYPT_DECRYPT" });
        setup(key);
        await expectCodeAsync(
            AwsKmsSigner.create({ keyId: key.keyId, client: client() }),
            RemoteSignerErrorCodes.KeyNotUsable,
        );
    });

    it("wraps KMS failures and keeps the original error as cause", async () => {
        setup();
        const err = await expectCodeAsync(
            AwsKmsSigner.create({ keyId: "alias/missing", client: client() }),
            RemoteSignerErrorCodes.BackendRequestFailed,
        );
        expect((err.cause as Error).name).toBe("NotFoundException");
    });
});

describe("AwsKmsSigner.sign (ECDSA secp256k1)", () => {
    it("asks KMS to sign the Keccak-256 digest, not the raw message", async () => {
        const key = makeKey("ECC_SECG_P256K1");
        const m = setup(key);
        const signer = await AwsKmsSigner.create({
            keyId: key.alias,
            client: client(),
        });
        const body = randomBytes(300);

        const sig = await signer.sign(body);

        const call = m.commandCalls(SignCommand)[0]!.args[0].input;
        expect(call.KeyId).toBe(key.arn);
        expect(call.MessageType).toBe("DIGEST");
        expect(call.SigningAlgorithm).toBe("ECDSA_SHA_256");
        expect(new Uint8Array(call.Message as Uint8Array)).toEqual(
            keccak_256(body),
        );
        expect(sig.length).toBe(64);
        expect(signer.publicKey.verify(body, sig)).toBe(true);
    });

    it("produces SDK-valid signatures even when KMS always returns high-S", async () => {
        const key = makeKey("ECC_SECG_P256K1", { behaviour: "always-high-s" });
        setup(key);
        const signer = await AwsKmsSigner.create({
            keyId: key.keyId,
            client: client(),
        });
        for (let i = 0; i < 25; i++) {
            const body = randomBytes(50 + i);
            expect(signer.publicKey.verify(body, await signer.sign(body))).toBe(
                true,
            );
        }
    });

    it("refuses to return a signature that does not verify", async () => {
        const key = makeKey("ECC_SECG_P256K1", { behaviour: "corrupt" });
        setup(key);
        const signer = await AwsKmsSigner.create({
            keyId: key.keyId,
            client: client(),
        });
        await expectCodeAsync(
            signer.sign(randomBytes(64)),
            RemoteSignerErrorCodes.SignatureInvalid,
        );
    });

    it("skips local verification when disabled", async () => {
        const key = makeKey("ECC_SECG_P256K1", { behaviour: "corrupt" });
        setup(key);
        const signer = await AwsKmsSigner.create({
            keyId: key.keyId,
            client: client(),
            verifySignatures: false,
        });
        const body = randomBytes(64);
        const sig = await signer.sign(body);
        expect(signer.publicKey.verify(body, sig)).toBe(false);
    });
});

describe("AwsKmsSigner.sign (Ed25519)", () => {
    it("asks KMS to sign the raw message with pure Ed25519", async () => {
        const key = makeKey("ECC_NIST_EDWARDS25519");
        const m = setup(key);
        const signer = await AwsKmsSigner.create({
            keyId: key.keyId,
            client: client(),
        });
        const body = randomBytes(500);

        const sig = await signer.sign(body);

        const call = m.commandCalls(SignCommand)[0]!.args[0].input;
        expect(call.MessageType).toBe("RAW");
        expect(call.SigningAlgorithm).toBe("ED25519_SHA_512");
        expect(signer.publicKey.verify(body, sig)).toBe(true);
    });

    it("rejects bodies over the KMS 4096-byte limit without calling KMS", async () => {
        const key = makeKey("ECC_NIST_EDWARDS25519");
        const m = setup(key);
        const signer = await AwsKmsSigner.create({
            keyId: key.keyId,
            client: client(),
        });
        await expectCodeAsync(
            signer.sign(randomBytes(4097)),
            RemoteSignerErrorCodes.MessageRejected,
        );
        expect(m.commandCalls(SignCommand)).toHaveLength(0);
    });
});

describe.each(["ECC_SECG_P256K1", "ECC_NIST_EDWARDS25519"] as const)(
    "Hiero SDK integration (%s)",
    (spec) => {
        const transfer = (payer: string) =>
            new TransferTransaction()
                .addHbarTransfer(payer, Hbar.fromTinybars(-1000))
                .addHbarTransfer("0.0.1001", Hbar.fromTinybars(1000))
                .setTransactionId(TransactionId.generate(payer));

        it("signs every per-node body of a frozen transaction", async () => {
            const key = makeKey(spec);
            const m = setup(key);
            const signer = await AwsKmsSigner.create({
                keyId: key.alias,
                client: client(),
            });
            const network = hieroClient();

            const tx = transfer("0.0.1234").freezeWith(network);
            await tx.signWith(signer.publicKey, signer.sign);

            expect(signer.publicKey.verifyTransaction(tx)).toBe(true);
            // One KMS call per node account ID; see README on request volume.
            expect(m.commandCalls(SignCommand)).toHaveLength(3);

            // Signatures survive serialization, as they must for offline signing.
            const restored = Transaction.fromBytes(tx.toBytes());
            expect(signer.publicKey.verifyTransaction(restored)).toBe(true);
            network.close();
        });

        it("works as the client operator", async () => {
            const key = makeKey(spec);
            setup(key);
            const signer = await AwsKmsSigner.create({
                keyId: key.keyId,
                client: client(),
            });
            const network = hieroClient();
            setClientOperator(
                network,
                AccountId.fromString("0.0.1234"),
                signer,
            );

            expect(network.operatorPublicKey?.toStringRaw()).toBe(
                signer.publicKey.toStringRaw(),
            );

            const tx = transfer("0.0.1234").freezeWith(network);
            await tx.signWithOperator(network);
            expect(signer.publicKey.verifyTransaction(tx)).toBe(true);
            network.close();
        });

        it("combines with local keys for multi-signature transactions", async () => {
            const key = makeKey(spec);
            setup(key);
            const signer = await AwsKmsSigner.create({
                keyId: key.keyId,
                client: client(),
            });
            const local = PrivateKey.generateED25519();
            const network = hieroClient();

            const tx = transfer("0.0.1234").freezeWith(network);
            await tx.sign(local);
            await tx.signWith(signer.publicKey, signer.sign);

            expect(local.publicKey.verifyTransaction(tx)).toBe(true);
            expect(signer.publicKey.verifyTransaction(tx)).toBe(true);
            network.close();
        });
    },
);

it("reports the Ed25519 size limit clearly for large file appends", async () => {
    const key = makeKey("ECC_NIST_EDWARDS25519");
    setup(key);
    const signer = await AwsKmsSigner.create({
        keyId: key.keyId,
        client: client(),
    });
    const network = hieroClient();

    // The SDK's default 4096-byte chunk plus body headers exceeds the KMS limit.
    const tx = new FileAppendTransaction()
        .setFileId("0.0.5005")
        .setContents(new Uint8Array(4096))
        .setNodeAccountIds([AccountId.fromString("0.0.3")])
        .setTransactionId(TransactionId.generate("0.0.1234"))
        .freezeWith(network);

    await expectCodeAsync(
        tx.signWith(signer.publicKey, signer.sign),
        RemoteSignerErrorCodes.MessageRejected,
    );
    network.close();
});

it("never asks KMS for anything but GetPublicKey and Sign", async () => {
    const key = makeKey("ECC_SECG_P256K1");
    const m = setup(key);
    const signer = await AwsKmsSigner.create({
        keyId: key.keyId,
        client: client(),
    });
    await signer.sign(randomBytes(10));
    expect(m.commandCalls(GetPublicKeyCommand)).toHaveLength(1);
    expect(m.calls()).toHaveLength(2);
});

describe("AwsKmsSigner defensive checks", () => {
    it("creates its own KMS client from clientConfig when none is given", async () => {
        const key = makeKey("ECC_SECG_P256K1");
        setup(key);
        const signer = await AwsKmsSigner.create({
            keyId: key.keyId,
            clientConfig: {
                region: "eu-central-1",
                credentials: { accessKeyId: "x", secretAccessKey: "x" },
            },
        });
        expect(signer.keyArn).toBe(key.arn);
    });

    it("passes grant tokens through to KMS", async () => {
        const key = makeKey("ECC_SECG_P256K1");
        const m = setup(key);
        const signer = await AwsKmsSigner.create({
            keyId: key.keyId,
            client: client(),
            grantTokens: ["grant-1"],
        });
        await signer.sign(randomBytes(10));
        expect(
            m.commandCalls(GetPublicKeyCommand)[0]!.args[0].input.GrantTokens,
        ).toEqual(["grant-1"]);
        expect(
            m.commandCalls(SignCommand)[0]!.args[0].input.GrantTokens,
        ).toEqual(["grant-1"]);
    });

    it("rejects a response without a key spec or key usage", async () => {
        setup().on(GetPublicKeyCommand).resolves({});
        await expectCodeAsync(
            AwsKmsSigner.create({ keyId: "k", client: client() }),
            RemoteSignerErrorCodes.UnsupportedKey,
        );

        setup()
            .on(GetPublicKeyCommand)
            .resolves({ KeySpec: "ECC_SECG_P256K1" });
        await expectCodeAsync(
            AwsKmsSigner.create({ keyId: "k", client: client() }),
            RemoteSignerErrorCodes.KeyNotUsable,
        );
    });

    it("rejects keys that do not offer the required algorithm", async () => {
        const key = makeKey("ECC_SECG_P256K1");
        setup()
            .on(GetPublicKeyCommand)
            .resolves({
                KeyId: key.arn,
                KeySpec: "ECC_SECG_P256K1",
                KeyUsage: "SIGN_VERIFY",
                SigningAlgorithms: ["ECDSA_SHA_384"],
                PublicKey: key.spki,
            });
        await expectCodeAsync(
            AwsKmsSigner.create({ keyId: key.keyId, client: client() }),
            RemoteSignerErrorCodes.KeyNotUsable,
        );
    });

    it("rejects a response without a public key", async () => {
        setup().on(GetPublicKeyCommand).resolves({
            KeySpec: "ECC_SECG_P256K1",
            KeyUsage: "SIGN_VERIFY",
        });
        await expectCodeAsync(
            AwsKmsSigner.create({ keyId: "k", client: client() }),
            RemoteSignerErrorCodes.MalformedDer,
        );
    });

    it("rejects a public key that does not match the reported key spec", async () => {
        const ed25519 = makeKey("ECC_NIST_EDWARDS25519");
        setup().on(GetPublicKeyCommand).resolves({
            KeySpec: "ECC_SECG_P256K1",
            KeyUsage: "SIGN_VERIFY",
            PublicKey: ed25519.spki,
        });
        await expectCodeAsync(
            AwsKmsSigner.create({ keyId: "k", client: client() }),
            RemoteSignerErrorCodes.UnsupportedKey,
        );
    });

    it("falls back to the requested key ID when KMS omits the ARN", async () => {
        const key = makeKey("ECC_SECG_P256K1");
        setup().on(GetPublicKeyCommand).resolves({
            KeySpec: "ECC_SECG_P256K1",
            KeyUsage: "SIGN_VERIFY",
            PublicKey: key.spki,
        });
        const signer = await AwsKmsSigner.create({
            keyId: key.alias,
            client: client(),
        });
        expect(signer.keyArn).toBe(key.alias);
    });

    it("wraps Sign failures and keeps the original error as cause", async () => {
        const key = makeKey("ECC_SECG_P256K1");
        const m = setup(key);
        const signer = await AwsKmsSigner.create({
            keyId: key.keyId,
            client: client(),
        });
        m.on(SignCommand).rejects(new Error("throttled"));
        const err = await expectCodeAsync(
            signer.sign(randomBytes(10)),
            RemoteSignerErrorCodes.BackendRequestFailed,
        );
        expect((err.cause as Error).message).toBe("throttled");
    });

    it("rejects a Sign response without a signature", async () => {
        const key = makeKey("ECC_SECG_P256K1");
        const m = setup(key);
        const signer = await AwsKmsSigner.create({
            keyId: key.keyId,
            client: client(),
        });
        m.on(SignCommand).resolves({});
        await expectCodeAsync(
            signer.sign(randomBytes(10)),
            RemoteSignerErrorCodes.SignatureInvalid,
        );
    });

    it("rejects an Ed25519 signature that is not 64 bytes", async () => {
        const key = makeKey("ECC_NIST_EDWARDS25519");
        const m = setup(key);
        const signer = await AwsKmsSigner.create({
            keyId: key.keyId,
            client: client(),
        });
        m.on(SignCommand).resolves({ Signature: new Uint8Array(63) });
        await expectCodeAsync(
            signer.sign(randomBytes(10)),
            RemoteSignerErrorCodes.SignatureInvalid,
        );
    });
});
