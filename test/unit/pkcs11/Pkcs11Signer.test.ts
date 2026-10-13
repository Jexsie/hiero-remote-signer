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
import {
    Pkcs11Constants as C,
    Pkcs11Signer,
} from "../../../src/pkcs11/index.js";
import type { Pkcs11SignerOptions } from "../../../src/pkcs11/index.js";
import { expectCodeAsync } from "../../utils/assertions.js";
import { createFakePkcs11, makePkcs11Key } from "../../utils/fake-pkcs11.js";
import type { FakePkcs11Key } from "../../utils/fake-pkcs11.js";

function setup(keys: FakePkcs11Key[]) {
    const fake = createFakePkcs11(keys);
    const create = (options: Partial<Pkcs11SignerOptions> = {}) =>
        Pkcs11Signer.create({
            pkcs11: fake.pkcs11,
            tokenLabel: "hiero",
            pin: "1234",
            keyLabel: keys[0]?.label,
            ...options,
        });
    return { ...fake, create };
}

function hieroClient(): Client {
    return Client.forNetwork({
        "127.0.0.1:50211": "0.0.3",
        "127.0.0.1:50212": "0.0.4",
        "127.0.0.1:50213": "0.0.5",
    });
}

describe("Pkcs11Signer.create", () => {
    it("loads a secp256k1 key pair by label", async () => {
        const key = makePkcs11Key("secp256k1");
        const signer = await setup([key]).create();
        expect(signer.keyType).toBe("ECDSA_SECP256K1");
        expect(signer.publicKey.toStringRaw()).toBe(
            PrivateKey.fromBytesECDSA(key.privateKey).publicKey.toStringRaw(),
        );
        await signer.close();
    });

    it("loads an Ed25519 key pair by ID", async () => {
        const key = makePkcs11Key("ed25519");
        const signer = await setup([key]).create({
            keyLabel: undefined,
            keyId: key.id,
        });
        expect(signer.keyType).toBe("ED25519");
        expect(signer.publicKey.toStringRaw()).toBe(
            PrivateKey.fromBytesED25519(key.privateKey).publicKey.toStringRaw(),
        );
        await signer.close();
    });

    it.each([
        ["the edwards25519 curve name", { paramsStyle: "printable" }],
        ["a raw EC point", { pointStyle: "raw" }],
    ] as const)("accepts Ed25519 keys with %s", async (_, overrides) => {
        const key = makePkcs11Key("ed25519", overrides);
        const signer = await setup([key]).create();
        expect(signer.keyType).toBe("ED25519");
        await signer.close();
    });

    it("accepts a raw uncompressed secp256k1 point", async () => {
        const key = makePkcs11Key("secp256k1", { pointStyle: "raw" });
        const signer = await setup([key]).create();
        expect(signer.keyType).toBe("ECDSA_SECP256K1");
        await signer.close();
    });

    it("rejects keys on other curves and closes the session", async () => {
        const fake = setup([makePkcs11Key("p256")]);
        await expectCodeAsync(
            fake.create(),
            RemoteSignerErrorCodes.UnsupportedKey,
        );
        expect(fake.module.openSessions).toBe(0);
    });

    it("rejects private keys without CKA_SIGN", async () => {
        await expectCodeAsync(
            setup([makePkcs11Key("secp256k1", { canSign: false })]).create(),
            RemoteSignerErrorCodes.KeyNotUsable,
        );
    });

    it("rejects an ambiguous label", async () => {
        const a = makePkcs11Key("secp256k1", { label: "same" });
        const b = makePkcs11Key("ed25519", { label: "same" });
        await expectCodeAsync(
            setup([a, b]).create(),
            RemoteSignerErrorCodes.KeyNotUsable,
        );
    });

    it("reports a missing key", async () => {
        await expectCodeAsync(
            setup([makePkcs11Key("secp256k1")]).create({ keyLabel: "nope" }),
            RemoteSignerErrorCodes.BackendRequestFailed,
        );
    });

    it("reports a missing token", async () => {
        await expectCodeAsync(
            setup([makePkcs11Key("secp256k1")]).create({ tokenLabel: "nope" }),
            RemoteSignerErrorCodes.BackendRequestFailed,
        );
    });

    it("reports a wrong PIN and keeps the PKCS#11 error as cause", async () => {
        const fake = setup([makePkcs11Key("secp256k1")]);
        const err = await expectCodeAsync(
            fake.create({ pin: "0000" }),
            RemoteSignerErrorCodes.BackendRequestFailed,
        );
        expect((err.cause as { code: number }).code).toBe(0xa0);
        expect(fake.module.openSessions).toBe(0);
    });

    it("shares a module between signers that are already logged in", async () => {
        const fake = setup([
            makePkcs11Key("secp256k1"),
            makePkcs11Key("ed25519"),
        ]);
        const ecdsa = await fake.create({ keyLabel: "hiero-secp256k1" });
        const ed = await fake.create({ keyLabel: "hiero-ed25519" });
        const body = randomBytes(32);
        expect(ed.publicKey.verify(body, await ed.sign(body))).toBe(true);
        expect(ecdsa.publicKey.verify(body, await ecdsa.sign(body))).toBe(true);
        await ecdsa.close();
        await ed.close();
        expect(fake.module.openSessions).toBe(0);
    });

    it("requires a key label or ID, and a library or module", async () => {
        await expect(setup([]).create({ keyLabel: undefined })).rejects.toThrow(
            TypeError,
        );
        await expect(
            Pkcs11Signer.create({
                tokenLabel: "hiero",
                pin: "1234",
                keyLabel: "k",
            }),
        ).rejects.toThrow(TypeError);
    });

    it("reports a PKCS#11 library that cannot be loaded", async () => {
        await expectCodeAsync(
            Pkcs11Signer.create({
                library: "/nonexistent/libpkcs11.so",
                tokenLabel: "hiero",
                pin: "1234",
                keyLabel: "k",
            }),
            RemoteSignerErrorCodes.BackendRequestFailed,
        );
    });
});

describe("Pkcs11Signer.sign", () => {
    it("signs the Keccak-256 digest with CKM_ECDSA", async () => {
        const key = makePkcs11Key("secp256k1");
        const fake = setup([key]);
        const signer = await fake.create();
        const body = randomBytes(300);

        const sig = await signer.sign(body);

        expect(fake.module.calls).toEqual([
            { fn: "C_SignInit", mechanism: C.CKM_ECDSA },
            { fn: "C_Sign", data: keccak_256(body) },
        ]);
        expect(signer.publicKey.verify(body, sig)).toBe(true);
        await signer.close();
    });

    it("signs the raw bytes with CKM_EDDSA", async () => {
        const fake = setup([makePkcs11Key("ed25519")]);
        const signer = await fake.create();
        const body = randomBytes(8192);

        const sig = await signer.sign(body);

        expect(fake.module.calls).toEqual([
            { fn: "C_SignInit", mechanism: C.CKM_EDDSA },
            { fn: "C_Sign", data: new Uint8Array(body) },
        ]);
        expect(signer.publicKey.verify(body, sig)).toBe(true);
        await signer.close();
    });

    it.each(["raw", "der"] as const)(
        "normalizes high-S signatures in %s form",
        async (signatureFormat) => {
            const signer = await setup([
                makePkcs11Key("secp256k1", {
                    behaviour: "always-high-s",
                    signatureFormat,
                }),
            ]).create();
            for (let i = 0; i < 25; i++) {
                const body = randomBytes(50 + i);
                expect(
                    signer.publicKey.verify(body, await signer.sign(body)),
                ).toBe(true);
            }
            await signer.close();
        },
    );

    it("queues concurrent signs on the single session", async () => {
        const signer = await setup([makePkcs11Key("secp256k1")]).create();
        const bodies = Array.from({ length: 10 }, () => randomBytes(64));
        const signatures = await Promise.all(bodies.map(signer.sign));
        signatures.forEach((sig, i) =>
            expect(signer.publicKey.verify(bodies[i]!, sig)).toBe(true),
        );
        await signer.close();
    });

    it("refuses to return a signature that does not verify", async () => {
        const signer = await setup([
            makePkcs11Key("ed25519", { behaviour: "corrupt" }),
        ]).create();
        await expectCodeAsync(
            signer.sign(randomBytes(64)),
            RemoteSignerErrorCodes.SignatureInvalid,
        );
        await signer.close();
    });

    it("skips local verification when disabled", async () => {
        const signer = await setup([
            makePkcs11Key("ed25519", { behaviour: "corrupt" }),
        ]).create({ verifySignatures: false });
        const body = randomBytes(64);
        expect(signer.publicKey.verify(body, await signer.sign(body))).toBe(
            false,
        );
        await signer.close();
    });

    it("rejects an Ed25519 signature that is not 64 bytes", async () => {
        const key = makePkcs11Key("ed25519");
        const fake = createFakePkcs11([key]);
        const signer = await Pkcs11Signer.create({
            pkcs11: {
                ...fake.pkcs11,
                C_Sign: (
                    _s: Buffer,
                    _d: Buffer,
                    _o: Buffer,
                    cb: (e: Error | null, d: Buffer) => void,
                ) => cb(null, Buffer.alloc(63)),
            } as unknown as typeof fake.pkcs11,
            tokenLabel: "hiero",
            pin: "1234",
            keyLabel: key.label,
        });
        await expectCodeAsync(
            signer.sign(randomBytes(32)),
            RemoteSignerErrorCodes.SignatureInvalid,
        );
    });

    it("wraps token errors and keeps signing afterwards", async () => {
        const key = makePkcs11Key("secp256k1");
        const fake = createFakePkcs11([key]);
        let fail = true;
        const signer = await Pkcs11Signer.create({
            pkcs11: {
                ...fake.pkcs11,
                C_SignInit: (
                    ...args: Parameters<typeof fake.module.C_SignInit>
                ) => {
                    if (fail) {
                        fail = false;
                        throw new Error("device removed");
                    }
                    fake.module.C_SignInit(...args);
                },
            },
            tokenLabel: "hiero",
            pin: "1234",
            keyLabel: key.label,
        });

        const err = await expectCodeAsync(
            signer.sign(randomBytes(32)),
            RemoteSignerErrorCodes.BackendRequestFailed,
        );
        expect((err.cause as Error).message).toBe("device removed");
        const body = randomBytes(32);
        expect(signer.publicKey.verify(body, await signer.sign(body))).toBe(
            true,
        );
        await signer.close();
    });

    it("refuses to sign after close, and close is idempotent", async () => {
        const fake = setup([makePkcs11Key("secp256k1")]);
        const signer = await fake.create();
        await signer.close();
        await signer.close();
        expect(fake.module.openSessions).toBe(0);
        await expectCodeAsync(
            signer.sign(randomBytes(32)),
            RemoteSignerErrorCodes.BackendRequestFailed,
        );
    });
});

describe.each(["secp256k1", "ed25519"] as const)(
    "Hiero SDK integration (PKCS#11 %s)",
    (curve) => {
        const transfer = (payer: string) =>
            new TransferTransaction()
                .addHbarTransfer(payer, Hbar.fromTinybars(-1000))
                .addHbarTransfer("0.0.1001", Hbar.fromTinybars(1000))
                .setTransactionId(TransactionId.generate(payer));

        it("signs every per-node body of a frozen transaction", async () => {
            const signer = await setup([makePkcs11Key(curve)]).create();
            const network = hieroClient();

            const tx = transfer("0.0.1234").freezeWith(network);
            await tx.signWith(signer.publicKey, signer.sign);

            expect(signer.publicKey.verifyTransaction(tx)).toBe(true);
            const restored = Transaction.fromBytes(tx.toBytes());
            expect(signer.publicKey.verifyTransaction(restored)).toBe(true);
            network.close();
            await signer.close();
        });

        it("works as the client operator", async () => {
            const signer = await setup([makePkcs11Key(curve)]).create();
            const network = hieroClient();
            setClientOperator(network, "0.0.1234", signer);

            const tx = transfer("0.0.1234").freezeWith(network);
            await tx.signWithOperator(network);
            expect(signer.publicKey.verifyTransaction(tx)).toBe(true);
            network.close();
            await signer.close();
        });
    },
);

describe("Pkcs11Signer token failures", () => {
    /** A fake module with `method` replaced by `replacement`. */
    function withOverride(
        key: FakePkcs11Key,
        method: string,
        replacement: (...args: never[]) => unknown,
    ) {
        const fake = createFakePkcs11([key]);
        return Pkcs11Signer.create({
            pkcs11: {
                ...fake.pkcs11,
                [method]: replacement,
            },
            tokenLabel: "hiero",
            pin: "1234",
            keyLabel: key.label,
        });
    }
    const fail = () => {
        throw new Error("token error");
    };

    it.each([
        "C_GetSlotList",
        "C_OpenSession",
        "C_FindObjectsInit",
        "C_GetAttributeValue",
    ])("wraps a failing %s", async (method) => {
        const err = await expectCodeAsync(
            withOverride(makePkcs11Key("secp256k1"), method, fail),
            RemoteSignerErrorCodes.BackendRequestFailed,
        );
        expect((err.cause as Error).message).toBe("token error");
    });

    it("wraps an error reported by the C_Sign callback", async () => {
        const signer = await withOverride(
            makePkcs11Key("secp256k1"),
            "C_Sign",
            (...args: never[]) =>
                (args[3] as unknown as (e: Error) => void)(
                    new Error("sign error"),
                ),
        );
        const err = await expectCodeAsync(
            signer.sign(randomBytes(32)),
            RemoteSignerErrorCodes.BackendRequestFailed,
        );
        expect((err.cause as Error).message).toBe("sign error");
    });

    it("rejects CKA_EC_PARAMS naming another curve", async () => {
        const key = makePkcs11Key("ed25519");
        await expectCodeAsync(
            withOverride(key, "C_GetAttributeValue", (...args: never[]) =>
                (args[2] as unknown as { type: number }[]).map(({ type }) => ({
                    type,
                    value:
                        type === C.CKA_EC_PARAMS
                            ? Buffer.from([0x13, 3, 0x61, 0x62, 0x63])
                            : Buffer.from([1]),
                })),
            ),
            RemoteSignerErrorCodes.UnsupportedKey,
        );
    });

    it("rejects a CKA_EC_POINT of the wrong length", async () => {
        const key = makePkcs11Key("ed25519", {
            pointStyle: "raw",
            point: new Uint8Array(31),
        });
        await expectCodeAsync(
            setup([key]).create(),
            RemoteSignerErrorCodes.MalformedDer,
        );
    });

    it("accepts a raw Ed25519 point that starts with the OCTET STRING tag", async () => {
        let key = makePkcs11Key("ed25519");
        // Find a raw key whose first byte is 0x04 so it looks like DER.
        while (key.point[0] !== 0x04) key = makePkcs11Key("ed25519");
        key.pointStyle = "raw";
        const signer = await setup([key]).create();
        expect(signer.publicKey.toBytesRaw()).toEqual(key.point);
        await signer.close();
    });
});
