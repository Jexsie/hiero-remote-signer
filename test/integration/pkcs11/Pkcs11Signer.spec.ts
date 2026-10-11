/**
 * Tests against a real PKCS#11 token, such as SoftHSM.
 *
 * The first suite needs PKCS11_LIBRARY, PKCS11_TOKEN_LABEL and PKCS11_PIN for
 * an initialized token. It generates secp256k1 and Ed25519 key pairs on the
 * token and checks every signature with the Hiero SDK. CI runs it against
 * SoftHSM:
 *
 *   softhsm2-util --init-token --free --label hiero --pin 1234 --so-pin 5678
 *
 * The second suite also needs the Hiero network variables (see
 * test/utils/live-network.ts) and runs the full account flow on a live network.
 */
import { randomBytes, randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
    Client,
    Hbar,
    Status,
    TransactionId,
    TransferTransaction,
} from "@hiero-ledger/sdk";
import * as pkcs11js from "pkcs11js";

import {
    Pkcs11Constants as C,
    Pkcs11Signer,
} from "../../../src/pkcs11/index.js";
import {
    createAccountAndSpend,
    hieroNetworkConfigured,
} from "../../utils/live-network.js";

const library = process.env.PKCS11_LIBRARY;
const tokenLabel = process.env.PKCS11_TOKEN_LABEL ?? "hiero";
const pin = process.env.PKCS11_PIN;
const tokenConfigured = Boolean(library && pin);

const CKM_EC_KEY_PAIR_GEN = 0x1040;
const CKM_EC_EDWARDS_KEY_PAIR_GEN = 0x1055;
const CURVES = {
    secp256k1: {
        mechanism: CKM_EC_KEY_PAIR_GEN,
        params: Buffer.from("06052b8104000a", "hex"),
    },
    ed25519: {
        mechanism: CKM_EC_EDWARDS_KEY_PAIR_GEN,
        params: Buffer.from("06032b6570", "hex"),
    },
} as const;

/** Generates a token key pair on `curve` and returns its label. */
function generateKeyPair(curve: keyof typeof CURVES): string {
    const module = new pkcs11js.PKCS11();
    module.load(library!);
    module.C_Initialize();
    try {
        const slot = module
            .C_GetSlotList(true)
            .find((s) => module.C_GetTokenInfo(s).label.trim() === tokenLabel);
        const session = module.C_OpenSession(
            slot!,
            C.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION,
        );
        module.C_Login(session, C.CKU_USER, pin);
        const label = `hiero-${curve}-${randomUUID().slice(0, 8)}`;
        const id = randomBytes(8);
        module.C_GenerateKeyPair(
            session,
            { mechanism: CURVES[curve].mechanism },
            [
                { type: pkcs11js.CKA_TOKEN, value: true },
                { type: C.CKA_LABEL, value: label },
                { type: C.CKA_ID, value: id },
                { type: pkcs11js.CKA_VERIFY, value: true },
                { type: C.CKA_EC_PARAMS, value: CURVES[curve].params },
            ],
            [
                { type: pkcs11js.CKA_TOKEN, value: true },
                { type: C.CKA_LABEL, value: label },
                { type: C.CKA_ID, value: id },
                { type: C.CKA_SIGN, value: true },
                { type: pkcs11js.CKA_PRIVATE, value: true },
                { type: pkcs11js.CKA_SENSITIVE, value: true },
                { type: pkcs11js.CKA_EXTRACTABLE, value: false },
            ],
        );
        module.C_Logout(session);
        module.C_CloseSession(session);
        return label;
    } finally {
        module.C_Finalize();
        module.close();
    }
}

describe.skipIf(!tokenConfigured)("Pkcs11Signer on a real token", () => {
    describe.each(["secp256k1", "ed25519"] as const)("%s", (curve) => {
        let signer: Pkcs11Signer;

        beforeAll(async () => {
            signer = await Pkcs11Signer.create({
                library: library!,
                tokenLabel,
                pin: pin!,
                keyLabel: generateKeyPair(curve),
            });
        });
        afterAll(() => signer?.close());

        it("signs a frozen transaction for every node", async () => {
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

        it("signs concurrent requests on one session", async () => {
            const bodies = Array.from({ length: 20 }, () => randomBytes(200));
            const signatures = await Promise.all(bodies.map(signer.sign));
            signatures.forEach((sig, i) =>
                expect(signer.publicKey.verify(bodies[i]!, sig)).toBe(true),
            );
        });
    });
});

const networkConfigured =
    tokenConfigured &&
    hieroNetworkConfigured &&
    Boolean(process.env.PKCS11_KEY_LABEL);

describe.skipIf(!networkConfigured)(
    "Pkcs11Signer on a live Hiero network",
    () => {
        it("creates an account owned by the token key and spends from it", async () => {
            const signer = await Pkcs11Signer.create({
                library: library!,
                tokenLabel,
                pin: pin!,
                keyLabel: process.env.PKCS11_KEY_LABEL!,
            });
            try {
                expect(await createAccountAndSpend(signer)).toBe(
                    Status.Success,
                );
            } finally {
                await signer.close();
            }
        }, 120_000);
    },
);
