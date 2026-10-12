/**
 * Generates a non-extractable signing key pair on a PKCS#11 token (SoftHSM or
 * a hardware HSM), labelled PKCS11_KEY_LABEL. The curve is PKCS11_KEY_CURVE:
 * secp256k1 (default, a Hiero ECDSA key) or ed25519.
 *
 *   npm run pkcs11:keygen
 */
import { randomBytes } from "node:crypto";

import { Pkcs11Constants as C } from "hiero-remote-signer/pkcs11";
import * as pkcs11js from "pkcs11js";

import { optional, required } from "./config.js";

const CURVES = {
    secp256k1: {
        mechanism: 0x1040, // CKM_EC_KEY_PAIR_GEN
        params: Buffer.from("06052b8104000a", "hex"), // OID 1.3.132.0.10
    },
    ed25519: {
        mechanism: 0x1055, // CKM_EC_EDWARDS_KEY_PAIR_GEN
        params: Buffer.from("06032b6570", "hex"), // OID 1.3.101.112
    },
} as const;

const library = required("PKCS11_LIBRARY");
const tokenLabel = required("PKCS11_TOKEN_LABEL");
const pin = required("PKCS11_PIN");
const label = required("PKCS11_KEY_LABEL");
const curve = (optional("PKCS11_KEY_CURVE") ?? "secp256k1").toLowerCase();
if (curve !== "secp256k1" && curve !== "ed25519") {
    throw new Error(
        `PKCS11_KEY_CURVE must be secp256k1 or ed25519, got ${curve}`,
    );
}
const { mechanism, params } = CURVES[curve];

const module = new pkcs11js.PKCS11();
module.load(library);
module.C_Initialize();
try {
    const slot = module
        .C_GetSlotList(true)
        .find((s) => module.C_GetTokenInfo(s).label.trim() === tokenLabel);
    if (!slot) throw new Error(`no token labelled ${tokenLabel}`);

    const session = module.C_OpenSession(
        slot,
        C.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION,
    );
    module.C_Login(session, C.CKU_USER, pin);
    try {
        module.C_FindObjectsInit(session, [
            { type: C.CKA_LABEL, value: label },
        ]);
        const existing = module.C_FindObjects(session, 1);
        module.C_FindObjectsFinal(session);
        if (existing.length > 0) {
            throw new Error(
                `token ${tokenLabel} already has an object labelled ${label}; ` +
                    `pick another PKCS11_KEY_LABEL`,
            );
        }

        const id = randomBytes(8);
        module.C_GenerateKeyPair(
            session,
            { mechanism },
            [
                { type: pkcs11js.CKA_TOKEN, value: true },
                { type: C.CKA_LABEL, value: label },
                { type: C.CKA_ID, value: id },
                { type: pkcs11js.CKA_VERIFY, value: true },
                { type: C.CKA_EC_PARAMS, value: params },
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
        console.log(
            `Generated a ${curve} key pair labelled ${label} on token ${tokenLabel} ` +
                `(CKA_ID ${id.toString("hex")})`,
        );
    } finally {
        module.C_Logout(session);
        module.C_CloseSession(session);
    }
} finally {
    module.C_Finalize();
    module.close();
}
