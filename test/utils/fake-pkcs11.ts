import { secp256k1 } from "@noble/curves/secp256k1.js";

import { Pkcs11Constants as C } from "../../src/pkcs11/index.js";
import type { Pkcs11Module } from "../../src/pkcs11/index.js";
import {
    generateKeyMaterial,
    signEd25519,
    signSecp256k1Digest,
} from "./key-material.js";
import type { SignBehaviour } from "./key-material.js";

/** PKCS#11 return values the fake raises. */
export const CKR = {
    DATA_LEN_RANGE: 0x21,
    KEY_TYPE_INCONSISTENT: 0x63,
    KEY_FUNCTION_NOT_PERMITTED: 0x68,
    OPERATION_ACTIVE: 0x90,
    OPERATION_NOT_INITIALIZED: 0x91,
    PIN_INCORRECT: 0xa0,
    SESSION_HANDLE_INVALID: 0xb3,
    SESSION_PARALLEL_NOT_SUPPORTED: 0xb4,
    USER_ALREADY_LOGGED_IN: 0x100,
    USER_NOT_LOGGED_IN: 0x101,
} as const;

export class Pkcs11Error extends Error {
    constructor(readonly code: number) {
        super(`CKR 0x${code.toString(16)}`);
        this.name = "Pkcs11Error";
    }
}

export type Pkcs11Curve = "secp256k1" | "ed25519" | "p256";

export interface FakePkcs11Key {
    label: string;
    id: Buffer;
    curve: Pkcs11Curve;
    privateKey: Uint8Array;
    /** Public point: 65-byte uncompressed for EC curves, 32 bytes for Ed25519. */
    point: Uint8Array;
    canSign: boolean;
    /** How CKA_EC_PARAMS names Ed25519: the v3.0 OID or the older curve name. */
    paramsStyle: "oid" | "printable";
    /** Whether CKA_EC_POINT is DER-wrapped (standard) or raw. */
    pointStyle: "der" | "raw";
    /** ECDSA output: r || s (standard) or DER. */
    signatureFormat: "raw" | "der";
    behaviour: SignBehaviour;
}

export function makePkcs11Key(
    curve: Pkcs11Curve,
    overrides: Partial<FakePkcs11Key> = {},
): FakePkcs11Key {
    const material = generateKeyMaterial(curve);
    const jwk = material.publicJwk;
    const point =
        curve === "ed25519"
            ? new Uint8Array(Buffer.from(jwk.x!, "base64url"))
            : new Uint8Array([
                  0x04,
                  ...Buffer.from(jwk.x!, "base64url"),
                  ...Buffer.from(jwk.y!, "base64url"),
              ]);
    return {
        label: `hiero-${curve}`,
        id: Buffer.from([curve.length, 1]),
        curve,
        privateKey: material.privateKey,
        point,
        canSign: true,
        paramsStyle: "oid",
        pointStyle: "der",
        signatureFormat: "raw",
        behaviour: "normal",
        ...overrides,
    };
}

const EC_PARAMS: Record<Pkcs11Curve, Buffer> = {
    secp256k1: Buffer.from("06052b8104000a", "hex"),
    ed25519: Buffer.from("06032b6570", "hex"),
    p256: Buffer.from("06082a8648ce3d030107", "hex"),
};
const EDWARDS25519_NAME = Buffer.concat([
    Buffer.from([0x13, 12]),
    Buffer.from("edwards25519", "ascii"),
]);

interface StoredObject {
    handle: Buffer;
    objectClass: number;
    isPrivate: boolean;
    key: FakePkcs11Key;
}

interface Session {
    slot: number;
    found?: Buffer[];
    signing?: { mechanism: number; key: FakePkcs11Key };
}

/**
 * An in-memory PKCS#11 module with one token. It enforces the rules a real
 * token applies to the calls the signer makes: private objects are hidden
 * until login, a session runs one operation at a time, C_Sign needs a
 * matching C_SignInit, and mechanisms must fit the key type. C_Sign answers
 * asynchronously, so a signer that interleaves operations on one session
 * fails here.
 */
export function createFakePkcs11(
    keys: FakePkcs11Key[],
    token: { label?: string; pin?: string } = {},
) {
    const tokenLabel = token.label ?? "hiero";
    const pin = token.pin ?? "1234";
    const slot = Buffer.from([1, 0, 0, 0, 0, 0, 0, 0]);
    const sessions = new Map<string, Session>();
    let loggedIn = false;
    let nextHandle = 1;
    const calls: { fn: string; mechanism?: number; data?: Uint8Array }[] = [];

    const handle = () => {
        const h = Buffer.alloc(8);
        h.writeUInt32LE(nextHandle++);
        return h;
    };
    const objects: StoredObject[] = keys.flatMap((key) => [
        {
            handle: handle(),
            objectClass: C.CKO_PRIVATE_KEY,
            isPrivate: true,
            key,
        },
        {
            handle: handle(),
            objectClass: C.CKO_PUBLIC_KEY,
            isPrivate: false,
            key,
        },
    ]);

    const session = (h: Buffer) => {
        const s = sessions.get(h.toString("hex"));
        if (!s) throw new Pkcs11Error(CKR.SESSION_HANDLE_INVALID);
        return s;
    };
    const object = (h: Buffer) => objects.find((o) => o.handle.equals(h))!;

    const attribute = (o: StoredObject, type: number): Buffer => {
        const key = o.key;
        switch (type) {
            case C.CKA_SIGN:
                return Buffer.from([
                    o.objectClass === C.CKO_PRIVATE_KEY && key.canSign ? 1 : 0,
                ]);
            case C.CKA_EC_PARAMS:
                return key.curve === "ed25519" &&
                    key.paramsStyle === "printable"
                    ? EDWARDS25519_NAME
                    : EC_PARAMS[key.curve];
            case C.CKA_EC_POINT:
                return key.pointStyle === "raw"
                    ? Buffer.from(key.point)
                    : Buffer.from([0x04, key.point.length, ...key.point]);
            default:
                throw new Pkcs11Error(0x12); // CKR_ATTRIBUTE_TYPE_INVALID
        }
    };

    const module = {
        calls,
        get openSessions() {
            return sessions.size;
        },
        C_GetSlotList: () => [slot],
        C_GetTokenInfo: () => ({ label: tokenLabel.padEnd(32, " ") }),
        C_OpenSession(s: Buffer, flags: number) {
            if (!(flags & C.CKF_SERIAL_SESSION)) {
                throw new Pkcs11Error(CKR.SESSION_PARALLEL_NOT_SUPPORTED);
            }
            const h = handle();
            sessions.set(h.toString("hex"), { slot: s.readUInt32LE(0) });
            return h;
        },
        C_CloseSession(h: Buffer) {
            session(h);
            sessions.delete(h.toString("hex"));
            if (sessions.size === 0) loggedIn = false;
        },
        C_Login(h: Buffer, _userType: number, given?: string) {
            session(h);
            if (given !== pin) throw new Pkcs11Error(CKR.PIN_INCORRECT);
            if (loggedIn) throw new Pkcs11Error(CKR.USER_ALREADY_LOGGED_IN);
            loggedIn = true;
        },
        C_FindObjectsInit(
            h: Buffer,
            template: { type: number; value?: unknown }[],
        ) {
            const s = session(h);
            if (s.found) throw new Pkcs11Error(CKR.OPERATION_ACTIVE);
            s.found = objects
                .filter((o) => loggedIn || !o.isPrivate)
                .filter((o) =>
                    template.every(({ type, value }) =>
                        type === C.CKA_CLASS
                            ? value === o.objectClass
                            : type === C.CKA_LABEL
                              ? value === o.key.label
                              : type === C.CKA_ID
                                ? Buffer.isBuffer(value) &&
                                  value.equals(o.key.id)
                                : false,
                    ),
                )
                .map((o) => o.handle);
        },
        C_FindObjects(h: Buffer, max: number) {
            const s = session(h);
            if (!s.found) throw new Pkcs11Error(CKR.OPERATION_NOT_INITIALIZED);
            return s.found.splice(0, max);
        },
        C_FindObjectsFinal(h: Buffer) {
            delete session(h).found;
        },
        C_GetAttributeValue(
            _h: Buffer,
            o: Buffer,
            template: { type: number }[],
        ) {
            return template.map(({ type }) => ({
                type,
                value: attribute(object(o), type),
            }));
        },
        C_SignInit(h: Buffer, mechanism: { mechanism: number }, k: Buffer) {
            const s = session(h);
            calls.push({ fn: "C_SignInit", mechanism: mechanism.mechanism });
            if (s.signing) throw new Pkcs11Error(CKR.OPERATION_ACTIVE);
            if (!loggedIn) throw new Pkcs11Error(CKR.USER_NOT_LOGGED_IN);
            const o = object(k);
            if (o.objectClass !== C.CKO_PRIVATE_KEY || !o.key.canSign) {
                throw new Pkcs11Error(CKR.KEY_FUNCTION_NOT_PERMITTED);
            }
            const expected =
                o.key.curve === "ed25519" ? C.CKM_EDDSA : C.CKM_ECDSA;
            if (mechanism.mechanism !== expected) {
                throw new Pkcs11Error(CKR.KEY_TYPE_INCONSISTENT);
            }
            s.signing = { mechanism: mechanism.mechanism, key: o.key };
        },
        C_Sign(
            h: Buffer,
            data: Buffer,
            _out: Buffer,
            cb: (error: Error | null, data: Buffer) => void,
        ) {
            const s = session(h);
            calls.push({ fn: "C_Sign", data: new Uint8Array(data) });
            const op = s.signing;
            // Like a real token, the operation stays active until C_Sign
            // completes, so overlapping calls on one session fail.
            setImmediate(() => {
                delete s.signing;
                if (!op) {
                    return cb(
                        new Pkcs11Error(CKR.OPERATION_NOT_INITIALIZED),
                        Buffer.alloc(0),
                    );
                }
                const key = op.key;
                if (op.mechanism === C.CKM_EDDSA) {
                    return cb(
                        null,
                        Buffer.from(
                            signEd25519(data, key.privateKey, key.behaviour),
                        ),
                    );
                }
                if (data.length !== 32) {
                    return cb(
                        new Pkcs11Error(CKR.DATA_LEN_RANGE),
                        Buffer.alloc(0),
                    );
                }
                const der = signSecp256k1Digest(
                    data,
                    key.privateKey,
                    key.behaviour,
                );
                cb(
                    null,
                    Buffer.from(
                        key.signatureFormat === "der" ||
                            key.behaviour === "corrupt"
                            ? der
                            : secp256k1.Signature.fromBytes(der, "der").toBytes(
                                  "compact",
                              ),
                    ),
                );
            });
        },
    };

    return { module, pkcs11: module as unknown as Pkcs11Module };
}
