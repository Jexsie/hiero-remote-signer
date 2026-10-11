import { generateKeyPairSync } from "node:crypto";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { ed25519 } from "@noble/curves/ed25519.js";

/**
 * Real key material and signing shared by every fake backend. Each fake only
 * adds its backend's request contract on top, so all of them sign with real
 * keys and their signatures verify with the Hiero SDK.
 */

export type KeyCurve = "secp256k1" | "ed25519" | "p256" | "rsa";

/** Controls how a fake backend misbehaves, to exercise the signer's defences. */
export type SignBehaviour = "normal" | "always-high-s" | "corrupt";

export interface KeyMaterial {
    curve: KeyCurve;
    /** DER-encoded SubjectPublicKeyInfo */
    spki: Uint8Array;
    /** PEM-encoded SubjectPublicKeyInfo */
    pem: string;
    /** Raw private scalar (secp256k1, P-256) or seed (Ed25519); empty for RSA. Test-only. */
    privateKey: Uint8Array;
}

const N = secp256k1.Point.CURVE().n;

function b64urlToBytes(s: string): Uint8Array {
    return new Uint8Array(Buffer.from(s, "base64url"));
}

export function generateKeyMaterial(curve: KeyCurve): KeyMaterial {
    const pair =
        curve === "secp256k1" || curve === "p256"
            ? generateKeyPairSync("ec", {
                  namedCurve:
                      curve === "secp256k1" ? "secp256k1" : "prime256v1",
              })
            : curve === "ed25519"
              ? generateKeyPairSync("ed25519")
              : generateKeyPairSync("rsa", { modulusLength: 2048 });

    return {
        curve,
        spki: new Uint8Array(
            pair.publicKey.export({ type: "spki", format: "der" }),
        ),
        pem: pair.publicKey.export({ type: "spki", format: "pem" }).toString(),
        privateKey:
            curve === "rsa"
                ? new Uint8Array()
                : b64urlToBytes(pair.privateKey.export({ format: "jwk" }).d!),
    };
}

/** Signs a 32-byte digest with secp256k1 and returns a DER signature. */
export function signSecp256k1Digest(
    digest: Uint8Array,
    privateKey: Uint8Array,
    behaviour: SignBehaviour,
): Uint8Array {
    let sig = secp256k1.Signature.fromBytes(
        secp256k1.sign(digest, privateKey, { prehash: false, lowS: true }),
        "compact",
    );
    if (behaviour === "always-high-s") {
        sig = new secp256k1.Signature(sig.r, N - sig.s);
    }
    return corrupt(sig.toBytes("der"), behaviour);
}

/** Signs a message with pure Ed25519 and returns the 64-byte signature. */
export function signEd25519(
    message: Uint8Array,
    privateKey: Uint8Array,
    behaviour: SignBehaviour,
): Uint8Array {
    return corrupt(ed25519.sign(message, privateKey), behaviour);
}

function corrupt(signature: Uint8Array, behaviour: SignBehaviour): Uint8Array {
    if (behaviour !== "corrupt") return signature;
    const out = new Uint8Array(signature);
    out[out.length - 1]! ^= 0x01;
    return out;
}
