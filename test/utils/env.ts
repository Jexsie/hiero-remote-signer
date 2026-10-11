import { PrivateKey } from "@hiero-ledger/sdk";

/**
 * Parses `HIERO_OPERATOR_KEY` according to `HIERO_OPERATOR_KEY_TYPE`
 * (`der`, `ecdsa` or `ed25519`; defaults to `der`).
 */
export function operatorKeyFromEnv(
    key: string,
    type = process.env.HIERO_OPERATOR_KEY_TYPE ?? "der",
): PrivateKey {
    switch (type.toLowerCase()) {
        case "ecdsa":
            return PrivateKey.fromStringECDSA(key);
        case "ed25519":
            return PrivateKey.fromStringED25519(key);
        case "der":
            return PrivateKey.fromStringDer(key);
        default:
            throw new Error(
                `HIERO_OPERATOR_KEY_TYPE must be der, ecdsa or ed25519, got ${type}`,
            );
    }
}
