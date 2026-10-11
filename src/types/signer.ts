import type { PublicKey } from "@hiero-ledger/sdk";

/** Key types that Hiero consensus nodes verify. */
export type HieroKeyType = "ECDSA_SECP256K1" | "ED25519";

/**
 * A signing key held by a remote signing backend (a cloud KMS or an HSM).
 *
 * `sign` has the exact shape of the SDK's `transactionSigner` callback, so it
 * can be passed straight to `Transaction.signWith()` and
 * `Client.setOperatorWith()`. It receives the serialized TransactionBody bytes
 * and returns a signature in the form Hiero expects (64 bytes for both key
 * types).
 */
export interface HieroRemoteSigner {
    readonly keyType: HieroKeyType;
    readonly publicKey: PublicKey;
    readonly sign: (bodyBytes: Uint8Array) => Promise<Uint8Array>;
}
