import type {
    AccountId,
    Client,
    PublicKey,
    Transaction,
} from "@hiero-ledger/sdk";

import type { HieroKeyType, HieroRemoteSigner } from "../types/index.js";

/**
 * Base class of every backend signer. Backends provide the key type, the
 * public key and `sign`; this class adds what works the same for all of them.
 */
export abstract class RemoteSigner implements HieroRemoteSigner {
    abstract readonly keyType: HieroKeyType;
    abstract readonly publicKey: PublicKey;
    abstract readonly sign: (bodyBytes: Uint8Array) => Promise<Uint8Array>;

    /**
     * Adds this key's signature to a frozen `transaction` and returns it.
     *
     * Use this whenever the key has to approve a transaction, whoever pays
     * for it: as the owner of a debited account, as one party of a threshold
     * key, or as an admin key. Each party can sign its own copy restored with
     * `Transaction.fromBytes()` and pass the bytes on.
     */
    signTransaction<T extends Transaction>(transaction: T): Promise<T> {
        return transaction.signWith(this.publicKey, this.sign);
    }

    /**
     * Makes this key the operator of `client`. Every transaction the client
     * sends is paid for by `accountId` and signed by the backend, and the
     * private key never enters this process. Returns `client`.
     */
    setClientOperator(client: Client, accountId: AccountId | string): Client {
        return client.setOperatorWith(accountId, this.publicKey, this.sign);
    }
}
