import type { AccountId, Client, PublicKey } from "@hiero-ledger/sdk";

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
     * Makes this key the operator of `client`. Every transaction the client
     * sends is paid for by `accountId` and signed by the backend, and the
     * private key never enters this process. Returns `client`.
     */
    setClientOperator(client: Client, accountId: AccountId | string): Client {
        return client.setOperatorWith(accountId, this.publicKey, this.sign);
    }
}
