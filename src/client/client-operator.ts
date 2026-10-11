import type { AccountId, Client } from "@hiero-ledger/sdk";

import type { HieroRemoteSigner } from "../types/index.js";

/**
 * Configures `client` to pay for and sign transactions as `accountId`, with
 * the operator key held by the remote signer. The key never enters this process.
 */
export function setClientOperator(
    client: Client,
    accountId: AccountId | string,
    signer: HieroRemoteSigner,
): Client {
    return client.setOperatorWith(accountId, signer.publicKey, signer.sign);
}
