import {
    AccountCreateTransaction,
    Client,
    Hbar,
    TransferTransaction,
} from "@hiero-ledger/sdk";
import type { Status } from "@hiero-ledger/sdk";

import { setClientOperator } from "../../src/client/index.js";
import type { HieroRemoteSigner } from "../../src/types/index.js";
import { operatorKeyFromEnv } from "./env.js";

/**
 * Shared flow for the live network specs. They run against a real Hiero
 * network, for example a local Solo network, and need:
 *   HIERO_NETWORK        JSON map of node address to account ID,
 *                        for example {"127.0.0.1:50211":"0.0.3"}
 *   HIERO_OPERATOR_ID    funded account used to create the test account
 *   HIERO_OPERATOR_KEY   private key of that account (a local test key);
 *                        HIERO_OPERATOR_KEY_TYPE selects der (default), ecdsa or ed25519
 */

const env = process.env;

/** Whether the Hiero network variables are set. */
export const hieroNetworkConfigured = Boolean(
    env.HIERO_NETWORK && env.HIERO_OPERATOR_ID && env.HIERO_OPERATOR_KEY,
);

/**
 * Creates an account owned by `signer`'s key, then has that account pay for
 * and sign a transfer purely through the remote signer. Returns the
 * transfer's receipt status.
 */
export async function createAccountAndSpend(
    signer: HieroRemoteSigner,
): Promise<Status> {
    const network = JSON.parse(env.HIERO_NETWORK!) as Record<string, string>;
    const funding = Client.forNetwork(network).setOperator(
        env.HIERO_OPERATOR_ID!,
        operatorKeyFromEnv(env.HIERO_OPERATOR_KEY!),
    );
    let remote: Client | undefined;
    try {
        const created = await new AccountCreateTransaction()
            .setKeyWithoutAlias(signer.publicKey)
            .setInitialBalance(new Hbar(5))
            .execute(funding);
        const accountId = (await created.getReceipt(funding)).accountId!;

        remote = setClientOperator(
            Client.forNetwork(network),
            accountId,
            signer,
        );
        const transfer = await new TransferTransaction()
            .addHbarTransfer(accountId, new Hbar(-1))
            .addHbarTransfer(env.HIERO_OPERATOR_ID!, new Hbar(1))
            .execute(remote);
        return (await transfer.getReceipt(remote)).status;
    } finally {
        funding.close();
        remote?.close();
    }
}
