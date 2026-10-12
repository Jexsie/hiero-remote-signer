/**
 * Step 2: create a testnet account whose only key is the remote key. Your
 * existing testnet account (FUNDING_*) pays the fee and the initial balance.
 */
import { AccountCreateTransaction, Hbar } from "@hiero-ledger/sdk";

import {
    fundingAccount,
    hashscanAccount,
    network,
    networkClient,
    optional,
} from "./config.js";
import { withSigner } from "./signer.js";

const initialBalance = new Hbar(Number(optional("INITIAL_BALANCE_HBAR") ?? 10));
const funding = fundingAccount();
const client = networkClient().setOperator(funding.id, funding.key);

try {
    await withSigner(async ({ backend, signer }) => {
        console.log(
            `Creating a ${network()} account owned by the ${backend} ${signer.keyType} key`,
        );
        console.log(`Public key: ${signer.publicKey.toStringDer()}`);

        const response = await new AccountCreateTransaction()
            .setKeyWithoutAlias(signer.publicKey)
            .setInitialBalance(initialBalance)
            .setAccountMemo(`hiero-remote-signer ${backend} example`)
            .execute(client);
        const receipt = await response.getReceipt(client);
        const accountId = receipt.accountId!;

        console.log(`\nCreated account ${accountId.toString()}`);
        console.log(
            `Funded with ${initialBalance.toString()} from ${funding.id.toString()}`,
        );
        console.log(`HashScan: ${hashscanAccount(accountId)}`);
        console.log(`\nAdd this line to example/.env:`);
        console.log(`REMOTE_ACCOUNT_ID=${accountId.toString()}`);
    });
} finally {
    client.close();
}
