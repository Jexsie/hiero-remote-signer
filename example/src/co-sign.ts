/**
 * Step 4: a transaction paid for by someone else that also needs the remote
 * key's signature. Your funding account is the payer and signs with its local
 * key; the remote key adds its signature with `signWith`, as a treasury or
 * custody key would approve a payout prepared by another service.
 */
import {
    AccountBalanceQuery,
    AccountId,
    Hbar,
    TransferTransaction,
} from "@hiero-ledger/sdk";

import {
    fundingAccount,
    hashscanAccount,
    networkClient,
    optional,
    remoteAccountId,
} from "./config.js";
import { withSigner } from "./signer.js";

const amount = new Hbar(Number(optional("TRANSFER_HBAR") ?? 1));
const source = remoteAccountId();
const funding = fundingAccount();
const recipient = AccountId.fromString(
    optional("RECIPIENT_ACCOUNT_ID") ?? funding.id.toString(),
);
const client = networkClient().setOperator(funding.id, funding.key);

try {
    await withSigner(async ({ backend, signer }) => {
        // The payer (the client operator) signs automatically on execute.
        // The remote key must also sign because it owns the debited account.
        const transaction = await new TransferTransaction()
            .addHbarTransfer(source, amount.negated())
            .addHbarTransfer(recipient, amount)
            .setTransactionMemo(
                `co-signed by ${backend} via hiero-remote-signer`,
            )
            .freezeWith(client)
            .signWith(signer.publicKey, signer.sign);

        const response = await transaction.execute(client);
        const receipt = await response.getReceipt(client);
        const balance = await new AccountBalanceQuery()
            .setAccountId(source)
            .execute(client);

        console.log(
            `Moved ${amount.toString()} from ${source.toString()} to ${recipient.toString()}; fee paid by ${funding.id.toString()}`,
        );
        console.log(`Status:         ${receipt.status.toString()}`);
        console.log(`Transaction ID: ${response.transactionId.toString()}`);
        console.log(`Source balance: ${balance.hbars.toString()}`);
        console.log(`HashScan:       ${hashscanAccount(source)}`);
    });
} finally {
    client.close();
}
