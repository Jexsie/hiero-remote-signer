/**
 * Step 3: the remote-key account pays for and signs an HBAR transfer. The
 * client's operator is the remote signer, so every transaction it sends is
 * signed by the backend and no private key is in this process.
 */
import { AccountId, Hbar, TransferTransaction } from "@hiero-ledger/sdk";
import { setClientOperator } from "hiero-remote-signer";

import {
    fundingAccount,
    hashscanAccount,
    mirrorBalance,
    networkClient,
    optional,
    remoteAccountId,
} from "./config.js";
import { withSigner } from "./signer.js";

const amount = new Hbar(Number(optional("TRANSFER_HBAR") ?? 1));
const sender = remoteAccountId();
const recipient = AccountId.fromString(
    optional("RECIPIENT_ACCOUNT_ID") ?? fundingAccount().id.toString(),
);

await withSigner(async ({ backend, signer }) => {
    const client = setClientOperator(networkClient(), sender, signer);
    try {
        const before = await mirrorBalance(client, sender);
        console.log(
            `${sender.toString()} holds ${before.toString()}; sending ${amount.toString()} to ${recipient.toString()}`,
        );

        const response = await new TransferTransaction()
            .addHbarTransfer(sender, amount.negated())
            .addHbarTransfer(recipient, amount)
            .setTransactionMemo(`signed by ${backend} via hiero-remote-signer`)
            .execute(client);
        const receipt = await response.getReceipt(client);

        const after = await mirrorBalance(client, sender, before);
        console.log(`Status:         ${receipt.status.toString()}`);
        console.log(`Transaction ID: ${response.transactionId.toString()}`);
        console.log(`New balance:    ${after.toString()}`);
        console.log(`HashScan:       ${hashscanAccount(sender)}`);
    } finally {
        client.close();
    }
});
