/**
 * Hiero testnet walkthrough with a key held in HashiCorp Vault (or OpenBao) transit.
 *
 * Prerequisite: follow "Option D: HashiCorp Vault or OpenBao transit" in README.md and fill in example/.env.
 * Run: npm run vault
 *
 * The private key never leaves Vault. The script:
 *   1. reads the settings
 *   2. connects to Vault and loads the public key
 *   3. creates a testnet account owned by that key (your funding account pays)
 *   4. sends HBAR from the new account, which pays and signs through Vault
 *   5. sends HBAR again, paid by your funding account and co-signed by Vault
 *   6. reads the new account's balance from the mirror node
 *   7. deletes the new account, returning its HBAR to your funding account
 *   8. logs the results
 */
import { existsSync } from "node:fs";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";

import {
    AccountCreateTransaction,
    AccountDeleteTransaction,
    AccountId,
    Client,
    Hbar,
    MirrorNodeAccountBalanceQuery,
    MirrorNodeStatusError,
    PrivateKey,
    Status,
    TransferTransaction,
} from "@hiero-ledger/sdk";
import {
    setClientOperator,
    VaultTransitSigner,
} from "hiero-remote-signer/vault";

// ---------------------------------------------------------------------------
// Step 1: read the settings from example/.env
// ---------------------------------------------------------------------------
const envFile = fileURLToPath(new URL("../.env", import.meta.url));
if (existsSync(envFile)) process.loadEnvFile(envFile);

function setting(name: string): string {
    const value = process.env[name]?.trim();
    if (!value) throw new Error(`${name} is not set; see example/.env.example`);
    return value;
}

// Your existing testnet account. Its key stays local and only pays for the
// account creation (step 3) and the co-signed transfer (step 5).
const fundingAccountId = AccountId.fromString(setting("FUNDING_ACCOUNT_ID"));
const fundingKeyType = (process.env.FUNDING_KEY_TYPE ?? "ecdsa").toLowerCase();
const fundingKey =
    fundingKeyType === "ed25519"
        ? PrivateKey.fromStringED25519(setting("FUNDING_PRIVATE_KEY"))
        : fundingKeyType === "der"
          ? PrivateKey.fromStringDer(setting("FUNDING_PRIVATE_KEY"))
          : PrivateKey.fromStringECDSA(setting("FUNDING_PRIVATE_KEY"));

// The Vault server, a token that can read and sign with the key, and the
// name of an ed25519 transit key.
const vaultAddress = setting("VAULT_ADDR");
const vaultToken = setting("VAULT_TOKEN");
const transitKey = setting("VAULT_TRANSIT_KEY");

const initialBalance = new Hbar(10);
const transferAmount = new Hbar(1);

console.log("Step 1: settings loaded");
console.log(`  funding account: ${fundingAccountId.toString()}`);
console.log(`  Vault:           ${vaultAddress}, key ${transitKey}`);

// Hiero clients for the funding account and, from step 4 on, the new account.
const fundingClient = Client.forTestnet().setOperator(
    fundingAccountId,
    fundingKey,
);
let remoteClient: Client | undefined;

try {
    // -----------------------------------------------------------------------
    // Step 2: connect to Vault and load the public key
    // -----------------------------------------------------------------------
    const signer = await VaultTransitSigner.create({
        address: vaultAddress,
        token: vaultToken,
        keyName: transitKey,
    });
    console.log("\nStep 2: connected to Vault");
    console.log(`  key type:   ${signer.keyType}`);
    console.log(`  public key: ${signer.publicKey.toStringDer()}`);

    // -----------------------------------------------------------------------
    // Step 3: create a testnet account whose only key is the remote key
    // -----------------------------------------------------------------------
    const createResponse = await new AccountCreateTransaction()
        .setKeyWithoutAlias(signer.publicKey)
        .setInitialBalance(initialBalance)
        .setAccountMemo("hiero-remote-signer vault example")
        .execute(fundingClient);
    const createReceipt = await createResponse.getReceipt(fundingClient);
    const accountId = createReceipt.accountId!;

    console.log("\nStep 3: account created");
    console.log(`  account:     ${accountId.toString()}`);
    console.log(
        `  balance:     ${initialBalance.toString()}, paid by ${fundingAccountId.toString()}`,
    );
    console.log(`  transaction: ${createResponse.transactionId.toString()}`);

    // -----------------------------------------------------------------------
    // Step 4: the new account pays for and signs a transfer. With the
    // remote signer as the client's operator, every signature on every
    // transaction this client sends comes from Vault.
    // -----------------------------------------------------------------------
    remoteClient = setClientOperator(Client.forTestnet(), accountId, signer);

    const transferResponse = await new TransferTransaction()
        .addHbarTransfer(accountId, transferAmount.negated())
        .addHbarTransfer(fundingAccountId, transferAmount)
        .setTransactionMemo("signed by Vault")
        .execute(remoteClient);
    const transferReceipt = await transferResponse.getReceipt(remoteClient);

    console.log("\nStep 4: transfer paid and signed by the remote key");
    console.log(
        `  ${transferAmount.toString()} ${accountId.toString()} -> ${fundingAccountId.toString()}`,
    );
    console.log(`  status:      ${transferReceipt.status.toString()}`);
    console.log(`  transaction: ${transferResponse.transactionId.toString()}`);

    // -----------------------------------------------------------------------
    // Step 5: the funding account pays the fee and signs locally; the
    // remote key co-signs with signWith because it owns the debited account.
    // -----------------------------------------------------------------------
    const coSigned = await new TransferTransaction()
        .addHbarTransfer(accountId, transferAmount.negated())
        .addHbarTransfer(fundingAccountId, transferAmount)
        .setTransactionMemo("co-signed by Vault")
        .freezeWith(fundingClient)
        .signWith(signer.publicKey, signer.sign);
    const coSignResponse = await coSigned.execute(fundingClient);
    const coSignReceipt = await coSignResponse.getReceipt(fundingClient);

    console.log(
        "\nStep 5: transfer paid by the funding account, co-signed by the remote key",
    );
    console.log(
        `  ${transferAmount.toString()} ${accountId.toString()} -> ${fundingAccountId.toString()}`,
    );
    console.log(`  status:      ${coSignReceipt.status.toString()}`);
    console.log(`  transaction: ${coSignResponse.transactionId.toString()}`);

    // -----------------------------------------------------------------------
    // Step 6: read the balance from the mirror node. The mirror node trails
    // consensus by a few seconds, so poll until both transfers show up:
    // the balance must have dropped by at least twice the amount.
    // -----------------------------------------------------------------------
    const expectedAtMost = initialBalance
        .toTinybars()
        .subtract(transferAmount.toTinybars().multiply(2));
    let balance: Hbar | undefined;
    for (let attempt = 0; attempt < 30; attempt++) {
        try {
            const result = await new MirrorNodeAccountBalanceQuery()
                .setAccountId(accountId)
                .execute(remoteClient);
            balance = result.hbars;
            if (balance.toTinybars().lte(expectedAtMost)) break;
        } catch (error) {
            // A brand-new account is unknown until the mirror node catches up.
            const notIndexedYet =
                error instanceof MirrorNodeStatusError &&
                error.status === Status.InvalidAccountId;
            if (!notIndexedYet) throw error;
        }
        await sleep(1000);
    }

    console.log("\nStep 6: balance from the mirror node");
    console.log(
        `  ${accountId.toString()} holds ${balance?.toString() ?? "unknown (mirror node not caught up)"}`,
    );

    // -----------------------------------------------------------------------
    // Step 7: delete the new account and send what is left to the funding
    // account. The remote key pays for and signs this too.
    // -----------------------------------------------------------------------
    const deleteResponse = await new AccountDeleteTransaction()
        .setAccountId(accountId)
        .setTransferAccountId(fundingAccountId)
        .execute(remoteClient);
    const deleteReceipt = await deleteResponse.getReceipt(remoteClient);

    console.log("\nStep 7: account deleted, remaining HBAR returned");
    console.log(`  status:      ${deleteReceipt.status.toString()}`);
    console.log(`  transaction: ${deleteResponse.transactionId.toString()}`);

    // -----------------------------------------------------------------------
    // Step 8: results
    // -----------------------------------------------------------------------
    console.log("\nStep 8: results");
    console.table([
        {
            step: "create account",
            status: createReceipt.status.toString(),
            transaction: createResponse.transactionId.toString(),
        },
        {
            step: "transfer (operator)",
            status: transferReceipt.status.toString(),
            transaction: transferResponse.transactionId.toString(),
        },
        {
            step: "transfer (co-signed)",
            status: coSignReceipt.status.toString(),
            transaction: coSignResponse.transactionId.toString(),
        },
        {
            step: "delete account",
            status: deleteReceipt.status.toString(),
            transaction: deleteResponse.transactionId.toString(),
        },
    ]);
    console.log(
        `History: https://hashscan.io/testnet/account/${accountId.toString()}`,
    );
} finally {
    fundingClient.close();
    remoteClient?.close();
}
