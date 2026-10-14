/**
 * Multi-party governance on Hedera testnet: three parties, each with a key in
 * a different backend, jointly control a treasury account. Any two of them
 * must approve every transaction; no single party can move funds alone.
 *
 *   Finance     AWS KMS          (AWS_KMS_*)
 *   Operations  Vault transit    (VAULT_*)
 *   Compliance  PKCS#11 token    (PKCS11_*; run `npm run pkcs11` once first
 *                                 to generate the key pair on the token)
 *
 * Prerequisite: set up those three backends as described in README.md and
 * fill in example/.env.
 * Run: npm run governance
 *
 * The script:
 *   1. reads the settings
 *   2. connects to the three parties' keys
 *   3. creates a treasury account whose key is "2 of these 3 keys"
 *   4. proposes a payout and has only Finance sign it: the network rejects it
 *   5. proposes the payout again; Finance and Operations each sign their own
 *      copy of the transaction bytes, and the network accepts it
 *   6. deletes the treasury, approved by a different pair (Operations and
 *      Compliance), returning its HBAR to your funding account
 *   7. logs the results
 *
 * Your funding account coordinates: it pays the fees and submits, but its key
 * is not part of the treasury key, so it can't approve anything itself.
 */
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { KMSClient } from "@aws-sdk/client-kms";
import {
    AccountCreateTransaction,
    AccountDeleteTransaction,
    AccountId,
    Client,
    Hbar,
    KeyList,
    PrivateKey,
    ReceiptStatusError,
    Transaction,
    TransferTransaction,
} from "@hiero-ledger/sdk";
import type { RemoteSigner } from "hiero-remote-signer";
import { AwsKmsSigner } from "hiero-remote-signer/aws";
import { Pkcs11Signer } from "hiero-remote-signer/pkcs11";
import { VaultTransitSigner } from "hiero-remote-signer/vault";

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

// Your existing testnet account: the coordinator that pays and submits.
const fundingAccountId = AccountId.fromString(setting("FUNDING_ACCOUNT_ID"));
const fundingKeyType = (process.env.FUNDING_KEY_TYPE ?? "ecdsa").toLowerCase();
const fundingKey =
    fundingKeyType === "ed25519"
        ? PrivateKey.fromStringED25519(setting("FUNDING_PRIVATE_KEY"))
        : fundingKeyType === "der"
          ? PrivateKey.fromStringDer(setting("FUNDING_PRIVATE_KEY"))
          : PrivateKey.fromStringECDSA(setting("FUNDING_PRIVATE_KEY"));

const treasuryBalance = new Hbar(10);
const payoutAmount = new Hbar(1);

console.log("Step 1: settings loaded");
console.log(`  coordinator: ${fundingAccountId.toString()}`);

const kms = new KMSClient({});
const coordinator = Client.forTestnet().setOperator(
    fundingAccountId,
    fundingKey,
);
let compliance: Pkcs11Signer | undefined;

try {
    // -----------------------------------------------------------------------
    // Step 2: connect to the three parties' keys. In production each party
    // runs this in its own environment, with its own credentials; nobody
    // holds anyone else's key or credentials.
    // -----------------------------------------------------------------------
    const finance = await AwsKmsSigner.create({
        keyId: setting("AWS_KMS_KEY_ID"),
        client: kms,
    });
    const operations = await VaultTransitSigner.create({
        address: setting("VAULT_ADDR"),
        token: setting("VAULT_TOKEN"),
        keyName: setting("VAULT_TRANSIT_KEY"),
    });
    compliance = await Pkcs11Signer.create({
        library: setting("PKCS11_LIBRARY"),
        tokenLabel: setting("PKCS11_TOKEN_LABEL"),
        pin: setting("PKCS11_PIN"),
        keyLabel: setting("PKCS11_KEY_LABEL"),
    });

    console.log("\nStep 2: connected to the three parties");
    for (const [name, party] of [
        ["Finance (AWS KMS)", finance],
        ["Operations (Vault)", operations],
        ["Compliance (PKCS#11)", compliance],
    ] as const) {
        console.log(
            `  ${name.padEnd(21)} ${party.keyType.padEnd(15)} ${party.publicKey.toStringDer()}`,
        );
    }

    // -----------------------------------------------------------------------
    // Step 3: create the treasury. Its key is a threshold key list: any 2 of
    // the 3 parties' keys must sign. The coordinator pays.
    // -----------------------------------------------------------------------
    const treasuryKey = KeyList.of(
        finance.publicKey,
        operations.publicKey,
        compliance.publicKey,
    ).setThreshold(2);

    const createResponse = await new AccountCreateTransaction()
        .setKeyWithoutAlias(treasuryKey)
        .setInitialBalance(treasuryBalance)
        .setAccountMemo("hiero-remote-signer governance example")
        .execute(coordinator);
    const createReceipt = await createResponse.getReceipt(coordinator);
    const treasuryId = createReceipt.accountId!;

    console.log("\nStep 3: treasury created, key = 2 of 3 parties");
    console.log(`  treasury:    ${treasuryId.toString()}`);
    console.log(`  balance:     ${treasuryBalance.toString()}`);
    console.log(`  transaction: ${createResponse.transactionId.toString()}`);

    // -----------------------------------------------------------------------
    // Step 4: a payout approved by Finance alone. The coordinator freezes it
    // and sends the bytes to Finance, which signs and sends them back. One
    // signature doesn't meet the threshold, so the network rejects it.
    // -----------------------------------------------------------------------
    const proposal1 = new TransferTransaction()
        .addHbarTransfer(treasuryId, payoutAmount.negated())
        .addHbarTransfer(fundingAccountId, payoutAmount)
        .setTransactionMemo("payout approved by one party")
        .freezeWith(coordinator)
        .toBytes();

    const financeOnly = Transaction.fromBytes(proposal1);
    await finance.signTransaction(financeOnly);

    const rejectedResponse = await financeOnly.execute(coordinator);
    let rejectedStatus: string;
    try {
        rejectedStatus = (
            await rejectedResponse.getReceipt(coordinator)
        ).status.toString();
    } catch (error) {
        if (!(error instanceof ReceiptStatusError)) throw error;
        rejectedStatus = error.status.toString();
    }

    console.log("\nStep 4: payout signed by Finance only");
    console.log(
        `  status:      ${rejectedStatus} (1 of 2 required signatures)`,
    );
    console.log(`  transaction: ${rejectedResponse.transactionId.toString()}`);

    // -----------------------------------------------------------------------
    // Step 5: the same payout, approved by Finance and Operations. Each
    // party restores the bytes, adds its signature and passes the bytes on;
    // the bytes are all that travels between parties.
    // -----------------------------------------------------------------------
    let proposal2 = new TransferTransaction()
        .addHbarTransfer(treasuryId, payoutAmount.negated())
        .addHbarTransfer(fundingAccountId, payoutAmount)
        .setTransactionMemo("payout approved by two parties")
        .freezeWith(coordinator)
        .toBytes();

    for (const party of [finance, operations] satisfies RemoteSigner[]) {
        const copy = Transaction.fromBytes(proposal2);
        await party.signTransaction(copy);
        proposal2 = copy.toBytes();
    }

    const approvedResponse =
        await Transaction.fromBytes(proposal2).execute(coordinator);
    const approvedReceipt = await approvedResponse.getReceipt(coordinator);

    console.log("\nStep 5: payout signed by Finance and Operations");
    console.log(
        `  ${payoutAmount.toString()} ${treasuryId.toString()} -> ${fundingAccountId.toString()}`,
    );
    console.log(`  status:      ${approvedReceipt.status.toString()}`);
    console.log(`  transaction: ${approvedResponse.transactionId.toString()}`);

    // -----------------------------------------------------------------------
    // Step 6: delete the treasury and return its HBAR. Any 2 of 3 will do,
    // so this time Operations and Compliance approve.
    // -----------------------------------------------------------------------
    const deletion = new AccountDeleteTransaction()
        .setAccountId(treasuryId)
        .setTransferAccountId(fundingAccountId)
        .freezeWith(coordinator);
    await operations.signTransaction(deletion);
    await compliance.signTransaction(deletion);

    const deleteResponse = await deletion.execute(coordinator);
    const deleteReceipt = await deleteResponse.getReceipt(coordinator);

    console.log("\nStep 6: treasury deleted by Operations and Compliance");
    console.log(`  status:      ${deleteReceipt.status.toString()}`);
    console.log(`  transaction: ${deleteResponse.transactionId.toString()}`);

    // -----------------------------------------------------------------------
    // Step 7: results
    // -----------------------------------------------------------------------
    console.log("\nStep 7: results");
    console.table([
        {
            step: "create treasury (2 of 3)",
            approvedBy: "-",
            status: createReceipt.status.toString(),
        },
        {
            step: "payout",
            approvedBy: "Finance",
            status: rejectedStatus,
        },
        {
            step: "payout",
            approvedBy: "Finance, Operations",
            status: approvedReceipt.status.toString(),
        },
        {
            step: "delete treasury",
            approvedBy: "Operations, Compliance",
            status: deleteReceipt.status.toString(),
        },
    ]);
    console.log(
        `History: https://hashscan.io/testnet/account/${treasuryId.toString()}`,
    );
} finally {
    coordinator.close();
    kms.destroy();
    await compliance?.close();
}
