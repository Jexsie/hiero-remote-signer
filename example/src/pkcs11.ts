/**
 * Hiero testnet walkthrough with a key held in a PKCS#11 token (SoftHSM or an HSM).
 *
 * Prerequisite: follow "Option E: PKCS#11 with SoftHSM" in README.md and fill in example/.env.
 * Run: npm run pkcs11
 *
 * The private key never leaves the token. The script:
 *   1. reads the settings
 *   2. connects to the token and loads the public key
 *   3. creates a testnet account owned by that key (your funding account pays)
 *   4. sends HBAR from the new account, which pays and signs through the token
 *   5. sends HBAR again, paid by your funding account and co-signed by the token
 *   6. reads the new account's balance from the mirror node
 *   7. deletes the new account, returning its HBAR to your funding account
 *   8. logs the results
 */
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";

import * as pkcs11js from "pkcs11js";
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
    Pkcs11Constants as C,
    Pkcs11Signer,
    setClientOperator,
} from "hiero-remote-signer/pkcs11";

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

// The PKCS#11 library, the token and its user PIN, and the label of the key
// pair. If the token has no key pair with that label yet, step 2 generates
// one on the curve in PKCS11_KEY_CURVE (secp256k1 or ed25519).
const library = setting("PKCS11_LIBRARY");
const tokenLabel = setting("PKCS11_TOKEN_LABEL");
const pin = setting("PKCS11_PIN");
const keyLabel = setting("PKCS11_KEY_LABEL");
const curve = (process.env.PKCS11_KEY_CURVE ?? "secp256k1").toLowerCase();
if (curve !== "secp256k1" && curve !== "ed25519") {
    throw new Error(
        `PKCS11_KEY_CURVE must be secp256k1 or ed25519, got ${curve}`,
    );
}

const initialBalance = new Hbar(10);
const transferAmount = new Hbar(1);

console.log("Step 1: settings loaded");
console.log(`  funding account: ${fundingAccountId.toString()}`);
console.log(`  token:           ${tokenLabel}, key ${keyLabel}`);

// One loaded module shared by the key generation below and the signer.
const pkcs11 = new pkcs11js.PKCS11();
pkcs11.load(library);
pkcs11.C_Initialize();

// Hiero clients for the funding account and, from step 4 on, the new account.
const fundingClient = Client.forTestnet().setOperator(
    fundingAccountId,
    fundingKey,
);
let remoteClient: Client | undefined;

try {
    // -----------------------------------------------------------------------
    // Step 2: connect to the token and load the public key
    // -----------------------------------------------------------------------
    const slot = pkcs11
        .C_GetSlotList(true)
        .find((s) => pkcs11.C_GetTokenInfo(s).label.trim() === tokenLabel);
    if (!slot) throw new Error(`no token labelled ${tokenLabel}`);

    // Generate a non-extractable key pair on the token unless one with this
    // label already exists. The private key is created inside the token and
    // can never be read out.
    const session = pkcs11.C_OpenSession(
        slot,
        C.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION,
    );
    pkcs11.C_Login(session, C.CKU_USER, pin);
    try {
        pkcs11.C_FindObjectsInit(session, [
            { type: C.CKA_LABEL, value: keyLabel },
        ]);
        const existing = pkcs11.C_FindObjects(session, 1);
        pkcs11.C_FindObjectsFinal(session);

        if (existing.length === 0) {
            const id = randomBytes(8);
            const [mechanism, ecParams] =
                curve === "ed25519"
                    ? // CKM_EC_EDWARDS_KEY_PAIR_GEN, OID 1.3.101.112
                      [0x1055, Buffer.from("06032b6570", "hex")]
                    : // CKM_EC_KEY_PAIR_GEN, OID 1.3.132.0.10
                      [0x1040, Buffer.from("06052b8104000a", "hex")];
            pkcs11.C_GenerateKeyPair(
                session,
                { mechanism },
                [
                    { type: pkcs11js.CKA_TOKEN, value: true },
                    { type: C.CKA_LABEL, value: keyLabel },
                    { type: C.CKA_ID, value: id },
                    { type: pkcs11js.CKA_VERIFY, value: true },
                    { type: C.CKA_EC_PARAMS, value: ecParams },
                ],
                [
                    { type: pkcs11js.CKA_TOKEN, value: true },
                    { type: C.CKA_LABEL, value: keyLabel },
                    { type: C.CKA_ID, value: id },
                    { type: C.CKA_SIGN, value: true },
                    { type: pkcs11js.CKA_PRIVATE, value: true },
                    { type: pkcs11js.CKA_SENSITIVE, value: true },
                    { type: pkcs11js.CKA_EXTRACTABLE, value: false },
                ],
            );
            console.log(
                `\n  generated a ${curve} key pair labelled ${keyLabel}`,
            );
        }
    } finally {
        // Log out so the signer can open and log in to its own session.
        pkcs11.C_Logout(session);
        pkcs11.C_CloseSession(session);
    }

    const signer = await Pkcs11Signer.create({
        pkcs11,
        tokenLabel,
        pin,
        keyLabel,
    });
    console.log("\nStep 2: connected to the token");
    console.log(`  key type:   ${signer.keyType}`);
    console.log(`  public key: ${signer.publicKey.toStringDer()}`);

    // -----------------------------------------------------------------------
    // Step 3: create a testnet account whose only key is the remote key
    // -----------------------------------------------------------------------
    const createResponse = await new AccountCreateTransaction()
        .setKeyWithoutAlias(signer.publicKey)
        .setInitialBalance(initialBalance)
        .setAccountMemo("hiero-remote-signer pkcs11 example")
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
    // transaction this client sends comes from the token.
    // -----------------------------------------------------------------------
    remoteClient = setClientOperator(Client.forTestnet(), accountId, signer);

    const transferResponse = await new TransferTransaction()
        .addHbarTransfer(accountId, transferAmount.negated())
        .addHbarTransfer(fundingAccountId, transferAmount)
        .setTransactionMemo("signed by the token")
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
        .setTransactionMemo("co-signed by the token")
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
    pkcs11.C_Finalize();
    pkcs11.close();
}
