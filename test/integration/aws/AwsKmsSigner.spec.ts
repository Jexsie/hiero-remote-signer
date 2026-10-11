/**
 * End-to-end test against a live Hiero network and a real AWS KMS key.
 *
 * Skipped unless all of these are set:
 *   HIERO_NETWORK        JSON map of node address to account ID,
 *                        for example {"127.0.0.1:50211":"0.0.3"} for a local Solo network
 *   HIERO_OPERATOR_ID    funded account used to create the test account
 *   HIERO_OPERATOR_KEY   private key of that account (a local test key);
 *                        HIERO_OPERATOR_KEY_TYPE selects der (default), ecdsa or ed25519
 *   AWS_KMS_KEY_ID       KMS key (ECC_SECG_P256K1 or ECC_NIST_EDWARDS25519)
 * plus the usual AWS credential and region environment variables.
 */
import { describe, expect, it } from "vitest";
import {
    AccountCreateTransaction,
    Client,
    Hbar,
    Status,
    TransferTransaction,
} from "@hiero-ledger/sdk";

import { AwsKmsSigner } from "../../../src/aws/index.js";
import { setClientOperator } from "../../../src/client/index.js";
import { operatorKeyFromEnv } from "../../utils/env.js";

const env = process.env;
const configured = Boolean(
    env.HIERO_NETWORK &&
    env.HIERO_OPERATOR_ID &&
    env.HIERO_OPERATOR_KEY &&
    env.AWS_KMS_KEY_ID,
);

describe.skipIf(!configured)("live Hiero network", () => {
    it("creates an account owned by the KMS key and spends from it", async () => {
        const network = JSON.parse(env.HIERO_NETWORK!) as Record<
            string,
            string
        >;
        const signer = await AwsKmsSigner.create({
            keyId: env.AWS_KMS_KEY_ID!,
        });

        const funding = Client.forNetwork(network).setOperator(
            env.HIERO_OPERATOR_ID!,
            operatorKeyFromEnv(env.HIERO_OPERATOR_KEY!),
        );
        const created = await new AccountCreateTransaction()
            .setKeyWithoutAlias(signer.publicKey)
            .setInitialBalance(new Hbar(5))
            .execute(funding);
        const accountId = (await created.getReceipt(funding)).accountId!;

        // The new account pays for and signs this transfer purely through KMS.
        const kmsClient = setClientOperator(
            Client.forNetwork(network),
            accountId,
            signer,
        );
        const transfer = await new TransferTransaction()
            .addHbarTransfer(accountId, new Hbar(-1))
            .addHbarTransfer(env.HIERO_OPERATOR_ID!, new Hbar(1))
            .execute(kmsClient);
        const receipt = await transfer.getReceipt(kmsClient);

        expect(receipt.status).toBe(Status.Success);
        funding.close();
        kmsClient.close();
    }, 120_000);
});
