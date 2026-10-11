/**
 * End-to-end test against a live Hiero network and a real Azure Key Vault key.
 *
 * Skipped unless the Hiero network variables (see test/utils/live-network.ts)
 * and AZURE_KEY_VAULT_KEY_ID (a versioned identifier of an EC or EC-HSM key
 * on curve P-256K) are set. Credentials come from DefaultAzureCredential.
 */
import { describe, expect, it } from "vitest";
import { DefaultAzureCredential } from "@azure/identity";
import { Status } from "@hiero-ledger/sdk";

import { AzureKeyVaultSigner } from "../../../src/azure/index.js";
import {
    createAccountAndSpend,
    hieroNetworkConfigured,
} from "../../utils/live-network.js";

const configured =
    hieroNetworkConfigured && Boolean(process.env.AZURE_KEY_VAULT_KEY_ID);

describe.skipIf(!configured)(
    "AzureKeyVaultSigner on a live Hiero network",
    () => {
        it("creates an account owned by the Key Vault key and spends from it", async () => {
            const signer = await AzureKeyVaultSigner.create({
                keyId: process.env.AZURE_KEY_VAULT_KEY_ID!,
                credential: new DefaultAzureCredential(),
            });
            expect(await createAccountAndSpend(signer)).toBe(Status.Success);
        }, 120_000);
    },
);
