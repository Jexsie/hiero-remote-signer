/**
 * End-to-end test against a live Hiero network and a real AWS KMS key.
 *
 * Skipped unless the Hiero network variables (see test/utils/live-network.ts)
 * and AWS_KMS_KEY_ID (an ECC_SECG_P256K1 or ECC_NIST_EDWARDS25519 key) are
 * set, plus the usual AWS credential and region environment variables.
 */
import { describe, expect, it } from "vitest";
import { Status } from "@hiero-ledger/sdk";

import { AwsKmsSigner } from "../../../src/aws/index.js";
import {
    createAccountAndSpend,
    hieroNetworkConfigured,
} from "../../utils/live-network.js";

const configured =
    hieroNetworkConfigured && Boolean(process.env.AWS_KMS_KEY_ID);

describe.skipIf(!configured)("AwsKmsSigner on a live Hiero network", () => {
    it("creates an account owned by the KMS key and spends from it", async () => {
        const signer = await AwsKmsSigner.create({
            keyId: process.env.AWS_KMS_KEY_ID!,
        });
        expect(await createAccountAndSpend(signer)).toBe(Status.Success);
    }, 120_000);
});
