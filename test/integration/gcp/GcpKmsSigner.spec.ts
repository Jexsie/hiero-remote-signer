/**
 * End-to-end test against a live Hiero network and a real Google Cloud KMS key.
 *
 * Skipped unless the Hiero network variables (see test/utils/live-network.ts)
 * and GCP_KMS_KEY_VERSION (the full resource name of an
 * EC_SIGN_SECP256K1_SHA256 or EC_SIGN_ED25519 key version) are set.
 * Credentials come from Application Default Credentials.
 */
import { describe, expect, it } from "vitest";
import { Status } from "@hiero-ledger/sdk";

import { GcpKmsSigner } from "../../../src/gcp/index.js";
import {
    createAccountAndSpend,
    hieroNetworkConfigured,
} from "../../utils/live-network.js";

const configured =
    hieroNetworkConfigured && Boolean(process.env.GCP_KMS_KEY_VERSION);

describe.skipIf(!configured)("GcpKmsSigner on a live Hiero network", () => {
    it("creates an account owned by the Cloud KMS key and spends from it", async () => {
        const signer = await GcpKmsSigner.create({
            keyVersionName: process.env.GCP_KMS_KEY_VERSION!,
        });
        expect(await createAccountAndSpend(signer)).toBe(Status.Success);
    }, 120_000);
});
