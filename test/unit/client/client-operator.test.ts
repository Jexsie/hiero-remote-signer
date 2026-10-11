import { describe, expect, it } from "vitest";
import { Client, PrivateKey } from "@hiero-ledger/sdk";

import { setClientOperator } from "../../../src/client/index.js";
import type { HieroKmsSigner } from "../../../src/types/index.js";

describe("setClientOperator", () => {
    it("sets the signer's public key as the client operator", () => {
        const key = PrivateKey.generateED25519();
        const signer: HieroKmsSigner = {
            keyType: "ED25519",
            publicKey: key.publicKey,
            sign: (bodyBytes) => Promise.resolve(key.sign(bodyBytes)),
        };
        const client = Client.forNetwork({ "127.0.0.1:50211": "0.0.3" });

        const result = setClientOperator(client, "0.0.1234", signer);

        expect(result).toBe(client);
        expect(client.operatorAccountId?.toString()).toBe("0.0.1234");
        expect(client.operatorPublicKey?.toStringRaw()).toBe(
            key.publicKey.toStringRaw(),
        );
        client.close();
    });
});
