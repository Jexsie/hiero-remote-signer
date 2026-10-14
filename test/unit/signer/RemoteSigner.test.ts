import { describe, expect, it } from "vitest";
import {
    Client,
    Hbar,
    PrivateKey,
    TransferTransaction,
} from "@hiero-ledger/sdk";

import { AwsKmsSigner } from "../../../src/aws/index.js";
import { AzureKeyVaultSigner } from "../../../src/azure/index.js";
import { GcpKmsSigner } from "../../../src/gcp/index.js";
import { Pkcs11Signer } from "../../../src/pkcs11/index.js";
import { RemoteSigner } from "../../../src/signer/index.js";
import type { HieroKeyType } from "../../../src/types/index.js";
import { VaultTransitSigner } from "../../../src/vault/index.js";

/** A RemoteSigner backed by a local key, standing in for a backend. */
class LocalSigner extends RemoteSigner {
    readonly keyType: HieroKeyType = "ED25519";
    readonly #key = PrivateKey.generateED25519();
    readonly publicKey = this.#key.publicKey;
    readonly sign = (bodyBytes: Uint8Array) =>
        Promise.resolve(this.#key.sign(bodyBytes));
}

describe("RemoteSigner.setClientOperator", () => {
    it("makes the key the client's operator and returns the client", () => {
        const signer = new LocalSigner();
        const client = Client.forNetwork({ "127.0.0.1:50211": "0.0.3" });

        const result = signer.setClientOperator(client, "0.0.1234");

        expect(result).toBe(client);
        expect(client.operatorAccountId?.toString()).toBe("0.0.1234");
        expect(client.operatorPublicKey?.toStringRaw()).toBe(
            signer.publicKey.toStringRaw(),
        );
        client.close();
    });

    it("signs the client's transactions with the signer", async () => {
        const signer = new LocalSigner();
        const client = signer.setClientOperator(
            Client.forNetwork({ "127.0.0.1:50211": "0.0.3" }),
            "0.0.1234",
        );

        const tx = new TransferTransaction()
            .addHbarTransfer("0.0.1234", new Hbar(-1))
            .addHbarTransfer("0.0.5678", new Hbar(1))
            .freezeWith(client);
        await tx.signWithOperator(client);

        expect(signer.publicKey.verifyTransaction(tx)).toBe(true);
        client.close();
    });
});

describe.each(
    [
        AwsKmsSigner,
        AzureKeyVaultSigner,
        GcpKmsSigner,
        Pkcs11Signer,
        VaultTransitSigner,
    ].map((Signer) => [Signer.name, Signer] as const),
)("%s", (_name, Signer) => {
    it("extends RemoteSigner", () => {
        expect(Signer.prototype).toBeInstanceOf(RemoteSigner);
    });
});
