import { describe, expect, it } from "vitest";
import {
    AccountId,
    Client,
    Hbar,
    KeyList,
    PrivateKey,
    Transaction,
    TransactionId,
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

const network = () => Client.forNetwork({ "127.0.0.1:50211": "0.0.3" });

const payout = (client: Client) =>
    new TransferTransaction()
        .addHbarTransfer("0.0.1001", new Hbar(-100))
        .addHbarTransfer("0.0.5678", new Hbar(100))
        .setTransactionId(
            // Any payer; signTransaction does not depend on the operator.
            TransactionId.generate("0.0.2"),
        )
        .setNodeAccountIds([new AccountId(3)])
        .freezeWith(client);

describe("RemoteSigner.signTransaction", () => {
    it("adds the key's signature and returns the same transaction", async () => {
        const signer = new LocalSigner();
        const client = network();
        const tx = payout(client);

        const result = await signer.signTransaction(tx);

        expect(result).toBe(tx);
        expect(signer.publicKey.verifyTransaction(tx)).toBe(true);
        client.close();
    });

    it("lets each party of a threshold key sign its own copy of the bytes", async () => {
        const [a, b, c] = [
            new LocalSigner(),
            new LocalSigner(),
            new LocalSigner(),
        ];
        const council = KeyList.of(a.publicKey, b.publicKey, c.publicKey);
        council.setThreshold(2);
        const client = network();

        // The coordinator freezes the payout and sends the bytes around.
        let bytes = payout(client).toBytes();
        for (const party of [a, b]) {
            const copy = Transaction.fromBytes(bytes);
            await party.signTransaction(copy);
            bytes = copy.toBytes();
        }
        const signed = Transaction.fromBytes(bytes);

        expect(a.publicKey.verifyTransaction(signed)).toBe(true);
        expect(b.publicKey.verifyTransaction(signed)).toBe(true);
        expect(c.publicKey.verifyTransaction(signed)).toBe(false);
        client.close();
    });
});

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
