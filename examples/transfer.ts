/**
 * Sends a transfer from an account whose key is held in AWS KMS.
 *
 *   HIERO_NETWORK='{"127.0.0.1:50211":"0.0.3"}' \
 *   HIERO_ACCOUNT_ID=0.0.1234 \
 *   AWS_KMS_KEY_ID=alias/hiero-treasury AWS_REGION=eu-central-1 \
 *   node --experimental-strip-types examples/transfer.ts
 */
import { Client, Hbar, TransferTransaction } from "@hiero-ledger/sdk";
import { AwsKmsSigner } from "hiero-kms-signer/aws";
import { setClientOperator } from "hiero-kms-signer";

const network = JSON.parse(process.env.HIERO_NETWORK!) as Record<
    string,
    string
>;
const accountId = process.env.HIERO_ACCOUNT_ID!;

const signer = await AwsKmsSigner.create({
    keyId: process.env.AWS_KMS_KEY_ID!,
});
console.log(
    `KMS key ${signer.keyArn} (${signer.keyType}) -> ${signer.publicKey.toStringDer()}`,
);

const client = setClientOperator(Client.forNetwork(network), accountId, signer);

const response = await new TransferTransaction()
    .addHbarTransfer(accountId, new Hbar(-1))
    .addHbarTransfer("0.0.98", new Hbar(1))
    .execute(client);

const receipt = await response.getReceipt(client);
console.log(
    `${response.transactionId.toString()} -> ${receipt.status.toString()}`,
);
client.close();
