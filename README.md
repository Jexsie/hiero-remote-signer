# hiero-remote-signer

[![CI](https://github.com/Jexsie/hiero-remote-signer/actions/workflows/ci.yml/badge.svg)](https://github.com/Jexsie/hiero-remote-signer/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Sign Hiero transactions with keys that never leave your KMS or HSM.

Give it a key in AWS KMS, Google Cloud KMS, Azure Key Vault, HashiCorp Vault or a PKCS#11 hardware security module, and it returns a signer that the [Hiero JavaScript SDK](https://github.com/hiero-ledger/hiero-sdk-js) already accepts in `Client.setOperatorWith()` and `Transaction.signWith()`. The private key stays in the backend. Your process only sees the public key and the signatures, so you get the backend's access control, audit log and revocation without forking the SDK or adding a wallet layer.

## Install

Requires Node.js 20 or later and `@hiero-ledger/sdk` 2.89 or later. The package is not on npm yet, so install it from GitHub, with the SDK and the client library of your backend:

```sh
npm install github:Jexsie/hiero-remote-signer @hiero-ledger/sdk @aws-sdk/client-kms
```

Each backend has its own entry point, and its client library is an optional peer dependency, so you only install the one you use:

| Backend                                  | Entry point                  | Client library to install | secp256k1 keys | Ed25519 keys |
| ---------------------------------------- | ---------------------------- | ------------------------- | -------------- | ------------ |
| AWS KMS                                  | `hiero-remote-signer/aws`    | `@aws-sdk/client-kms`     | yes            | yes          |
| Google Cloud KMS                         | `hiero-remote-signer/gcp`    | `@google-cloud/kms`       | yes (HSM)      | yes          |
| Azure Key Vault and Managed HSM          | `hiero-remote-signer/azure`  | `@azure/keyvault-keys`    | yes            | no           |
| HashiCorp Vault transit, OpenBao         | `hiero-remote-signer/vault`  | none, uses `fetch`        | no             | yes          |
| Any PKCS#11 token (HSMs, SoftHSM)        | `hiero-remote-signer/pkcs11` | `pkcs11js`                | yes            | yes          |

## Usage

Create a signer for your key, then make it the operator of a client. Every transaction that client sends is paid for and signed by the backend:

```ts
import { Client, Hbar, TransferTransaction } from "@hiero-ledger/sdk";
import { AwsKmsSigner } from "hiero-remote-signer/aws";

const signer = await AwsKmsSigner.create({ keyId: "alias/hiero-treasury" });

// 0.0.1234 is an account whose key is the KMS public key.
const client = signer.setClientOperator(Client.forTestnet(), "0.0.1234");

const response = await new TransferTransaction()
    .addHbarTransfer("0.0.1234", new Hbar(-1))
    .addHbarTransfer("0.0.5678", new Hbar(1))
    .execute(client);

console.log((await response.getReceipt(client)).status.toString()); // SUCCESS
client.close();
```

### Create an account owned by the remote key

An existing account pays, and the new account's key is the backend's public key:

```ts
import { AccountCreateTransaction, Hbar } from "@hiero-ledger/sdk";

const receipt = await (
    await new AccountCreateTransaction()
        .setKeyWithoutAlias(signer.publicKey)
        .setInitialBalance(new Hbar(10))
        .execute(fundingClient)
).getReceipt(fundingClient);

console.log(receipt.accountId?.toString()); // 0.0.7654321
```

### Add the remote key as one signature among several

When someone else pays for a transaction, the remote key can approve it, for example as a treasury key:

```ts
const transaction = await new TransferTransaction()
    .addHbarTransfer(treasuryId, new Hbar(-100))
    .addHbarTransfer(recipientId, new Hbar(100))
    .freezeWith(payerClient)
    .signWith(signer.publicKey, signer.sign);

await transaction.execute(payerClient);
```

### Other backends

Only the signer changes. Credentials follow each cloud SDK's usual resolution: AWS profiles and roles, Google Application Default Credentials, `DefaultAzureCredential`.

```ts
import { GcpKmsSigner } from "hiero-remote-signer/gcp";
const gcp = await GcpKmsSigner.create({
    keyVersionName: "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
});

import { DefaultAzureCredential } from "@azure/identity";
import { AzureKeyVaultSigner } from "hiero-remote-signer/azure";
const azure = await AzureKeyVaultSigner.create({
    keyId: "https://my-vault.vault.azure.net/keys/hiero-treasury/<version>",
    credential: new DefaultAzureCredential(),
});

import { VaultTransitSigner } from "hiero-remote-signer/vault";
const vault = await VaultTransitSigner.create({
    address: "https://vault.example.com:8200",
    token: process.env.VAULT_TOKEN!, // or a function that returns a current token
    keyName: "hiero-treasury",
});

import { Pkcs11Signer } from "hiero-remote-signer/pkcs11";
const hsm = await Pkcs11Signer.create({
    library: "/usr/lib/softhsm/libsofthsm2.so",
    tokenLabel: "hiero",
    pin: process.env.HSM_PIN!,
    keyLabel: "hiero-treasury",
});
// ...
await hsm.close();
```

Every signer extends `RemoteSigner`, so `setClientOperator` works the same on all of them.

Each `create()` also accepts an existing backend client to share connections and credentials with the rest of your application. See the options types in [`src/`](src) for every setting.

### Handling errors

Every failure is a `RemoteSignerError` with a `code`. Backend client errors are attached as `cause`:

```ts
import { RemoteSignerError, RemoteSignerErrorCodes } from "hiero-remote-signer";
import { AwsKmsSigner } from "hiero-remote-signer/aws";

try {
    await AwsKmsSigner.create({ keyId: "alias/hiero-treasury" });
} catch (error) {
    if (
        error instanceof RemoteSignerError &&
        error.code === RemoteSignerErrorCodes.UnsupportedKey
    ) {
        console.error("Hiero cannot verify this key type:", error.message);
    }
    throw error;
}
```

| Code                     | Raised when                                                                                                |
| ------------------------ | ---------------------------------------------------------------------------------------------------------- |
| `UNSUPPORTED_KEY`        | The key's algorithm or curve can't be verified by Hiero networks.                                          |
| `KEY_NOT_USABLE`         | The key exists but can't sign: wrong usage, disabled, derived Vault key, or an ambiguous PKCS#11 label.    |
| `MALFORMED_DER`          | A public key from the backend can't be parsed or is not on its curve.                                      |
| `MALFORMED_SIGNATURE`    | A signature has invalid scalars.                                                                           |
| `MESSAGE_REJECTED`       | An Ed25519 transaction body is over the AWS KMS limit of 4096 bytes.                                       |
| `SIGNATURE_INVALID`      | The backend returned no signature, or one that fails local verification.                                   |
| `INTEGRITY_CHECK_FAILED` | A Cloud KMS response failed its CRC32C check. Retrying is safe.                                            |
| `BACKEND_REQUEST_FAILED` | A request to the backend failed, or the key or token wasn't found.                                         |

### Example: testnet walkthrough

[`example/`](example) has one self-contained script per backend. Each script creates a Hedera testnet account owned by your backend key, spends from it as operator and as co-signer, reads the balance from the mirror node, then deletes the account. Its README covers setting up a key on each backend, from creating the cloud account to the `.env` lines.

```sh
cd example
cp .env.example .env   # add your testnet account and backend key
npm run vault          # or aws, gcp, azure, pkcs11
```

## What It Does

- **Produces signatures Hiero accepts.** It hashes with Keccak-256 for secp256k1 keys and normalizes to low-S, because the SDK rejects high-S signatures, which backends return about half the time. Ed25519 keys sign the raw body.
- **Checks every signature before returning it.** It verifies each signature locally against the public key, so a misconfigured key fails in the signer with a typed error instead of at a consensus node. Disable this with `verifySignatures: false`.
- **Validates public keys.** It decodes DER, PEM, JWK, base64 and `CKA_EC_POINT` keys, checks that secp256k1 points lie on the curve, and refuses curves Hiero cannot verify.
- **Pins the key.** An AWS alias, or an unversioned Azure or Vault key, is resolved once at startup and pinned. Rotating the key can't change the signer under a running process.
- **Leaves the SDK unchanged.** `sign` has the SDK's callback type, so multi-signature transactions, offline signing and `Transaction.fromBytes()` work as they do with local keys.

## Limitations

- **One backend request per node.** The SDK signs a separate body for each node a transaction may be sent to. Use `setNodeAccountIds()` to limit cost, latency and rate-limit use.
- **AWS KMS Ed25519 bodies are capped at 4096 bytes.** `FileAppendTransaction` with its default chunk size exceeds this, so use smaller chunks.
- **No transaction policy checks.** The signer signs whatever the SDK gives it. Spending limits or allow-lists belong in a separate layer that wraps the signer.
- **No key management.** Creating keys, rotating them and updating Hiero account keys are left to each backend's own tooling and approval process.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to report bugs, run the tests and add a backend.

```sh
git clone https://github.com/Jexsie/hiero-remote-signer.git
cd hiero-remote-signer
npm install
npm run test:unit
```

Open a PR with your changes. For larger changes, such as a new backend, please open an issue first to discuss.

## License

Apache-2.0. See [LICENSE](LICENSE).
