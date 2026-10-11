# hiero-remote-signer

`hiero-remote-signer` signs transactions for Hiero-based networks with private keys that stay inside a cloud key management service. It produces the `transactionSigner` callback that the Hiero JavaScript SDK (`@hiero-ledger/sdk`) already accepts in `Transaction.signWith()` and `Client.setOperatorWith()`, so no SDK fork or wallet layer is involved. The first provider is AWS KMS. The only runtime dependency is `@noble/hashes` for Keccak-256, with the SDK and the AWS client declared as peer dependencies.

## Model

### Signer interface

Every provider implements one interface.

```ts
interface HieroRemoteSigner {
    readonly keyType: "ECDSA_SECP256K1" | "ED25519";
    readonly publicKey: PublicKey;                              // @hiero-ledger/sdk PublicKey
    readonly sign: (bodyBytes: Uint8Array) => Promise<Uint8Array>; // 64-byte signature
}
```

The SDK calls `sign` with the serialized `TransactionBody` bytes and stores the result in the transaction's `SignatureMap`. `sign` is bound at construction, so it can be passed as a bare function.

### Key types

Hiero consensus nodes verify two key types. The signer maps AWS KMS key specs onto them and rejects every other spec at construction time.

| AWS key spec | Hiero key type | KMS algorithm | KMS message type | What KMS receives |
|---|---|---|---|---|
| `ECC_SECG_P256K1` | ECDSA secp256k1 | `ECDSA_SHA_256` | `DIGEST` | The Keccak-256 hash of the body, computed locally. |
| `ECC_NIST_EDWARDS25519` | ED25519 | `ED25519_SHA_512` | `RAW` | The body bytes themselves. |

NIST P-256 and RSA keys are refused with `UNSUPPORTED_KEY` because Hiero networks cannot verify them. `ED25519_PH_SHA_512` is never used because Hiero verifies pure Ed25519 and a pre-hashed signature would not validate.

### ECDSA signing procedure

1. The body bytes are hashed with Keccak-256. KMS offers no Keccak option, and signing with `MessageType: RAW` would make KMS apply SHA-256, producing a signature over the wrong digest.
2. The 32-byte digest is sent to KMS `Sign` with `MessageType: DIGEST` and `SigningAlgorithm: ECDSA_SHA_256`. The algorithm name only selects the curve operation when the message is a digest.
3. KMS returns a DER `ECDSA-Sig-Value`. `derSignatureToCompact` parses it strictly, rejects zero, negative and out-of-range scalars, and left-pads `r` and `s` to 32 bytes each.
4. `s` is replaced with `n - s` whenever it lies in the upper half of the curve order. KMS returns a high `s` for about half of all signatures. The SDK verifies with the low-S rule and rejects those signatures, so a signer without this step fails intermittently. Both values form valid signatures over the same digest.
5. The 64-byte `r || s` result is verified locally against the KMS public key before it is returned. This step can be disabled with `verifySignatures: false`.

### Ed25519 signing procedure

The body bytes are sent unchanged with `MessageType: RAW`. AWS KMS accepts at most 4096 bytes in this mode. Bodies above the limit are rejected locally with `MESSAGE_REJECTED` before any KMS request is made. The SDK's default `FileAppendTransaction` chunk of 4096 bytes produces a body above the limit, so file uploads with an Ed25519 KMS key need a smaller chunk size.

### Public key derivation

`AwsKmsSigner.create()` calls `GetPublicKey` once. It checks that `KeyUsage` is `SIGN_VERIFY` and that the required signing algorithm is offered, then parses the DER `SubjectPublicKeyInfo`. The algorithm OID must be `1.3.101.112` for Ed25519, or `1.2.840.10045.2.1` with the named curve `1.3.132.0.10` for secp256k1. secp256k1 points are compressed to 33 bytes, which is the form Hiero stores in account keys. An alias is resolved to the key ARN, and every later `Sign` request uses the ARN so that re-pointing the alias cannot change the signing key under a running process.

### Errors

Every failure surfaces as a `RemoteSignerError` with a `code`. Backend client errors are attached as `cause`.

| Code | Raised when |
|---|---|
| `UNSUPPORTED_KEY` | The key spec or curve cannot be verified by Hiero networks. |
| `KEY_NOT_USABLE` | The key is not a signing key or lacks the required algorithm. |
| `MALFORMED_DER` | A public key structure from KMS cannot be parsed. |
| `MALFORMED_SIGNATURE` | A DER signature has invalid scalars. |
| `MESSAGE_REJECTED` | An Ed25519 body exceeds the 4096-byte KMS limit. |
| `SIGNATURE_INVALID` | KMS returned no signature or one that fails local verification. |
| `BACKEND_REQUEST_FAILED` | A `GetPublicKey` or `Sign` request failed. |

## Flow

```
   construction (once)                         signing (per transaction)

   AwsKmsSigner.create({ keyId })              tx.freezeWith(client)
            |                                           |
   KMS GetPublicKey                            SDK calls sign(bodyBytes) once per node
            |                                           |
   check key spec, usage, algorithm            ECDSA key: hash with Keccak-256
            |                                  Ed25519 key: check size limit
   parse SubjectPublicKeyInfo                           |
            |                                  KMS Sign with DIGEST or RAW
   build SDK PublicKey                                  |
                                               ECDSA key: DER to r||s with low S
                                                        |
                                               verify locally against public key
                                                        |
                                               SDK adds the signature pair
```

## Properties

| Property | Mechanism | Consequence |
|---|---|---|
| The private key never enters the process. | Only `GetPublicKey` and `Sign` are called. | A compromised host can request signatures while it holds credentials, but cannot copy the key. |
| Signing is auditable. | Every `Sign` call is a KMS API request. | CloudTrail records each signature with the caller identity and key ARN. |
| Access is revocable. | Signing rights come from IAM and key policy. | Removing `kms:Sign` stops all signing immediately without rotating the Hiero account key. |
| Signatures are network-valid. | Keccak-256 digest, low-S normalization and local verification. | A signature that would fail at a consensus node fails in the signer instead, with a typed error. |
| The SDK stays unmodified. | The signer matches the SDK callback type. | Offline signing, multi-signature transactions and serialization through `Transaction.fromBytes()` behave as they do with local keys. |

## Request volume

The SDK builds one `TransactionBody` per node account ID and signs each one. A transaction frozen against a client with three nodes therefore makes three `Sign` requests. To limit cost and rate-limit pressure, set fewer node account IDs on the transaction with `setNodeAccountIds()`. AWS KMS meters asymmetric `Sign` requests under their own request quota, separate from symmetric operations.

## Setup

| Requirement | Note |
|---|---|
| Node.js 20 or later | The package is ESM only. |
| `@hiero-ledger/sdk` 2.89 or later | Peer dependency. |
| `@aws-sdk/client-kms` 3.1149 or later | Peer dependency for the `hiero-remote-signer/aws` entry point. |
| A KMS key | Key spec `ECC_SECG_P256K1` or `ECC_NIST_EDWARDS25519`, key usage `SIGN_VERIFY`. |
| IAM permissions | `kms:GetPublicKey` and `kms:Sign` on that key. |

```sh
npm install hiero-remote-signer @hiero-ledger/sdk @aws-sdk/client-kms   # library and peers
aws kms create-key --key-spec ECC_SECG_P256K1 --key-usage SIGN_VERIFY # creates the signing key
```

```ts
import { AccountCreateTransaction, Client, Hbar, TransferTransaction } from "@hiero-ledger/sdk";
import { AwsKmsSigner } from "hiero-remote-signer/aws";
import { setClientOperator } from "hiero-remote-signer";

const signer = await AwsKmsSigner.create({ keyId: "alias/hiero-treasury" });

// Create an account owned by the KMS key (paid for by an existing operator).
await new AccountCreateTransaction().setKeyWithoutAlias(signer.publicKey).setInitialBalance(new Hbar(10)).execute(funder);

// Use the KMS key as the operator of any Hiero network.
const client = setClientOperator(Client.forNetwork({ "127.0.0.1:50211": "0.0.3" }), accountId, signer);

// Or add it as one signature among several.
await tx.freezeWith(client).signWith(signer.publicKey, signer.sign);
```

`AwsKmsSigner.create()` accepts an existing `KMSClient` as `client`, or a `KMSClientConfig` as `clientConfig`, plus `verifySignatures` and `grantTokens`. Credentials and region follow the standard AWS SDK resolution chain. A runnable script is in `examples/transfer.ts`.

## Tests

`npm run test:unit` runs the unit suite with no network access. AWS KMS is replaced by a mock that signs with real secp256k1 and Ed25519 keys and enforces the KMS request contract, so a wrong message type, algorithm or digest length fails the test. Every signature is checked with the SDK's own `PublicKey.verify()` and `verifyTransaction()`, including transactions frozen against three nodes, round-tripped through `Transaction.fromBytes()`, and combined with local keys. `npm run test:unit:coverage` enforces 90% coverage on every metric.

`npm run test:integration` creates an account owned by a real KMS key on a live Hiero network and spends from it. It is skipped unless `HIERO_NETWORK`, `HIERO_OPERATOR_ID`, `HIERO_OPERATOR_KEY` and `AWS_KMS_KEY_ID` are set, either in the environment or in `test/.env` (see `test/.env.example`). A local network started with Solo is sufficient.

`npm run format:check` runs Prettier. `npm run build` type-checks the tests with TypeScript 7, emits ESM and declarations with `tsc`, builds per-file CommonJS with Babel, and mirrors the declarations to `.d.cts`, the same pipeline as hiero-sdk-js.

## Layout

```
src/
  index.ts                    public entry point
  types/                      HieroKeyType and the HieroRemoteSigner interface
  errors/                     RemoteSignerError and RemoteSignerErrorCodes
  client/                     setClientOperator
  der/                        DER reader, SubjectPublicKeyInfo parsing, signature conversion, low-S rule
  aws/                        AWS KMS provider (hiero-remote-signer/aws)
test/
  unit/                       unit tests, mirroring src/
  integration/                live network specs
  utils/                      contract-enforcing AWS KMS mock, assertions, env loading
  vitest.config.ts            unit config (coverage thresholds)
  vitest-integration.config.ts
  tsconfig.test.json
examples/transfer.ts          operator transfer signed through KMS
```

Only `aws/` contains provider code. A new provider implements `HieroRemoteSigner`, reuses `parseSpki` and `derSignatureToCompact`, and lives in its own entry point so that applications only install the cloud client they use.

## Out of scope

**Other KMS providers.** Google Cloud KMS, Azure Key Vault and HashiCorp Vault Transit all offer secp256k1 signing over a supplied digest and return DER signatures, so each needs only key lookup and request code on top of the shared `der/` helpers. They are left out of the first release to keep the AWS implementation reviewable. Adding one costs a peer dependency and a contract mock per provider.

**PKCS#11 hardware modules.** On-premises HSMs reached through PKCS#11 suit operators who cannot use a cloud KMS. The binding requires a native module such as `pkcs11js`, which ties the package to a compiler toolchain and platform builds, so it belongs in a separate package.

**Transaction policy checks.** A wrapper could decode each body before signing and refuse transfers above a limit or to unknown accounts. This is the most useful extension for treasury keys, but it requires decoding protobuf bodies and a policy language, and a mistake there silently blocks or permits funds movement. It is planned as a separate layer that wraps any `HieroRemoteSigner`.

**Parallel per-node signing.** The SDK awaits each node's signature in sequence, so signing latency grows with the node count. Parallelism would require changes inside the SDK. Restricting node account IDs addresses both latency and cost without it.

**Key creation and rotation.** Creating KMS keys and updating Hiero account keys are administrative operations with their own approval paths. Folding them into a signing library would require broader IAM permissions than signing needs.

## License

Apache License 2.0. See `LICENSE`.
