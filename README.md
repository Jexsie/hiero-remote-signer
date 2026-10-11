# hiero-remote-signer

`hiero-remote-signer` signs transactions for Hiero-based networks with private keys that stay outside the process: in a cloud key management service or a hardware security module. It produces the `transactionSigner` callback that the Hiero JavaScript SDK (`@hiero-ledger/sdk`) already accepts in `Transaction.signWith()` and `Client.setOperatorWith()`, so no SDK fork or wallet layer is involved.

Each backend lives in its own entry point, and its client library is an optional peer dependency, so an application installs only the client it uses. The only runtime dependency is `@noble/hashes` for Keccak-256.

| Entry point | Backend | secp256k1 | Ed25519 | Peer dependency |
|---|---|---|---|---|
| `hiero-remote-signer/aws` | AWS KMS | yes | yes (bodies up to 4096 bytes) | `@aws-sdk/client-kms` |
| `hiero-remote-signer/gcp` | Google Cloud KMS | yes (HSM protection level) | yes (software protection level) | `@google-cloud/kms` |
| `hiero-remote-signer/azure` | Azure Key Vault and Managed HSM | yes | no, Key Vault has no Ed25519 keys | `@azure/keyvault-keys` |
| `hiero-remote-signer/vault` | HashiCorp Vault transit, OpenBao | no, transit has no secp256k1 keys | yes | none, uses `fetch` |
| `hiero-remote-signer/pkcs11` | Any PKCS#11 token (HSMs, SoftHSM) | yes | yes (PKCS#11 v3.0 `CKM_EDDSA`) | `pkcs11js` |

## Model

### Signer interface

Every backend implements one interface.

```ts
interface HieroRemoteSigner {
    readonly keyType: "ECDSA_SECP256K1" | "ED25519";
    readonly publicKey: PublicKey;                                 // @hiero-ledger/sdk PublicKey
    readonly sign: (bodyBytes: Uint8Array) => Promise<Uint8Array>; // 64-byte signature
}
```

The SDK calls `sign` with the serialized `TransactionBody` bytes and stores the result in the transaction's `SignatureMap`. `sign` is bound at construction, so it can be passed as a bare function. Each backend is constructed with an async `create()` that reads and validates the public key once.

### ECDSA secp256k1 signing

1. The body bytes are hashed with Keccak-256, the digest Hiero verifies. No backend offers Keccak, so every backend is asked to sign a supplied 32-byte digest. Asking a backend to hash the raw message would produce a signature over the wrong digest.
2. The backend signs the digest. Algorithm names such as `ECDSA_SHA_256`, `EC_SIGN_SECP256K1_SHA256` or `ES256K` only select the curve operation when the input is a digest.
3. The signature comes back as DER (AWS, GCP, some PKCS#11 tokens) or as 64-byte `r || s` (Azure, PKCS#11). `derSignatureToCompact` and `normalizeCompactSignature` parse it strictly and reject zero, negative and out-of-range scalars.
4. `s` is replaced with `n - s` whenever it lies in the upper half of the curve order. Backends return a high `s` for about half of all signatures. The SDK verifies with the low-S rule and rejects those signatures, so a signer without this step fails intermittently. Both values form valid signatures over the same digest.
5. The 64-byte result is verified locally against the public key before it is returned. This step can be disabled with `verifySignatures: false`.

### Ed25519 signing

The body bytes are sent unchanged and signed with pure Ed25519, which is what Hiero verifies. Pre-hashed variants (Ed25519ph) are never used because their signatures would not validate.

### Public keys

Backends report public keys as DER `SubjectPublicKeyInfo` (AWS), PEM (GCP), JWK coordinates (Azure), raw base64 (Vault) or `CKA_EC_POINT` (PKCS#11). Each is reduced to the form Hiero stores in account keys: a 32-byte Ed25519 key or a 33-byte compressed secp256k1 point. Uncompressed secp256k1 points are checked against the curve equation before compression, because compression keeps only `x` and the parity of `y` and would silently turn an off-curve point into a different key. Keys on any other curve are refused with `UNSUPPORTED_KEY`, because Hiero networks cannot verify them.

Where a backend resolves a moving reference, the signer pins what it resolved: an AWS alias becomes the key ARN, and an unversioned Azure or Vault key is pinned to its latest version at construction. Re-pointing the alias or rotating the key therefore cannot change the signing key under a running process.

### Errors

Every failure surfaces as a `RemoteSignerError` with a `code`. Backend client errors are attached as `cause`.

| Code | Raised when |
|---|---|
| `UNSUPPORTED_KEY` | The key's algorithm or curve cannot be verified by Hiero networks. |
| `KEY_NOT_USABLE` | The key exists but cannot sign: wrong usage, disabled, missing algorithm, derived Vault key, or an ambiguous PKCS#11 label. |
| `MALFORMED_DER` | A public key returned by the backend cannot be parsed or is not on its curve. |
| `MALFORMED_SIGNATURE` | A signature has invalid scalars. |
| `MESSAGE_REJECTED` | An Ed25519 body exceeds the AWS KMS 4096-byte limit. |
| `SIGNATURE_INVALID` | The backend returned no signature or one that fails local verification. |
| `INTEGRITY_CHECK_FAILED` | A Cloud KMS response failed its CRC32C check. Discard it; retrying is safe. |
| `BACKEND_REQUEST_FAILED` | A request to the backend failed, or the key or token was not found. |

## Backends

### AWS KMS

| Key spec | Hiero key type | Algorithm | Message type |
|---|---|---|---|
| `ECC_SECG_P256K1` | ECDSA secp256k1 | `ECDSA_SHA_256` | `DIGEST` (the Keccak-256 hash) |
| `ECC_NIST_EDWARDS25519` | ED25519 | `ED25519_SHA_512` | `RAW` (the body) |

AWS KMS accepts at most 4096 bytes with `MessageType: RAW`. Larger Ed25519 bodies are rejected locally with `MESSAGE_REJECTED` before any request. The SDK's default `FileAppendTransaction` chunk of 4096 bytes produces a body above the limit, so file uploads with an Ed25519 KMS key need a smaller chunk size. Required permissions are `kms:GetPublicKey` and `kms:Sign`.

```ts
import { AwsKmsSigner } from "hiero-remote-signer/aws";

const signer = await AwsKmsSigner.create({ keyId: "alias/hiero-treasury" });
```

`create()` also accepts an existing `KMSClient` as `client` or a `KMSClientConfig` as `clientConfig`, and `grantTokens`. Credentials and region follow the standard AWS SDK resolution chain.

### Google Cloud KMS

| Algorithm | Hiero key type | Protection level | Request field |
|---|---|---|---|
| `EC_SIGN_SECP256K1_SHA256` | ECDSA secp256k1 | HSM | `digest.sha256` (the Keccak-256 hash) |
| `EC_SIGN_ED25519` | ED25519 | software | `data` (the body) |

Every request carries a CRC32C checksum, and every response is checked for `verifiedDigestCrc32c` or `verifiedDataCrc32c`, the signature checksum and the key version name, as Cloud KMS recommends. Required permissions are `cloudkms.cryptoKeyVersions.viewPublicKey` and `cloudkms.cryptoKeyVersions.useToSign`.

```ts
import { GcpKmsSigner } from "hiero-remote-signer/gcp";

const signer = await GcpKmsSigner.create({
    keyVersionName: "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
});
```

### Azure Key Vault and Managed HSM

Supports `EC` and `EC-HSM` keys on curve `P-256K`, signed with `ES256K` over the Keccak-256 digest. Key Vault returns the JWS `r || s` form. The key needs the `sign` operation, and the caller needs the `keys/get` and `keys/sign` permissions (for example the Key Vault Crypto User role).

```ts
import { DefaultAzureCredential } from "@azure/identity";
import { AzureKeyVaultSigner } from "hiero-remote-signer/azure";

const signer = await AzureKeyVaultSigner.create({
    keyId: "https://my-vault.vault.azure.net/keys/hiero-treasury/<version>",
    credential: new DefaultAzureCredential(),
});
```

Existing `KeyClient` and `CryptographyClient` instances can be passed as `keyClient` and `cryptographyClient`.

### HashiCorp Vault transit

Supports non-derived `ed25519` transit keys. Derived keys are rejected because they need a per-request context. The signer calls the transit HTTP API with `fetch`, so it needs no Vault client library and also works with OpenBao. The token needs `read` on `<mount>/keys/<name>` and `update` on `<mount>/sign/<name>`.

```ts
import { VaultTransitSigner } from "hiero-remote-signer/vault";

const signer = await VaultTransitSigner.create({
    address: "https://vault.example.com:8200",
    token: () => readCurrentToken(), // a string, or a function for renewing tokens
    keyName: "hiero-treasury",
});
```

`mountPath`, `keyVersion`, `namespace` (Vault Enterprise) and a custom `fetch` (for example with a TLS agent) are optional.

### PKCS#11

Supports EC keys on secp256k1, signed with `CKM_ECDSA` over the Keccak-256 digest, and Edwards keys on Ed25519, signed with `CKM_EDDSA` over the body (PKCS#11 v3.0). Both the standard DER-wrapped and the raw `CKA_EC_POINT` encodings are accepted, as are the OID and `edwards25519` name forms of `CKA_EC_PARAMS`. A session runs one operation at a time, so concurrent `sign` calls are queued.

```ts
import { Pkcs11Signer } from "hiero-remote-signer/pkcs11";

const signer = await Pkcs11Signer.create({
    library: "/usr/lib/softhsm/libsofthsm2.so",
    tokenLabel: "hiero",
    pin: process.env.HSM_PIN!,
    keyLabel: "hiero-treasury",
});
// ...
await signer.close();
```

The key pair is found by `keyLabel`, `keyId` (`CKA_ID`) or both. Several signers can share one initialized `pkcs11js` module through the `pkcs11` option. `close()` closes the session, and finalizes the module only if the signer initialized it.

## Usage

```ts
import { AccountCreateTransaction, Client, Hbar } from "@hiero-ledger/sdk";
import { setClientOperator } from "hiero-remote-signer";

// Create an account owned by the remote key (paid for by an existing operator).
await new AccountCreateTransaction().setKeyWithoutAlias(signer.publicKey).setInitialBalance(new Hbar(10)).execute(funder);

// Use the remote key as the operator of any Hiero network.
const client = setClientOperator(Client.forNetwork({ "127.0.0.1:50211": "0.0.3" }), accountId, signer);

// Or add it as one signature among several.
await tx.freezeWith(client).signWith(signer.publicKey, signer.sign);
```

## Flow

```
   construction (once)                         signing (per transaction)

   <Backend>Signer.create(options)             tx.freezeWith(client)
            |                                           |
   read the public key                         SDK calls sign(bodyBytes) once per node
            |                                           |
   check key type, usage, algorithm            ECDSA key: hash with Keccak-256
            |                                  Ed25519 key: send the body
   decode and validate the public key                   |
            |                                  backend signs
   pin the resolved key or version                      |
            |                                  ECDSA key: to r||s with low S
   build SDK PublicKey                                  |
                                               verify locally against public key
                                                        |
                                               SDK adds the signature pair
```

## Properties

| Property | Mechanism | Consequence |
|---|---|---|
| The private key never enters the process. | Only public-key reads and sign operations are called. | A compromised host can request signatures while it holds credentials, but cannot copy the key. |
| Signing is auditable. | Every signature is a backend request. | Cloud audit logs (CloudTrail, Cloud Audit Logs, Azure Monitor, Vault audit devices) record each signature with the caller identity. |
| Access is revocable. | Signing rights come from the backend's access control. | Removing the sign permission stops all signing immediately without rotating the Hiero account key. |
| Signatures are network-valid. | Keccak-256 digest, low-S normalization and local verification. | A signature that would fail at a consensus node fails in the signer instead, with a typed error. |
| The SDK stays unmodified. | The signer matches the SDK callback type. | Offline signing, multi-signature transactions and serialization through `Transaction.fromBytes()` behave as they do with local keys. |

## Request volume

The SDK builds one `TransactionBody` per node account ID and signs each one. A transaction frozen against a client with three nodes therefore makes three sign requests. To limit cost, latency and rate-limit pressure, set fewer node account IDs on the transaction with `setNodeAccountIds()`.

## Setup

| Requirement | Note |
|---|---|
| Node.js 20 or later | ESM and CommonJS builds are published. Loading the CommonJS build needs Node.js 20.19 or 22.12 or later, because `@noble/hashes` is ESM only. |
| `@hiero-ledger/sdk` 2.89 or later | Peer dependency. |
| The backend's client library | Optional peer dependency, see the table at the top. |

```sh
npm install hiero-remote-signer @hiero-ledger/sdk @aws-sdk/client-kms   # library, SDK and one backend client
```

## Tests

`npm run test:unit` runs the unit suite with no network access. Each backend is replaced by a fake that signs with real secp256k1 and Ed25519 keys and enforces that backend's request contract, so a wrong message type, digest field, checksum, key version or PKCS#11 operation order fails the test. Every signature is checked with the SDK's own `PublicKey.verify()` and `verifyTransaction()`, including transactions frozen against three nodes, round-tripped through `Transaction.fromBytes()`, and combined with local keys. `npm run test:unit:coverage` enforces 90% coverage on every metric.

`npm run test:integration` runs the specs under `test/integration`, each skipped unless its variables are set in the environment or in `test/.env` (see `test/.env.example`):

| Spec | Needs | Runs in CI |
|---|---|---|
| Vault against a real server | `VAULT_ADDR`, `VAULT_TOKEN` (a dev server is enough) | yes, against a Vault container |
| PKCS#11 against a real token | `PKCS11_LIBRARY`, `PKCS11_TOKEN_LABEL`, `PKCS11_PIN` | yes, against SoftHSM |
| Every backend on a live Hiero network | `HIERO_NETWORK`, `HIERO_OPERATOR_ID`, `HIERO_OPERATOR_KEY` and the backend's key variable | no, needs cloud credentials |

The live network specs create an account owned by the remote key and spend from it. A local network started with Solo is sufficient.

`npm run format:check` runs Prettier. `npm run build` type-checks the tests with TypeScript 7, emits ESM and declarations with `tsc`, builds per-file CommonJS with Babel, and mirrors the declarations to `.d.cts`, the same pipeline as hiero-sdk-js.

## Layout

```
src/
  index.ts                    public entry point
  types/                      HieroKeyType and the HieroRemoteSigner interface
  errors/                     RemoteSignerError and RemoteSignerErrorCodes
  client/                     setClientOperator
  der/                        DER and PEM decoding, SubjectPublicKeyInfo parsing, signature conversion, low-S rule
  aws/                        AWS KMS (hiero-remote-signer/aws)
  gcp/                        Google Cloud KMS (hiero-remote-signer/gcp)
  azure/                      Azure Key Vault (hiero-remote-signer/azure)
  vault/                      HashiCorp Vault transit (hiero-remote-signer/vault)
  pkcs11/                     PKCS#11 (hiero-remote-signer/pkcs11)
test/
  unit/                       unit tests, mirroring src/
  integration/                real backend and live network specs
  utils/                      contract-enforcing backend fakes, shared key material, assertions, env loading
  vitest.config.ts            unit config (coverage thresholds)
  vitest-integration.config.ts
  tsconfig.test.json
```

`types/`, `errors/`, `client/` and `der/` contain no backend code. A new backend implements `HieroRemoteSigner`, reuses the `der/` helpers, gets a contract-enforcing fake under `test/utils/`, and lives in its own entry point with its client library as an optional peer dependency.

## Out of scope

**Transaction policy checks.** A wrapper could decode each body before signing and refuse transfers above a limit or to unknown accounts. This is the most useful extension for treasury keys, but it requires decoding protobuf bodies and a policy language, and a mistake there silently blocks or permits funds movement. It is planned as a separate layer that wraps any `HieroRemoteSigner`.

**Parallel per-node signing.** The SDK awaits each node's signature in sequence, so signing latency grows with the node count. Parallelism would require changes inside the SDK. Restricting node account IDs addresses both latency and cost without it.

**Key creation and rotation.** Creating keys and updating Hiero account keys are administrative operations with their own approval paths. Folding them into a signing library would require broader permissions than signing needs.

## License

Apache License 2.0. See `LICENSE`.
