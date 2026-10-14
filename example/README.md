# hiero-remote-signer example

This walkthrough creates a real Hedera testnet account whose only key lives in a remote signer, then spends from it. The private key never leaves the signer: AWS KMS, Google Cloud KMS, Azure Key Vault, HashiCorp Vault (or OpenBao) transit, or a PKCS#11 token such as SoftHSM.

It uses two accounts:

- **Funding account:** the testnet account you already have, with its private key held locally. It pays to create the second account.
- **Remote-key account:** a new account created by the example. It can only be controlled through the remote signer.

Every script in `src/` is self-contained and reads top to bottom, with every step written out in that file. There is one script per backend, plus a governance script that combines three backends:

| Command              | File                | Backend                                                |
| -------------------- | ------------------- | ------------------------------------------------------ |
| `npm run governance` | `src/governance.ts` | AWS KMS, Vault and PKCS#11 together, as three parties  |
| `npm run aws`    | `src/aws.ts`    | AWS KMS                              |
| `npm run gcp`    | `src/gcp.ts`    | Google Cloud KMS                     |
| `npm run azure`  | `src/azure.ts`  | Azure Key Vault                      |
| `npm run vault`  | `src/vault.ts`  | HashiCorp Vault or OpenBao transit   |
| `npm run pkcs11` | `src/pkcs11.ts` | PKCS#11 token (SoftHSM or a real HSM) |

The five backend scripts run the same eight steps:

1. **Settings:** reads `example/.env`.
2. **Connect:** connects to the backend and loads the public key. The PKCS#11 script first generates the key pair on the token if it doesn't exist yet.
3. **Create the account:** creates a testnet account whose only key is the remote key, with 10 HBAR. Your funding account pays.
4. **Transfer as operator:** the new account sends 1 HBAR to your funding account. The new account pays the fee, and every signature comes from the backend (`signer.setClientOperator`).
5. **Co-signed transfer:** 1 HBAR more, with the fee paid by your funding account. The remote key approves the debit with `signer.signTransaction`, which is how a treasury or custody key approves a payout prepared by another service.
6. **Balance:** reads the new account's balance from the mirror node. The mirror node trails the network by a few seconds, so the script waits until both transfers show up.
7. **Clean up:** deletes the new account, which is also signed by the remote key, and returns the remaining HBAR to your funding account. A run costs only transaction fees.
8. **Results:** prints a table with each transaction's status and ID, plus a HashScan link.

For a backend script, set up **one** backend in [step 2](#2-set-up-one-backend). For the governance script, set up AWS KMS, Vault and PKCS#11 (options A, D and E). The rest of the steps are the same for every script.

### The governance script

Three parties jointly control a treasury account, each with a key in a different backend: Finance on AWS KMS, Operations on Vault and Compliance on a PKCS#11 token. The treasury's key is a threshold key list, so any two of the three must approve every transaction. Your funding account acts as coordinator: it pays the fees and submits, but its key isn't part of the treasury key, so it can't approve anything.

1. **Settings and parties:** reads `example/.env` and connects to the three keys.
2. **Create the treasury:** an account whose key is "2 of these 3 keys", funded with 10 HBAR.
3. **One approval:** the coordinator proposes a payout and only Finance signs it. The network rejects it with `INVALID_SIGNATURE`.
4. **Two approvals:** the same payout, and this time Finance and Operations each restore the transaction bytes, sign their copy with `signTransaction`, and pass the bytes on. The network accepts it.
5. **Clean up:** a different pair, Operations and Compliance, approves deleting the treasury, and the remaining HBAR returns to your funding account.
6. **Results:** a table of who approved what, plus a HashScan link.

The script reuses the AWS, Vault and PKCS#11 settings from `.env`. It doesn't generate the PKCS#11 key pair, so run `npm run pkcs11` once first; its step 2 creates the key on the token.

## 1. Prepare the repository and your testnet account

1. Install Node.js 20.12 or newer.
2. From the repository root, install dependencies. This also builds the package into `dist/`, which the example imports:

    ```sh
    npm install
    ```

3. Create your settings file:

    ```sh
    cd example
    cp .env.example .env
    ```

4. Fill in your testnet account in `example/.env`.

    You need an account ID and private key from [portal.hedera.com](https://portal.hedera.com): sign in, choose **Testnet**, and create an account if you don't have one.

    ```sh
    FUNDING_ACCOUNT_ID=0.0.1234567
    FUNDING_PRIVATE_KEY=0x...        # the HEX key from the portal
    FUNDING_KEY_TYPE=ecdsa           # ecdsa for the portal's HEX ECDSA key,
                                     # der for a DER string (302e... / 3030...),
                                     # ed25519 for a hex Ed25519 key
    ```

    The account needs about 15 HBAR; most of it comes back at the end of each run. If it runs low, refill it from the portal faucet.

`.env` is git-ignored, so keep secrets there and nowhere else.

## 2. Set up one backend

Each section creates a signing key, gives your identity permission to read its public key and sign with it, and lists the `.env` lines to set.

Supported key types:

| Backend        | secp256k1 (Hiero ECDSA)    | Ed25519           |
| -------------- | -------------------------- | ----------------- |
| AWS KMS        | yes                        | yes               |
| Google Cloud   | yes (HSM protection level) | yes (software)    |
| Azure          | yes (`P-256K`)             | no                |
| Vault, OpenBao | no                         | yes               |
| PKCS#11        | yes, if the token has it   | yes, on SoftHSM 2.6+ |

### Option A: AWS KMS

1. **AWS account.** Create one at [aws.amazon.com](https://aws.amazon.com) if you don't have one.

2. **AWS CLI.** Install it with `brew install awscli`, then sign in. Either use IAM Identity Center:

    ```sh
    aws configure sso --profile hiero-signer
    ```

    Or use an IAM user's access key:

    ```sh
    aws configure --profile hiero-signer
    ```

3. **Create the key.** Use secp256k1, or Ed25519 with `--key-spec ECC_NIST_EDWARDS25519`:

    ```sh
    export AWS_PROFILE=hiero-signer AWS_REGION=eu-central-1

    KEY_ID=$(aws kms create-key \
      --key-spec ECC_SECG_P256K1 \
      --key-usage SIGN_VERIFY \
      --description "Hiero testnet operator" \
      --query KeyMetadata.KeyId --output text)

    aws kms create-alias --alias-name alias/hiero-operator --target-key-id "$KEY_ID"
    ```

4. **Permissions.** An administrator identity can already use the key. For a least-privilege role or user that runs the example, attach this policy:

    ```json
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["kms:GetPublicKey", "kms:Sign"],
                "Resource": "arn:aws:kms:eu-central-1:<account-id>:key/<key-id>"
            }
        ]
    }
    ```

5. **Settings.** Set these in `.env`:

    ```sh
    AWS_KMS_KEY_ID=alias/hiero-operator
    AWS_REGION=eu-central-1
    AWS_PROFILE=hiero-signer
    ```

**Cost:** about USD 1 a month per key, plus a small charge per request. When you're done, run `aws kms schedule-key-deletion --key-id "$KEY_ID" --pending-window-in-days 7`.

### Option B: Google Cloud KMS

1. **Project.** Create a Google Cloud project with billing enabled at [console.cloud.google.com](https://console.cloud.google.com).

2. **gcloud CLI.** Install it with `brew install --cask google-cloud-sdk`, then sign in:

    ```sh
    gcloud auth login
    gcloud config set project <project-id>
    gcloud auth application-default login            # credentials the example uses
    gcloud auth application-default set-quota-project <project-id>
    gcloud services enable cloudkms.googleapis.com
    ```

3. **Create a key ring and a key.**

    ```sh
    gcloud kms keyrings create hiero --location europe-west1
    ```

    For secp256k1, which needs the HSM protection level:

    ```sh
    gcloud kms keys create hiero-operator \
      --keyring hiero --location europe-west1 \
      --purpose asymmetric-signing \
      --default-algorithm ec-sign-secp256k1-sha256 \
      --protection-level hsm
    ```

    For Ed25519, use `--default-algorithm ec-sign-ed25519 --protection-level software` instead.

4. **Permissions.** Project owners already have access. For any other identity, grant both roles:

    ```sh
    for role in roles/cloudkms.signerVerifier roles/cloudkms.publicKeyViewer; do
      gcloud kms keys add-iam-policy-binding hiero-operator \
        --keyring hiero --location europe-west1 \
        --member "user:<you@example.com>" --role "$role"
    done
    ```

5. **Settings.** Set these in `.env`:

    ```sh
    GCP_KMS_KEY_VERSION=projects/<project-id>/locations/europe-west1/keyRings/hiero/cryptoKeys/hiero-operator/cryptoKeyVersions/1
    ```

**Cost:** a small monthly fee per active key version, with HSM keys costing more, plus a charge per request. Key rings can't be deleted. When you're done, run `gcloud kms keys versions destroy 1 --key hiero-operator --keyring hiero --location europe-west1` to stop the charges.

### Option C: Azure Key Vault

Key Vault has no Ed25519 keys, so this option always gives you a secp256k1 (`P-256K`) key.

1. **Subscription.** Create one at [azure.microsoft.com](https://azure.microsoft.com); the free account works.

2. **Azure CLI.** Install it with `brew install azure-cli` and sign in. `DefaultAzureCredential` in the example uses this login:

    ```sh
    az login
    ```

3. **Create a vault that uses Azure RBAC.** Vault names are globally unique.

    ```sh
    az group create --name hiero-signer --location westeurope
    az keyvault create --name <vault-name> --resource-group hiero-signer \
      --location westeurope --enable-rbac-authorization true
    ```

4. **Give yourself rights on the vault's keys.** Key Vault Crypto Officer covers creating keys and signing. A service identity that only signs needs just "Key Vault Crypto User".

    ```sh
    az role assignment create --role "Key Vault Crypto Officer" \
      --assignee "$(az ad signed-in-user show --query id -o tsv)" \
      --scope "$(az keyvault show --name <vault-name> --query id -o tsv)"
    ```

    The role can take a minute or two to apply.

5. **Create the key and copy its versioned ID.** Use `--kty EC-HSM` for an HSM-backed key in a Premium vault.

    ```sh
    az keyvault key create --vault-name <vault-name> --name hiero-operator \
      --kty EC --curve P-256K --ops sign verify
    az keyvault key show --vault-name <vault-name> --name hiero-operator \
      --query key.kid -o tsv
    ```

6. **Settings.** Set these in `.env`:

    ```sh
    AZURE_KEY_VAULT_KEY_ID=https://<vault-name>.vault.azure.net/keys/hiero-operator/<version>
    ```

**Cleanup:** `az group delete --name hiero-signer`, then `az keyvault purge --name <vault-name>`. The purge is needed because soft delete keeps the vault name reserved.

### Option D: HashiCorp Vault or OpenBao transit

Transit only has Ed25519 keys. **Don't use `vault server -dev`** for this walkthrough: a dev server keeps keys in memory, so restarting it loses the only key that controls your testnet account. Run a small server that persists to disk instead.

1. **Install** with `brew tap hashicorp/tap && brew install hashicorp/tap/vault`. For OpenBao, run `brew install openbao` and use `bao` in place of `vault` below.

2. **Start a local server with file storage.** Keep this terminal open:

    ```sh
    mkdir -p ~/hiero-vault/data && cd ~/hiero-vault
    cat > vault.hcl <<'HCL'
    storage "file" { path = "./data" }
    listener "tcp" {
      address     = "127.0.0.1:8200"
      tls_disable = true
    }
    api_addr      = "http://127.0.0.1:8200"
    disable_mlock = true
    HCL
    vault server -config=vault.hcl
    ```

3. **Initialize, unseal and log in** from a second terminal. Save the unseal key and the root token that `init` prints: after every restart you must run `vault operator unseal` again.

    ```sh
    export VAULT_ADDR=http://127.0.0.1:8200
    vault operator init -key-shares=1 -key-threshold=1
    vault operator unseal <unseal-key>
    vault login <root-token>
    ```

4. **Enable transit and create the key:**

    ```sh
    vault secrets enable transit
    vault write -f transit/keys/hiero-operator type=ed25519
    ```

5. **Create a token that can only read and sign with this key:**

    ```sh
    vault policy write hiero-signer - <<'HCL'
    path "transit/keys/hiero-operator" { capabilities = ["read"] }
    path "transit/sign/hiero-operator" { capabilities = ["update"] }
    HCL
    vault token create -policy=hiero-signer -period=24h -field=token
    ```

6. **Settings.** Set these in `.env`:

    ```sh
    VAULT_ADDR=http://127.0.0.1:8200
    VAULT_TOKEN=<token from step 5>
    VAULT_TRANSIT_KEY=hiero-operator
    ```

### Option E: PKCS#11 with SoftHSM

SoftHSM is a software token with the same PKCS#11 interface as a hardware HSM, so the same steps work on a real HSM.

1. **Install SoftHSM and the build tools for `pkcs11js`.** `pkcs11js` is a native module.

    ```sh
    xcode-select --install       # skip if already installed
    brew install softhsm
    ```

    On Debian or Ubuntu, run `sudo apt install softhsm2 build-essential` and set the library to `/usr/lib/softhsm/libsofthsm2.so`.

2. **Create a token.** Choose your own PINs:

    ```sh
    softhsm2-util --init-token --free --label hiero --pin <user-pin> --so-pin <so-pin>
    ```

3. **Settings.** Set these in `.env`:

    ```sh
    PKCS11_LIBRARY=/opt/homebrew/lib/softhsm/libsofthsm2.so
    PKCS11_TOKEN_LABEL=hiero
    PKCS11_PIN=<user-pin>
    PKCS11_KEY_LABEL=hiero-operator
    PKCS11_KEY_CURVE=secp256k1   # or ed25519
    ```

    On an Intel Mac, the library is at `/usr/local/lib/softhsm/libsofthsm2.so`.

    You don't need to generate a key yourself. On its first run, `npm run pkcs11` generates a non-extractable key pair with this label on the token, then uses it.

The token's files are stored under Homebrew's `var/lib/softhsm/tokens`. Deleting them loses the key.

## 3. Run the walkthrough

Run the script for the backend you set up, from the `example` folder:

```sh
npm run aws      # or gcp, azure, vault, pkcs11, governance
```

The output follows the eight steps and ends with a summary table:

```text
Step 1: settings loaded
  funding account: 0.0.1234567
  ...
Step 3: account created
  account:     0.0.7654321
...
Step 8: results
┌─────────┬────────────────────────┬───────────┬──────────────────────────────────────┐
│ (index) │ step                   │ status    │ transaction                          │
├─────────┼────────────────────────┼───────────┼──────────────────────────────────────┤
│ 0       │ 'create account'       │ 'SUCCESS' │ '0.0.1234567@1760000000.000000000'   │
│ ...                                                                                  │
└─────────┴────────────────────────┴───────────┴──────────────────────────────────────┘
History: https://hashscan.io/testnet/account/0.0.7654321
```

Open the HashScan link to see the account's key (the remote public key from step 2) and all four transactions. If the script stops at step 2, the problem is backend access, not Hedera.

## How it fits together

Stripped of logging, every script uses the package like this, shown here for AWS:

```ts
import { AwsKmsSigner } from "hiero-remote-signer/aws";

const signer = await AwsKmsSigner.create({ keyId: "alias/hiero-operator" });

// Every transaction this client sends is paid for and signed by the KMS key.
const client = signer.setClientOperator(Client.forTestnet(), accountId);

// Or add the KMS signature to a transaction someone else pays for.
await signer.signTransaction(transaction.freezeWith(otherClient));
```

Only the backend's signer class and its client library differ between the five scripts. Compare `src/aws.ts` with `src/vault.ts` to see the difference.

## Things to know

- **One backend call per node.** The SDK signs a transaction separately for every node it might send it to, so each transaction makes several calls to the backend. This counts towards cloud KMS request charges and rate limits.
- **The account is only as durable as the key.** If you delete the KMS key, the Vault data or the SoftHSM token, the remote-key account and its HBAR can no longer be used. If a run stops after step 3, step 7 never ran: the account keeps its HBAR, and only the backend key can move it.
- **Testnet resets.** Testnet is reset from time to time, and accounts created on it disappear.
- **Testnet only.** The scripts use `Client.forTestnet()`, so they can't touch mainnet.
