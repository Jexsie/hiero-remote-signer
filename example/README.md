# hiero-remote-signer example

This walkthrough creates a real Hedera testnet account whose only key lives in a remote signer, then spends from it. The private key never leaves the signer: AWS KMS, Google Cloud KMS, Azure Key Vault, HashiCorp Vault (or OpenBao) transit, or a PKCS#11 token such as SoftHSM.

It uses two accounts:

- **Funding account:** the testnet account you already have, with its private key held locally. It pays to create the second account.
- **Remote-key account:** a new account created by the example. It can only be controlled through the remote signer.

The example has five scripts, run from the `example` folder:

| Script                   | What it does                                                                                                                          |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------- |
| `npm run show-key`       | Connects to the backend, prints the public key and checks a test signature. It sends nothing to the network.                          |
| `npm run create-account` | Creates the remote-key account. The funding account pays the fee and the initial balance.                                             |
| `npm run transfer`       | Sends HBAR as the remote-key account, which pays the fee too. Its client uses the remote signer as the operator (`setClientOperator`). |
| `npm run co-sign`        | The funding account pays the fee and the remote key approves the debit with `signWith`. This is how a treasury key approves a payout. |
| `npm run pkcs11:keygen`  | Generates a key pair on a PKCS#11 token. Use it only with the PKCS#11 backend.                                                        |

Pick **one** backend in [step 2](#2-set-up-one-backend). The rest of the steps are the same for every backend.

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
    HIERO_NETWORK=testnet
    FUNDING_ACCOUNT_ID=0.0.1234567
    FUNDING_PRIVATE_KEY=0x...        # the HEX key from the portal
    FUNDING_KEY_TYPE=ecdsa           # ecdsa for the portal's HEX ECDSA key,
                                     # der for a DER string (302e... / 3030...),
                                     # ed25519 for a hex Ed25519 key
    ```

    The account needs about 15 HBAR. If it runs low, refill it from the portal faucet.

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
    REMOTE_SIGNER_BACKEND=aws
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
    REMOTE_SIGNER_BACKEND=gcp
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
    REMOTE_SIGNER_BACKEND=azure
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
    REMOTE_SIGNER_BACKEND=vault
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
    REMOTE_SIGNER_BACKEND=pkcs11
    PKCS11_LIBRARY=/opt/homebrew/lib/softhsm/libsofthsm2.so
    PKCS11_TOKEN_LABEL=hiero
    PKCS11_PIN=<user-pin>
    PKCS11_KEY_LABEL=hiero-operator
    PKCS11_KEY_CURVE=secp256k1   # or ed25519
    ```

    On an Intel Mac, the library is at `/usr/local/lib/softhsm/libsofthsm2.so`.

4. **Generate a non-extractable key pair on the token:**

    ```sh
    npm run pkcs11:keygen
    ```

The token's files are stored under Homebrew's `var/lib/softhsm/tokens`. Deleting them loses the key.

## 3. Check the signer

Run:

```sh
npm run show-key
```

It prints the backend, the key type, the public key in DER and raw form (and the EVM address for secp256k1), then checks a test signature. If this step fails, the problem is with backend access, not with Hedera.

## 4. Create the remote-key account

Run:

```sh
npm run create-account
```

The funding account creates a new account whose key is the remote public key, with an initial balance of 10 HBAR (`INITIAL_BALANCE_HBAR`). Copy the printed line into `.env`:

```sh
REMOTE_ACCOUNT_ID=0.0.7654321
```

Open the printed HashScan link. The account's key there matches the public key from step 3.

## 5. Spend with the remote key

1. **The remote-key account pays and signs.**

    ```sh
    npm run transfer
    ```

    This sends 1 HBAR (`TRANSFER_HBAR`) to the funding account, or to `RECIPIENT_ACCOUNT_ID` if you set it. The transaction ID is printed and the account's HashScan page shows the transfer. Every signature on it came from the backend.

2. **Another account pays and the remote key co-signs.**

    ```sh
    npm run co-sign
    ```

    The funding account pays the fee and signs locally. The remote key signs the same frozen transaction through `signWith`, which approves the debit from the remote-key account.

## How it fits together

Both scripts open the signer the same way:

```ts
import { AwsKmsSigner } from "hiero-remote-signer/aws";
import { setClientOperator } from "hiero-remote-signer";

const signer = await AwsKmsSigner.create({ keyId: "alias/hiero-operator" });

// Every transaction this client sends is paid for and signed by the KMS key.
const client = setClientOperator(Client.forTestnet(), accountId, signer);

// Or add the KMS signature to a transaction someone else pays for.
await transaction.freezeWith(otherClient).signWith(signer.publicKey, signer.sign);
```

`src/signer.ts` shows the equivalent code for every backend. It imports the backends on demand, so only the client library of the backend you choose is loaded.

## Things to know

- **One backend call per node.** The SDK signs a transaction separately for every node it might send it to, so each transaction makes several calls to the backend. This counts towards cloud KMS request charges and rate limits.
- **The account is only as durable as the key.** If you delete the KMS key, the Vault data or the SoftHSM token, the remote-key account and its HBAR can no longer be used. To recover the HBAR first, run `npm run transfer` with `TRANSFER_HBAR` set to the balance minus a small fee.
- **Testnet resets.** Testnet is reset from time to time, and accounts created on it disappear.
- **Mainnet is blocked on purpose.** `HIERO_NETWORK` only accepts `testnet` and `previewnet`.
