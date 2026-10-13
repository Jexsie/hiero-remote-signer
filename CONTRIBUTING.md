# Contributing to hiero-remote-signer

Thank you for your interest in contributing. We welcome bug reports, feature requests, new backends and documentation fixes.

**Jump To:**

- [Bug Reports](#bug-reports)
- [Feature Requests](#feature-requests)
- [Code Contributions](#code-contributions)

## Bug Reports

Bug reports are accepted through the [Issues](https://github.com/Jexsie/hiero-remote-signer/issues) page.

### Before Submitting a Bug Report

1. Search the existing issues to check it hasn't been reported already. If it has, add a +1 to help us prioritise.
2. Try the latest commit on `main`; the bug may already be fixed.

### Submitting a Bug Report

Please include:

- **A short, descriptive title.**
- **Expected and actual behaviour.**
- **The backend and key type,** for example AWS KMS with `ECC_SECG_P256K1` or SoftHSM with Ed25519.
- **Versions:** Node.js, `@hiero-ledger/sdk` and the backend client library.
- **The `RemoteSignerError` code and message, and its `cause` if present.**
- **A minimal script that reproduces the issue,** if you can make one.

Never paste private keys, tokens, PINs or credentials. Replace key IDs and account IDs if they are sensitive.

## Feature Requests

Open an issue describing the problem you want solved and the backend it concerns. For a new backend, say how it returns public keys and signatures, and whether it supports secp256k1, Ed25519 or both. That decides whether Hiero can use it.

## Code Contributions

### Requirements

- **Node.js 22.22 or later.** Babel 8, Vitest 5 and lint-staged require it, though the published package itself runs on Node.js 20.
- **npm.** The repository uses npm workspaces: the root package plus [`example/`](example).

TypeScript is installed twice. TypeScript 7 (`typescript-7`) compiles and type-checks; every script calls it explicitly. TypeScript 6.0 is the plain `typescript` package because `typescript-eslint` needs its JavaScript API, which TypeScript 7 doesn't provide. So `npx tsc` runs 6.0. Use the npm scripts instead.

### Building and testing

```sh
npm install              # installs dependencies and builds dist/
npm run build            # type-checks the tests, then builds ESM, CommonJS and declarations
npm run test:unit        # unit tests, no network needed
npm run lint             # ESLint with type-aware rules; `npm run lint:fix` fixes what it can
npm run format:check     # Prettier, as CI runs it; `npm run format` rewrites files
```

| What it proves                             | Command                              | Needs                                       |
| ------------------------------------------ | ------------------------------------ | ------------------------------------------- |
| No lint errors, no deprecated APIs        | `npm run lint`                       | nothing                                     |
| Every signer against its backend contract | `npm run test:unit`                  | nothing                                     |
| The same, with the coverage gate (90%)     | `npm run test:unit:coverage`         | nothing                                     |
| Published types resolve in ESM and CJS     | `npx attw --pack --profile node16`   | a build                                     |
| The example compiles against the package   | `npm run typecheck -w example`       | a build                                     |
| Vault against a real server                | `npm run test:integration`           | `VAULT_ADDR`, `VAULT_TOKEN`                 |
| PKCS#11 against a real token               | `npm run test:integration`           | `PKCS11_LIBRARY`, `PKCS11_TOKEN_LABEL`, `PKCS11_PIN` |
| Each backend on a live Hiero network       | `npm run test:integration`           | `HIERO_*` variables and the backend's key   |

CI runs all of these on every pull request except the live network specs and the AWS, Google Cloud and Azure specs, which need credentials.

### Unit tests

The unit tests replace each backend with a fake in [`test/utils/`](test/utils). Each fake signs with real secp256k1 and Ed25519 keys and enforces that backend's request contract: message type, digest field, CRC32C checksums, key versions and the PKCS#11 operation order. A signer that calls a backend wrongly fails the test. Every signature is checked with the SDK's own `PublicKey.verify()` and `verifyTransaction()`.

### Integration tests

Each spec under [`test/integration/`](test/integration) skips itself unless its variables are set, in the environment or in `test/.env`:

```sh
cp test/.env.example test/.env   # fill in the sections you need
npm run test:integration
```

A quick local setup:

- **Vault:** a dev server is enough. Run `vault server -dev`, then set `VAULT_ADDR` and `VAULT_TOKEN`. The spec mounts transit and creates its own keys.
- **PKCS#11:** install SoftHSM and create a token with `softhsm2-util --init-token --free --label hiero --pin 1234 --so-pin 5678`. The spec generates its own key pairs.
- **Live network:** a local [Solo](https://solo.hiero.org) network or a funded testnet account. These specs create an account owned by the remote key and spend from it.

### Repository layout

```
src/
  types/        HieroKeyType and the HieroRemoteSigner interface
  errors/       RemoteSignerError and RemoteSignerErrorCodes
  client/       setClientOperator
  der/          DER and PEM decoding, public key parsing, signature conversion, low-S rule
  aws/ gcp/ azure/ vault/ pkcs11/    one directory per backend entry point
test/
  unit/         unit tests, mirroring src/
  integration/  real backend and live network specs
  utils/        contract-enforcing backend fakes, shared key material, env loading
example/        testnet walkthrough, one self-contained script per backend
scripts/        declaration mirroring for the CommonJS build
```

`types/`, `errors/`, `client/` and `der/` contain no backend code.

### Adding a backend

1. Add `src/<backend>/` with a `<Backend>Signer` class that implements `HieroRemoteSigner`, an options interface, and an async `create()` that reads and validates the public key once.
2. Reuse the `der/` helpers to parse public keys and signatures, and throw `RemoteSignerError` with the closest existing code. Expose `sign` as a readonly bound function, not a method, so callers can pass `signer.sign` to the SDK.
3. In `src/<backend>/index.ts`, re-export the shared helpers (`setClientOperator`, the errors and the types) as the other backends do, so one import covers the backend.
4. Add the entry point to `exports` in `package.json`, and the client library as an optional peer dependency and a dev dependency.
5. Add a fake in `test/utils/` that enforces the backend's real request contract, plus unit tests in `test/unit/<backend>/`.
6. Add an integration spec, a section in `test/.env.example`, a row in the README table, and a script in `example/`.

### Code style

- Prettier formats everything (four-space indents), and ESLint checks the code with the type-aware `typescript-eslint` rules (`eslint.config.js`).
- A Husky pre-commit hook runs lint-staged, which applies `eslint --fix` and Prettier to the staged files. `npm install` sets up the hook. It does this by setting `core.hooksPath` in the repository's local git config.
- Deprecated APIs are a lint error (`@typescript-eslint/no-deprecated`).
- Write comments only where the reason isn't obvious from the code.

### Commits and pull requests

- Use [Conventional Commits](https://www.conventionalcommits.org), for example `feat(gcp): ...`, `fix(der): ...` or `docs: ...`, and keep each commit to one logical change.
- Sign off every commit for the [Developer Certificate of Origin](https://developercertificate.org) with `git commit -s`, and sign it cryptographically with GPG or SSH.
- Open the pull request against `main`. CI must pass: formatting, lint, build, published types, example typecheck, unit tests with coverage, and the Vault and SoftHSM jobs.
- Update the README in the same pull request when you change behaviour or the public API.

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
