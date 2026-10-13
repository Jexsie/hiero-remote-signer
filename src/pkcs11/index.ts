export { Pkcs11Signer, Pkcs11Constants } from "./Pkcs11Signer.js";
export type {
    Pkcs11Module,
    Pkcs11SignerOptions,
} from "./Pkcs11SignerOptions.js";

// Shared helpers, re-exported so one import covers a backend
export { setClientOperator } from "../client/index.js";
export { RemoteSignerError, RemoteSignerErrorCodes } from "../errors/index.js";
export type { RemoteSignerErrorCode } from "../errors/index.js";
export type { HieroKeyType, HieroRemoteSigner } from "../types/index.js";
