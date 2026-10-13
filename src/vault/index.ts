export { VaultTransitSigner } from "./VaultTransitSigner.js";
export type {
    VaultToken,
    VaultTransitSignerOptions,
} from "./VaultTransitSignerOptions.js";

// Shared helpers, re-exported so one import covers a backend
export { setClientOperator } from "../client/index.js";
export { RemoteSignerError, RemoteSignerErrorCodes } from "../errors/index.js";
export type { RemoteSignerErrorCode } from "../errors/index.js";
export type { HieroKeyType, HieroRemoteSigner } from "../types/index.js";
