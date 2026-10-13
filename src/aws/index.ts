export { AwsKmsSigner, AWS_KMS_MAX_RAW_MESSAGE_BYTES } from "./AwsKmsSigner.js";
export type { AwsKmsSignerOptions } from "./AwsKmsSignerOptions.js";

// Shared helpers, re-exported so one import covers a backend
export { setClientOperator } from "../client/index.js";
export { RemoteSignerError, RemoteSignerErrorCodes } from "../errors/index.js";
export type { RemoteSignerErrorCode } from "../errors/index.js";
export type { HieroKeyType, HieroRemoteSigner } from "../types/index.js";
