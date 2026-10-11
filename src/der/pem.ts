import { RemoteSignerError, RemoteSignerErrorCodes } from "../errors/index.js";

const PEM_BLOCK =
    /-----BEGIN ([A-Z0-9 ]+)-----([A-Za-z0-9+/=\s]+)-----END \1-----/;

/**
 * Decodes the first PEM block in `pem` to DER bytes. `label` is the expected
 * block type, for example `PUBLIC KEY` for a SubjectPublicKeyInfo.
 */
export function pemToDer(pem: string, label = "PUBLIC KEY"): Uint8Array {
    const match = PEM_BLOCK.exec(pem);
    if (!match || match[1] !== label) {
        throw new RemoteSignerError(
            RemoteSignerErrorCodes.MalformedDer,
            `expected a PEM "${label}" block`,
        );
    }
    return new Uint8Array(Buffer.from(match[2]!.replace(/\s+/g, ""), "base64"));
}
