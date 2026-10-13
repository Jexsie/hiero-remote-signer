import { describe, expect, it } from "vitest";

import * as aws from "../../../src/aws/index.js";
import * as azure from "../../../src/azure/index.js";
import { setClientOperator } from "../../../src/client/index.js";
import {
    RemoteSignerError,
    RemoteSignerErrorCodes,
} from "../../../src/errors/index.js";
import * as gcp from "../../../src/gcp/index.js";
import * as pkcs11 from "../../../src/pkcs11/index.js";
import * as vault from "../../../src/vault/index.js";

describe.each([
    ["aws", aws],
    ["azure", azure],
    ["gcp", gcp],
    ["pkcs11", pkcs11],
    ["vault", vault],
])("the %s entry point", (_name, entry) => {
    it("re-exports the shared helpers, not copies of them", () => {
        // Same references, so `instanceof RemoteSignerError` holds whichever
        // entry point the error class was imported from.
        expect(entry.setClientOperator).toBe(setClientOperator);
        expect(entry.RemoteSignerError).toBe(RemoteSignerError);
        expect(entry.RemoteSignerErrorCodes).toBe(RemoteSignerErrorCodes);
    });
});
