import { describe, expect, it } from "vitest";

import { decodeOid, readTlv } from "../../../src/der/tlv.js";
import { RemoteSignerErrorCodes } from "../../../src/errors/index.js";
import { expectCode } from "../../utils/assertions.js";

describe("readTlv", () => {
    it("reads short and long-form lengths", () => {
        expect(readTlv(new Uint8Array([0x04, 0x01, 0xaa]), 0)).toEqual({
            tag: 0x04,
            value: new Uint8Array([0xaa]),
            end: 3,
        });

        const long = new Uint8Array([0x04, 0x81, 0x80, ...new Uint8Array(128)]);
        const tlv = readTlv(long, 0);
        expect(tlv.value.length).toBe(128);
        expect(tlv.end).toBe(long.length);
    });

    it("rejects a truncated header", () => {
        expectCode(
            () => readTlv(new Uint8Array([0x30]), 0),
            RemoteSignerErrorCodes.MalformedDer,
        );
    });

    it("rejects indefinite and oversized length encodings", () => {
        expectCode(
            () => readTlv(new Uint8Array([0x30, 0x80]), 0),
            RemoteSignerErrorCodes.MalformedDer,
        );
        expectCode(
            () => readTlv(new Uint8Array([0x30, 0x83, 0, 0, 1]), 0),
            RemoteSignerErrorCodes.MalformedDer,
        );
    });

    it("rejects a truncated long-form length", () => {
        expectCode(
            () => readTlv(new Uint8Array([0x30, 0x82, 0x01]), 0),
            RemoteSignerErrorCodes.MalformedDer,
        );
    });
});

describe("decodeOid", () => {
    it("decodes multi-byte arcs", () => {
        // 1.2.840.10045.2.1 (ecPublicKey)
        const oid = new Uint8Array([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
        expect(decodeOid(oid)).toBe("1.2.840.10045.2.1");
    });

    it("rejects an empty OID", () => {
        expectCode(
            () => decodeOid(new Uint8Array()),
            RemoteSignerErrorCodes.MalformedDer,
        );
    });
});
