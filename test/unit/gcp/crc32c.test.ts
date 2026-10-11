import { describe, expect, it } from "vitest";

import { crc32c } from "../../../src/gcp/crc32c.js";

describe("crc32c", () => {
    it("matches the standard check value", () => {
        // CRC-32C check value for "123456789" (RFC 3720, appendix B.4)
        expect(crc32c(new TextEncoder().encode("123456789"))).toBe(0xe3069283);
    });

    it("is zero for empty input", () => {
        expect(crc32c(new Uint8Array())).toBe(0);
    });
});
