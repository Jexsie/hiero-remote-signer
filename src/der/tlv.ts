import { RemoteSignerError, RemoteSignerErrorCodes } from "../errors/index.js";

/** DER tags used by the structures this package reads. */
export const DerTag = {
    Integer: 0x02,
    BitString: 0x03,
    OctetString: 0x04,
    ObjectIdentifier: 0x06,
    Sequence: 0x30,
} as const;

/** One decoded DER element. */
export interface Tlv {
    tag: number;
    value: Uint8Array;
    /** Offset of the first byte after this element. */
    end: number;
}

/** Reads one DER TLV element at `offset`. Only definite lengths are accepted. */
export function readTlv(bytes: Uint8Array, offset: number): Tlv {
    if (offset + 2 > bytes.length) {
        throw new RemoteSignerError(
            RemoteSignerErrorCodes.MalformedDer,
            "DER element truncated",
        );
    }
    const tag = bytes[offset]!;
    let length = bytes[offset + 1]!;
    let cursor = offset + 2;

    if (length & 0x80) {
        const lengthBytes = length & 0x7f;
        if (lengthBytes === 0 || lengthBytes > 2) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.MalformedDer,
                "unsupported DER length encoding",
            );
        }
        if (cursor + lengthBytes > bytes.length) {
            throw new RemoteSignerError(
                RemoteSignerErrorCodes.MalformedDer,
                "DER length truncated",
            );
        }
        length = 0;
        for (let i = 0; i < lengthBytes; i++) {
            length = (length << 8) | bytes[cursor + i]!;
        }
        cursor += lengthBytes;
    }

    const end = cursor + length;
    if (end > bytes.length) {
        throw new RemoteSignerError(
            RemoteSignerErrorCodes.MalformedDer,
            "DER value exceeds input",
        );
    }
    return { tag, value: bytes.subarray(cursor, end), end };
}

/** Throws unless `tlv` carries `tag`. `what` names the element in the error. */
export function expectTag(tlv: Tlv, tag: number, what: string): void {
    if (tlv.tag !== tag) {
        throw new RemoteSignerError(
            RemoteSignerErrorCodes.MalformedDer,
            `expected ${what} (tag 0x${tag.toString(16)}), got tag 0x${tlv.tag.toString(16)}`,
        );
    }
}

/** Decodes the value of a DER OBJECT IDENTIFIER into dotted form. */
export function decodeOid(value: Uint8Array): string {
    if (value.length === 0) {
        throw new RemoteSignerError(
            RemoteSignerErrorCodes.MalformedDer,
            "empty OID",
        );
    }
    const first = value[0]!;
    const arc0 = Math.min(Math.floor(first / 40), 2);
    const parts: number[] = [arc0, first - arc0 * 40];
    let acc = 0;
    for (let i = 1; i < value.length; i++) {
        const b = value[i]!;
        acc = acc * 128 + (b & 0x7f);
        if (!(b & 0x80)) {
            parts.push(acc);
            acc = 0;
        }
    }
    return parts.join(".");
}
