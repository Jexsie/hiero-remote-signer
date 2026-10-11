/**
 * CRC32C (Castagnoli), the checksum Cloud KMS uses for end-to-end integrity
 * verification of requests and responses.
 */

const TABLE = (() => {
    const table = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
        let c = n;
        for (let k = 0; k < 8; k++) {
            c = c & 1 ? 0x82f63b78 ^ (c >>> 1) : c >>> 1;
        }
        table[n] = c >>> 0;
    }
    return table;
})();

export function crc32c(bytes: Uint8Array): number {
    let crc = 0xffffffff;
    for (const b of bytes) {
        crc = TABLE[(crc ^ b) & 0xff]! ^ (crc >>> 8);
    }
    return (crc ^ 0xffffffff) >>> 0;
}
