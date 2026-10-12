/**
 * Step 1: connect to the remote signer, print its public key, and prove the
 * backend can sign. No transaction is sent and nothing is spent.
 */
import { withSigner } from "./signer.js";

await withSigner(async ({ backend, signer }) => {
    const { publicKey, keyType } = signer;
    console.log(`Backend:          ${backend}`);
    console.log(`Key type:         ${keyType}`);
    console.log(`Public key (DER): ${publicKey.toStringDer()}`);
    console.log(`Public key (raw): ${publicKey.toStringRaw()}`);
    if (keyType === "ECDSA_SECP256K1") {
        console.log(`EVM address:      0x${publicKey.toEvmAddress()}`);
    }

    // Sign a throwaway message exactly as a transaction body is signed, and
    // check the result against the public key.
    const message = new TextEncoder().encode(
        `hiero-remote-signer check ${new Date().toISOString()}`,
    );
    const signature = await signer.sign(message);
    if (!publicKey.verify(message, signature)) {
        throw new Error("the backend's signature did not verify");
    }
    console.log(`Test signature:   ${signature.length} bytes, verified`);
});
