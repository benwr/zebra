import * as wasm from "zebra_wasm";

export function verifySignature(messageString) {
    const isValid = wasm.verify_signature(messageString);
    console.log(`Signature is valid: ${isValid}`);
}
