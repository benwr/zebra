use wasm_bindgen::prelude::*;
use zebra_crypto::{PublicKey, Signature, Scalar, RistrettoPoint, SignedMessage};
use std::str::FromStr;

#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
pub fn verify_signature(message: &str) -> bool {
    match SignedMessage::from_str(message) {
        Ok(signed_message) => signed_message.verify(),
        Err(_) => false,
    }
}
