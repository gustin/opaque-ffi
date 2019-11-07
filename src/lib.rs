use ed25519_dalek::PublicKey;
use ed25519_dalek::{Digest, Keypair};
use rand::rngs::OsRng;
use std::str;

mod authenticators;
mod storage;

#[no_mangle]
pub extern "C" fn generate_key() -> String {
    /*    let mut csprng: OsRng = OsRng::new().unwrap();
    let keypair: Keypair = Keypair::generate(&mut csprng);
    let s = match str::from_utf8(&keypair.public.to_bytes()) {
        Ok(v) => v,
        Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
    };

    println!("result: {}", s);*/
    return "Holla".to_string();
}
