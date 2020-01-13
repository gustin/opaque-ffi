/*
 * Copyright 2019 Plaintext, LLC - All Rights Reserved
 *
 * Unauthorized copying of this file, via any medium is strictly prohibited.
 * Proprietary and confidential.
 *
 */

//use crate::storage;
use blake2::{Blake2b, Digest};
use lazy_static::lazy_static;
use qrcodegen::QrCode;
use qrcodegen::QrCodeEcc;

use slauth::oath::totp::*;
use slauth::oath::OtpAuth;
use std::collections::HashMap;
use std::sync::Mutex;

/*
 * An authenticator is derived from a main private key.
 * Supporting methods for various authenticators, e.g possession,
 * knowledge.
 */
struct Authenticator {}

lazy_static! {
    static ref AUTHENTICATOR_MAP: Mutex<HashMap<String, Vec<u8>>> =
        { Mutex::new(HashMap::new()) };
}

/*
 * Generate a fresh qr code that a user can register an authenticator with.
 */
pub fn generate_qr_code(user_id: &str) -> String {
    // https://github.com/google/google-authenticator/wiki/Key-Uri-Format

    // generate secret and store it locally
    // access when checking totp
    // send secret to superagent, sync
    let mut hasher = Blake2b::new();
    hasher.input(user_id);
    let key = hasher.result();

    //    storage::store(user_id, &key);
    AUTHENTICATOR_MAP
        .lock()
        .unwrap()
        .insert(user_id.to_string(), key.to_vec());

    let totp = TOTPContext::builder().period(30).secret(&key).build();

    let uri = totp.to_uri(Some("Plaintext"), Some("Plaintext"));

    let qr = QrCode::encode_text(&uri, QrCodeEcc::Medium).unwrap();
    let svg = qr.to_svg_string(4);
    let (_first, last) = svg.split_at(138);
    String::from(last)
}

/*
 * Confirm the current TOTP against the provided user id.
 */
pub fn confirm_current(user_id: &str, code: &str) -> bool {
    let secret_key = AUTHENTICATOR_MAP
        .lock()
        .unwrap()
        .get(user_id)
        .unwrap()
        .clone();
    let totp = TOTPContext::builder().period(30).secret(&secret_key).build();
    totp.validate_current(&code)
}

/*
 * Utility method to print out a QR code in block form.
 */
fn print_qr(qr: &QrCode) {
    let border: i32 = 4;
    for y in -border..qr.size() + border {
        for x in -border..qr.size() + border {
            let c: char = if qr.get_module(x, y) { '█' } else { ' ' };
            print!("{0}{0}", c);
        }
        println!();
    }
    println!();
}


#[test]
fn test_qr_generation() {
    let user_id = "1337";
    let qr = generate_qr_code(user_id);
    //    println!("Yeah {}", storage::retrieve(user_id));
    println!("QR Code SVG: {}", qr);
}

#[test]
fn test_confirmation_of_totp() {
    let user_id = "1337";
    generate_qr_code(user_id);

    let secret_key = AUTHENTICATOR_MAP
        .lock()
        .unwrap()
        .get(user_id)
        .unwrap()
        .clone();
    println!("Show me all your secrets:");
    println!("{:?}", secret_key);

    let totp = TOTPContext::builder().period(5).secret(&secret_key).build();
    let code = totp.gen();

    let valid = confirm_current(user_id, &code);
    println!("#{:?}", code);
    assert_eq!(valid, true);

    let invalid = confirm_current(user_id, "blah");
    assert_eq!(invalid, false);
}
