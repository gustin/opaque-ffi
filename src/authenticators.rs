/*
 * Copyright 2019 Plaintext, LLC - All Rights Reserved
 *
 * Unauthorized copying of this file, via any medium is strictly prohibited.
 * Proprietary and confidential.
 *
 */

//use crate::storage;
use blake2::{Blake2b, Digest};
use qrcodegen::QrCode;
use qrcodegen::QrCodeEcc;
use qrcodegen::QrSegment;
use slauth::oath::totp::*;
use slauth::oath::OtpAuth;

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

pub fn generate_totp(user_id: &str) -> String {
    // https://github.com/google/google-authenticator/wiki/Key-Uri-Format

    // generate secret and store it locally
    // access when checking totp
    // send secret to superagent, sync
    let mut hasher = Blake2b::new();
    hasher.input(user_id);
    let key = hasher.result();
    println!("{:?}", key);

    //    storage::store(user_id, &key);

    let mut totp = TOTPContext::builder().period(5).secret(&key).build();

    let uri = totp.to_uri(Some("Plaintext"), Some("Plaintext"));
    println!("{}", uri);

    let qr = QrCode::encode_text(&uri, QrCodeEcc::Medium).unwrap();
    let svg = qr.to_svg_string(4);
    let (first, last) = svg.split_at(138);
    String::from(last)
}

#[test]
fn test_totp_generation() {
    let user_id = "1337";
    let qr = generate_totp(user_id);
    //    println!("Yeah {}", storage::retrieve(user_id));
    println!("QR Code SVG: {}", qr);
}
