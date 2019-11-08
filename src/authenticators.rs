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

fn generate_totp(user_id: &str) {
    // https://github.com/google/google-authenticator/wiki/Key-Uri-Format

    // generate secret and store it locally
    // access when checking totp
    // send secret to superagent, sync
    let mut hasher = Blake2b::new();
    hasher.input(b"some-rando-generated-string");
    let key = hasher.result();
    println!("{:?}", key);

    let mut totp = TOTPContext::builder()
        .period(5)
        .secret(&key)
        .build();

    let uri = totp.to_uri(Some("Plaintext"), Some("Plaintext"));
    println!("{}", uri);

    let qr = QrCode::encode_text(&uri, QrCodeEcc::Medium).unwrap();
    let svg = qr.to_svg_string(4);
    println!("{}", svg);

    print_qr(&qr);
}

#[test]
fn test_totp_generation() {
    generate_totp("user_1337")
}



