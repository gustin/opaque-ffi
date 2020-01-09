/*
 * Copyright 2019 Plaintext, LLC - All Rights Reserved
 *
 * Unauthorized copying of this file, via any medium is strictly prohibited.
 * Proprietary and confidential.
 *
 */

use chrono::prelude::*;
use ring::{
    rand,
    signature::{self},
};

pub fn generate() -> String {
    let rng = rand::SystemRandom::new();
    let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let keypair =
        signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
    let current_date_time = Utc::now();

    let dt = Utc
        .ymd(current_date_time.year() + 1, 7, 8)
        .and_hms(9, 10, 11);

    paseto::tokens::PasetoBuilder::new()
        .set_ed25519_key(keypair)
        //        .set_encryption_key(Vec::from("YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes()))
        .set_issued_at(None)
        .set_expiration(dt)
        .set_issuer(String::from("instructure"))
        .set_audience(String::from("wizards"))
        .set_jti(String::from("gandalf0"))
        .set_not_before(Utc::now())
        .set_subject(String::from("gandalf"))
        .set_footer(String::from("key-id:gandalf0"))
        .build()
        .expect("Failed to construct paseto token w/ builder!")
}
