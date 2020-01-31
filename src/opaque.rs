/*
 * Copyright 2019 Plaintext, LLC - All Rights Reserved
 *
 * Unauthorized copying of this file, via any medium is strictly prohibited.
 * Proprietary and confidential.
 *
 */

use crate::token;

pub fn registration_start(
    username: &str,
    alpha: &[u8; 32],
) -> ([u8; 32], [u8; 32], [u8; 32]) {
    opaque::registration_start(username, &alpha)
}

pub fn registration_finalize(
    username: &str,
    pub_c: &[u8; 32],
    envelope: &Vec<u8>,
) {
    opaque::registration_finalize(username, &pub_c, &envelope)
}

pub fn authenticate_start(
    username: &str,
    alpha: &[u8; 32],
    key: &[u8; 32],
) -> ([u8; 32], [u8; 32], Vec<u8>, Vec<u8>, [u8; 32]) {
    opaque::authenticate_start(username, &alpha, &key)
}

pub fn authenticate_finalize(
    username: &str,
    key: &Vec<u8>,
    x: &[u8; 32],
) -> String {
    opaque::authenticate_finalize(username, &key, &x);
    token::generate()
}

pub fn client_registration_start(
    password: &str,
) -> ([u8; 32], [u8; 32], [u8; 32]) {
    opaque::client::registration_start(password)
}

pub fn client_registration_finalize(
    password: &str,
    beta: &[u8; 32],
    v: &[u8; 32],
    pub_u: &[u8; 32],
    pub_s: &[u8; 32],
    priv_u: &[u8; 32],
) -> (Vec<u8>) {
    opaque::client::registration_finalize(
        password, beta, v, pub_u, pub_s, priv_u,
    )
}
