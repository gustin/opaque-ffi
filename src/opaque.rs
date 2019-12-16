pub fn registration_start(
    username: &str,
    alpha: &[u8; 32],
) -> ([u8; 32], [u8; 32], [u8; 32]) {
    // opaque client code, call function in lib for now
    // client_registration_values
    // then package and post to a url

    // => Registration 1
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
