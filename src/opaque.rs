

pub fn registration_init(username: &str, alpha: &[u8; 32]) {
    // opaque client code, call function in lib for now
    // client_registration_values
    // then package and post to a url


    // => Registration 1
    let (beta, v, pub_s) = opaque::registration_1(username, &alpha);
}


