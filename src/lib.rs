/*
 * Copyright 2019 Plaintext, LLC - All Rights Reserved
 *
 * Unauthorized copying of this file, via any medium is strictly prohibited.
 * Proprietary and confidential.
 *
 */

mod authenticators;
mod opaque;
//mod storage;
mod token;
use libc::c_char;
use std::convert::From;
use std::ffi::{CStr, CString};
use std::slice;

// Authenticators

// TOTP / Authy

#[no_mangle]
pub extern "C" fn generate_qr_code(user_id: *const c_char) -> *mut c_char {
    let c_str = unsafe {
        assert!(!user_id.is_null());
        CStr::from_ptr(user_id)
    };

    let user_id = c_str.to_str().unwrap();
    let qr_code_svg = authenticators::generate_qr_code(user_id);

    let c_str_back_at_ya = CString::new(qr_code_svg).unwrap();
    c_str_back_at_ya.into_raw()
}

#[no_mangle]
pub extern "C" fn free_qr_code(qr: *mut c_char) {
    unsafe {
        if qr.is_null() {
            return;
        }
        CString::from_raw(qr)
    };
}

#[no_mangle]
pub extern "C" fn confirm_second_factor(
    user_id: *const c_char,
    code: *const c_char,
) -> bool {
    let c_user_id = unsafe {
        assert!(!user_id.is_null());
        CStr::from_ptr(user_id)
    };
    let c_code = unsafe {
        assert!(!user_id.is_null());
        CStr::from_ptr(user_id)
    };

    let user_id = c_user_id.to_str().unwrap();
    let code = c_code.to_str().unwrap();

    authenticators::confirm_current(user_id, code)
}

// OPAQUE interface

#[repr(C)]
pub struct Registration {
    beta: *const u8,
    v: *const u8,
    pub_s: *const u8,
}

#[repr(C)]
pub struct Authentication {
    beta: *const u8,
    v: *const u8,
    //pub_s: *const u8, NOTE: needed?
    envelope: *const u8,
    ke_2: *const u8,
    y: *const u8,
}

#[no_mangle]
pub extern "C" fn authenticate_start(
    username: *const c_char,
    alpha: *const u8,
    key: *const u8,
) -> Authentication {
    let username_c_str = unsafe {
        assert!(!username.is_null());
        CStr::from_ptr(username)
    };
    let username = username_c_str.to_str().unwrap();

    let defrag: &[u8] = unsafe {
        assert!(!alpha.is_null());
        slice::from_raw_parts(alpha, 32 as usize)
    };
    let mut alpha: [u8; 32] = [0; 32];
    alpha.copy_from_slice(&defrag[..32]);

    let defrag: &[u8] = unsafe {
        assert!(!key.is_null());
        slice::from_raw_parts(key, 32 as usize)
    };
    let mut key: [u8; 32] = [0; 32];
    key.copy_from_slice(&defrag[..32]);

    println!("Username: {}", username);
    println!("Alpha: {:?}", alpha);
    println!("KE1: {:?}", key);

    let (beta, v, envelope, ke_2, y) =
        opaque::authenticate_start(username, &alpha, &key);

    println!("PreBoxed KE2: {:?}", ke_2);
    println!("KE2 Size: {:?}", ke_2.capacity());
    println!("PreBoxed Envelope: {:?}", envelope);
    println!("Envelope Size : {:?}", envelope.capacity());

    let beta = Box::new(beta);
    let v = Box::new(v);
    let y = Box::new(y);

    Authentication {
        beta: Box::into_raw(beta) as *mut u8,
        v: Box::into_raw(v) as *mut u8,
        envelope: envelope.as_ptr() as *mut u8, // LEAK: boxing seemed to fail
        ke_2: ke_2.as_ptr() as *mut u8,
        y: Box::into_raw(y) as *mut u8,
    }
}

#[no_mangle]
pub extern "C" fn authenticate_finalize(
    username: *const c_char,
    key: *const u8,
    x: *const u8,
) -> *mut c_char {
    println!(":- Agent -> Authenticate Finalize:");
    let username_c_str = unsafe {
        assert!(!username.is_null());
        CStr::from_ptr(username)
    };
    let username = username_c_str.to_str().unwrap();

    let defrag: &[u8] = unsafe {
        assert!(!key.is_null());
        slice::from_raw_parts(key, 192 as usize)
    };
    let mut key: Vec<u8> = vec![0; 192];
    key.copy_from_slice(&defrag[..192]);

    let defrag: &[u8] = unsafe {
        assert!(!x.is_null());
        slice::from_raw_parts(x, 32 as usize) // size of encrypted 112
    };
    let mut x: [u8; 32] = [0; 32];
    x.copy_from_slice(&defrag[..32]);

    println!("Username: {}", username);
    println!("Key 3: {:?}", key);
    println!("X: {:?}", x);

    let token = opaque::authenticate_finalize(&username, &key, &x);
    println!("Token: {:?}", token);
    CString::new(token).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn registration_start(
    username: *const c_char,
    alpha: *const u8,
) -> Registration {
    let username_c_str = unsafe {
        assert!(!username.is_null());
        CStr::from_ptr(username)
    };
    let username = username_c_str.to_str().unwrap();

    let defrag: &[u8] = unsafe {
        assert!(!alpha.is_null());
        slice::from_raw_parts(alpha, 32 as usize)
    };
    let mut alpha: [u8; 32] = [0; 32];
    alpha.copy_from_slice(&defrag[..32]);

    println!("Username: {}", username);
    println!("Alpha;: {:?}", alpha);
    let (beta, v, pub_s) = opaque::registration_start(username, &alpha);
    let beta = Box::new(beta);
    let v = Box::new(v);
    let pub_s = Box::new(pub_s);

    println!("Beta;: {:?}", beta);
    println!("V:: {:?}", v);
    println!("PubS:: {:?}", pub_s);

    Registration {
        beta: Box::into_raw(beta) as *mut u8,
        v: Box::into_raw(v) as *mut u8,
        pub_s: Box::into_raw(pub_s) as *mut u8,
    }
}

#[no_mangle]
pub extern "C" fn registration_finalize(
    username: *const c_char,
    pub_u: *const u8,
    envelope: *const u8,
) {
    let username_c_str = unsafe {
        assert!(!username.is_null());
        CStr::from_ptr(username)
    };
    let username = username_c_str.to_str().unwrap();

    let defrag: &[u8] = unsafe {
        assert!(!pub_u.is_null());
        slice::from_raw_parts(pub_u, 32 as usize)
    };
    let mut pub_u: [u8; 32] = [0; 32];

    pub_u.copy_from_slice(&defrag[..32]);

    let defrag: &[u8] = unsafe {
        assert!(!envelope.is_null());
        slice::from_raw_parts(envelope, 112 as usize) // size of encrypted 112
    };
    let mut envelope: Vec<u8> = vec![0; 112];
    envelope.copy_from_slice(&defrag[..112]);

    println!("Username: {}", username);
    println!("Pub U: {:?}", pub_u);
    println!("Envelope: {:?}", envelope);

    opaque::registration_finalize(&username, &pub_u, &envelope);
}

#[no_mangle]
pub extern "C" fn free_token(token: *mut c_char) {
    unsafe {
        if token.is_null() {
            return;
        }
        CString::from_raw(token)
    };
}

impl From<(*const u8, *const u8, *const u8)> for Registration {
    fn from(registration: (*const u8, *const u8, *const u8)) -> Registration {
        Registration {
            beta: registration.0,
            v: registration.1,
            pub_s: registration.2,
        }
    }
}

impl From<Registration> for (*const u8, *const u8, *const u8) {
    fn from(registration: Registration) -> (*const u8, *const u8, *const u8) {
        (registration.beta, registration.v, registration.pub_s)
    }
}
