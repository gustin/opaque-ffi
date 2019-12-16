mod authenticators;
mod opaque;
//mod storage;
use libc::c_char;
use std::convert::From;
use std::ffi::{CStr, CString};
use std::slice;
use std::str;

#[no_mangle]
pub extern "C" fn generate_totp_qr(user_id: *const c_char) -> *mut c_char {
    let c_str = unsafe {
        assert!(!user_id.is_null());
        CStr::from_ptr(user_id)
    };

    let user_id = c_str.to_str().unwrap();
    let qr_code_svg = authenticators::generate_totp(user_id);

    let c_str_back_at_ya = CString::new(qr_code_svg).unwrap();
    c_str_back_at_ya.into_raw()
}

#[no_mangle]
pub extern "C" fn free_totp_qr(qr: *mut c_char) {
    unsafe {
        if qr.is_null() {
            return;
        }
        CString::from_raw(qr)
    };
}

// OPAQUE interface

#[repr(C)]
pub struct Registration {
    beta: *const u8,
    v: *const u8,
    pub_s: *const u8,
}

#[no_mangle]
pub extern "C" fn registration_start(
    username: *const c_char,
    alpha: *const u8,
) -> Registration {
    println!("Welcome to Rustyville");
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

    println!("Later, Rustafarian");

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
    envelope: *const u8
) {
    println!("Welcome to Rustyville");
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


impl From<(*const u8, *const u8, *const u8)> for Registration {
    fn from(registration:(*const u8, *const u8, *const u8)) -> Registration {
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

