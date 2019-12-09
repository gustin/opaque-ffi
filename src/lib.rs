mod authenticators;
mod opaque;
//mod storage;
use libc::c_char;
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

#[no_mangle]
pub extern "C" fn registration_1(
    username: *const c_char,
    alpha: *const u8,
) {
    let username_c_str = unsafe {
        assert!(!username.is_null());
        CStr::from_ptr(username)
    };
    let username = username_c_str.to_str().unwrap();

    let defrag: &[u8] = unsafe { slice::from_raw_parts(alpha, 32 as usize) };
    let mut alpha: [u8; 32] = [0; 32];
    alpha.copy_from_slice(&defrag[..32]);

    opaque::registration_init(username, &alpha);
}
