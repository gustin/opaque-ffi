
mod authenticators;
//mod storage;
use libc::{c_char};
use std::ffi::{CStr, CString};
use std::str;

#[no_mangle]
pub extern fn generate_totp_qr(user_id: *const c_char) -> *mut c_char {
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
pub extern fn free_totp_qr(qr: *mut c_char) {
    unsafe {
        if qr.is_null() { return }
        CString::from_raw(qr)
    };
}
