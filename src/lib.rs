
mod authenticators;
//mod storage;
use libc::{c_char};
use std::ffi::CStr;
use std::str;

#[no_mangle]
pub extern fn generate_totp(user_id: *const c_char) {
    let c_str = unsafe {
        assert!(!user_id.is_null());
        CStr::from_ptr(user_id)
    };

    let user_id = c_str.to_str().unwrap();
    let totp = authenticators::generate_totp(user_id);
}
