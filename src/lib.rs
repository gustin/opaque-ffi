use std::str;

mod authenticators;
//mod storage;

#[no_mangle]
pub extern "C" fn generate_totp(user_id: &str) -> String {
    let totp = authenticators::generate_totp(user_id);

    return "Holla".to_string();
}
