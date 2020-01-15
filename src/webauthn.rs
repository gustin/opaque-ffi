use webauthn_rs::ephemeral::WebauthnEphemeralConfig;
use webauthn_rs::*;

/*
 * generate_challenge_response
 * register_credential
 * generate_challenge_authenticate
 * authenticate_credential
 */

/*
 * Each of these is described in turn, but they will all map to routes in your application. The
 * generate functions return Json challenges that are intended to be processed by the client
 * browser, and the register and authenticate will recieve Json that is processed and verified.
 *
 * During this processing, callbacks are initiated, which you can provide by implementing
 * WebauthnConfig for a type. The ephemeral module contains an example, in memory only
 * implementation of these callbacks as an example, or for testing.
 *
 * As a result of this design, you will either need to provide thread safety around the Webauthn
 * type (due to the &mut requirements in some callbacks), or you can use many Webauthn types, where
 * each WebauthnConfig you have is able to use interior mutability to protect and synchronise
 * values.
*/

fn webauthn() {
    let config = WebauthnEphemeralConfig::new(
        "relaying_party_name",
        "relaying_party_origin",
        "relaying_party_id",
    );
    let mut auth = Webauthn::new(config);
    let challenge =
        auth.generate_challenge_authenticate(String::from("username"));
    println!("{:?}", challenge);
}

#[test]
fn test_webauthn() {
    webauthn();
}
