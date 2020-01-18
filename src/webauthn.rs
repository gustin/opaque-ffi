use serde::{Deserialize, Serialize};
use serde_json::Result;
use webauthn_rs::*;
use webauthn_rs::ephemeral::WebauthnEphemeralConfig;

/*
 * WebAuthN Glossary
 *
 * Challenge: a challenge issued by the server. This contains a set of random bytes which should
 * always be kept private. This type can be serialised or deserialised by serde as required for
 * your storage needs.
 *
 * CreationChallengeResponse: A JSON serialisable challenge which is issued to the user's
 * webbrowser for handling. This is meant to be opaque, that is, you should not need to inspect or
 * alter the content of the struct - you should serialise it and transmit it to the client only.
 *
 * Credential: A user's authenticator credential. It contains an id, the public key and a counter
 * of how many times the authenticator has been used.
 *
 * PublicKeyCredential: A client response to an authentication challenge. This contains all
 * required information to asses and assert trust in a credentials legitimacy, followed by
 * authentication to a user.
 *
 * RegisterPublicKeyCredential: A client response to a registration challenge. This contains all
 * required information to asses and assert trust in a credentials legitimacy, followed by
 * registration to a user.
 *
 * RequestChallengeResponse: A JSON serialisable challenge which is issued to the user's
 * webbrowser for handling. This is meant to be opaque, that is, you should not need to inspect or
 * alter the content of the struct - you should serialise it and transmit it to the client only.
*/

/*
 * WebAuthN Functions:
 *
 * generate_challenge_response
 * register_credential
 * generate_challenge_authenticate
 * authenticate_credential
 *
 * Each of these is described in turn, but they will all map to routes in your application. The
 * generate functions return Json challenges that are intended to be processed by the client
 * browser, and the register and authenticate will recieve Json that is processed and verified.
 *
 * As a result of this design, you will either need to provide thread safety around the Webauthn
 * type (due to the &mut requirements in some callbacks), or you can use many Webauthn types, where
 * each WebauthnConfig you have is able to use interior mutability to protect and synchronise
 * values.
*/

fn registration_challenge(username: &str) -> String {
    let config = WebauthnEphemeralConfig::new(
        "relaying_party_name",
        "relaying_party_origin",
        "relaying_party_id",
    );
    let mut auth = Webauthn::new(config);
    let challenge = auth.generate_challenge_register(String::from(username));
    println!("{:?}", challenge);
    let json = serde_json::to_string(&challenge.unwrap());
    json.unwrap()
}




#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge() {
        println!("WebauthN");
        let challenge = registration_challenge("jerryg");
        println!("{:?}", challenge);
    }
}
