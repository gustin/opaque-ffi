use serde::{Deserialize, Serialize};
use webauthn_rs::ephemeral::WebauthnEphemeralConfig;
use webauthn_rs::error::WebauthnError;
use webauthn_rs::proto::RegisterPublicKeyCredential;
use webauthn_rs::*;

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

/*
 */
pub fn registration_challenge(username: &str) -> String {
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

/*
 */
pub fn register_credential(
    username: &str,
    credential: &str,
) -> Result<(), WebauthnError> {
    println!("Register Credential: {:?}", credential);

    let config = WebauthnEphemeralConfig::new(
        "relaying_party_name",
        "relaying_party_origin",
        "relaying_party_id",
    );
    let mut auth = Webauthn::new(config);

    let registerKey: RegisterPublicKeyCredential =
        serde_json::from_str(credential).unwrap();
    println!("Rehydrated register key: {:?}", registerKey);
    let result = auth.register_credential(registerKey, String::from(username));
    println!("Result: {:?}", result);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge() {
        println!("WebauthN");
        let challenge = registration_challenge("jerryG");
        println!("{:?}", challenge);
    }

    #[test]
    fn credential_registration() {
        let credential = r#"
            {
                "id":"Gss9igxU-3iZffReo4citavDk5c6l9YQcsFAK8OPbBTFfTah3sApRZerYS48GzcN",
                "type":"public-key",
                "rawId":"W29iamVjdCBBcnJheUJ1ZmZlcl0=",
                "response":{
                    "clientDataJSON":"W29iamVjdCBBcnJheUJ1ZmZlcl0=",
                    "attestationObject":"W29iamVjdCBBcnJheUJ1ZmZlcl0="
                }
            }
        "#;
        let valid = register_credential("jerryG", credential);
        println!("{:?}", valid);
    }
}
