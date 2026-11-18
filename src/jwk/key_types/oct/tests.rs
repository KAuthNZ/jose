use super::OctErrors;

use super::OctSecretKey;

// RFC 7517 A.3: the A128KW key and the HMAC key of RFC 7515 A.1.
const K_16: &str = "GawgguFyGrWKav7AX4VKUg";

const K_64: &str =
    "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";

fn refused(k: &str) -> OctErrors {
    match OctSecretKey::read(k) {
        Ok(_) => panic!("read"),

        Err(error) => error,
    }
}

#[test]
fn reads_the_symmetric_keys_of_rfc_7517() {
    assert_eq!(OctSecretKey::read(K_16).unwrap().len(), 16);

    assert_eq!(OctSecretKey::read(K_64).unwrap().len(), 64);
}

#[test]
fn the_secret_is_the_decoded_k() {
    let key = OctSecretKey::read("AQID").unwrap();

    assert_eq!(key.secret(), [1, 2, 3]);
}

#[test]
fn an_empty_k_is_no_key() {
    assert_eq!(refused(""), OctErrors::Empty);
}

#[test]
fn k_must_be_unpadded_canonical_base64url() {
    for k in [
        "GawgguFyGrWKav7AX4VKUg==",
        "GawgguFyGrWKav7AX4VKUg+/",
        "GawgguFyGrWKav7AX4VKUh",
        "GawgguFyGrWKav7AX4VKU",
        "Gawg guFyGrWKav7AX4VKUg",
    ] {
        assert_eq!(refused(k), OctErrors::InvalidEncoding, "{k}");
    }
}

#[test]
fn any_bytes_are_a_key_whatever_their_length() {
    // How long a key must be is a rule of each algorithm, judged with it.
    for k in ["AA", "AQID", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"] {
        assert!(OctSecretKey::read(k).is_ok(), "{k}");
    }
}
