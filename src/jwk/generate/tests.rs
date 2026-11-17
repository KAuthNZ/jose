use crate::base64url;

use crate::jwa::Es256;

use crate::jwa::Es384;

use crate::jwa::Es512;

use crate::jwa::Hs256;

use crate::jwa::Hs384;

use crate::jwa::Hs512;

use crate::jwa::Rs256;

use crate::jwa::Ed25519;

use crate::jwk::key::Jwk;

use crate::jwk::mode::Secret;

use crate::jwk::mode::Private;

use crate::jwk::members::KidErrors;

use crate::jwk::key_types::Publishes;

use crate::jwa::TypedSigningAlgorithm;

use super::RsaModulus;

/// The public JWK of a generated key, read back as any other: a key this library generates is
/// one it reads.
fn read_back(json: String) -> Jwk<crate::jwk::mode::Public> {
    match Jwk::read_public(json.as_bytes()) {
        Ok(jwk) => jwk,

        Err(error) => panic!("{error:?}: {json}"),
    }
}

#[test]
fn a_generated_ed25519_key_has_its_thumbprint_as_kid_and_reads_back() {
    let signer = Jwk::<Private<Ed25519>>::generate().unwrap();

    let thumbprint = signer.thumbprint().to_string();

    assert_eq!(signer.kid(), Some(thumbprint.as_str()));

    let read = read_back(signer.held.public_members().thumbprint_json())
        .bind::<Ed25519>()
        .unwrap();

    assert_eq!(read.held, signer.public().held);

    assert_eq!(read.thumbprint().to_string(), thumbprint);
}

#[test]
fn a_generated_ec_key_of_each_curve_has_its_thumbprint_as_kid_and_reads_back() {
    let es256 = Jwk::<Private<Es256>>::generate().unwrap();

    let es384 = Jwk::<Private<Es384>>::generate().unwrap();

    let es512 = Jwk::<Private<Es512>>::generate().unwrap();

    assert_eq!(es256.kid(), Some(es256.thumbprint().to_string().as_str()));

    assert_eq!(es384.kid(), Some(es384.thumbprint().to_string().as_str()));

    assert_eq!(es512.kid(), Some(es512.thumbprint().to_string().as_str()));

    let read = read_back(es256.held.public_members().thumbprint_json());

    assert_eq!(read.bind::<Es256>().unwrap().held, es256.public().held);

    let read = read_back(es384.held.public_members().thumbprint_json());

    assert_eq!(read.bind::<Es384>().unwrap().held, es384.public().held);

    let read = read_back(es512.held.public_members().thumbprint_json());

    assert_eq!(read.bind::<Es512>().unwrap().held, es512.public().held);
}

#[test]
fn two_generated_keys_are_two_keys() {
    let first = Jwk::<Private<Ed25519>>::generate().unwrap();

    let second = Jwk::<Private<Ed25519>>::generate().unwrap();

    assert_ne!(first.thumbprint(), second.thumbprint());

    assert_ne!(first.kid(), second.kid());
}

#[test]
fn a_generated_secret_is_as_long_as_its_algorithm_asks_and_has_a_random_kid() {
    let hs256 = Jwk::<Secret<Hs256>>::generate().unwrap();

    let hs384 = Jwk::<Secret<Hs384>>::generate().unwrap();

    let hs512 = Jwk::<Secret<Hs512>>::generate().unwrap();

    assert_eq!(Some(hs256.held.len()), Hs256::ALG.min_secret_len());

    assert_eq!(Some(hs384.held.len()), Hs384::ALG.min_secret_len());

    assert_eq!(Some(hs512.held.len()), Hs512::ALG.min_secret_len());

    // 16 random bytes, 22 characters of base64url.
    for kid in [hs256.kid(), hs384.kid(), hs512.kid()] {
        assert_eq!(kid.map(str::len), Some(22));
    }

    let again = Jwk::<Secret<Hs256>>::generate().unwrap();

    assert_ne!(again.kid(), hs256.kid());

    assert_ne!(again.held.secret(), hs256.held.secret());
}

#[test]
fn a_generated_rsa_key_is_of_its_size_has_its_thumbprint_as_kid_and_reads_back() {
    let signer = Jwk::<Private<Rs256>>::generate_rsa(RsaModulus::Bits2048).unwrap();

    assert_eq!(signer.kid(), Some(signer.thumbprint().to_string().as_str()));

    let read = read_back(signer.held.public_members().thumbprint_json());

    let bound = read.bind::<Rs256>().unwrap();

    assert_eq!(bound.held, signer.public().held);

    let n = bound
        .held
        .public_members()
        .iter()
        .find_map(|(name, value)| (name == "n").then(|| base64url::decode(value)))
        .unwrap()
        .unwrap();

    assert_eq!(n.len() * 8, 2048);
}

#[test]
fn with_kid_changes_the_kid_of_the_key_and_holds_it_to_the_rules() {
    let signer = Jwk::<Private<Ed25519>>::generate().unwrap();

    let thumbprint = signer.thumbprint();

    let renamed = signer.with_kid("2026-11-tenant-a").unwrap();

    assert_eq!(renamed.kid(), Some("2026-11-tenant-a"));

    // The key is the same one: only its name changed.
    assert_eq!(renamed.thumbprint(), thumbprint);

    assert_eq!(renamed.with_kid("").err(), Some(KidErrors::Empty));
}
