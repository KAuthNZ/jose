use crate::base64url;

use crate::jwa::Es256;

use crate::jwa::Es384;

use crate::jwa::Es512;

use crate::jwa::Hs256;

use crate::jwa::Hs384;

use crate::jwa::Hs512;

use crate::jwa::Rs256;

use crate::jwa::Ed25519;

use crate::jwa::Algorithm;

use crate::jwa::SigningAlgorithm as Sig;

use crate::jwk::key::Jwk;

use crate::jwk::mode::Secret;

use crate::jwk::mode::Private;

use crate::jwk::members::KeyAlg;

use crate::jwk::members::KidErrors;

use crate::jwk::bind::AnyBoundSecret;

use crate::jwk::bind::AnyBoundPrivate;

use crate::jwk::key_types::Publishes;

use crate::jwa::TypedSigningAlgorithm;

use super::RsaModulus;

use super::GenerateErrors;

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

    let read = read_back(signer.to_public_json());

    assert_eq!(read.kid(), signer.kid());

    let read = read.bind::<Ed25519>().unwrap();

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

    let read = read_back(es256.to_public_json());

    assert_eq!(read.bind::<Es256>().unwrap().held, es256.public().held);

    let read = read_back(es384.to_public_json());

    assert_eq!(read.bind::<Es384>().unwrap().held, es384.public().held);

    let read = read_back(es512.to_public_json());

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

    let read = read_back(signer.to_public_json());

    // Without its alg, an RSA key is a candidate for every RS, PS and RSA-OAEP one.
    assert_eq!(
        read.held.candidates.algs(),
        [KeyAlg::from(Algorithm::Signing(Rs256::ALG))]
    );

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

#[test]
fn a_key_generated_at_run_time_is_of_the_algorithm_asked() {
    assert!(matches!(
        Jwk::<Private>::generate_expected(Sig::Ed25519),
        Ok(AnyBoundPrivate::Ed25519(_))
    ));

    assert!(matches!(
        Jwk::<Private>::generate_expected(Sig::Es256),
        Ok(AnyBoundPrivate::Es256(_))
    ));

    assert!(matches!(
        Jwk::<Private>::generate_expected(Sig::Es384),
        Ok(AnyBoundPrivate::Es384(_))
    ));

    assert!(matches!(
        Jwk::<Private>::generate_expected(Sig::Es512),
        Ok(AnyBoundPrivate::Es512(_))
    ));
}

#[test]
fn a_private_key_at_run_time_is_never_symmetric_rsa_without_size_or_unsupported() {
    for (alg, expected) in [
        (Sig::Hs256, GenerateErrors::NotForThisMode),
        (Sig::Hs512, GenerateErrors::NotForThisMode),
        (Sig::Rs256, GenerateErrors::RsaSizeRequired),
        (Sig::Ps512, GenerateErrors::RsaSizeRequired),
        (Sig::Ed448, GenerateErrors::Unsupported),
        (Sig::Es256k, GenerateErrors::Unsupported),
        (Sig::MlDsa65, GenerateErrors::Unsupported),
    ] {
        assert_eq!(
            Jwk::<Private>::generate_expected(alg).err(),
            Some(expected),
            "{alg:?}"
        );
    }
}

#[test]
fn an_rsa_key_at_run_time_is_of_the_algorithm_and_size_asked() {
    let key = Jwk::<Private>::generate_rsa_expected(Sig::Ps256, RsaModulus::Bits2048).unwrap();

    let AnyBoundPrivate::Ps256(signer) = key else {
        panic!("not PS256");
    };

    let n = signer
        .held
        .public_members()
        .iter()
        .find_map(|(name, value)| (name == "n").then(|| base64url::decode(value)))
        .unwrap()
        .unwrap();

    assert_eq!(n.len() * 8, 2048);
}

#[test]
fn only_an_rsa_algorithm_is_generated_with_a_size() {
    for alg in [Sig::Es256, Sig::Ed25519, Sig::Hs256, Sig::Ed448] {
        assert_eq!(
            Jwk::<Private>::generate_rsa_expected(alg, RsaModulus::Bits2048).err(),
            Some(GenerateErrors::NotRsa),
            "{alg:?}"
        );
    }
}

#[test]
fn a_secret_at_run_time_is_of_the_algorithm_asked_and_only_symmetric() {
    assert!(matches!(
        Jwk::<Secret>::generate_expected(Sig::Hs256),
        Ok(AnyBoundSecret::Hs256(_))
    ));

    assert!(matches!(
        Jwk::<Secret>::generate_expected(Sig::Hs384),
        Ok(AnyBoundSecret::Hs384(_))
    ));

    assert!(matches!(
        Jwk::<Secret>::generate_expected(Sig::Hs512),
        Ok(AnyBoundSecret::Hs512(_))
    ));

    for alg in [Sig::Es256, Sig::Rs256, Sig::Ed25519, Sig::MlDsa44] {
        assert_eq!(
            Jwk::<Secret>::generate_expected(alg).err(),
            Some(GenerateErrors::NotForThisMode),
            "{alg:?}"
        );
    }
}
