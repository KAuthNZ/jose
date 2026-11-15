use serde_json::Value;

use serde_json::json;

use crate::jwa::Algorithm;

use crate::jwa::SigningAlgorithm as Sig;

use crate::jwa::KeyManagementAlgorithm as Km;

use crate::jwk::mode::Public;

use crate::jwk::mode::Secret;

use crate::jwk::mode::Private;

use crate::jwk::fit::FitErrors;

use crate::jwk::members::KeyAlg;

use crate::jwk::raw::RawJwkErrors;

use crate::jwk::members::KidErrors;

use crate::jwk::members::KeyUseErrors;

use crate::jwk::key_types::AnyPublicKey;

use crate::jwk::members::KeyMetadataErrors;

use crate::jwk::decoding::JwkDecodingErrors;

use crate::jwk::key_types::ClassificationErrors;

use super::Jwk;

use super::JwkErrors;

// RFC 7517 A.1 and A.2, the P-256 key.
const EC_X: &str = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4";

const EC_Y: &str = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM";

const EC_D: &str = "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE";

// RFC 8037 A.1.
const OKP_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

fn bytes(value: Value) -> Vec<u8> {
    value.to_string().into_bytes()
}

fn public(value: Value) -> Result<Jwk<Public>, JwkErrors> {
    Jwk::read_public(&bytes(value))
}

fn private(value: Value) -> Result<Jwk<Private>, JwkErrors> {
    Jwk::read_private(&bytes(value))
}

fn secret(value: Value) -> Result<Jwk<Secret>, JwkErrors> {
    Jwk::read_secret(&bytes(value))
}

fn refused_public(value: Value) -> JwkErrors {
    match public(value) {
        Ok(_) => panic!("read"),

        Err(error) => error,
    }
}

fn sig(alg: Sig) -> KeyAlg {
    KeyAlg::from(Algorithm::Signing(alg))
}

fn ecdh_es() -> Vec<KeyAlg> {
    [
        Km::EcdhEs,
        Km::EcdhEsA128Kw,
        Km::EcdhEsA192Kw,
        Km::EcdhEsA256Kw,
    ]
    .map(|alg| KeyAlg::from(Algorithm::KeyManagement(alg)))
    .to_vec()
}

#[test]
fn a_public_key_is_read_with_its_kid_and_candidates() {
    let jwk = public(json!({
        "kty": "EC", "crv": "P-256", "x": EC_X, "y": EC_Y, "kid": "2026-11", "alg": "ES256",
    }))
    .unwrap();

    assert_eq!(jwk.kid(), Some("2026-11"));

    assert!(matches!(jwk.held.material, AnyPublicKey::Ec(_)));

    assert_eq!(jwk.held.candidates.algs(), [sig(Sig::Es256)]);
}

#[test]
fn a_key_without_kid_is_read_without_one() {
    let jwk = public(json!({ "kty": "OKP", "crv": "Ed25519", "x": OKP_X })).unwrap();

    assert_eq!(jwk.kid(), None);

    assert_eq!(jwk.held.candidates.algs(), [sig(Sig::Ed25519)]);
}

#[test]
fn a_private_key_is_read_in_its_own_mode() {
    let jwk = private(json!({
        "kty": "EC", "crv": "P-256", "x": EC_X, "y": EC_Y, "d": EC_D, "key_ops": ["sign"],
    }))
    .unwrap();

    assert_eq!(jwk.held.candidates.algs(), [sig(Sig::Es256)]);
}

#[test]
fn an_ecdh_public_key_as_webcrypto_exports_it_is_read() {
    let jwk = public(json!({
        "kty": "EC", "crv": "P-256", "x": EC_X, "y": EC_Y, "key_ops": [], "ext": true,
    }))
    .unwrap();

    assert_eq!(jwk.held.candidates.algs(), ecdh_es());
}

#[test]
fn each_stage_refuses_with_its_own_error() {
    assert_eq!(
        Jwk::read_public(b"[]").err(),
        Some(JwkErrors::Decoding(JwkDecodingErrors::NotAnObject))
    );

    assert_eq!(
        refused_public(json!({ "crv": "P-256", "x": EC_X, "y": EC_Y })),
        JwkErrors::Raw(RawJwkErrors::MissingKty)
    );

    assert_eq!(
        refused_public(json!({ "kty": "OKP", "crv": "Ed25519", "x": OKP_X, "kid": "" })),
        JwkErrors::Kid(KidErrors::Empty)
    );

    assert_eq!(
        refused_public(json!({ "kty": "EC", "crv": "P-256", "x": EC_X, "y": EC_Y, "use": "both" })),
        JwkErrors::Metadata(KeyMetadataErrors::Use(KeyUseErrors::Unregistered))
    );

    assert_eq!(
        refused_public(json!({ "kty": "EC", "x": EC_X, "y": EC_Y })),
        JwkErrors::Classification(ClassificationErrors::MissingMember("crv"))
    );

    assert_eq!(
        refused_public(json!({ "kty": "OKP", "crv": "Ed25519", "x": OKP_X, "use": "enc" })),
        JwkErrors::Fit(FitErrors::UseAndKey)
    );
}

#[test]
fn the_bytes_are_judged_before_the_key() {
    assert_eq!(
        Jwk::read_public(br#"{"kty": "EC", "kty": "EC"}"#).err(),
        Some(JwkErrors::Decoding(JwkDecodingErrors::DuplicateMembers))
    );
}

#[test]
fn an_empty_kid_is_refused_in_every_mode() {
    let empty = Some(JwkErrors::Kid(KidErrors::Empty));

    assert_eq!(
        public(json!({ "kty": "OKP", "crv": "Ed25519", "x": OKP_X, "kid": "" })).err(),
        empty
    );

    assert_eq!(
        private(json!({ "kty": "EC", "crv": "P-256", "x": EC_X, "y": EC_Y, "d": EC_D, "kid": "" }))
            .err(),
        empty
    );

    assert_eq!(
        secret(json!({ "kty": "oct", "k": "GawgguFyGrWKav7AX4VKUg", "kid": "" })).err(),
        empty
    );
}

#[test]
fn the_kid_is_judged_before_the_metadata() {
    assert_eq!(
        refused_public(
            json!({ "kty": "OKP", "crv": "Ed25519", "x": OKP_X, "kid": "", "use": "both" })
        ),
        JwkErrors::Kid(KidErrors::Empty)
    );
}

#[test]
fn the_metadata_are_judged_before_the_material_is_decoded() {
    assert_eq!(
        refused_public(json!({ "kty": "EC", "crv": "P-256", "x": "!!", "use": "both" })),
        JwkErrors::Metadata(KeyMetadataErrors::Use(KeyUseErrors::Unregistered))
    );
}

#[test]
fn a_private_key_read_as_public_is_refused_not_trimmed() {
    assert_eq!(
        refused_public(json!({ "kty": "EC", "crv": "P-256", "x": EC_X, "y": EC_Y, "d": EC_D })),
        JwkErrors::Classification(ClassificationErrors::SecretMember("d"))
    );
}

#[test]
fn certificate_members_are_dropped_unread() {
    let jwk = public(json!({
        "kty": "EC", "crv": "P-256", "x": EC_X, "y": EC_Y,
        "x5c": ["not a certificate"], "x5t": "x", "x5t#S256": "x", "x5u": "https://example.com",
    }))
    .unwrap();

    let mut p256 = vec![sig(Sig::Es256)];

    p256.extend(ecdh_es());

    assert_eq!(jwk.held.candidates.algs(), p256);
}

#[test]
fn the_symmetric_keys_of_rfc_7517_are_read_as_secret_by_their_size() {
    let hmac = secret(json!({
        "kty": "oct",
        "k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
        "kid": "HMAC key used in JWS spec Appendix A.1 example",
    }))
    .unwrap();

    assert_eq!(
        hmac.held.candidates.algs(),
        [Sig::Hs256, Sig::Hs384, Sig::Hs512].map(sig)
    );

    // The A128KW key: no JWE yet, and 16 bytes are too short for any HS.
    assert_eq!(
        secret(json!({ "kty": "oct", "alg": "A128KW", "k": "GawgguFyGrWKav7AX4VKUg" })).err(),
        Some(JwkErrors::Fit(FitErrors::NoAlgorithm))
    );
}
