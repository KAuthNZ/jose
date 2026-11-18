use std::collections::BTreeMap;

use crate::json::write_object;

use crate::jwk::mode::HoldsAlg;

use crate::jwk::members::KeyUse;

use crate::jwk::key_types::Publishes;

use super::jwk::Jwk;

use super::holds::Holds;

impl<M> Jwk<M>
where
    M: Holds + HoldsAlg,
    M::Held: Publishes,
{
    /// The JWK of its public key, to publish: the public members of its family, its `kid` and,
    /// if it is bound, the `alg` it is bound to and `"use": "sig"`, both from its type. Of a
    /// private key too, without what makes it private: what is written is what it publishes,
    /// never a secret member.
    ///
    /// `use` because a set with signing and encryption keys needs it on every key (OpenID Connect
    /// Discovery §3); never `key_ops` with it (RFC 7517 §4.3). What was read with the key and
    /// not kept is not written: an unbound key has no `alg` nor `use`, whatever it declared. In
    /// the order of the names, without whitespace.
    ///
    /// ```
    /// use kauthnz_jose::jwa::Ed25519;
    ///
    /// use kauthnz_jose::jwk::Jwk;
    ///
    /// // RFC 8037 A.1.
    /// let signer = Jwk::read_private(br#"{"kty": "OKP", "crv": "Ed25519", "kid": "2026-11",
    ///     "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
    ///     "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}"#)?
    ///     .bind::<Ed25519>()?;
    ///
    /// assert_eq!(
    ///     signer.to_public_json(),
    ///     r#"{"alg":"Ed25519","crv":"Ed25519","kid":"2026-11","kty":"OKP","use":"sig","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#
    /// );
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// Not of a secret: it has no public side.
    ///
    /// ```compile_fail,E0599
    /// use kauthnz_jose::jwk::Jwk;
    ///
    /// let secret = Jwk::read_secret(br#"{"kty": "oct",
    ///     "k": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"}"#)?;
    ///
    /// let json = secret.to_public_json();
    /// # Ok::<(), kauthnz_jose::jwk::JwkErrors>(())
    /// ```
    pub fn to_public_json(&self) -> String {
        let public = self.held.public_members();

        let mut members: BTreeMap<&str, &str> = public.iter().collect();

        if let Some(kid) = &self.kid {
            members.insert("kid", kid.as_str());
        }

        if let Some(alg) = M::ALG {
            members.insert("alg", alg.name());

            members.insert("use", KeyUse::Signature.name());
        }

        write_object(&members)
    }
}
