use crate::jwk::key::Jwk;

use crate::jwk::mode::Public;

use super::jwk_set::JwkSet;

use super::get_errors::GetErrors;

impl JwkSet<Public> {
    /// The key with this `kid`, its own copy, to bind to the algorithm the caller expects. Without
    /// a `kid`, as from a token that has none, only the key of a set of one: a key is never tried.
    ///
    /// ```
    /// use kauthnz_jose::jwa::Es256;
    ///
    /// use kauthnz_jose::jwk::JwkSet;
    ///
    /// // RFC 8037 A.2 and RFC 7517 A.1.
    /// let set = JwkSet::read_public(br#"{"keys": [
    ///     {"kty": "OKP", "crv": "Ed25519", "kid": "okp",
    ///         "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"},
    ///     {"kty": "EC", "crv": "P-256", "kid": "ec",
    ///         "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
    ///         "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}
    /// ]}"#)?;
    ///
    /// let key = set.get(Some("ec"))?.bind::<Es256>()?;
    ///
    /// assert_eq!(key.kid(), Some("ec"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn get(&self, kid: Option<&str>) -> Result<Jwk<Public>, GetErrors> {
        let key = match (kid, self.keys.as_slice()) {
            (Some(kid), keys) => keys
                .iter()
                .find(|key| key.kid() == Some(kid))
                .ok_or(GetErrors::UnknownKid)?,

            (None, [only]) => only,

            (None, _) => return Err(GetErrors::KidRequired),
        };

        Ok(key.clone())
    }
}
