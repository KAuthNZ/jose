/// `alg`, `use` and `key_ops` of one JWK, each as it came. Named fields, so that `alg` and
/// `use`, both a string, can't be swapped by position.
pub(in crate::jwk) struct KeyMetadataMembers<'a> {
    pub(in crate::jwk) alg: Option<&'a str>,

    pub(in crate::jwk) key_use: Option<&'a str>,

    pub(in crate::jwk) key_ops: Option<&'a [String]>,
}
