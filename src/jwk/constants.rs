/// Every key member of the JSON Web Key Parameters registry (RFC 7518 §7.5), and `pub` and `priv`
/// of AKP (draft-ietf-cose-dilithium), read by this library or not: what is not here and not
/// common to every key is not registered, and is dropped (RFC 7517 §4).
pub(super) const KEY_MEMBERS: [&str; 15] = [
    "crv", "d", "dp", "dq", "e", "k", "n", "oth", "p", "priv", "pub", "q", "qi", "x", "y",
];

/// The key members the registry gives the "Private" class (RFC 7517 §8.1.1), of any `kty`: a
/// public key that has one of them is not public, whatever its `kty` says.
pub(super) const SECRET_MEMBERS: [&str; 9] = ["d", "dp", "dq", "k", "oth", "p", "priv", "q", "qi"];

#[cfg(test)]
mod tests {
    use super::KEY_MEMBERS;

    use super::SECRET_MEMBERS;

    #[test]
    fn key_members_are_the_registry() {
        // Written out again on purpose: a test that iterates `KEY_MEMBERS` can't see one missing.
        let registry = [
            "crv", "d", "dp", "dq", "e", "k", "n", "oth", "p", "priv", "pub", "q", "qi", "x", "y",
        ];

        assert_eq!(KEY_MEMBERS, registry);
    }

    #[test]
    fn secret_members_are_the_private_class_of_the_registry() {
        let private_class = ["d", "dp", "dq", "k", "oth", "p", "priv", "q", "qi"];

        assert_eq!(SECRET_MEMBERS, private_class);
    }

    #[test]
    fn every_secret_member_is_a_key_member() {
        for name in SECRET_MEMBERS {
            assert!(KEY_MEMBERS.contains(&name), "{name}");
        }
    }
}
