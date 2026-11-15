/// Every key member of the JSON Web Key Parameters registry (RFC 7518 §7.5), and `pub` and `priv`
/// of AKP (draft-ietf-cose-dilithium), read by this library or not: what is not here and not
/// common to every key is not registered, and is dropped (RFC 7517 §4).
pub(super) const KEY_MEMBERS: [&str; 15] = [
    "crv", "d", "dp", "dq", "e", "k", "n", "oth", "p", "priv", "pub", "q", "qi", "x", "y",
];

#[cfg(test)]
mod tests {
    use super::KEY_MEMBERS;

    #[test]
    fn key_members_are_the_registry() {
        // Written out again on purpose: a test that iterates `KEY_MEMBERS` can't see one missing.
        let registry = [
            "crv", "d", "dp", "dq", "e", "k", "n", "oth", "p", "priv", "pub", "q", "qi", "x", "y",
        ];

        assert_eq!(KEY_MEMBERS, registry);
    }
}
