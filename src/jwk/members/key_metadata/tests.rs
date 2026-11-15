use crate::jwa::Algorithm;

use crate::jwa::SigningAlgorithm;

use crate::jwa::KeyManagementAlgorithm;

use super::super::alg::KeyAlg;

use super::super::alg::AlgErrors;

use super::super::key_ops::KeyOp;

use super::super::key_use::KeyUse;

use super::super::key_ops::KeyOpsErrors;

use super::super::key_use::KeyUseErrors;

use super::KeyMetadata;

use super::KeyMetadataMembers;

use super::CoherenceErrors;

use super::KeyMetadataErrors;

fn ops(list: &[&str]) -> Vec<String> {
    list.iter().map(|name| (*name).to_owned()).collect()
}

/// The members of one JWK, by name: what a case doesn't name is absent.
#[derive(Default)]
struct Given<'a> {
    alg: Option<&'a str>,

    key_use: Option<&'a str>,

    key_ops: Option<&'a [&'a str]>,
}

fn read(given: Given<'_>) -> Result<KeyMetadata, KeyMetadataErrors> {
    let key_ops = given.key_ops.map(ops);

    KeyMetadata::read(KeyMetadataMembers {
        alg: given.alg,
        key_use: given.key_use,
        key_ops: key_ops.as_deref(),
    })
}

#[test]
fn nothing_present_is_nothing_said() {
    let metadata = read(Given::default()).unwrap();

    assert_eq!(metadata.key_use(), None);

    assert_eq!(metadata.key_ops(), None);

    assert_eq!(metadata.alg(), None);
}

#[test]
fn members_that_agree_are_read() {
    let metadata = read(Given {
        alg: Some("ES256"),
        key_use: Some("sig"),
        key_ops: Some(&["verify"]),
    })
    .unwrap();

    assert_eq!(metadata.key_use(), Some(KeyUse::Signature));

    assert_eq!(
        metadata.key_ops().map(|ops| ops.ops()),
        Some(&[KeyOp::Verify][..])
    );

    assert_eq!(
        metadata.alg().map(KeyAlg::algorithm),
        Some(Algorithm::Signing(SigningAlgorithm::Es256))
    );

    let metadata = read(Given {
        alg: Some("RSA-OAEP-256"),
        key_use: Some("enc"),
        key_ops: Some(&["wrapKey", "unwrapKey"]),
    })
    .unwrap();

    assert_eq!(
        metadata.alg().map(KeyAlg::algorithm),
        Some(Algorithm::KeyManagement(KeyManagementAlgorithm::RsaOaep256))
    );
}

#[test]
fn each_member_alone_is_judged_by_its_own_rules() {
    assert_eq!(
        read(Given {
            key_use: Some("both"),
            ..Given::default()
        }),
        Err(KeyMetadataErrors::Use(KeyUseErrors::Unregistered))
    );

    assert_eq!(
        read(Given {
            key_ops: Some(&["frobnicate"]),
            ..Given::default()
        }),
        Err(KeyMetadataErrors::KeyOps(KeyOpsErrors::Unregistered))
    );

    assert_eq!(
        read(Given {
            alg: Some("RSA1_5"),
            ..Given::default()
        }),
        Err(KeyMetadataErrors::Alg(AlgErrors::Unsupported))
    );
}

// Whether a key of no operation is of any use is judged with the key: here it contradicts nothing.
#[test]
fn an_empty_key_ops_contradicts_no_member() {
    for (alg, key_use) in [
        (None, None),
        (None, Some("enc")),
        (None, Some("sig")),
        (Some("ECDH-ES"), None),
        (Some("ES256"), Some("sig")),
    ] {
        let metadata = read(Given {
            alg,
            key_use,
            key_ops: Some(&[]),
        })
        .unwrap();

        assert_eq!(
            metadata.key_ops().map(|ops| ops.ops().len()),
            Some(0),
            "{alg:?} {key_use:?}"
        );
    }
}

#[test]
fn use_and_key_ops_may_come_together_but_not_contradict() {
    assert!(
        read(Given {
            key_use: Some("sig"),
            key_ops: Some(&["sign", "verify"]),
            ..Given::default()
        })
        .is_ok()
    );

    assert_eq!(
        read(Given {
            key_use: Some("sig"),
            key_ops: Some(&["encrypt"]),
            ..Given::default()
        }),
        Err(KeyMetadataErrors::Coherence(CoherenceErrors::UseAndKeyOps))
    );

    assert_eq!(
        read(Given {
            key_use: Some("enc"),
            key_ops: Some(&["verify"]),
            ..Given::default()
        }),
        Err(KeyMetadataErrors::Coherence(CoherenceErrors::UseAndKeyOps))
    );
}

#[test]
fn use_and_alg_may_not_contradict() {
    assert_eq!(
        read(Given {
            alg: Some("ES256"),
            key_use: Some("enc"),
            ..Given::default()
        }),
        Err(KeyMetadataErrors::Coherence(CoherenceErrors::UseAndAlg))
    );

    assert_eq!(
        read(Given {
            alg: Some("ECDH-ES"),
            key_use: Some("sig"),
            ..Given::default()
        }),
        Err(KeyMetadataErrors::Coherence(CoherenceErrors::UseAndAlg))
    );
}

#[test]
fn key_ops_and_alg_may_not_contradict_without_a_use() {
    assert_eq!(
        read(Given {
            alg: Some("RSA-OAEP"),
            key_ops: Some(&["verify"]),
            ..Given::default()
        }),
        Err(KeyMetadataErrors::Coherence(CoherenceErrors::KeyOpsAndAlg))
    );

    assert_eq!(
        read(Given {
            alg: Some("PS256"),
            key_ops: Some(&["decrypt"]),
            ..Given::default()
        }),
        Err(KeyMetadataErrors::Coherence(CoherenceErrors::KeyOpsAndAlg))
    );
}

#[test]
fn with_an_alg_the_operations_of_that_one_algorithm_come_together() {
    for (key_ops, alg) in [
        (&["sign", "verify"][..], "ES256"),
        (&["encrypt", "decrypt", "wrapKey", "unwrapKey"], "RSA-OAEP"),
        (&["wrapKey", "encrypt"], "RSA-OAEP-256"),
        (&["deriveKey", "deriveBits"], "ECDH-ES"),
        (&["deriveBits", "deriveKey"], "ECDH-ES+A256KW"),
        (&["encrypt", "decrypt"], "dir"),
    ] {
        assert!(
            read(Given {
                alg: Some(alg),
                key_ops: Some(key_ops),
                ..Given::default()
            })
            .is_ok(),
            "{alg} {key_ops:?}"
        );
    }
}

#[test]
fn with_an_alg_an_operation_of_another_algorithm_is_refused() {
    for (key_ops, alg) in [
        (&["verify", "encrypt"][..], "RS256"),
        (&["wrapKey", "encrypt"], "A256KW"),
        (&["wrapKey"], "ECDH-ES+A256KW"),
        (&["deriveKey"], "RSA-OAEP"),
        (&["wrapKey"], "dir"),
        (&["encrypt"], "A128GCMKW"),
    ] {
        assert_eq!(
            read(Given {
                alg: Some(alg),
                key_ops: Some(key_ops),
                ..Given::default()
            }),
            Err(KeyMetadataErrors::Coherence(CoherenceErrors::KeyOpsAndAlg)),
            "{alg} {key_ops:?}"
        );
    }
}

#[test]
fn every_operation_is_held_to_use_not_only_the_first() {
    assert_eq!(
        read(Given {
            key_use: Some("sig"),
            key_ops: Some(&["verify", "encrypt"]),
            ..Given::default()
        }),
        Err(KeyMetadataErrors::Coherence(CoherenceErrors::UseAndKeyOps))
    );

    assert_eq!(
        read(Given {
            alg: Some("RSA-OAEP"),
            key_use: Some("enc"),
            key_ops: Some(&["wrapKey", "sign"])
        }),
        Err(KeyMetadataErrors::Coherence(CoherenceErrors::UseAndKeyOps))
    );
}

// The three of RFC 7517 §4.3 and the derivation one of WebCrypto ECDH, written out instead of
// taken from `KeyOp::counterpart`.
const PERMITTED_PAIRS: [(&str, &str); 4] = [
    ("sign", "verify"),
    ("encrypt", "decrypt"),
    ("wrapKey", "unwrapKey"),
    ("deriveKey", "deriveBits"),
];

fn permitted(one: &str, other: &str) -> bool {
    PERMITTED_PAIRS
        .iter()
        .any(|&(a, b)| (a, b) == (one, other) || (b, a) == (one, other))
}

fn unrelated() -> Result<KeyMetadata, KeyMetadataErrors> {
    Err(KeyMetadataErrors::Coherence(CoherenceErrors::UnrelatedOps))
}

#[test]
fn without_an_alg_any_operation_alone_comes() {
    for op in KeyOp::ALL {
        assert!(
            read(Given {
                key_ops: Some(&[op.name()]),
                ..Given::default()
            })
            .is_ok(),
            "{op:?}"
        );
    }
}

#[test]
fn an_ecdh_key_as_webcrypto_exports_it_is_read() {
    for key_ops in [
        &["deriveKey", "deriveBits"][..],
        &["deriveBits", "deriveKey"],
    ] {
        assert!(
            read(Given {
                key_ops: Some(key_ops),
                ..Given::default()
            })
            .is_ok(),
            "{key_ops:?}"
        );
    }
}

#[test]
fn without_an_alg_two_operations_come_only_as_a_permitted_pair() {
    for one in KeyOp::ALL {
        for other in KeyOp::ALL {
            if one == other {
                continue;
            }

            let read = read(Given {
                key_ops: Some(&[one.name(), other.name()]),
                ..Given::default()
            });

            if permitted(one.name(), other.name()) {
                assert!(read.is_ok(), "{one:?} {other:?}");
            } else {
                assert_eq!(read, unrelated(), "{one:?} {other:?}");
            }
        }
    }
}

#[test]
fn without_an_alg_unrelated_operations_are_refused() {
    for key_ops in [
        // Of both uses.
        &["sign", "encrypt"][..],
        &["verify", "encrypt"],
        &["decrypt", "verify"],
        // Of one use, but not one pair.
        &["encrypt", "wrapKey"],
        &["decrypt", "unwrapKey"],
        &["wrapKey", "deriveKey"],
        &["unwrapKey", "deriveBits"],
        // A pair and one more.
        &["sign", "verify", "encrypt"],
        &["wrapKey", "unwrapKey", "encrypt"],
        &["wrapKey", "unwrapKey", "deriveBits"],
        &["deriveKey", "deriveBits", "wrapKey"],
        &["encrypt", "decrypt", "wrapKey", "unwrapKey"],
        &[
            "sign",
            "verify",
            "encrypt",
            "decrypt",
            "wrapKey",
            "unwrapKey",
            "deriveKey",
            "deriveBits",
        ],
    ] {
        assert_eq!(
            read(Given {
                key_ops: Some(key_ops),
                ..Given::default()
            }),
            unrelated(),
            "{key_ops:?}"
        );
    }
}
