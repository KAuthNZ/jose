use crate::jwa::SigningAlgorithm;

use super::*;

// No wildcard on purpose: a new variant does not compile here until it has a marker.
fn marker_alg(alg: SigningAlgorithm) -> SigningAlgorithm {
    match alg {
        SigningAlgorithm::Hs256 => Hs256::ALG,
        SigningAlgorithm::Hs384 => Hs384::ALG,
        SigningAlgorithm::Hs512 => Hs512::ALG,
        SigningAlgorithm::Rs256 => Rs256::ALG,
        SigningAlgorithm::Rs384 => Rs384::ALG,
        SigningAlgorithm::Rs512 => Rs512::ALG,
        SigningAlgorithm::Ps256 => Ps256::ALG,
        SigningAlgorithm::Ps384 => Ps384::ALG,
        SigningAlgorithm::Ps512 => Ps512::ALG,
        SigningAlgorithm::Es256 => Es256::ALG,
        SigningAlgorithm::Es384 => Es384::ALG,
        SigningAlgorithm::Es512 => Es512::ALG,
        SigningAlgorithm::Es256k => Es256k::ALG,
        SigningAlgorithm::Ed25519 => Ed25519::ALG,
        SigningAlgorithm::Ed448 => Ed448::ALG,
        SigningAlgorithm::MlDsa44 => MlDsa44::ALG,
        SigningAlgorithm::MlDsa65 => MlDsa65::ALG,
        SigningAlgorithm::MlDsa87 => MlDsa87::ALG,
    }
}

#[test]
fn every_algorithm_has_the_marker_of_its_own_name() {
    for alg in SigningAlgorithm::ALL {
        assert_eq!(marker_alg(alg), alg, "{alg:?}");
    }
}
