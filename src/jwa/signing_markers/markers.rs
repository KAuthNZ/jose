/// One marker per variant of [`SigningAlgorithm`](crate::jwa::SigningAlgorithm), with its same
/// name: a marker can't stand for another algorithm.
macro_rules! signing_markers {
    ($($name:ident),+ $(,)?) => {$(
        pub enum $name {}

        impl super::closed_set::ClosedSet for $name {}

        impl super::typed_signing_algorithm::TypedSigningAlgorithm for $name {
            const ALG: crate::jwa::SigningAlgorithm = crate::jwa::SigningAlgorithm::$name;
        }
    )+};
}

signing_markers!(Hs256, Hs384, Hs512);

signing_markers!(Rs256, Rs384, Rs512);

signing_markers!(Ps256, Ps384, Ps512);

signing_markers!(Es256, Es384, Es512);

signing_markers!(Ed25519);

signing_markers!(MlDsa44, MlDsa65, MlDsa87,);
