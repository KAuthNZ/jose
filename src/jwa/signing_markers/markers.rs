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

pub(super) use signing_markers;
