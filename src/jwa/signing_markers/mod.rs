mod hs;

mod es;

mod ps;

mod rs;

mod ml_dsa;

mod markers;

mod ed25519;

mod closed_set;

mod typed_signing_algorithm;

#[cfg(test)]
mod tests;

pub use ed25519::Ed25519;

pub use hs::{Hs256, Hs384, Hs512};

pub use es::{Es256, Es384, Es512};

pub use ps::{Ps256, Ps384, Ps512};

pub use rs::{Rs256, Rs384, Rs512};

pub use ml_dsa::{MlDsa44, MlDsa65, MlDsa87};

pub use typed_signing_algorithm::TypedSigningAlgorithm;
