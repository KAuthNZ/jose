use core::marker::PhantomData;

use super::*;

use crate::jwa::Es256;

use crate::jwa::Ed25519;

use crate::jwa::SigningAlgorithm;

fn is_a_mode<M>()
where
    M: KeyMode,
{
}

#[test]
fn the_three_unbound_modes_are_modes() {
    is_a_mode::<Public>();

    is_a_mode::<Private>();

    is_a_mode::<Secret>();
}

#[test]
fn a_mode_without_its_parameter_is_unbound() {
    let _: PhantomData<Public<Unbound>> = PhantomData::<Public>;

    let _: PhantomData<Private<Unbound>> = PhantomData::<Private>;

    let _: PhantomData<Secret<Unbound>> = PhantomData::<Secret>;
}

#[test]
fn an_unbound_mode_holds_no_alg() {
    assert_eq!(<Public as HoldsAlg>::ALG, None);

    assert_eq!(<Private as HoldsAlg>::ALG, None);
}

#[test]
fn a_bound_mode_holds_the_alg_it_was_bound_to() {
    assert_eq!(<Public<Es256> as HoldsAlg>::ALG, Some(SigningAlgorithm::Es256));

    assert_eq!(<Private<Ed25519> as HoldsAlg>::ALG, Some(SigningAlgorithm::Ed25519));
}
