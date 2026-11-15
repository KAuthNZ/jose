use core::marker::PhantomData;

use super::*;

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
