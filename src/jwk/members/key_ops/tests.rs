use super::KeyOp;

use super::KeyOps;

use super::KeyOpsErrors;

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|name| (*name).to_owned()).collect()
}

#[test]
fn operations_are_read_in_order() {
    let ops = KeyOps::read(&names(&["verify", "sign"])).unwrap();

    assert_eq!(ops.ops(), [KeyOp::Verify, KeyOp::Sign]);

    let ops = KeyOps::read(&names(&["unwrapKey", "wrapKey"])).unwrap();

    assert_eq!(ops.ops(), [KeyOp::UnwrapKey, KeyOp::WrapKey]);
}

#[test]
fn any_operation_alone_is_read() {
    for op in KeyOp::ALL {
        let ops = KeyOps::read(&names(&[op.name()])).unwrap();

        assert_eq!(ops.ops(), [op]);
    }
}

#[test]
fn which_operations_come_together_is_not_judged_here() {
    for list in [
        &["sign", "encrypt"][..],
        &["encrypt", "decrypt", "wrapKey", "unwrapKey"],
        &["deriveKey", "deriveBits"],
    ] {
        assert!(KeyOps::read(&names(list)).is_ok(), "{list:?}");
    }
}

#[test]
fn an_operation_out_of_the_registry_refuses_the_list() {
    for list in [
        &["verify", "Sign"][..],
        &["frobnicate"],
        &["sign", ""],
        &["verify "],
    ] {
        assert_eq!(
            KeyOps::read(&names(list)),
            Err(KeyOpsErrors::Unregistered),
            "{list:?}"
        );
    }
}

#[test]
fn an_operation_listed_twice_refuses_the_list() {
    assert_eq!(
        KeyOps::read(&names(&["verify", "sign", "verify"])),
        Err(KeyOpsErrors::Duplicate(KeyOp::Verify))
    );
}

#[test]
fn an_empty_list_is_a_key_of_no_operation() {
    let ops = KeyOps::read(&[]).unwrap();

    assert!(ops.ops().is_empty());
}
