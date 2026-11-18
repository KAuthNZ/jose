use std::collections::BTreeMap;

use super::write_object;

#[test]
fn an_empty_object_is_two_braces() {
    assert_eq!(write_object::<&str>(&BTreeMap::new()), "{}");
}

#[test]
fn the_members_are_written_in_the_order_of_their_names() {
    let members = BTreeMap::from([("y", "4"), ("kty", "EC"), ("crv", "P-256"), ("x", "3")]);

    assert_eq!(
        write_object(&members),
        r#"{"crv":"P-256","kty":"EC","x":"3","y":"4"}"#
    );
}

#[test]
fn a_name_and_a_value_are_written_as_json_strings() {
    let members = BTreeMap::from([(r#"n"a\me"#, r#"a"b\c"#.to_owned())]);

    assert_eq!(write_object(&members), r#"{"n\"a\\me":"a\"b\\c"}"#);
}

#[test]
fn a_control_character_is_escaped() {
    let members = BTreeMap::from([("k", "a\nb\u{0}")]);

    assert_eq!(write_object(&members), r#"{"k":"a\nb\u0000"}"#);
}
