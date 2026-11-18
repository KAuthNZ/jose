use super::Kid;

use super::KidErrors;

use super::constants::KID_MAX_LEN;

fn read(kid: &str) -> Result<Kid, KidErrors> {
    Kid::read(kid.to_owned())
}

#[test]
fn a_kid_is_kept_as_it_came() {
    for kid in [
        "1",
        "2026-11",
        "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg",
        "HMAC key used in JWS spec Appendix A.1 example",
    ] {
        assert_eq!(read(kid).unwrap().as_str(), kid);
    }
}

#[test]
fn case_is_not_folded() {
    assert_ne!(read("Key-1").unwrap(), read("key-1").unwrap());
}

#[test]
fn an_empty_kid_is_refused() {
    assert_eq!(read(""), Err(KidErrors::Empty));
}

#[test]
fn the_longest_kid_is_read_and_one_byte_more_is_refused() {
    assert!(read(&"k".repeat(KID_MAX_LEN)).is_ok());

    assert_eq!(read(&"k".repeat(KID_MAX_LEN + 1)), Err(KidErrors::TooLong));
}

#[test]
fn a_long_kid_is_too_long_before_it_is_looked_at() {
    assert_eq!(
        read(&"\u{200b}".repeat(KID_MAX_LEN)),
        Err(KidErrors::TooLong)
    );
}

#[test]
fn a_kid_that_hides_or_disguises_itself_is_refused() {
    for kid in [
        "k1\n",
        "k1\t",
        "k1\u{0}",
        "k1\u{7f}",
        "k1\u{a0}",
        "k1\u{200b}",
        "\u{202e}1k",
        "k\u{0430}",
    ] {
        assert_eq!(read(kid), Err(KidErrors::NotPrintableAscii), "{kid:?}");
    }
}

#[test]
fn a_space_at_an_edge_is_refused() {
    for kid in [" ", " k1", "k1 ", "  k 1  "] {
        assert_eq!(read(kid), Err(KidErrors::SpaceAtEdge), "{kid:?}");
    }
}

#[test]
fn the_limit_written_in_the_doc_and_the_error_is_the_constant() {
    // `KidErrors::TooLong` and its message say 256: change the three together.
    assert_eq!(KID_MAX_LEN, 256);

    assert_eq!(
        KidErrors::TooLong.to_string(),
        "kid is longer than 256 bytes"
    );
}
