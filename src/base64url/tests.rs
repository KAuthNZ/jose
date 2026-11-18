use super::*;

#[test]
fn rfc4648_vectors_without_padding() {
    let vectors: [(&[u8], &str); 7] = [
        (b"", ""),
        (b"f", "Zg"),
        (b"fo", "Zm8"),
        (b"foo", "Zm9v"),
        (b"foob", "Zm9vYg"),
        (b"fooba", "Zm9vYmE"),
        (b"foobar", "Zm9vYmFy"),
    ];

    for (raw, b64) in vectors {
        assert_eq!(encode(raw), b64);
        assert_eq!(decode(b64).unwrap(), raw);
    }
}

#[test]
fn the_two_url_characters() {
    assert_eq!(encode(&[0xfb, 0xff]), "-_8");
    assert_eq!(decode("-_8").unwrap(), [0xfb, 0xff]);
}

#[test]
fn lengths_match_real_output() {
    for n in 0..64 {
        let b64 = encode(&vec![0xa5; n]);

        assert_eq!(b64.len(), encoded_len(n));
        assert_eq!(decoded_len(b64.len()), Ok(n));
    }
}

#[test]
fn decoding_errors() {
    use Base64DecodingErrors::*;

    assert_eq!(decode("Zg=="), Err(DisallowedPadding));
    assert_eq!(decode("Zm9vY"), Err(InvalidLength));
    assert_eq!(decode("Zm+v"), Err(InvalidCharacter));
    assert_eq!(decode("Z+"), Err(InvalidCharacter));
    assert_eq!(decode("Zh"), Err(NonCanonical));
    assert_eq!(decode("Zm9"), Err(NonCanonical));
    assert_eq!(decode_into("Zm9v", &mut [0u8; 2]), Err(InvalidOutputLength));
}

#[test]
fn non_ascii_input_is_an_invalid_character() {
    use Base64DecodingErrors::*;

    assert_eq!(decode("Zé"), Err(InvalidCharacter));
    assert_eq!(decode("Z\u{0}"), Err(InvalidCharacter));
    assert_eq!(decode("😀😀"), Err(InvalidCharacter));
}
