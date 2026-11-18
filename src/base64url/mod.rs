mod decoding;

mod encoding;

mod decoding_errors;

#[cfg(test)]
mod tests;

pub(crate) use encoding::encode;

pub(crate) use decoding::decode;

pub(crate) use decoding::decode_into;

pub(crate) use decoding::decoded_len;

pub(crate) use encoding::encoded_len;

pub(crate) use decoding_errors::Base64DecodingErrors;
