#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JsonErrors {
    /// The input is longer than the cap the caller passed.
    TooLarge,

    /// Not valid JSON: syntax, invalid UTF-8, a lone surrogate, bytes after the value, or
    /// nesting deeper than the limit of the parser.
    Malformed,

    /// Valid JSON, but the top level is not an object.
    NotAnObject,

    /// A member name repeated (RFC 7515 §4, RFC 8259 §4). Which one is not said: it is text from
    /// whoever sent the input.
    DuplicateMembers,
}
