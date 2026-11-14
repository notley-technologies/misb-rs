//! Errors from parsing KLV.

use std::fmt;

/// Why a KLV structure could not be parsed, or why a [`Config`] was
/// refused.
///
/// Decoding never panics on hostile input; it reports one of these instead.
/// A [`Packet`](crate::Packet) whose set stopped early keeps the items decoded
/// before the problem and records the error in
/// [`Packet::error`](crate::Packet::error).
///
/// With the `serde` feature an error serializes as `{"kind": ..,
/// "message": ..}`: [`Error::kind`] and the [`Display`](fmt::Display)
/// text, e.g. `{"kind":"truncated","message":"truncated: needed 5 bytes, 2
/// available"}`.
///
/// [`Config`]: crate::Config
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// Input ended before the structure did.
    #[non_exhaustive]
    Truncated {
        /// Bytes the structure needs: at least this many, as a lower bound
        /// while a long-form length field is itself cut short.
        needed: usize,
        /// Bytes that were available.
        available: usize,
    },
    /// BER length is malformed: the reserved form 0xFF, the indefinite form
    /// 0x80 (which needs an end of data to find the end of the value), or a
    /// length that does not fit in memory.
    BadLength,
    /// BER-OID tag is malformed: its value overflows u64.
    BadTag,
    /// A packet value longer than
    /// [`Config::max_packet_bytes`](crate::Config::max_packet_bytes). Sizes
    /// in bytes.
    #[non_exhaustive]
    TooLarge {
        /// Bytes found in the input (`usize::MAX` when it does not fit).
        size: usize,
        /// The configured limit it exceeds, in bytes.
        limit: usize,
    },
    /// A set with more items than
    /// [`Config::max_items`](crate::Config::max_items) allows, or a packet
    /// whose sets together hold more than
    /// [`Config::max_total_items`](crate::Config::max_total_items).
    /// Counts in items.
    #[non_exhaustive]
    TooManyItems {
        /// Items found when the limit was reached: the limit plus one.
        count: usize,
        /// The configured limit it exceeds, in items.
        limit: usize,
    },
    /// The buffer does not start with the ST 0601 UAS Datalink Local Set
    /// key ([`st0601::KEY`](crate::st0601::KEY)).
    NotSt0601,
    /// Nesting deeper than [`Config::max_depth`](crate::Config::max_depth).
    TooDeep,
    /// A [`Config`] that [`Config::validate`](crate::Config::validate)
    /// refuses; the text names the field and the rule.
    ///
    /// [`Config`]: crate::Config
    InvalidConfig(&'static str),
}

impl Error {
    /// A short snake_case name for the kind of error, the same for every
    /// value of a variant: `"truncated"`, `"bad_length"`, `"bad_tag"`,
    /// `"too_large"`, `"too_many_items"`, `"not_st0601"`, `"too_deep"` or
    /// `"invalid_config"`. Stable across releases, for logs and metrics.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Error::Truncated { .. } => "truncated",
            Error::BadLength => "bad_length",
            Error::BadTag => "bad_tag",
            Error::TooLarge { .. } => "too_large",
            Error::TooManyItems { .. } => "too_many_items",
            Error::NotSt0601 => "not_st0601",
            Error::TooDeep => "too_deep",
            Error::InvalidConfig(_) => "invalid_config",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Truncated { needed, available } => {
                write!(f, "truncated: needed {needed} bytes, {available} available")
            }
            Error::BadLength => f.write_str("malformed BER length"),
            Error::BadTag => f.write_str("malformed BER-OID tag"),
            Error::TooLarge { size, limit } => {
                write!(f, "too large: {size} bytes exceed the limit of {limit}")
            }
            Error::TooManyItems { count, limit } => {
                write!(f, "too many items: {count} exceed the limit of {limit}")
            }
            Error::NotSt0601 => f.write_str("not an ST 0601 packet"),
            Error::TooDeep => f.write_str("sets nested too deeply"),
            Error::InvalidConfig(why) => write!(f, "invalid config: {why}"),
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Error {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("Error", 2)?;
        st.serialize_field("kind", self.kind())?;
        st.serialize_field("message", &self.to_string())?;
        st.end()
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display() {
        let e = Error::Truncated { needed: 5, available: 2 };
        assert_eq!(e.to_string(), "truncated: needed 5 bytes, 2 available");
        assert_eq!(Error::BadLength.to_string(), "malformed BER length");
        assert_eq!(Error::BadTag.to_string(), "malformed BER-OID tag");
        assert_eq!(
            Error::TooLarge { size: 10, limit: 4 }.to_string(),
            "too large: 10 bytes exceed the limit of 4"
        );
        assert_eq!(
            Error::TooManyItems { count: 3, limit: 2 }.to_string(),
            "too many items: 3 exceed the limit of 2"
        );
        assert_eq!(Error::NotSt0601.to_string(), "not an ST 0601 packet");
        assert_eq!(Error::TooDeep.to_string(), "sets nested too deeply");
        assert_eq!(
            Error::InvalidConfig("max_items is 0").to_string(),
            "invalid config: max_items is 0"
        );
    }

    #[test]
    fn kinds_are_distinct() {
        let all = [
            Error::Truncated { needed: 1, available: 0 },
            Error::BadLength,
            Error::BadTag,
            Error::TooLarge { size: 2, limit: 1 },
            Error::TooManyItems { count: 2, limit: 1 },
            Error::NotSt0601,
            Error::TooDeep,
            Error::InvalidConfig("x"),
        ];
        let kinds: std::collections::HashSet<&str> = all.iter().map(Error::kind).collect();
        assert_eq!(kinds.len(), all.len());
        assert!(kinds.iter().all(|k| k.bytes().all(|b| b.is_ascii_lowercase() || b == b'_' || b.is_ascii_digit())));
    }

    #[test]
    fn hashable() {
        let set: std::collections::HashSet<Error> = [Error::BadTag, Error::BadTag, Error::TooDeep].into_iter().collect();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn is_std_error() {
        fn takes(_: &dyn std::error::Error) {}
        takes(&Error::BadTag);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serializes_kind_and_message() {
        let json = serde_json::to_string(&Error::Truncated { needed: 5, available: 2 }).unwrap();
        assert_eq!(json, r#"{"kind":"truncated","message":"truncated: needed 5 bytes, 2 available"}"#);
        let json = serde_json::to_string(&Error::InvalidConfig("max_items is 0")).unwrap();
        assert_eq!(json, r#"{"kind":"invalid_config","message":"invalid config: max_items is 0"}"#);
    }
}
