//! Decoder configuration.

use crate::Error;

/// Limits and options for decoding.
///
/// Start from [`Config::default`] and change the fields you need:
///
/// ```
/// let mut config = misb::Config::default();
/// config.reject_bad_checksum = true; // drop ST 0601 packets without a valid tag 1
/// let decoder = misb::Decoder::with_config(config)?;
/// # Ok::<(), misb::Error>(())
/// ```
///
/// Every function that takes a `Config` checks it with
/// [`Config::validate`] first and refuses a bad one with
/// [`Error::InvalidConfig`](crate::Error::InvalidConfig).
///
/// A live decoder buffers one partial packet and a queue of complete
/// packets. An empty queue can hold one packet larger than
/// [`max_buffer_bytes`](Self::max_buffer_bytes). Each decoded packet holds
/// up to [`max_total_items`](Self::max_total_items) local-set items. Their
/// values, pack fields, series and retained wire bytes use additional memory.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
#[non_exhaustive]
pub struct Config {
    /// Largest ST 0601 packet value accepted, in bytes. Longer packets are skipped by
    /// the [`Decoder`](crate::Decoder) without being buffered and counted in
    /// [`Stats::oversized`](crate::Stats::oversized), and rejected by
    /// [`decode_with`](crate::decode_with) with
    /// [`Error::TooLarge`](crate::Error::TooLarge) as soon as the length
    /// field is read. Values above `isize::MAX - 256` behave as that.
    /// Default 1 MiB.
    pub max_packet_bytes: usize,
    /// Most memory, in bytes, the [`Decoder`](crate::Decoder) holds in
    /// complete packets waiting for
    /// [`next_packet`](crate::Decoder::next_packet): each counts its bytes
    /// plus a fixed bookkeeping overhead of about 64 bytes. A packet that
    /// would take the queue over this is dropped and counted in
    /// [`Stats::dropped`](crate::Stats::dropped); one packet is always
    /// accepted into an empty queue. So one
    /// [`push`](crate::Decoder::push) of more than this many bytes can drop
    /// packets even if the caller drains straight after it; use
    /// [`push_with`](crate::Decoder::push_with) for large buffers. Default
    /// 4 MiB.
    pub max_buffer_bytes: usize,
    /// Largest KLV triplet (key, length field and value) the
    /// [`Decoder`](crate::Decoder) skips by its declared length without
    /// decoding it: a packet with another key, or an ST 0601 packet over
    /// [`max_packet_bytes`](Config::max_packet_bytes). A longer declared
    /// length is treated as damage instead (counted in
    /// [`Stats::bad_lengths`](crate::Stats::bad_lengths)), and the decoder
    /// resynchronises on the next key after its first byte.
    ///
    /// One bit error in a long-form length can declare gigabytes; skipping
    /// that many bytes would blind a live decoder to everything after it.
    /// The cost is that a genuine packet of another key longer than this is
    /// scanned through, where a false key inside its value could be found
    /// (an ST 0601 packet found that way still has to pass its checksum).
    /// Default 1 MiB.
    pub max_skip_bytes: usize,
    /// Deepest nesting of local sets inside local sets (0 decodes only the
    /// top level). Deeper sets are reported with [`Error::TooDeep`](crate::Error::TooDeep).
    /// At most [`Config::MAX_DEPTH_LIMIT`] (32); [`Config::validate`]
    /// refuses more. Default 8.
    pub max_depth: usize,
    /// Most items decoded from one set; parsing stops with
    /// [`Error::TooManyItems`](crate::Error::TooManyItems) after that.
    /// Lists and packs inside an item hold at most this many elements.
    /// Default 65,536.
    pub max_items: usize,
    /// Most items decoded from one ST 0601 packet, counting the items of
    /// every nested set; parsing of the set that would go over stops with
    /// [`Error::TooManyItems`](crate::Error::TooManyItems), and so does
    /// every set after it. [`max_items`](Config::max_items) applies to each set
    /// separately, so without this a packet of many nested sets could
    /// decode to about 50 times its size. Items of packs and series inside
    /// an ST 0903 set are bounded by `max_items` per set. Default 65,536.
    pub max_total_items: usize,
    /// Check the ST 0601 checksum (tag 1). When false, and
    /// [`reject_bad_checksum`](Config::reject_bad_checksum) is false too,
    /// every packet reports
    /// [`Checksum::NotApplicable`](crate::Checksum::NotApplicable). Default true.
    pub verify_checksum: bool,
    /// Drop ST 0601 packets whose checksum is missing or does not match
    /// (ST 0601.8-08 requires discarding them, and ST 0601.8-11 requires tag
    /// 1 as the final item) instead of returning them with
    /// [`Checksum::Mismatch`](crate::Checksum::Mismatch) or
    /// [`Checksum::Missing`](crate::Checksum::Missing). Setting this also
    /// verifies the checksum whatever
    /// [`verify_checksum`](Config::verify_checksum) says. Only the
    /// [`Decoder`](crate::Decoder) drops packets; they are counted in
    /// [`Stats::checksum_errors`](crate::Stats::checksum_errors) or
    /// [`Stats::checksum_missing`](crate::Stats::checksum_missing) and in
    /// [`Stats::bytes_skipped`](crate::Stats::bytes_skipped). Default false.
    pub reject_bad_checksum: bool,
    /// Keep a copy of every item's value bytes in
    /// [`Item::raw`](crate::Item::raw). When false, `raw` is left empty for
    /// items whose value decoded validly (it is still kept for
    /// [`Value::Invalid`](crate::Value::Invalid) and
    /// [`Value::OutOfRange`](crate::Value::OutOfRange) values and for nested
    /// sets that stopped with an error), which saves most of the memory a
    /// decoded packet holds: with nesting, every level otherwise keeps its
    /// own copy of the bytes below it. Default true.
    pub keep_raw: bool,
}

impl Config {
    /// Hard ceiling on [`max_depth`](Config::max_depth), so that hostile
    /// nesting can never exhaust the stack: [`Config::validate`] refuses a
    /// larger value, and the decoders never nest deeper even for a config
    /// that was not validated. ST 0601 nests at most about four levels
    /// deep (ST 0601 > ST 0903 > VTarget > VObject > VFeature, or ST 1607
    /// Segment > ST 0601).
    pub const MAX_DEPTH_LIMIT: usize = 32;

    /// [`max_depth`](Config::max_depth) capped at
    /// [`Config::MAX_DEPTH_LIMIT`]: what the decoders compare nesting
    /// levels with, so that even a config that skipped
    /// [`validate`](Config::validate) cannot exhaust the stack.
    pub(crate) fn depth_limit(&self) -> usize {
        self.max_depth.min(Config::MAX_DEPTH_LIMIT)
    }

    /// Check the limits, returning [`Error::InvalidConfig`] naming the
    /// first rule broken:
    ///
    /// - `max_packet_bytes`, `max_buffer_bytes`, `max_skip_bytes`,
    ///   `max_items` and `max_total_items` must not be 0. A zero packet or
    ///   item limit would refuse every packet (each has at least its
    ///   checksum item), a zero queue would hold nothing, and a zero skip
    ///   limit would treat every packet with another key as damage.
    /// - `max_depth` must be at most [`Config::MAX_DEPTH_LIMIT`]: deeper
    ///   nesting than that could not be decoded without risking the
    ///   stack, and no MISB structure comes close.
    ///
    /// Large byte and item limits are accepted: `usize::MAX` means "no
    /// limit of its own", and the other limits still bound memory. Every
    /// function and constructor that takes a `Config` calls this first.
    ///
    /// ```
    /// let mut config = misb::Config::default();
    /// assert!(config.validate().is_ok());
    /// config.max_items = 0;
    /// assert!(matches!(config.validate(), Err(misb::Error::InvalidConfig(_))));
    /// ```
    pub fn validate(&self) -> Result<(), Error> {
        let rules: [(bool, &'static str); 6] = [
            (self.max_packet_bytes == 0, "max_packet_bytes is 0"),
            (self.max_buffer_bytes == 0, "max_buffer_bytes is 0"),
            (self.max_skip_bytes == 0, "max_skip_bytes is 0"),
            (self.max_items == 0, "max_items is 0"),
            (self.max_total_items == 0, "max_total_items is 0"),
            (self.max_depth > Config::MAX_DEPTH_LIMIT, "max_depth is above Config::MAX_DEPTH_LIMIT"),
        ];
        match rules.iter().find(|(broken, _)| *broken) {
            Some(&(_, why)) => Err(Error::InvalidConfig(why)),
            None => Ok(()),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            max_packet_bytes: 1 << 20,
            max_buffer_bytes: 4 << 20,
            max_skip_bytes: 1 << 20,
            max_depth: 8,
            max_items: 65_536,
            max_total_items: 65_536,
            verify_checksum: true,
            reject_bad_checksum: false,
            keep_raw: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults() {
        let c = Config::default();
        assert_eq!(c.max_packet_bytes, 1_048_576);
        assert_eq!(c.max_buffer_bytes, 4_194_304);
        assert_eq!(c.max_skip_bytes, 1_048_576);
        assert_eq!(c.max_depth, 8);
        assert_eq!(c.max_items, 65_536);
        assert_eq!(c.max_total_items, 65_536);
        assert!(c.verify_checksum);
        assert!(!c.reject_bad_checksum);
        assert!(c.keep_raw);
    }

    #[test]
    fn validate_refuses_zero_and_absurd_limits() {
        assert_eq!(Config::default().validate(), Ok(()));
        let cases: [(fn(&mut Config), &str); 6] = [
            (|c| c.max_packet_bytes = 0, "max_packet_bytes is 0"),
            (|c| c.max_buffer_bytes = 0, "max_buffer_bytes is 0"),
            (|c| c.max_skip_bytes = 0, "max_skip_bytes is 0"),
            (|c| c.max_items = 0, "max_items is 0"),
            (|c| c.max_total_items = 0, "max_total_items is 0"),
            (|c| c.max_depth = Config::MAX_DEPTH_LIMIT + 1, "max_depth is above Config::MAX_DEPTH_LIMIT"),
        ];
        for (set, why) in cases {
            let mut c = Config::default();
            set(&mut c);
            assert_eq!(c.validate(), Err(Error::InvalidConfig(why)));
        }
        // "No limit of its own" and the edges are fine.
        let mut c = Config::default();
        c.max_packet_bytes = usize::MAX;
        c.max_buffer_bytes = 1;
        c.max_skip_bytes = usize::MAX;
        c.max_items = 1;
        c.max_total_items = usize::MAX;
        c.max_depth = 0;
        assert_eq!(c.validate(), Ok(()));
        c.max_depth = Config::MAX_DEPTH_LIMIT;
        assert_eq!(c.validate(), Ok(()));
    }

    #[test]
    fn depth_limit_is_capped() {
        let mut c = Config::default();
        assert_eq!(c.depth_limit(), 8);
        c.max_depth = usize::MAX;
        assert_eq!(c.depth_limit(), Config::MAX_DEPTH_LIMIT);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn deserializes_with_defaults() {
        let c: Config = serde_json::from_str(r#"{"max_depth":4}"#).unwrap();
        assert_eq!(c.max_depth, 4);
        assert_eq!(Config { max_depth: 4, ..Config::default() }, c);
        let back: Config = serde_json::from_str(&serde_json::to_string(&Config::default()).unwrap()).unwrap();
        assert_eq!(back, Config::default());
    }
}
