//! Where the metadata comes from.

use crate::encode::{EncodeError, EncodeOptions, Input, St0601Builder};
use crate::st0601::Tag;
use crate::{Checksum, Config, Decoder, Error, MispTime, Value};

/// One metadata sample: a time and what to write at it.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct Sample {
    /// The MISP time the sample describes (its tag 2).
    pub time: MispTime,
    /// The content.
    pub data: SampleData,
}

/// The content of a [`Sample`].
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum SampleData {
    /// A complete ST 0601 packet as recorded. It is written unchanged:
    /// tag 2 of a recorded packet is never modified (st1402-time.md D-6),
    /// so it can only go out at its own time ([`Rate::Explicit`]).
    ///
    /// [`Rate::Explicit`]: super::Rate::Explicit
    Packet(Vec<u8>),
    /// Items to encode. Tag 2 is set when the packet is built: the
    /// sample's own time, or the time of the frame it is sampled at.
    Items {
        /// Tag 65 override.
        version: Option<u8>,
        /// The items; [`Input::Value`]`(`[`Value::Unknown`]`)` writes the
        /// item with zero length (unknown).
        items: Vec<(Tag, Input)>,
    },
}

impl Sample {
    /// A recorded packet, timed by its own tag 2.
    #[must_use]
    pub fn packet(time: MispTime, bytes: Vec<u8>) -> Sample {
        Sample { time, data: SampleData::Packet(bytes) }
    }

    /// Items to encode at `time`.
    #[must_use]
    pub fn items(time: MispTime, items: Vec<(Tag, Input)>) -> Sample {
        Sample { time, data: SampleData::Items { version: None, items } }
    }

    /// The ST 0601 packet of this sample with tag 2 = `time`: a recorded
    /// packet when `time` is its own time, otherwise the items encoded.
    pub fn encode_at(&self, time: MispTime, opts: &EncodeOptions) -> Result<Vec<u8>, SampleError> {
        match &self.data {
            SampleData::Packet(bytes) if time == self.time => Ok(bytes.clone()),
            SampleData::Packet(_) => Err(SampleError::Retime),
            SampleData::Items { version, items } => {
                let mut b = St0601Builder::with_options(time, opts.clone());
                if let Some(v) = version {
                    b.version(*v);
                }
                for (tag, input) in items {
                    match input {
                        Input::Value(Value::Unknown) => b.unknown(*tag)?,
                        _ => b.set(*tag, input.clone())?,
                    };
                }
                Ok(b.finish()?)
            }
        }
    }
}

#[cfg(feature = "json")]
impl From<crate::json::Record> for Sample {
    /// An authoring record (one NDJSON line). Its interpolation hints are
    /// not used yet.
    fn from(r: crate::json::Record) -> Sample {
        Sample { time: r.time, data: SampleData::Items { version: r.version, items: r.items } }
    }
}

/// Why a sample could not become a packet.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum SampleError {
    /// A recorded packet was asked for at another time than its own; its
    /// tag 2 is never rewritten (D-6).
    Retime,
    /// The items did not encode.
    Encode(EncodeError),
}

impl std::fmt::Display for SampleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SampleError::Retime => f.write_str("a recorded packet only goes out at its own tag 2 time"),
            SampleError::Encode(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for SampleError {}

impl From<EncodeError> for SampleError {
    fn from(e: EncodeError) -> SampleError {
        SampleError::Encode(e)
    }
}

/// Counters of a [`KlvSamples`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct KlvSampleStats {
    /// Packets turned into samples.
    pub samples: u64,
    /// Packets skipped for a checksum that is missing or wrong (kept when
    /// [`KlvSamples::keep_damaged`] is set).
    pub damaged: u64,
    /// Packets skipped because they have no tag 2 to time them by.
    pub untimed: u64,
}

/// Splits a recorded ST 0601 byte stream (a `.klv` file, or KLV extracted
/// from a transport stream) into [`Sample`]s, keeping every packet's bytes
/// as received.
///
/// Bytes are pushed in any chunking, as with [`Decoder`]; other keys and
/// damaged bytes between packets are skipped by the decoder. Packets
/// without a valid checksum are skipped by default, so damage is never
/// passed on; packets without tag 2 cannot be timed and are skipped.
///
/// ```
/// use misb::encode::St0601Builder;
/// use misb::mux::KlvSamples;
/// use misb::MispTime;
///
/// let mut bytes = Vec::new();
/// for t in [1_000_000, 1_033_366] {
///     bytes.extend(St0601Builder::new(MispTime::from_micros(t)).finish()?);
/// }
/// let mut source = KlvSamples::new();
/// source.push(&bytes);
/// source.finish();
/// let times: Vec<u64> = std::iter::from_fn(|| source.next_sample()).map(|s| s.time.as_micros()).collect();
/// assert_eq!(times, [1_000_000, 1_033_366]);
/// # Ok::<(), misb::encode::EncodeError>(())
/// ```
#[derive(Debug)]
pub struct KlvSamples {
    decoder: Decoder,
    keep_damaged: bool,
    stats: KlvSampleStats,
}

impl Default for KlvSamples {
    fn default() -> Self {
        KlvSamples::new()
    }
}

impl KlvSamples {
    /// A splitter with the decoder's default [`Config`].
    #[must_use]
    pub fn new() -> KlvSamples {
        KlvSamples { decoder: Decoder::new(), keep_damaged: false, stats: KlvSampleStats::default() }
    }

    /// A splitter with the decoder limits of `cfg`.
    pub fn with_config(cfg: Config) -> Result<KlvSamples, Error> {
        Ok(KlvSamples { decoder: Decoder::with_config(cfg)?, keep_damaged: false, stats: KlvSampleStats::default() })
    }

    /// Also keep packets whose checksum is missing or wrong (they are
    /// passed on unchanged, damage included).
    #[must_use]
    pub fn keep_damaged(mut self, keep: bool) -> KlvSamples {
        self.keep_damaged = keep;
        self
    }

    /// Add bytes.
    pub fn push(&mut self, bytes: &[u8]) {
        self.decoder.push(bytes);
    }

    /// The input has ended: a packet cut short at the end is dropped.
    pub fn finish(&mut self) {
        self.decoder.finish();
    }

    /// The next sample, in stream order.
    pub fn next_sample(&mut self) -> Option<Sample> {
        while let Some(r) = self.decoder.next_received() {
            if r.packet.checksum != Checksum::Valid && !self.keep_damaged {
                self.stats.damaged += 1;
                continue;
            }
            let Some(time) = r.packet.get(Tag::PrecisionTimeStamp).and_then(Value::as_time) else {
                self.stats.untimed += 1;
                continue;
            };
            self.stats.samples += 1;
            return Some(Sample::packet(MispTime::from_micros(time), r.bytes));
        }
        None
    }

    /// The counters.
    #[must_use]
    pub fn stats(&self) -> KlvSampleStats {
        self.stats
    }

    /// The decoder's own counters (bytes skipped, other keys, ...).
    #[must_use]
    pub fn decoder_stats(&self) -> &crate::Stats {
        self.decoder.stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(t: u64) -> Vec<u8> {
        let mut b = St0601Builder::new(MispTime::from_micros(t));
        b.set(Tag::SensorLatitude, 38.5).unwrap();
        b.finish().unwrap()
    }

    #[test]
    fn splits_keeps_bytes_and_skips_damage() {
        let (a, b, c) = (packet(10), packet(20), packet(30));
        let mut bad = b.clone();
        let n = bad.len();
        bad[n - 1] ^= 1;
        let mut stream = Vec::new();
        stream.extend_from_slice(&a);
        stream.extend_from_slice(b"junk");
        stream.extend_from_slice(&bad);
        stream.extend_from_slice(&c);
        let mut s = KlvSamples::new();
        for chunk in stream.chunks(7) {
            s.push(chunk);
        }
        s.finish();
        let got: Vec<Sample> = std::iter::from_fn(|| s.next_sample()).collect();
        assert_eq!(got, [Sample::packet(MispTime::from_micros(10), a), Sample::packet(MispTime::from_micros(30), c)]);
        assert_eq!(s.stats().damaged, 1);

        let mut s = KlvSamples::new().keep_damaged(true);
        s.push(&bad);
        s.finish();
        assert_eq!(s.next_sample().unwrap().data, SampleData::Packet(bad));
    }

    #[test]
    fn encode_at() {
        let opts = EncodeOptions::default();
        let rec = Sample::packet(MispTime::from_micros(10), packet(10));
        assert_eq!(rec.encode_at(MispTime::from_micros(10), &opts).unwrap(), packet(10));
        assert_eq!(rec.encode_at(MispTime::from_micros(11), &opts), Err(SampleError::Retime));
        let items = Sample::items(MispTime::from_micros(10), vec![(Tag::SensorLatitude, Input::Float(38.5))]);
        assert_eq!(items.encode_at(MispTime::from_micros(20), &opts).unwrap(), packet(20));
    }
}
