//! Push-based KLV stream decoder and metadata access unit cells.

use crate::klv;
use crate::registry::{decode_st0601, is_st0601_key};
use crate::{Checksum, Config, Error, Packet};

/// Counters kept by a [`Decoder`]. All byte counts are of input bytes.
///
/// The framing counters ([`bytes`](Stats::bytes),
/// [`bytes_skipped`](Stats::bytes_skipped), [`resyncs`](Stats::resyncs),
/// [`skipped_keys`](Stats::skipped_keys), [`oversized`](Stats::oversized),
/// [`bad_lengths`](Stats::bad_lengths),
/// [`truncated_at_finish`](Stats::truncated_at_finish) and
/// [`dropped`](Stats::dropped)) are current after every push. The packet
/// counters ([`packets`](Stats::packets),
/// [`packet_bytes`](Stats::packet_bytes),
/// [`checksum_errors`](Stats::checksum_errors),
/// [`checksum_missing`](Stats::checksum_missing),
/// [`malformed`](Stats::malformed) and
/// [`nested_errors`](Stats::nested_errors)) count packets as they are taken
/// with [`Decoder::next_packet`]. Once every packet is taken, every pushed
/// byte is in exactly one of `packet_bytes`, `bytes_skipped` or a partial
/// packet still buffered.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct Stats {
    /// Packets returned by [`Decoder::next_packet`].
    pub packets: u64,
    /// Bytes pushed.
    pub bytes: u64,
    /// Bytes not delivered in any packet: garbage between packets, packets
    /// with other keys, oversized, dropped and rejected packets, and
    /// incomplete bytes at [`Decoder::finish`].
    pub bytes_skipped: u64,
    /// Runs of unrecognised bytes skipped to find the next universal key.
    pub resyncs: u64,
    /// KLV packets skipped because their key is not the ST 0601 key (for
    /// example a standalone ST 0102 or ST 0903 packet in the same stream).
    pub skipped_keys: u64,
    /// ST 0601 packets skipped because their value is longer than
    /// [`Config::max_packet_bytes`]. One whose whole triplet is also longer
    /// than [`Config::max_skip_bytes`] is treated as damage instead and
    /// counted in [`bad_lengths`](Stats::bad_lengths).
    pub oversized: u64,
    /// ST 0601 packets whose checksum did not match (returned with
    /// [`Checksum::Mismatch`] or, with [`Config::reject_bad_checksum`],
    /// dropped).
    pub checksum_errors: u64,
    /// Packets returned with [`Packet::error`] set.
    pub malformed: u64,
    /// Incomplete KLV triplets cut off by [`Decoder::finish`]: an ST 0601
    /// packet, or a triplet of any key whose header was not yet complete
    /// (its key could not be checked).
    pub truncated_at_finish: u64,
    /// Complete packets dropped because they would have taken the queue
    /// over [`Config::max_buffer_bytes`].
    pub dropped: u64,
    /// ST 0601 packets without a checksum as their final item (returned
    /// with [`Checksum::Missing`] or, with [`Config::reject_bad_checksum`],
    /// dropped). Counted only when the checksum is checked.
    pub checksum_missing: u64,
    /// Packets returned whose top level parsed, but with a nested set that
    /// stopped with an error (see [`Packet::is_ok`]).
    pub nested_errors: u64,
    /// Bytes of the packets returned by [`Decoder::next_packet`], key and
    /// length included.
    pub packet_bytes: u64,
    /// Candidate keys followed by a malformed length (reserved, indefinite,
    /// impossibly large, or declaring a triplet to skip longer than
    /// [`Config::max_skip_bytes`]), or with a reserved category byte; the
    /// decoder resynchronises after them.
    pub bad_lengths: u64,
}

/// Decoder for a stream of ST 0601 packets, such as the payload of an
/// asynchronous KLV elementary stream (MISB ST 1402) or a `.klv` file.
///
/// Push bytes in chunks as they arrive and collect packets, draining after
/// every push. The packets found do not depend on how the input is split,
/// as long as the queue of complete packets never fills: one
/// [`push`](Decoder::push) queues at most [`Config::max_buffer_bytes`] of
/// packets, and drops (and counts in [`Stats::dropped`]) any more, even if
/// the caller drains straight after it. Feed a large buffer, such as a whole
/// file, with [`push_with`](Decoder::push_with), which never drops packets
/// to the queue limit, or use [`decode_iter`](crate::decode_iter).
///
/// Packets with other keys are skipped by their declared length and counted
/// in [`Stats::skipped_keys`]; damaged bytes, and lengths too long to skip
/// ([`Config::max_skip_bytes`]), are skipped by scanning for the next key
/// (every key starts `06 0E 2B 34`). The framing is the SMPTE ST
/// 336 stream decoder of the `smpte-klv` crate.
///
/// A decoder is [`Send`] but not [`Sync`]: wrap it in a mutex to share it.
///
/// ```
/// let mut decoder = misb::Decoder::new();
/// decoder.push(&[0x00, 0x01]); // garbage is skipped
/// decoder.finish();
/// assert!(decoder.next_packet().is_none());
/// assert_eq!(decoder.stats().bytes_skipped, 2);
/// ```
#[derive(Debug)]
pub struct Decoder {
    cfg: Config,
    /// Frames ST 0601 triplets, skipping everything else.
    klv: smpte_klv::Decoder,
    /// The counters this crate keeps; the framing counters are copied from
    /// `klv` by [`Decoder::sync_stats`].
    stats: Stats,
    /// Bytes of packets dropped by [`Config::reject_bad_checksum`], which
    /// the framing counted as delivered.
    rejected_bytes: u64,
}

/// One ST 0601 packet as received: the decoded packet with the exact bytes
/// it was decoded from and their position in the stream. See
/// [`Decoder::next_received`].
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct Received {
    /// The decoded packet.
    pub packet: Packet,
    /// Stream offset of the packet's first key byte: the number of bytes
    /// pushed before it since the decoder was created or reset.
    pub offset: u64,
    /// The whole KLV triplet as received: key, length and value.
    #[cfg_attr(feature = "serde", serde(serialize_with = "crate::value::ser::hex"))]
    pub bytes: Vec<u8>,
}

impl Received {
    /// The 16-byte universal key as received, including the version byte
    /// (byte 8) the decoder ignores when matching.
    #[must_use]
    pub fn key(&self) -> [u8; 16] {
        let mut key = [0; 16];
        let n = self.bytes.len().min(16);
        key[..n].copy_from_slice(&self.bytes[..n]);
        key
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Decoder::new()
    }
}

/// Largest KLV header: 16-byte key and a BER length of 1 + 126 bytes, with
/// a byte to spare.
const MAX_HEADER_BYTES: usize = 144;

/// Smallest KLV triplet: a 16-byte key and a one-byte length.
const MIN_PACKET: usize = 17;

/// Slice size a decoder for a complete buffer is sized for (see
/// [`Decoder::for_buffer`]).
const BUFFER_SLICE: usize = 4096;

/// The framing's value limit for `cfg`, capped so that its header + value
/// sum never overflows, also on 32-bit targets.
fn max_value_len(cfg: &Config) -> usize {
    cfg.max_packet_bytes.min(isize::MAX as usize - 256)
}

/// Most queue bytes the packets wholly inside a slice of `n` bytes can
/// take: each at least [`MIN_PACKET`] bytes, charged its size plus the
/// framing's per-packet overhead.
fn slice_charge(n: usize) -> usize {
    let overhead = smpte_klv::FRAME_OVERHEAD;
    n.saturating_mul(MIN_PACKET + overhead) / MIN_PACKET + overhead
}

/// Most queue bytes what was buffered before a slice can complete during
/// it: one partial packet (at most `max_value_len` plus the header) or a
/// header's worth of bytes that may hold a few small packets.
fn earlier_bytes(max_value_len: usize) -> usize {
    let partial = max_value_len.saturating_add(MAX_HEADER_BYTES + smpte_klv::FRAME_OVERHEAD);
    partial.max(slice_charge(MAX_HEADER_BYTES))
}

impl Decoder {
    /// A decoder with the default [`Config`].
    #[must_use]
    pub fn new() -> Self {
        Decoder::build(Config::default())
    }

    /// A decoder with this configuration, or [`Error::InvalidConfig`] if
    /// [`Config::validate`] refuses it.
    ///
    /// ```
    /// let mut config = misb::Config::default();
    /// config.max_packet_bytes = 64 * 1024;
    /// let decoder = misb::Decoder::with_config(config)?;
    /// assert_eq!(decoder.config().max_packet_bytes, 65_536);
    ///
    /// let mut bad = misb::Config::default();
    /// bad.max_items = 0;
    /// assert!(misb::Decoder::with_config(bad).is_err());
    /// # Ok::<(), misb::Error>(())
    /// ```
    pub fn with_config(cfg: Config) -> Result<Self, Error> {
        cfg.validate()?;
        Ok(Decoder::build(cfg))
    }

    /// A decoder with a configuration already validated (or the default).
    pub(crate) fn build(cfg: Config) -> Self {
        let queue = cfg.max_buffer_bytes;
        Decoder::build_with_queue(cfg, queue)
    }

    /// A decoder for a complete buffer, fed in slices of
    /// [`feed_step`](Decoder::feed_step) and drained after each, as
    /// [`decode_all_with`](crate::decode_all_with) and
    /// [`decode_iter_with`](crate::decode_iter_with) do. Its queue holds at
    /// least what one slice of 4 KiB can complete, so it never drops a packet
    /// however small [`Config::max_buffer_bytes`] is (a smaller queue could
    /// not hold the packets that one buffered header's worth of bytes
    /// completes at once). Memory stays bounded by
    /// [`Config::max_packet_bytes`].
    pub(crate) fn for_buffer(cfg: Config) -> Self {
        let earlier = earlier_bytes(max_value_len(&cfg));
        let queue = cfg.max_buffer_bytes.max(earlier.saturating_add(slice_charge(BUFFER_SLICE)));
        Decoder::build_with_queue(cfg, queue)
    }

    fn build_with_queue(cfg: Config, queue: usize) -> Self {
        let mut framing = smpte_klv::Config::default();
        framing.max_value_len = max_value_len(&cfg);
        framing.max_queue_bytes = queue;
        // A declared length too long to skip is damage, so one bit error in a
        // length cannot blind the decoder for gigabytes.
        framing.max_skip_len = cfg.max_skip_bytes as u64;
        framing.options = klv::OPTIONS;
        // Every key MISB uses is registered, so a reserved category byte
        // means the prefix turned up by chance in damaged data; jumping a
        // length read from it could swallow real packets.
        framing.resync_on_reserved_category = true;
        let mut klv = smpte_klv::Decoder::with_config(framing);
        klv.set_filter(|header| is_st0601_key(&header.key()));
        Decoder { cfg, klv, stats: Stats::default(), rejected_bytes: 0 }
    }

    /// The configuration in use.
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// Feed more input. Drain the packets with
    /// [`next_packet`](Decoder::next_packet) after every push: one push
    /// queues at most [`Config::max_buffer_bytes`] of complete packets and
    /// drops any more (counted in [`Stats::dropped`]). For a large buffer,
    /// such as a whole file, use [`push_with`](Decoder::push_with).
    pub fn push(&mut self, bytes: &[u8]) {
        self.klv.push(bytes);
        self.sync_stats();
    }

    /// Feed input of any size and pass every packet completed to
    /// `on_packet`, packets already queued first. The input is pushed in
    /// slices small enough that the queue never fills, so no packet is
    /// dropped to [`Config::max_buffer_bytes`] (as long as it is at least
    /// [`Config::max_packet_bytes`] plus 1 KiB, which the defaults are), and
    /// memory stays bounded however large `bytes` is.
    ///
    /// ```
    /// # let file: Vec<u8> = Vec::new();
    /// let mut decoder = misb::Decoder::new();
    /// let mut n = 0;
    /// decoder.push_with(&file, |packet| n += packet.len());
    /// decoder.finish();
    /// for packet in decoder.packets() {
    ///     n += packet.len();
    /// }
    /// assert_eq!(decoder.stats().dropped, 0);
    /// ```
    pub fn push_with(&mut self, mut bytes: &[u8], mut on_packet: impl FnMut(Packet)) {
        while let Some(p) = self.next_packet() {
            on_packet(p);
        }
        let step = self.feed_step();
        while !bytes.is_empty() {
            let n = step.min(bytes.len());
            self.push(&bytes[..n]);
            bytes = &bytes[n..];
            while let Some(p) = self.next_packet() {
                on_packet(p);
            }
        }
    }

    /// Largest slice that cannot overfill an empty queue. A slice completes
    /// packets wholly inside it, each at least 17 bytes and charged its size
    /// plus the framing's per-packet overhead, and what was buffered before
    /// it: one partial packet (at most `max_value_len` plus the header) or a
    /// header's worth of bytes that may hold a few small packets. A slice of
    /// 16 bytes cannot hold a whole packet.
    pub(crate) fn feed_step(&self) -> usize {
        const SLICE: usize = 64 * 1024;
        let earlier = earlier_bytes(self.klv.config().max_value_len);
        let room = self.klv.config().max_queue_bytes.saturating_sub(earlier);
        (room / (MIN_PACKET + smpte_klv::FRAME_OVERHEAD) * MIN_PACKET).clamp(16, SLICE)
    }

    /// Mark the end of input. An incomplete trailing packet is dropped and
    /// counted in [`Stats::truncated_at_finish`]. Packets already complete
    /// stay available, and the decoder can be fed again afterwards.
    pub fn finish(&mut self) {
        self.klv.finish();
        self.sync_stats();
    }

    /// Decode and return the oldest complete packet.
    ///
    /// With [`Config::reject_bad_checksum`], packets whose checksum is
    /// missing or does not match are dropped here and the next one is
    /// returned.
    #[must_use = "the packet is removed from the decoder"]
    pub fn next_packet(&mut self) -> Option<Packet> {
        self.next_received().map(|r| r.packet)
    }

    /// Like [`next_packet`](Decoder::next_packet), with the packet's exact
    /// bytes and stream offset, for archiving, forwarding or mapping a
    /// packet back to its place in a file.
    ///
    /// ```
    /// # let packet: Vec<u8> = Vec::new();
    /// let mut decoder = misb::Decoder::new();
    /// decoder.push(&packet);
    /// while let Some(r) = decoder.next_received() {
    ///     println!("{} bytes at offset {}: {}", r.bytes.len(), r.offset, r.packet);
    /// }
    /// ```
    #[must_use = "the packet is removed from the decoder"]
    pub fn next_received(&mut self) -> Option<Received> {
        while let Some(frame) = self.klv.next_frame() {
            let p = decode_st0601(&frame.triplet(), &self.cfg);
            let bad = match p.checksum {
                Checksum::Mismatch { .. } => {
                    self.stats.checksum_errors += 1;
                    true
                }
                Checksum::Missing => {
                    self.stats.checksum_missing += 1;
                    true
                }
                Checksum::Valid | Checksum::NotApplicable => false,
            };
            let len = frame.encoded_len() as u64;
            if bad && self.cfg.reject_bad_checksum {
                self.rejected_bytes += len;
                self.stats.bytes_skipped += len;
                continue;
            }
            if p.error.is_some() {
                self.stats.malformed += 1;
            } else if p.has_nested_error() {
                self.stats.nested_errors += 1;
            }
            self.stats.packets += 1;
            self.stats.packet_bytes += len;
            return Some(Received { packet: p, offset: frame.offset(), bytes: frame.into_bytes() });
        }
        None
    }

    /// Drain every complete packet.
    pub fn packets(&mut self) -> impl Iterator<Item = Packet> + '_ {
        std::iter::from_fn(move || self.next_packet())
    }

    /// Counters since creation or the last [`reset`](Decoder::reset).
    #[must_use]
    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Forget all buffered input, queued packets and counters, and release
    /// the buffer memory.
    pub fn reset(&mut self) {
        // Keep the queue size, which `for_buffer` may have raised.
        let queue = self.klv.config().max_queue_bytes;
        *self = Decoder::build_with_queue(self.cfg.clone(), queue);
    }

    fn sync_stats(&mut self) {
        let k = self.klv.stats();
        let s = &mut self.stats;
        s.bytes = k.bytes;
        s.bytes_skipped = k.bytes_skipped + self.rejected_bytes;
        s.resyncs = k.resyncs;
        s.skipped_keys = k.filtered;
        s.oversized = k.oversized;
        s.truncated_at_finish = k.truncated_at_finish;
        s.dropped = k.dropped;
        s.bad_lengths = k.malformed;
    }
}

/// One metadata access unit cell (ISO/IEC 13818-1 section 2.12.4, Table
/// 2-97), as carried in synchronous KLV PES packets (MISB ST 1402).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AuCell<'a> {
    /// metadata_service_id.
    pub service_id: u8,
    /// sequence_number.
    pub sequence_number: u8,
    /// cell_fragment_indication (2 bits, ISO/IEC 13818-1 Table 2-109): 3 =
    /// complete access unit, 2 = first fragment, 0 = middle fragment, 1 =
    /// last fragment.
    pub fragment: u8,
    /// decoder_config_flag.
    pub decoder_config: bool,
    /// random_access_indicator.
    pub random_access: bool,
    /// AU_cell_data_byte: a complete metadata access unit when
    /// [`fragment`](AuCell::fragment) is 3 (for KLV, one or more whole KLV
    /// packets), otherwise one fragment of an access unit. Fragments 2, 0
    /// .., 1 are joined in sequence_number order (modulo 256, discarding the
    /// access unit on a gap); pushing every cell's data of one service into
    /// one [`Decoder`] in order does that. Fragments may span PES packets,
    /// and an access unit over 65,535 bytes is always fragmented.
    pub data: &'a [u8],
}

/// Iterator over the AU cells of a PES payload; see [`au_cells`].
#[derive(Clone, Debug)]
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct AuCells<'a> {
    buf: &'a [u8],
    done: bool,
}

/// Split a synchronous metadata PES payload into its access unit cells
/// (ISO/IEC 13818-1 section 2.12.4). Each cell has a 5-byte header:
/// service id, sequence number, a flags byte (2-bit fragment indication,
/// decoder config flag, random access indicator, 4 reserved bits) and a
/// 16-bit big-endian data length. Yields one `Err` and stops if a cell is
/// cut short.
///
/// A cell whose [`fragment`](AuCell::fragment) is not 3 holds only part of
/// an access unit; see [`AuCell::data`].
///
/// ```
/// let pes = [0x00, 0x07, 0xDF, 0x00, 0x02, 0xAA, 0xBB];
/// let cell = misb::au_cells(&pes).next().unwrap().unwrap();
/// assert_eq!((cell.service_id, cell.sequence_number, cell.fragment), (0, 7, 3));
/// assert!(!cell.decoder_config && cell.random_access);
/// assert_eq!(cell.data, &[0xAA, 0xBB]);
/// ```
pub fn au_cells(pes_payload: &[u8]) -> AuCells<'_> {
    AuCells { buf: pes_payload, done: false }
}

impl<'a> Iterator for AuCells<'a> {
    type Item = Result<AuCell<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.buf.is_empty() {
            return None;
        }
        let b = self.buf;
        if b.len() < 5 {
            self.done = true;
            return Some(Err(Error::Truncated { needed: 5, available: b.len() }));
        }
        let len = u16::from_be_bytes([b[3], b[4]]) as usize;
        if b.len() < 5 + len {
            self.done = true;
            return Some(Err(Error::Truncated { needed: 5 + len, available: b.len() }));
        }
        let cell = AuCell {
            service_id: b[0],
            sequence_number: b[1],
            fragment: b[2] >> 6,
            decoder_config: b[2] & 0x20 != 0,
            random_access: b[2] & 0x10 != 0,
            data: &b[5..5 + len],
        };
        self.buf = &b[5 + len..];
        Some(Ok(cell))
    }
}

impl std::iter::FusedIterator for AuCells<'_> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{checksum, st0601, Standard};

    fn st0601_packet(payload: &[u8]) -> Vec<u8> {
        let mut body = vec![2];
        push_len(&mut body, payload.len());
        body.extend_from_slice(payload);
        body.extend([1, 2]);
        let mut out = st0601::KEY.to_vec();
        push_len(&mut out, body.len() + 2);
        out.extend(&body);
        let sum = checksum::st0601_checksum(&out);
        out.extend(sum.to_be_bytes());
        out
    }

    /// The bytes of item 2 (the test payload). ST 0601 decodes tag 2 as a
    /// timestamp, so compare what was received.
    fn payload(p: &Packet) -> Option<Vec<u8>> {
        p.item(2u64).map(|i| i.raw.clone())
    }

    fn push_len(out: &mut Vec<u8>, n: usize) {
        if n < 0x80 {
            out.push(n as u8);
        } else {
            out.extend([0x82, (n >> 8) as u8, n as u8]);
        }
    }

    fn other_key_packet(v: &[u8]) -> Vec<u8> {
        let mut out = st0601::KEY.to_vec();
        out[12] = 0x55;
        push_len(&mut out, v.len());
        out.extend_from_slice(v);
        out
    }

    /// A stream with garbage, split prefixes, false keys, an oversized
    /// packet, another key, a bad checksum and a truncated tail.
    fn sample_stream() -> Vec<u8> {
        let mut s = vec![0x00, 0x06, 0x0E, 0x2B]; // leading garbage, partial prefix
        s.extend(st0601_packet(b"first"));
        s.extend(st0601_packet(&[0x55; 300]));
        s.extend([0x06, 0x0E, 0x2B, 0x34, 0x99]); // false key: garbage
        // ST 0601 key with the forbidden indefinite length form.
        s.extend([0x06, 0x0E, 0x2B, 0x34, 2, 0x0B, 1, 1, 0x0E, 1, 3, 1, 1, 0, 0, 0, 0x80]);
        s.extend(st0601_packet(b"after garbage"));
        s.extend(st0601_packet(&[0xAB; 2000])); // oversized with max 1000
        s.extend(other_key_packet(b"other key"));
        let mut bad = st0601_packet(b"bad sum");
        let n = bad.len();
        bad[n - 1] ^= 0xFF;
        s.extend(bad);
        s.extend(st0601_packet(b"last"));
        let t = st0601_packet(b"cut short");
        s.extend(&t[..t.len() - 3]);
        s
    }

    fn cfg() -> Config {
        let mut c = Config::default();
        c.max_packet_bytes = 1000;
        c
    }

    /// Push in the given chunk sizes (cycled), draining after every push.
    fn run(stream: &[u8], cfg: Config, sizes: &mut dyn FnMut() -> usize) -> (Vec<Packet>, Stats) {
        let mut d = Decoder::with_config(cfg).unwrap();
        let mut out = Vec::new();
        let mut rest = stream;
        while !rest.is_empty() {
            let n = sizes().clamp(1, rest.len());
            d.push(&rest[..n]);
            rest = &rest[n..];
            out.extend(d.packets());
        }
        d.finish();
        out.extend(d.packets());
        (out, d.stats().clone())
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            // xorshift64
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    #[test]
    fn whole_stream() {
        let s = sample_stream();
        let (packets, stats) = run(&s, cfg(), &mut || usize::MAX);
        let payloads: Vec<_> = packets.iter().map(payload).collect();
        assert_eq!(packets.len(), 5, "{packets:#?}");
        assert_eq!(payloads[0], Some(b"first".to_vec()));
        assert_eq!(payloads[2], Some(b"after garbage".to_vec()));
        assert!(matches!(packets[3].checksum, Checksum::Mismatch { .. }));
        assert_eq!(payloads[4], Some(b"last".to_vec()));
        for (i, p) in packets.iter().enumerate() {
            assert_eq!(p.standard, Standard::St0601);
            assert_eq!(i == 3, p.checksum != Checksum::Valid);
        }
        assert_eq!(stats.packets, 5);
        assert_eq!(stats.skipped_keys, 1);
        assert_eq!(stats.bytes, s.len() as u64);
        assert_eq!(stats.oversized, 1);
        assert_eq!(stats.checksum_errors, 1);
        assert_eq!(stats.truncated_at_finish, 1);
        assert_eq!(stats.resyncs, 2);
        assert_eq!(stats.malformed, 0);
        assert_eq!(stats.dropped, 0);
        let delivered: usize = packets
            .iter()
            .map(|p| p.items.iter().map(|i| i.raw.len()).sum::<usize>())
            .sum();
        assert!(stats.bytes_skipped > 0 && (stats.bytes_skipped as usize) < s.len() - delivered);
    }

    #[test]
    fn chunking_does_not_change_results() {
        let s = sample_stream();
        let whole = run(&s, cfg(), &mut || usize::MAX);
        assert_eq!(run(&s, cfg(), &mut || 1), whole, "byte by byte");
        for fixed in [2, 3, 5, 16, 17, 18, 100, 4095, 4096, 4097] {
            assert_eq!(run(&s, cfg(), &mut || fixed), whole, "chunks of {fixed}");
        }
        for seed in 1..50u64 {
            let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
            let max = [8u64, 64, 700, 5000][seed as usize % 4];
            let got = run(&s, cfg(), &mut || (rng.next() % max) as usize + 1);
            assert_eq!(got, whole, "seed {seed}");
        }
    }

    #[test]
    fn random_streams_do_not_depend_on_chunking() {
        let mut rng = Rng(0x2545_F491_4F6C_DD1D);
        for _ in 0..300 {
            let mut s = Vec::new();
            for _ in 0..rng.next() % 8 {
                match rng.next() % 5 {
                    0 => s.extend(st0601_packet(&vec![rng.next() as u8; (rng.next() % 300) as usize])),
                    1 => s.extend(other_key_packet(&[0x06, 0x0E, 0x2B, 0x34])),
                    2 => s.extend(&st0601::KEY[..(rng.next() % 17) as usize]),
                    3 => s.push(rng.next() as u8),
                    _ => {
                        let mut p = st0601_packet(b"flip");
                        let i = (rng.next() as usize) % p.len();
                        p[i] ^= 1 << (rng.next() % 8);
                        s.extend(p);
                    }
                }
            }
            let mut c = Config::default();
            c.max_packet_bytes = 200;
            let whole = run(&s, c.clone(), &mut || usize::MAX);
            let max = rng.next() % 40 + 1;
            let mut r2 = Rng(rng.next() | 1);
            assert_eq!(run(&s, c, &mut || (r2.next() % max) as usize + 1), whole);
            let stats = &whole.1;
            assert_eq!(stats.bytes, s.len() as u64);
            assert!(stats.bytes_skipped <= stats.bytes);
        }
    }

    #[test]
    fn oversized_skipped_across_pushes_without_buffering() {
        let mut c = Config::default();
        c.max_packet_bytes = 10;
        let mut d = Decoder::with_config(c).unwrap();
        let big = st0601_packet(&[0x06; 5000]);
        d.push(&big[..20]);
        assert_eq!(d.stats().oversized, 1);
        for chunk in big[20..].chunks(7) {
            d.push(chunk);
            assert_eq!(d.klv.buffered(), 0, "oversized value must not be buffered");
        }
        d.push(&st0601_packet(b"ok"));
        d.push(&st0601_packet(b"no"));
        d.finish();
        let got: Vec<_> = d.packets().collect();
        assert_eq!(got.len(), 2);
        assert!(got.iter().all(|p| p.checksum == Checksum::Valid));
        assert_eq!(d.stats().oversized, 1);
        assert_eq!(d.stats().bytes_skipped, big.len() as u64);
    }

    #[test]
    fn other_keys_skipped_across_pushes_without_buffering() {
        let mut d = Decoder::new();
        // A large packet with another key whose value is full of ST 0601
        // packets: they must not be found, because the outer length is
        // jumped.
        let inner = st0601_packet(b"inner");
        let other = other_key_packet(&inner.repeat(300));
        d.push(&other[..30]);
        for chunk in other[30..].chunks(11) {
            d.push(chunk);
            assert_eq!(d.klv.buffered(), 0, "skipped value must not be buffered");
        }
        d.push(&st0601_packet(b"outer"));
        let got: Vec<_> = d.packets().collect();
        assert_eq!(got.len(), 1);
        assert_eq!(payload(&got[0]), Some(b"outer".to_vec()));
        assert_eq!(d.stats().skipped_keys, 1);
        assert_eq!(d.stats().oversized, 0);
    }

    #[test]
    fn implausible_key_is_garbage() {
        let mut s = st0601::KEY.to_vec();
        s[4] = 0x99; // not a category designator
        s.push(0x7F); // a length that must not be jumped
        s.extend(st0601_packet(b"real"));
        let (packets, stats) = run(&s, Config::default(), &mut || usize::MAX);
        assert_eq!(packets.len(), 1);
        assert_eq!(stats.skipped_keys, 0);
        assert_eq!(stats.resyncs, 1);
        assert_eq!(stats.bytes_skipped, 17);
    }

    #[test]
    fn small_packets_after_oversized() {
        let mut c = Config::default();
        c.max_packet_bytes = 100;
        let mut s = st0601_packet(&[0x06, 0x0E, 0x2B, 0x34].repeat(100));
        s.extend(st0601_packet(b"x"));
        let (packets, stats) = run(&s, c, &mut || 3);
        assert_eq!(stats.oversized, 1);
        assert_eq!(packets.len(), 1);
        assert_eq!(payload(&packets[0]), Some(b"x".to_vec()));
        assert_eq!(stats.resyncs, 0);
    }

    #[test]
    fn queue_bound_drops_newest() {
        let mut c = Config::default();
        let one = st0601_packet(b"0123456789");
        c.max_buffer_bytes = (one.len() + smpte_klv::FRAME_OVERHEAD) * 2 + 10;
        let mut d = Decoder::with_config(c).unwrap();
        for _ in 0..5 {
            d.push(&one);
        }
        assert_eq!(d.stats().dropped, 3);
        assert_eq!(d.packets().count(), 2);
        // The queue charges each packet its bytes plus the framing overhead.
        let mut c = Config::default();
        c.max_buffer_bytes = (one.len() + smpte_klv::FRAME_OVERHEAD) * 2;
        let mut d = Decoder::with_config(c).unwrap();
        for _ in 0..5 {
            d.push(&one);
        }
        assert_eq!(d.stats().dropped, 3);
        // One packet is always accepted into an empty queue.
        let mut c = Config::default();
        c.max_buffer_bytes = 1;
        let mut d = Decoder::with_config(c).unwrap();
        d.push(&one);
        assert_eq!(d.packets().count(), 1);
    }

    #[test]
    fn other_keys_skipped_and_bad_checksums_rejected() {
        let mut s = other_key_packet(b"u");
        let mut bad = st0601_packet(b"b");
        let n = bad.len();
        bad[n - 2] ^= 1;
        s.extend(&bad);
        s.extend(st0601_packet(b"g"));
        let mut c = Config::default();
        c.reject_bad_checksum = true;
        let (packets, stats) = run(&s, c, &mut || usize::MAX);
        assert_eq!(packets.len(), 1);
        assert_eq!(payload(&packets[0]), Some(b"g".to_vec()));
        assert_eq!(stats.checksum_errors, 1);
        assert_eq!(stats.packets, 1);
        assert_eq!(stats.skipped_keys, 1);
        assert_eq!(stats.resyncs, 0);
    }

    fn reject() -> Config {
        let mut c = Config::default();
        c.reject_bad_checksum = true;
        c
    }

    #[test]
    fn packets_without_a_verifiable_checksum_are_rejected() {
        // The outer length is 16 too long: the packet swallows the next
        // packet's key, and its last item is no checksum.
        let mut damaged = st0601_packet(b"damaged");
        damaged[16] += 16;
        let mut s = st0601_packet(b"one");
        s.extend(&damaged);
        for p in [b"two", b"333", b"444"] {
            s.extend(st0601_packet(p));
        }
        let (packets, stats) = run(&s, reject(), &mut || usize::MAX);
        assert!(packets.iter().all(|p| p.checksum == Checksum::Valid && p.is_ok()));
        let got: Vec<_> = packets.iter().map(payload).collect();
        assert_eq!(got, [Some(b"one".to_vec()), Some(b"333".to_vec()), Some(b"444".to_vec())]);
        assert_eq!(stats.checksum_errors, 0);

        // Without rejecting it is delivered, not ok.
        let (packets, _) = run(&s, Config::default(), &mut || usize::MAX);
        assert_eq!(packets.len(), 4);
        assert_eq!(packets[1].checksum, Checksum::Missing);
        assert!(!packets[1].is_ok());
    }

    #[test]
    fn rejecting_checks_even_when_verify_is_off() {
        let mut bad = st0601_packet(b"b");
        let n = bad.len();
        bad[n - 1] ^= 1;
        bad.extend(st0601_packet(b"g"));
        let mut c = reject();
        c.verify_checksum = false;
        let (packets, stats) = run(&bad, c, &mut || usize::MAX);
        assert_eq!(packets.len(), 1);
        assert_eq!(payload(&packets[0]), Some(b"g".to_vec()));
        assert_eq!(stats.checksum_errors, 1);
    }

    #[test]
    fn rejected_packets_count_as_skipped_bytes() {
        let other = other_key_packet(b"u");
        let mut bad = st0601_packet(b"b");
        let n = bad.len();
        bad[n - 2] ^= 1;
        let good = st0601_packet(b"g");
        let s = [other.clone(), bad.clone(), good.clone()].concat();
        let (_, stats) = run(&s, reject(), &mut || usize::MAX);
        assert_eq!(stats.bytes_skipped, (other.len() + bad.len()) as u64);
        assert_eq!(stats.bytes, stats.bytes_skipped + good.len() as u64);
    }

    #[test]
    fn one_large_push_drops_but_push_with_does_not() {
        let one = st0601_packet(&[7; 100]);
        let buf = one.repeat(50_000); // about 6 MB, over max_buffer_bytes
        // Documented: a single push queues at most max_buffer_bytes.
        let mut d = Decoder::new();
        d.push(&buf);
        let n = d.packets().count() as u64;
        assert!(d.stats().dropped > 0);
        assert_eq!(n + d.stats().dropped, 50_000);

        let mut d = Decoder::new();
        let mut n = 0;
        d.push_with(&buf, |p| {
            assert_eq!(p.checksum, Checksum::Valid);
            n += 1;
        });
        d.finish();
        assert_eq!(d.packets().count(), 0);
        assert_eq!((n, d.stats().dropped), (50_000, 0));
        assert_eq!(d.stats().packet_bytes, buf.len() as u64);
    }

    #[test]
    fn push_with_hands_over_queued_packets_first() {
        let mut d = Decoder::new();
        d.push(&st0601_packet(b"first"));
        let mut got = Vec::new();
        d.push_with(&st0601_packet(b"second"), |p| got.push(payload(&p).unwrap()));
        assert_eq!(got, [b"first".to_vec(), b"second".to_vec()]);
    }

    #[test]
    fn received_packets_keep_bytes_and_offsets() {
        let mut a = st0601_packet(b"a");
        a[7] = 0x0A; // another registry version: still ST 0601
        let b = st0601_packet(b"bb");
        let mut s = vec![0x55; 10];
        s.extend(&a);
        s.extend(&b);
        let mut d = Decoder::new();
        d.push(&s);
        let r = d.next_received().unwrap();
        assert_eq!((r.offset, &r.bytes[..], r.key()[7]), (10, &a[..], 0x0A));
        assert_eq!(payload(&r.packet), Some(b"a".to_vec()));
        let r = d.next_received().unwrap();
        assert_eq!((r.offset, &r.bytes[..]), (10 + a.len() as u64, &b[..]));
        assert_eq!(r.key(), st0601::KEY);
        assert!(d.next_received().is_none());
    }

    #[test]
    fn nested_errors_bad_lengths_and_byte_accounting() {
        // Tag 48 holds a cut-short ST 0102 set; the outer checksum is good.
        let mut body = vec![48, 3, 1, 5, 1];
        body.extend([1, 2]);
        let mut nested = st0601::KEY.to_vec();
        nested.push((body.len() + 2) as u8);
        nested.extend(&body);
        let sum = checksum::st0601_checksum(&nested);
        nested.extend(sum.to_be_bytes());
        let mut s = nested.clone();
        // A key with a reserved length byte.
        s.extend(&st0601::KEY);
        s.push(0xFF);
        s.extend(st0601_packet(b"ok"));
        let (packets, stats) = run(&s, Config::default(), &mut || 7);
        assert_eq!(packets.len(), 2);
        assert_eq!((packets[0].checksum, &packets[0].error), (Checksum::Valid, &None));
        assert!(!packets[0].is_ok());
        assert!(packets[1].is_ok());
        assert_eq!((stats.nested_errors, stats.malformed, stats.bad_lengths), (1, 0, 1));
        assert_eq!(stats.bytes, stats.packet_bytes + stats.bytes_skipped);
    }

    #[test]
    fn byte_accounting_holds_for_random_streams() {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        for _ in 0..200 {
            let mut s = Vec::new();
            for _ in 0..rng.next() % 10 {
                match rng.next() % 4 {
                    0 => s.extend(st0601_packet(&vec![rng.next() as u8; (rng.next() % 50) as usize])),
                    1 => s.extend(other_key_packet(b"x")),
                    2 => s.push(rng.next() as u8),
                    _ => {
                        let mut p = st0601_packet(b"flip");
                        let i = (rng.next() as usize) % p.len();
                        p[i] ^= 1 << (rng.next() % 8);
                        s.extend(p);
                    }
                }
            }
            for c in [Config::default(), reject()] {
                let (_, stats) = run(&s, c, &mut || 5);
                assert_eq!(stats.bytes, stats.packet_bytes + stats.bytes_skipped, "{stats:?}");
            }
        }
    }

    #[test]
    fn huge_packet_limit_is_capped_for_the_framing() {
        let mut c = Config::default();
        c.max_packet_bytes = usize::MAX;
        let mut d = Decoder::with_config(c).unwrap();
        assert!(d.klv.config().max_value_len < isize::MAX as usize);
        let mut s = st0601::KEY.to_vec();
        s.extend([0x84, 0xFF, 0xFF, 0xFF, 0xF0]);
        s.extend([0u8; 64]);
        d.push(&s);
        d.finish();
        assert!(d.next_packet().is_none());
    }

    /// A good packet, the same packet with one bit of its long-form length
    /// flipped (declaring hundreds of gigabytes), then 2000 good packets.
    fn length_bit_flip_stream(key_byte_12: u8) -> Vec<u8> {
        let mut good = st0601_packet(&[0x11; 150]);
        good[12] = key_byte_12;
        assert_eq!(good[16], 0x82);
        let mut flipped = good.clone();
        flipped[16] ^= 0x04; // 0x86: a 6-byte length
        let mut s = good.clone();
        s.extend(flipped);
        for _ in 0..2000 {
            s.extend(st0601_packet(&[0x22; 150]));
        }
        s
    }

    #[test]
    fn one_corrupt_length_does_not_blind_the_decoder() {
        for key_byte in [st0601::KEY[12], 0x55] {
            let s = length_bit_flip_stream(key_byte);
            for chunk in [188, 1, usize::MAX] {
                let (packets, stats) = run(&s, Config::default(), &mut || chunk);
                let st0601 = usize::from(key_byte == st0601::KEY[12]);
                assert_eq!(packets.len(), 2000 + st0601, "key byte {key_byte:02X}, chunks of {chunk}");
                assert!(packets.iter().all(Packet::is_ok));
                assert_eq!((stats.bad_lengths, stats.oversized), (1, 0));
                assert!(stats.resyncs >= 1);
            }
        }
    }

    #[test]
    fn au_cells_is_fused() {
        fn fused<I: std::iter::FusedIterator>(_: &I) {}
        let mut it = au_cells(&[1, 2]);
        fused(&it);
        assert!(it.next().unwrap().is_err());
        assert!(it.next().is_none() && it.next().is_none());
    }

    #[test]
    fn malformed_set_is_counted() {
        let mut s = st0601::KEY.to_vec();
        s.extend([3, 2, 5, 1]);
        let (packets, stats) = run(&s, Config::default(), &mut || usize::MAX);
        assert_eq!(packets.len(), 1);
        assert!(packets[0].error.is_some());
        assert_eq!(stats.malformed, 1);
    }

    #[test]
    fn finish_and_reset() {
        let mut d = Decoder::new();
        let p = st0601_packet(b"abc");
        d.push(&p[..p.len() - 1]);
        assert!(d.next_packet().is_none());
        d.finish();
        assert_eq!(d.stats().truncated_at_finish, 1);
        assert_eq!(d.stats().bytes_skipped, p.len() as u64 - 1);
        // Feeding again after finish works.
        d.push(&p);
        assert!(d.next_packet().is_some());
        d.push(&p);
        d.reset();
        assert!(d.next_packet().is_none());
        assert_eq!(d.stats(), &Stats::default());
        assert_eq!(d.config(), &Config::default());
    }

    #[test]
    fn hostile_lengths_do_not_allocate() {
        // Large but possible: skipped without buffering when skipping is
        // allowed.
        let mut c = Config::default();
        c.max_skip_bytes = usize::MAX;
        let mut d = Decoder::with_config(c).unwrap();
        // Leave room for the header under max_skip_bytes on both pointer widths.
        let declared = (usize::MAX / 2) as u64;
        let mut s = st0601::KEY.to_vec();
        s.push(0x88);
        s.extend(declared.to_be_bytes());
        d.push(&s);
        d.push(&[0u8; 10_000]);
        assert_eq!(d.stats().oversized, 1);
        assert_eq!(d.klv.buffered(), 0);

        // By default a length that long is damage: nothing buffered, and the
        // packet after it is found.
        let mut d = Decoder::new();
        s.extend([0u8; 100]);
        s.extend(st0601_packet(b"after"));
        d.push(&s);
        assert!(d.klv.buffered() < 1024);
        assert_eq!(d.packets().count(), 1);
        assert_eq!((d.stats().oversized, d.stats().bad_lengths), (0, 1));

        // Too large for any stream (key, length field and value overflow a
        // u64): damage, so the packet after it is still found.
        let mut d = Decoder::new();
        let mut s = st0601::KEY.to_vec();
        s.extend([0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        s.extend(st0601_packet(b"after"));
        d.push(&s);
        assert_eq!(d.packets().count(), 1);
        assert_eq!((d.stats().oversized, d.stats().resyncs), (0, 1));
        assert_eq!(d.stats().bytes_skipped, 25);
    }

    #[test]
    fn au_cell_parsing() {
        let mut pes = vec![1, 9, 0b1010_0000, 0, 3, 0xA, 0xB, 0xC];
        pes.extend([2, 10, 0b0111_1111, 0, 0]);
        let cells: Vec<_> = au_cells(&pes).collect::<Result<_, _>>().unwrap();
        assert_eq!(cells.len(), 2);
        assert_eq!(
            cells[0],
            AuCell {
                service_id: 1,
                sequence_number: 9,
                fragment: 2,
                decoder_config: true,
                random_access: false,
                data: &[0xA, 0xB, 0xC],
            }
        );
        assert_eq!(cells[1].fragment, 1);
        assert!(cells[1].decoder_config && cells[1].random_access);
        assert!(cells[1].data.is_empty());
        assert_eq!(au_cells(&[]).count(), 0);
    }

    #[test]
    fn au_cell_truncation() {
        let mut it = au_cells(&[1, 2, 3]);
        assert_eq!(it.next(), Some(Err(Error::Truncated { needed: 5, available: 3 })));
        assert_eq!(it.next(), None);
        let mut it = au_cells(&[0, 0, 0xC0, 0, 4, 1, 2]);
        assert_eq!(it.next(), Some(Err(Error::Truncated { needed: 9, available: 7 })));
        assert_eq!(it.next(), None);
    }
}
