//! The mapping between MISP time and the program clock.

use crate::MispTime;
use mpegts::{pts_delta, PTS_WRAP};

/// 90 kHz ticks per microsecond, as the fraction 9 / 100.
const TICKS_NUM: i128 = 9;
const TICKS_DEN: i128 = 100;

/// One pair of times, a video PTS and the MISP time it stands for, from
/// which every other PTS maps to a MISP time and back (MUXING_PLAN.md
/// section 5).
///
/// PTS values are unwrapped: a count of 90 kHz ticks that keeps growing
/// across the 2^33 wrap-around, as [`PtsUnwrapper`] produces (raw PTS
/// values are compared modulo 2^33, R-ISO13818-065). The conversions follow
/// st1402-time.md D-11:
///
/// - PTS to MISP: `misp = anchor_misp + floor(dticks x 100 / 9)`
///   microseconds, so a time never runs ahead of the frame it describes
///   (ST 0603.4-08 truncates finer times).
/// - MISP to PTS: `pts = anchor_pts + round_half_up(dus x 9 / 100)`, the
///   nearest 90 kHz tick.
///
/// Converting a PTS to MISP time and back returns the same PTS.
///
/// ```
/// use misb::mux::Anchor;
/// use misb::MispTime;
///
/// let anchor = Anchor::new(900_000, MispTime::from_micros(1_000_000_000));
/// // One frame at 29.97 fps later: 3003 ticks, 33,366.67 us, floored.
/// assert_eq!(anchor.misp_at(903_003), Some(MispTime::from_micros(1_000_033_366)));
/// assert_eq!(anchor.pts_at(MispTime::from_micros(1_000_033_366)), 903_003);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Anchor {
    /// Unwrapped PTS, 90 kHz ticks.
    pub pts: i64,
    /// The MISP time at that PTS.
    pub misp: MispTime,
}

impl Anchor {
    /// An anchor: the unwrapped PTS `pts` is MISP time `misp`.
    #[must_use]
    pub const fn new(pts: i64, misp: MispTime) -> Anchor {
        Anchor { pts, misp }
    }

    /// The MISP time at the unwrapped PTS `pts`, or `None` when it falls
    /// before the MISP epoch or beyond `u64` microseconds.
    #[must_use]
    pub fn misp_at(&self, pts: i64) -> Option<MispTime> {
        let dticks = i128::from(pts) - i128::from(self.pts);
        let dus = (dticks * TICKS_DEN).div_euclid(TICKS_NUM);
        let us = i128::from(self.misp.as_micros()) + dus;
        u64::try_from(us).ok().map(MispTime::from_micros)
    }

    /// The unwrapped PTS nearest to MISP time `misp` (halves round up).
    #[must_use]
    pub fn pts_at(&self, misp: MispTime) -> i64 {
        let dus = i128::from(misp.as_micros()) - i128::from(self.misp.as_micros());
        let dticks = (dus * TICKS_NUM + TICKS_DEN / 2).div_euclid(TICKS_DEN);
        // At most 2^64 us away: about 1.66e18 ticks, inside i64.
        (i128::from(self.pts) + dticks) as i64
    }

    /// The same mapping, anchored at another PTS: the new anchor's MISP
    /// time is this anchor's time at `pts`. Used to carry the time line
    /// across a program clock discontinuity.
    #[must_use]
    pub fn moved_to(&self, pts: i64) -> Option<Anchor> {
        self.misp_at(pts).map(|misp| Anchor::new(pts, misp))
    }
}

/// The 33-bit PTS of an unwrapped count of ticks.
#[must_use]
pub fn wrap_pts(pts: i64) -> u64 {
    pts.rem_euclid(PTS_WRAP as i64) as u64
}

/// Turns raw 33-bit PTS values into a count that keeps growing across the
/// 2^33 wrap-around (about every 26.5 hours).
///
/// Each value is placed at the signed distance from the previous one that
/// is smallest modulo 2^33 (D-ISO13818-17), so values may also step back
/// (B-frames arrive in decode order). The first value is taken as it is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PtsUnwrapper {
    last: Option<(u64, i64)>,
}

impl PtsUnwrapper {
    /// An unwrapper that has seen nothing.
    #[must_use]
    pub const fn new() -> PtsUnwrapper {
        PtsUnwrapper { last: None }
    }

    /// The unwrapped value of the raw PTS `pts`.
    pub fn unwrap(&mut self, pts: u64) -> i64 {
        let pts = pts % PTS_WRAP;
        let unwrapped = match self.last {
            Some((raw, unwrapped)) => unwrapped + pts_delta(pts, raw),
            None => pts as i64,
        };
        self.last = Some((pts, unwrapped));
        unwrapped
    }

    /// The unwrapped value `pts` would get, without recording it.
    #[must_use]
    pub fn peek(&self, pts: u64) -> i64 {
        match self.last {
            Some((raw, unwrapped)) => unwrapped + pts_delta(pts % PTS_WRAP, raw),
            None => (pts % PTS_WRAP) as i64,
        }
    }

    /// Forget the history, after a program clock discontinuity.
    pub fn reset(&mut self) {
        self.last = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pts_round_trips_through_misp() {
        let a = Anchor::new(123_456_789, MispTime::from_micros(1_657_616_732_000_618));
        for d in (-200_000i64..200_000).step_by(7).chain([-3003, -1, 0, 1, 3003, 1 << 34]) {
            let pts = a.pts + d;
            let misp = a.misp_at(pts).unwrap();
            assert_eq!(a.pts_at(misp), pts, "d = {d}");
        }
    }

    #[test]
    fn rounding_follows_d11() {
        let a = Anchor::new(0, MispTime::from_micros(1_000_000));
        // floor: 1 tick = 11.11 us -> 11; -1 tick = -11.11 us -> -12.
        assert_eq!(a.misp_at(1), Some(MispTime::from_micros(1_000_011)));
        assert_eq!(a.misp_at(-1), Some(MispTime::from_micros(999_988)));
        // Round half up: 50 us = 4.5 ticks -> 5; -50 us = -4.5 -> -4.
        assert_eq!(a.pts_at(MispTime::from_micros(1_000_050)), 5);
        assert_eq!(a.pts_at(MispTime::from_micros(999_950)), -4);
        assert_eq!(a.pts_at(MispTime::from_micros(1_000_055)), 5);
        assert_eq!(a.pts_at(MispTime::from_micros(1_000_056)), 5);
        assert_eq!(a.pts_at(MispTime::from_micros(1_000_061)), 5);
        assert_eq!(a.pts_at(MispTime::from_micros(1_000_062)), 6);
        // Before the epoch.
        assert_eq!(Anchor::new(0, MispTime::from_micros(5)).misp_at(-1), None);
    }

    #[test]
    fn unwrapper_crosses_the_wrap_both_ways() {
        let mut u = PtsUnwrapper::new();
        let top = PTS_WRAP - 3000;
        assert_eq!(u.unwrap(top), top as i64);
        assert_eq!(u.unwrap(3), PTS_WRAP as i64 + 3);
        // A B-frame from before the wrap.
        assert_eq!(u.unwrap(PTS_WRAP - 10), PTS_WRAP as i64 - 10);
        assert_eq!(u.peek(6006), PTS_WRAP as i64 + 6006);
        assert_eq!(wrap_pts(PTS_WRAP as i64 + 6006), 6006);
        assert_eq!(wrap_pts(-1), PTS_WRAP - 1);
        u.reset();
        assert_eq!(u.unwrap(7), 7);
    }
}
