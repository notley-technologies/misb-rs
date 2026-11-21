//! Which frames get metadata.

use std::fmt;

/// How often metadata goes into the stream.
///
/// No standard sets a rate (st1402-time.md D-17); the defaults are
/// [`Rate::SYNC_DEFAULT`] (every frame up to 30 Hz) for synchronous and
/// [`Rate::ASYNC_DEFAULT`] (10 Hz) for asynchronous carriage.
#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
pub enum Rate {
    /// Only the samples the source has, each at its own time: a recorded
    /// `.klv` file or a list of packets. The only rate for recorded
    /// packets, whose tag 2 is never changed (D-6).
    Explicit,
    /// Every video frame.
    EveryFrame,
    /// Every `n`th video frame (`n` at least 1), counting from the first.
    EveryNthFrame(u32),
    /// At most this many packets per second, on video frames: a frame gets
    /// metadata when at least `1 / hz` (less 1 ms) has passed since the
    /// last one, so 29.97 fps video at 30 Hz gets every frame and 59.94 fps
    /// video gets every second frame.
    Hz(f64),
}

impl Rate {
    /// Every frame up to 30 Hz (every second frame of 60 fps video).
    pub const SYNC_DEFAULT: Rate = Rate::Hz(30.0);
    /// 10 Hz.
    pub const ASYNC_DEFAULT: Rate = Rate::Hz(10.0);

    /// Check the parameters.
    pub fn validate(&self) -> Result<(), RateError> {
        match *self {
            Rate::EveryNthFrame(0) => Err(RateError("EveryNthFrame needs n of at least 1")),
            Rate::Hz(hz) if !(hz.is_finite() && hz > 0.0 && hz <= 1000.0) => {
                Err(RateError("Hz needs a rate above 0 and at most 1000"))
            }
            _ => Ok(()),
        }
    }
}

/// An invalid [`Rate`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateError(&'static str);

impl fmt::Display for RateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for RateError {}

/// Slack on the [`Rate::Hz`] interval, so frame periods that are a tick
/// shorter than the interval (29.97 fps against 30 Hz) still qualify.
const HZ_SLACK_TICKS: i64 = 90;

/// Applies a [`Rate`] to frames in presentation order.
#[derive(Clone, Debug)]
pub struct RateLimiter {
    rate: Rate,
    frames: u64,
    last: Option<i64>,
}

impl RateLimiter {
    /// A limiter for `rate`.
    pub fn new(rate: Rate) -> Result<RateLimiter, RateError> {
        rate.validate()?;
        Ok(RateLimiter { rate, frames: 0, last: None })
    }

    /// The rate.
    #[must_use]
    pub fn rate(&self) -> Rate {
        self.rate
    }

    /// Whether the frame at unwrapped PTS `pts` gets metadata. Frames must
    /// come in presentation order; a frame that does not move forward never
    /// qualifies. [`Rate::Explicit`] admits no frame.
    pub fn admit(&mut self, pts: i64) -> bool {
        if self.last.map_or(false, |last| pts <= last) {
            return false;
        }
        let n = self.frames;
        self.frames += 1;
        let ok = match self.rate {
            Rate::Explicit => false,
            Rate::EveryFrame => true,
            Rate::EveryNthFrame(every) => n % u64::from(every) == 0,
            Rate::Hz(hz) => {
                let interval = (90_000.0 / hz).round() as i64;
                self.last.map_or(true, |last| pts - last >= interval - HZ_SLACK_TICKS)
            }
        };
        if ok {
            self.last = Some(pts);
        }
        ok
    }

    /// Start again, as for a new time line.
    pub fn reset(&mut self) {
        self.frames = 0;
        self.last = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admitted(rate: Rate, step: f64, frames: usize) -> usize {
        let mut l = RateLimiter::new(rate).unwrap();
        (0..frames).filter(|&i| l.admit((i as f64 * step).round() as i64)).count()
    }

    #[test]
    fn rates_snap_to_frames() {
        // 29.97 fps (3003 ticks), 59.94 fps (1501.5), 50 fps (1800), 25 fps.
        assert_eq!(admitted(Rate::SYNC_DEFAULT, 3003.0, 300), 300);
        assert_eq!(admitted(Rate::SYNC_DEFAULT, 1501.5, 600), 300);
        assert_eq!(admitted(Rate::SYNC_DEFAULT, 1800.0, 500), 250);
        assert_eq!(admitted(Rate::SYNC_DEFAULT, 3600.0, 250), 250);
        assert_eq!(admitted(Rate::ASYNC_DEFAULT, 3003.0, 300), 100);
        assert_eq!(admitted(Rate::ASYNC_DEFAULT, 1501.5, 600), 100);
        assert_eq!(admitted(Rate::EveryFrame, 1501.5, 600), 600);
        assert_eq!(admitted(Rate::EveryNthFrame(3), 3003.0, 300), 100);
        assert_eq!(admitted(Rate::Explicit, 3003.0, 300), 0);
    }

    #[test]
    fn frames_must_move_forward() {
        let mut l = RateLimiter::new(Rate::EveryFrame).unwrap();
        assert!(l.admit(100));
        assert!(!l.admit(100));
        assert!(!l.admit(50));
        assert!(l.admit(3103));
        l.reset();
        assert!(l.admit(0));
    }

    #[test]
    fn invalid_rates() {
        assert!(Rate::EveryNthFrame(0).validate().is_err());
        assert!(Rate::Hz(0.0).validate().is_err());
        assert!(Rate::Hz(f64::NAN).validate().is_err());
        assert!(Rate::Hz(5000.0).validate().is_err());
        assert!(Rate::Hz(60.0).validate().is_ok());
    }
}
