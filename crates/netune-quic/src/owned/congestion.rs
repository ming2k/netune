// SPDX-License-Identifier: MIT

//! Congestion-control profiles for the owned QUIC engine.
//!
//! The controllers are deliberately sans-IO: the connection core supplies ACK
//! bytes, loss bytes and monotonic timestamps, and the controller returns the
//! congestion window. NewReno is the conservative default. Cubic keeps a
//! cubic epoch; BBR keeps a model of bottleneck bandwidth and minimum RTT. The
//! BBR implementation is model-window based and intentionally does not claim
//! pacing parity with a full BBRv3 deployment.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::profile::CongestionAlgorithm;

const MSS: u64 = 1200;
const MIN_CWND: u64 = 2 * MSS;

/// A pluggable congestion controller for the owned QUIC engine.
///
/// The engine calls these methods with monotonic timestamps and byte counts;
/// an implementation returns the congestion window it wants enforced. This is
/// the seam for protocol-specific controllers such as Hysteria 2's Brutal,
/// which pins a window to an operator-declared rate instead of inferring one
/// from loss.
pub trait CongestionController: Send + Sync {
    /// The current congestion window in bytes.
    fn window(&self) -> u64;
    /// One ACKed batch of bytes.
    fn on_ack(&mut self, acked_bytes: u64, now: Instant, rtt: Option<Duration>);
    /// One loss event; `lost_bytes` is the total size of the packets declared lost.
    fn on_loss(&mut self, now: Instant, lost_bytes: u64);
    /// A probe timeout expired.
    fn on_pto(&mut self, now: Instant);
}

/// Builds one controller per connection.
pub trait CongestionControllerFactory: Send + Sync {
    /// Construct a controller for a new connection. `mss` is the engine's
    /// packet payload ceiling, not a discovered path MTU.
    fn build(&self, now: Instant, mss: u16) -> Box<dyn CongestionController>;
}

pub(crate) enum Congestion {
    NewReno(NewReno),
    Cubic(Cubic),
    Bbr(Bbr),
    Custom(Box<dyn CongestionController>),
}

impl Congestion {
    pub(crate) fn new(algorithm: CongestionAlgorithm, now: Instant) -> Self {
        match algorithm {
            CongestionAlgorithm::NewReno => Self::NewReno(NewReno::new()),
            CongestionAlgorithm::Cubic => Self::Cubic(Cubic::new()),
            CongestionAlgorithm::Bbr => Self::Bbr(Bbr::new(now)),
        }
    }

    /// Builds the profile-selected controller, or the caller's factory when
    /// one was supplied.
    pub(crate) fn new_with_factory(
        algorithm: CongestionAlgorithm,
        factory: Option<&Arc<dyn CongestionControllerFactory>>,
        now: Instant,
    ) -> Self {
        match factory {
            Some(factory) => Self::Custom(factory.build(now, MSS as u16)),
            None => Self::new(algorithm, now),
        }
    }

    pub(crate) fn window(&self) -> u64 {
        match self {
            Self::NewReno(state) => state.cwnd,
            Self::Cubic(state) => state.cwnd,
            Self::Bbr(state) => state.cwnd,
            Self::Custom(state) => state.window(),
        }
    }

    pub(crate) fn on_ack(&mut self, acked_bytes: u64, now: Instant, rtt: Option<Duration>) {
        match self {
            Self::NewReno(state) => state.on_ack(acked_bytes),
            Self::Cubic(state) => state.on_ack(acked_bytes, now),
            Self::Bbr(state) => state.on_ack(acked_bytes, now, rtt),
            Self::Custom(state) => state.on_ack(acked_bytes, now, rtt),
        }
    }

    pub(crate) fn on_loss(&mut self, now: Instant, lost_bytes: u64) {
        match self {
            Self::NewReno(state) => state.on_loss(),
            Self::Cubic(state) => state.on_loss(),
            Self::Bbr(state) => state.on_loss(now),
            Self::Custom(state) => state.on_loss(now, lost_bytes),
        }
    }

    pub(crate) fn on_pto(&mut self, now: Instant) {
        match self {
            Self::NewReno(state) => state.on_loss(),
            Self::Cubic(state) => state.on_loss(),
            Self::Bbr(state) => state.on_pto(now),
            Self::Custom(state) => state.on_pto(now),
        }
    }
}

pub(crate) struct NewReno {
    cwnd: u64,
    ssthresh: u64,
}

impl NewReno {
    fn new() -> Self {
        Self {
            cwnd: 10 * MSS,
            ssthresh: u64::MAX,
        }
    }

    fn on_ack(&mut self, acked_bytes: u64) {
        if self.cwnd < self.ssthresh {
            self.cwnd = self.cwnd.saturating_add(acked_bytes);
        } else {
            self.cwnd = self
                .cwnd
                .saturating_add((MSS.saturating_mul(acked_bytes)) / self.cwnd.max(1));
        }
    }

    fn on_loss(&mut self) {
        self.ssthresh = (self.cwnd / 2).max(MIN_CWND);
        self.cwnd = self.ssthresh;
    }
}

pub(crate) struct Cubic {
    cwnd: u64,
    ssthresh: u64,
    w_max: f64,
    epoch: Option<Instant>,
    k: f64,
}

impl Cubic {
    const C: f64 = 0.4;
    const BETA: f64 = 0.7;

    fn new() -> Self {
        Self {
            cwnd: 10 * MSS,
            ssthresh: u64::MAX,
            w_max: 0.0,
            epoch: None,
            k: 0.0,
        }
    }

    fn on_ack(&mut self, acked_bytes: u64, now: Instant) {
        if self.cwnd < self.ssthresh {
            self.cwnd = self.cwnd.saturating_add(acked_bytes);
            return;
        }
        let cwnd = self.cwnd as f64;
        let epoch = *self.epoch.get_or_insert_with(|| {
            self.w_max = self.w_max.max(cwnd);
            self.k = ((self.w_max * (1.0 - Self::BETA) / Self::C).max(0.0)).cbrt();
            now
        });
        let elapsed = now.saturating_duration_since(epoch).as_secs_f64();
        let target = Self::C * (elapsed - self.k).powi(3) + self.w_max;
        let increment = ((target - cwnd) / cwnd.max(1.0)) * acked_bytes as f64;
        if increment > 0.0 {
            self.cwnd = self.cwnd.saturating_add(increment as u64);
        }
    }

    fn on_loss(&mut self) {
        self.w_max = self.cwnd as f64;
        self.ssthresh = ((self.cwnd as f64 * Self::BETA) as u64).max(MIN_CWND);
        self.cwnd = self.ssthresh;
        self.epoch = None;
    }
}

#[derive(Clone, Copy)]
enum BbrState {
    Startup,
    Drain,
    ProbeBw,
    ProbeRtt,
}

pub(crate) struct Bbr {
    cwnd: u64,
    min_rtt: Option<Duration>,
    max_bw: f64,
    last_ack: Instant,
    rounds: u32,
    state: BbrState,
    cwnd_gain: f64,
    cycle_start: Instant,
}

impl Bbr {
    fn new(now: Instant) -> Self {
        Self {
            cwnd: 10 * MSS,
            min_rtt: None,
            max_bw: 0.0,
            last_ack: now,
            rounds: 0,
            state: BbrState::Startup,
            cwnd_gain: 2.885,
            cycle_start: now,
        }
    }

    fn on_ack(&mut self, acked_bytes: u64, now: Instant, rtt: Option<Duration>) {
        let elapsed = now
            .saturating_duration_since(self.last_ack)
            .as_secs_f64()
            .max(0.001);
        self.last_ack = now;
        let bandwidth = acked_bytes as f64 / elapsed;
        self.max_bw = self.max_bw.max(bandwidth);
        if let Some(rtt) = rtt
            && self.min_rtt.is_none_or(|minimum| rtt < minimum)
        {
            self.min_rtt = Some(rtt);
        }
        self.rounds = self.rounds.saturating_add(1);
        if self.rounds >= 3 && matches!(self.state, BbrState::Startup) {
            self.state = BbrState::Drain;
            self.cwnd_gain = 1.0;
        }
        if now.saturating_duration_since(self.cycle_start) >= Duration::from_secs(8) {
            self.cycle_start = now;
            self.state = match self.state {
                BbrState::Startup => BbrState::Drain,
                BbrState::Drain | BbrState::ProbeRtt => BbrState::ProbeBw,
                BbrState::ProbeBw => BbrState::ProbeRtt,
            };
            self.cwnd_gain = match self.state {
                BbrState::Startup => 2.885,
                BbrState::Drain => 1.0,
                BbrState::ProbeBw => 1.25,
                BbrState::ProbeRtt => 1.0,
            };
        }
        if let Some(min_rtt) = self.min_rtt {
            let bdp = self.max_bw * min_rtt.as_secs_f64();
            let target = (bdp * self.cwnd_gain) as u64;
            self.cwnd = target.max(4 * MSS);
        }
    }

    fn on_loss(&mut self, _now: Instant) {
        self.cwnd = ((self.cwnd as f64 * 0.7) as u64).max(4 * MSS);
        self.state = BbrState::ProbeBw;
        self.cwnd_gain = 1.25;
    }

    fn on_pto(&mut self, now: Instant) {
        self.cwnd = (self.cwnd / 2).max(4 * MSS);
        self.state = BbrState::ProbeRtt;
        self.cwnd_gain = 1.0;
        self.cycle_start = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_reno_grows_and_reduces() {
        let mut state = NewReno::new();
        let start = state.cwnd;
        state.on_ack(10 * MSS);
        assert!(state.cwnd > start);
        state.on_loss();
        assert!(state.cwnd < start * 2);
    }

    #[test]
    fn cubic_has_an_increase_epoch() {
        let now = Instant::now();
        let mut state = Cubic::new();
        state.cwnd = 20 * MSS;
        state.ssthresh = 10 * MSS;
        state.on_ack(MSS, now);
        assert!(state.epoch.is_some());
        let before = state.cwnd;
        state.on_ack(MSS, now + Duration::from_millis(100));
        assert!(state.cwnd >= before);
    }

    #[test]
    fn bbr_keeps_a_positive_model_window() {
        let now = Instant::now();
        let mut state = Bbr::new(now);
        state.on_ack(
            10 * MSS,
            now + Duration::from_millis(10),
            Some(Duration::from_millis(20)),
        );
        assert!(state.cwnd >= 4 * MSS);
        assert!(state.max_bw > 0.0);
        state.on_pto(now + Duration::from_millis(30));
        assert!(state.cwnd >= 4 * MSS);
    }

    #[test]
    fn a_custom_factory_overrides_the_profile_algorithm() {
        // A product controller (Hysteria 2's Brutal) must be able to pin the window without
        // the engine knowing the product. The factory is consulted once and its window is
        // what `poll_transmit` sees.
        #[derive(Debug)]
        struct Fixed;
        impl CongestionController for Fixed {
            fn window(&self) -> u64 {
                77 * MSS
            }
            fn on_ack(&mut self, _acked_bytes: u64, _now: Instant, _rtt: Option<Duration>) {}
            fn on_loss(&mut self, _now: Instant, _lost_bytes: u64) {}
            fn on_pto(&mut self, _now: Instant) {}
        }
        #[derive(Debug)]
        struct Factory;
        impl CongestionControllerFactory for Factory {
            fn build(&self, _now: Instant, _mtu: u16) -> Box<dyn CongestionController> {
                Box::new(Fixed)
            }
        }

        let factory: Arc<dyn CongestionControllerFactory> = Arc::new(Factory);
        let mut control = Congestion::new_with_factory(
            CongestionAlgorithm::NewReno,
            Some(&factory),
            Instant::now(),
        );
        assert_eq!(control.window(), 77 * MSS);
        control.on_ack(MSS, Instant::now(), None);
        control.on_loss(Instant::now(), MSS);
        assert_eq!(control.window(), 77 * MSS);
    }
}
