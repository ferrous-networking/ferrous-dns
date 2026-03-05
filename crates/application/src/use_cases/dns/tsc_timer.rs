//! High-resolution timer for cache hit measurements.
//!
//! On x86_64: uses `rdtsc` (~1–5 ns overhead) with one-time TSC frequency calibration.
//! On other architectures: falls back to `CLOCK_MONOTONIC` via `Instant`.
//!
//! This replaces `CLOCK_MONOTONIC_COARSE` (resolution ~4–10 ms) for cache timing,
//! giving true µs-level precision without meaningful hot-path cost.

#[cfg(target_arch = "x86_64")]
mod imp {
    use std::sync::LazyLock;
    use std::time::Instant;

    /// Cycles per microsecond, calibrated once at first use.
    static CYCLES_PER_US: LazyLock<u64> = LazyLock::new(calibrate_tsc);

    /// Calibrates TSC frequency by comparing cycle count against `CLOCK_MONOTONIC`
    /// over a short busy-wait period (~1 ms). Called once at startup.
    fn calibrate_tsc() -> u64 {
        const CALIBRATION_US: u128 = 1_000;

        let t0 = Instant::now();
        let c0 = read_tsc();

        // Spin until 1 ms has elapsed — accurate, no sleep, ~1 ms of CPU at startup.
        while t0.elapsed().as_micros() < CALIBRATION_US {
            core::hint::spin_loop();
        }

        let elapsed_cycles = read_tsc().saturating_sub(c0);
        let elapsed_us = t0.elapsed().as_micros() as u64;

        if elapsed_us == 0 {
            return 1;
        }
        elapsed_cycles / elapsed_us
    }

    #[inline(always)]
    fn read_tsc() -> u64 {
        // SAFETY: `_rdtsc` is available on all x86_64 CPUs. No memory is accessed.
        unsafe { core::arch::x86_64::_rdtsc() }
    }

    /// Returns the current TSC cycle count.
    #[inline(always)]
    pub fn now() -> u64 {
        read_tsc()
    }

    /// Converts a cycle delta to microseconds using the calibrated frequency.
    #[inline(always)]
    pub fn to_us(cycles: u64) -> u64 {
        let cpus = *CYCLES_PER_US;
        if cpus == 0 {
            return 0;
        }
        cycles / cpus
    }

    /// Forces calibration to run now. Call once during application startup
    /// so the first DNS query doesn't pay the 1 ms calibration cost.
    pub fn init() {
        let _ = *CYCLES_PER_US;
    }
}

#[cfg(not(target_arch = "x86_64"))]
mod imp {
    use std::sync::LazyLock;
    use std::time::Instant;

    static START: LazyLock<Instant> = LazyLock::new(Instant::now);

    /// Returns nanoseconds since process start (used as "cycles" on non-x86_64).
    #[inline(always)]
    pub fn now() -> u64 {
        START.elapsed().as_nanos() as u64
    }

    /// Converts nanoseconds to microseconds.
    #[inline(always)]
    pub fn to_us(nanos: u64) -> u64 {
        nanos / 1_000
    }

    pub fn init() {
        let _ = *START;
    }
}

pub use imp::{init, now, to_us};

/// Measures elapsed microseconds between `start` (from `now()`) and the current instant.
#[inline(always)]
pub fn elapsed_us_since(start: u64) -> u64 {
    to_us(now().saturating_sub(start))
}
