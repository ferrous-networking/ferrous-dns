use rustc_hash::FxHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering as AtomicOrdering};

pub struct AtomicBloom {
    slots: [Vec<AtomicU64>; 2],
    active: AtomicUsize,
    mask: u64,
    num_hashes: usize,
}

impl AtomicBloom {
    pub fn new(capacity: usize, fp_rate: f64) -> Self {
        let num_bits = Self::optimal_num_bits(capacity, fp_rate);
        let num_hashes = Self::optimal_num_hashes(capacity, num_bits);
        let num_words = num_bits.div_ceil(64);
        let make_slot = || {
            (0..num_words)
                .map(|_| AtomicU64::new(0))
                .collect::<Vec<_>>()
        };
        Self {
            slots: [make_slot(), make_slot()],
            active: AtomicUsize::new(0),
            mask: (num_bits as u64) - 1,
            num_hashes,
        }
    }

    #[inline]
    pub fn check<K: Hash>(&self, key: &K) -> bool {
        let a = self.active.load(AtomicOrdering::Relaxed);
        let b = 1 - a;
        let (h1, h2) = Self::double_hash(key);
        let num_hashes = self.num_hashes;
        let mask = self.mask;

        if num_hashes == 5 {
            let check_both = |i: u64| -> bool {
                let idx = Self::nth_hash(h1, h2, i, mask);
                let bit = 1u64 << (idx % 64);
                let word = idx / 64;
                (self.slots[a][word].load(AtomicOrdering::Relaxed) & bit != 0)
                    || (self.slots[b][word].load(AtomicOrdering::Relaxed) & bit != 0)
            };

            check_both(0) && check_both(1) && check_both(2) && check_both(3) && check_both(4)
        } else {
            for i in 0..num_hashes as u64 {
                let idx = Self::nth_hash(h1, h2, i, mask);
                let bit = 1u64 << (idx % 64);
                let word = idx / 64;
                let in_active = self.slots[a][word].load(AtomicOrdering::Relaxed) & bit != 0;
                let in_inactive = self.slots[b][word].load(AtomicOrdering::Relaxed) & bit != 0;
                if !in_active && !in_inactive {
                    return false;
                }
            }
            true
        }
    }

    #[inline]
    pub fn set<K: Hash>(&self, key: &K) {
        let a = self.active.load(AtomicOrdering::Relaxed);
        let (h1, h2) = Self::double_hash(key);
        let num_hashes = self.num_hashes;
        let mask = self.mask;

        if num_hashes == 5 {
            let idx0 = Self::nth_hash(h1, h2, 0, mask);
            self.slots[a][idx0 / 64].fetch_or(1u64 << (idx0 % 64), AtomicOrdering::Relaxed);
            let idx1 = Self::nth_hash(h1, h2, 1, mask);
            self.slots[a][idx1 / 64].fetch_or(1u64 << (idx1 % 64), AtomicOrdering::Relaxed);
            let idx2 = Self::nth_hash(h1, h2, 2, mask);
            self.slots[a][idx2 / 64].fetch_or(1u64 << (idx2 % 64), AtomicOrdering::Relaxed);
            let idx3 = Self::nth_hash(h1, h2, 3, mask);
            self.slots[a][idx3 / 64].fetch_or(1u64 << (idx3 % 64), AtomicOrdering::Relaxed);
            let idx4 = Self::nth_hash(h1, h2, 4, mask);
            self.slots[a][idx4 / 64].fetch_or(1u64 << (idx4 % 64), AtomicOrdering::Relaxed);
        } else {
            for i in 0..num_hashes as u64 {
                let idx = Self::nth_hash(h1, h2, i, mask);
                self.slots[a][idx / 64].fetch_or(1u64 << (idx % 64), AtomicOrdering::Relaxed);
            }
        }
    }

    pub fn rotate(&self) {
        let old_active = self.active.load(AtomicOrdering::Relaxed);
        let new_active = 1 - old_active;
        for word in &self.slots[new_active] {
            word.store(0, AtomicOrdering::Relaxed);
        }
        self.active.store(new_active, AtomicOrdering::Relaxed);
    }

    pub fn clear(&self) {
        for slot in &self.slots {
            for word in slot {
                word.store(0, AtomicOrdering::Relaxed);
            }
        }
    }

    #[inline]
    fn double_hash<K: Hash>(key: &K) -> (u64, u64) {
        let mut hasher = FxHasher::default();
        key.hash(&mut hasher);
        let h1 = hasher.finish();
        let h2 = h1.wrapping_mul(0x517cc1b727220a95).rotate_right(17);
        (h1, h2)
    }

    #[inline]
    fn nth_hash(h1: u64, h2: u64, n: u64, mask: u64) -> usize {
        (h1.wrapping_add(n.wrapping_mul(h2)) & mask) as usize
    }

    fn optimal_num_bits(capacity: usize, fp_rate: f64) -> usize {
        let n = capacity as f64;
        let p = fp_rate;
        let m = (-(n * p.ln()) / (2.0_f64.ln().powi(2))).ceil() as usize;
        m.next_power_of_two()
    }

    fn optimal_num_hashes(capacity: usize, num_bits: usize) -> usize {
        let n = capacity as f64;
        let m = num_bits as f64;
        ((m / n) * 2.0_f64.ln()).ceil() as usize
    }
}
