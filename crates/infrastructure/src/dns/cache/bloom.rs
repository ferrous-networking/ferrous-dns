use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

pub struct AtomicBloom {
    bits: Vec<AtomicU64>,
    num_bits: usize,
    num_hashes: usize,
}

impl AtomicBloom {
    
    pub fn new(capacity: usize, fp_rate: f64) -> Self {
        let num_bits = Self::optimal_num_bits(capacity, fp_rate);
        let num_hashes = Self::optimal_num_hashes(capacity, num_bits);
        let num_words = num_bits.div_ceil(64);
        let bits = (0..num_words).map(|_| AtomicU64::new(0)).collect();
        Self {
            bits,
            num_bits,
            num_hashes,
        }
    }

    #[inline]
    pub fn check<K: Hash>(&self, key: &K) -> bool {
        let (h1, h2) = Self::double_hash(key);
        let num_hashes = self.num_hashes;

        if num_hashes == 5 {
            let idx0 = Self::nth_hash(h1, h2, 0, self.num_bits);
            let check0 = self.bits[idx0 / 64].load(AtomicOrdering::Relaxed) & (1u64 << (idx0 % 64));

            let idx1 = Self::nth_hash(h1, h2, 1, self.num_bits);
            let check1 = self.bits[idx1 / 64].load(AtomicOrdering::Relaxed) & (1u64 << (idx1 % 64));

            let idx2 = Self::nth_hash(h1, h2, 2, self.num_bits);
            let check2 = self.bits[idx2 / 64].load(AtomicOrdering::Relaxed) & (1u64 << (idx2 % 64));

            let idx3 = Self::nth_hash(h1, h2, 3, self.num_bits);
            let check3 = self.bits[idx3 / 64].load(AtomicOrdering::Relaxed) & (1u64 << (idx3 % 64));

            let idx4 = Self::nth_hash(h1, h2, 4, self.num_bits);
            let check4 = self.bits[idx4 / 64].load(AtomicOrdering::Relaxed) & (1u64 << (idx4 % 64));

            (check0 & check1 & check2 & check3 & check4) != 0
        } else {
            for i in 0..num_hashes {
                let bit_idx = Self::nth_hash(h1, h2, i as u64, self.num_bits);
                let word_idx = bit_idx / 64;
                let bit_pos = bit_idx % 64;
                if (self.bits[word_idx].load(AtomicOrdering::Relaxed) & (1u64 << bit_pos)) == 0 {
                    return false;
                }
            }
            true
        }
    }

    #[inline]
    pub fn set<K: Hash>(&self, key: &K) {
        let (h1, h2) = Self::double_hash(key);
        let num_hashes = self.num_hashes;

        if num_hashes == 5 {
            let idx0 = Self::nth_hash(h1, h2, 0, self.num_bits);
            self.bits[idx0 / 64].fetch_or(1u64 << (idx0 % 64), AtomicOrdering::Relaxed);

            let idx1 = Self::nth_hash(h1, h2, 1, self.num_bits);
            self.bits[idx1 / 64].fetch_or(1u64 << (idx1 % 64), AtomicOrdering::Relaxed);

            let idx2 = Self::nth_hash(h1, h2, 2, self.num_bits);
            self.bits[idx2 / 64].fetch_or(1u64 << (idx2 % 64), AtomicOrdering::Relaxed);

            let idx3 = Self::nth_hash(h1, h2, 3, self.num_bits);
            self.bits[idx3 / 64].fetch_or(1u64 << (idx3 % 64), AtomicOrdering::Relaxed);

            let idx4 = Self::nth_hash(h1, h2, 4, self.num_bits);
            self.bits[idx4 / 64].fetch_or(1u64 << (idx4 % 64), AtomicOrdering::Relaxed);
        } else {
            for i in 0..num_hashes {
                let bit_idx = Self::nth_hash(h1, h2, i as u64, self.num_bits);
                let word_idx = bit_idx / 64;
                let bit_pos = bit_idx % 64;
                self.bits[word_idx].fetch_or(1u64 << bit_pos, AtomicOrdering::Relaxed);
            }
        }
    }

    pub fn clear(&self) {
        for word in &self.bits {
            word.store(0, AtomicOrdering::Relaxed);
        }
    }

    #[inline]
    fn double_hash<K: Hash>(key: &K) -> (u64, u64) {
        let mut hasher1 = DefaultHasher::new();
        key.hash(&mut hasher1);
        let h1 = hasher1.finish();

        let mut hasher2 = DefaultHasher::new();
        h1.hash(&mut hasher2);
        let h2 = hasher2.finish();

        (h1, h2)
    }

    #[inline]
    fn nth_hash(h1: u64, h2: u64, n: u64, num_bits: usize) -> usize {
        (h1.wrapping_add(n.wrapping_mul(h2)) % num_bits as u64) as usize
    }

    fn optimal_num_bits(capacity: usize, fp_rate: f64) -> usize {
        let n = capacity as f64;
        let p = fp_rate;
        (-(n * p.ln()) / (2.0_f64.ln().powi(2))).ceil() as usize
    }

    fn optimal_num_hashes(capacity: usize, num_bits: usize) -> usize {
        let n = capacity as f64;
        let m = num_bits as f64;
        ((m / n) * 2.0_f64.ln()).ceil() as usize
    }
}
