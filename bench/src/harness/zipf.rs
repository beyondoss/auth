//! Zipf-distributed integer sampler.
//!
//! Real-world access patterns over a key space are rarely uniform — a small
//! "head" of objects is hot, the long tail is cold. Sampling uniformly over
//! `[0, n)` underweights the head and produces unrealistically poor cache
//! hit ratios in benches. `ZipfSampler` precomputes the CDF at construction
//! so each sample is O(log n) via binary search.
//!
//! Standard Zipf with exponent `s = 1.0` gives the canonical "80/20"-shaped
//! distribution. Higher `s` skews more aggressively toward the head; `s -> 0`
//! approaches uniform.
use rand::Rng;

pub struct ZipfSampler {
    /// Cumulative distribution function. `cdf[i]` is the probability that a
    /// sample is `<= i`. `cdf[n-1] == 1.0` (modulo float rounding).
    cdf: Vec<f64>,
}

impl ZipfSampler {
    /// Build a sampler over `[0, n)` with the given Zipf exponent.
    ///
    /// Panics if `n == 0`.
    pub fn new(n: usize, exponent: f64) -> Self {
        assert!(n > 0, "ZipfSampler requires n > 0");
        let mut cdf = Vec::with_capacity(n);
        let mut acc = 0.0f64;
        for i in 0..n {
            // Rank is 1-based in the Zipf weight: w_k = 1 / k^s.
            let k = (i + 1) as f64;
            acc += 1.0 / k.powf(exponent);
            cdf.push(acc);
        }
        // Normalize so the last entry is exactly 1.0.
        let total = *cdf.last().unwrap();
        for v in cdf.iter_mut() {
            *v /= total;
        }
        Self { cdf }
    }

    /// Returns the size of the sample space.
    #[allow(dead_code)]
    pub fn n(&self) -> usize {
        self.cdf.len()
    }

    /// Sample an index in `[0, n)`. O(log n) via binary search of the CDF.
    pub fn sample(&self, rng: &mut impl Rng) -> usize {
        let r: f64 = rng.r#gen();
        // partition_point returns the first index where predicate is false.
        // We want the smallest i with cdf[i] >= r.
        let idx = self.cdf.partition_point(|&p| p < r);
        idx.min(self.cdf.len() - 1)
    }
}
