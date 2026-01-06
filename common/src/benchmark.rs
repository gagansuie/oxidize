//! Benchmarking Infrastructure
//!
//! Provides tools for measuring and comparing performance of different
//! pipeline configurations and optimizations.

use std::time::{Duration, Instant};

/// Benchmark result for a single run
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    pub name: String,
    pub iterations: u64,
    pub total_time: Duration,
    pub avg_time_ns: u64,
    pub min_time_ns: u64,
    pub max_time_ns: u64,
    pub throughput_ops_sec: f64,
    pub throughput_mb_sec: f64,
}

impl BenchmarkResult {
    pub fn new(name: &str, times: &[Duration], bytes_per_op: usize) -> Self {
        let iterations = times.len() as u64;
        let total_time: Duration = times.iter().sum();

        let times_ns: Vec<u64> = times.iter().map(|d| d.as_nanos() as u64).collect();
        let avg_time_ns = times_ns.iter().sum::<u64>() / iterations;
        let min_time_ns = *times_ns.iter().min().unwrap_or(&0);
        let max_time_ns = *times_ns.iter().max().unwrap_or(&0);

        let throughput_ops_sec = if avg_time_ns > 0 {
            1_000_000_000.0 / avg_time_ns as f64
        } else {
            0.0
        };

        let throughput_mb_sec = throughput_ops_sec * bytes_per_op as f64 / 1_000_000.0;

        BenchmarkResult {
            name: name.to_string(),
            iterations,
            total_time,
            avg_time_ns,
            min_time_ns,
            max_time_ns,
            throughput_ops_sec,
            throughput_mb_sec,
        }
    }

    /// Format as human-readable string
    pub fn format(&self) -> String {
        format!(
            "{}: {} iterations, avg {:.2}µs, min {:.2}µs, max {:.2}µs, {:.2} ops/sec, {:.2} MB/s",
            self.name,
            self.iterations,
            self.avg_time_ns as f64 / 1000.0,
            self.min_time_ns as f64 / 1000.0,
            self.max_time_ns as f64 / 1000.0,
            self.throughput_ops_sec,
            self.throughput_mb_sec,
        )
    }
}

/// Benchmark runner
pub struct Benchmarker {
    /// Warmup iterations
    warmup: u64,
    /// Measurement iterations
    iterations: u64,
}

impl Benchmarker {
    pub fn new(warmup: u64, iterations: u64) -> Self {
        Benchmarker { warmup, iterations }
    }

    /// Run a benchmark with the given closure
    pub fn run<F>(&self, name: &str, bytes_per_op: usize, mut f: F) -> BenchmarkResult
    where
        F: FnMut(),
    {
        // Warmup
        for _ in 0..self.warmup {
            f();
        }

        // Measure
        let mut times = Vec::with_capacity(self.iterations as usize);
        for _ in 0..self.iterations {
            let start = Instant::now();
            f();
            times.push(start.elapsed());
        }

        BenchmarkResult::new(name, &times, bytes_per_op)
    }

    /// Run an async benchmark
    pub async fn run_async<F, Fut>(
        &self,
        name: &str,
        bytes_per_op: usize,
        mut f: F,
    ) -> BenchmarkResult
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        // Warmup
        for _ in 0..self.warmup {
            f().await;
        }

        // Measure
        let mut times = Vec::with_capacity(self.iterations as usize);
        for _ in 0..self.iterations {
            let start = Instant::now();
            f().await;
            times.push(start.elapsed());
        }

        BenchmarkResult::new(name, &times, bytes_per_op)
    }
}

impl Default for Benchmarker {
    fn default() -> Self {
        Self::new(100, 1000)
    }
}

/// Compare multiple benchmark results
#[derive(Debug, Default)]
pub struct BenchmarkComparison {
    results: Vec<BenchmarkResult>,
}

impl BenchmarkComparison {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, result: BenchmarkResult) {
        self.results.push(result);
    }

    /// Get the baseline (first result)
    pub fn baseline(&self) -> Option<&BenchmarkResult> {
        self.results.first()
    }

    /// Calculate speedup vs baseline
    pub fn speedup(&self, index: usize) -> Option<f64> {
        let baseline = self.baseline()?;
        let result = self.results.get(index)?;

        if result.avg_time_ns == 0 {
            return None;
        }

        Some(baseline.avg_time_ns as f64 / result.avg_time_ns as f64)
    }

    /// Format comparison as table
    pub fn format_table(&self) -> String {
        let mut output = String::new();
        output.push_str("┌─────────────────────────────────────────────────────────────────┐\n");
        output.push_str("│                    Benchmark Comparison                         │\n");
        output.push_str("├───────────────────────┬───────────┬───────────┬────────────────┤\n");
        output.push_str("│ Name                  │ Avg (µs)  │ Ops/sec   │ Speedup        │\n");
        output.push_str("├───────────────────────┼───────────┼───────────┼────────────────┤\n");

        for (i, result) in self.results.iter().enumerate() {
            let speedup = self.speedup(i).unwrap_or(1.0);
            let speedup_str = if i == 0 {
                "baseline".to_string()
            } else {
                format!("{:.2}x", speedup)
            };

            output.push_str(&format!(
                "│ {:21} │ {:9.2} │ {:9.0} │ {:14} │\n",
                truncate(&result.name, 21),
                result.avg_time_ns as f64 / 1000.0,
                result.throughput_ops_sec,
                speedup_str,
            ));
        }

        output.push_str("└───────────────────────┴───────────┴───────────┴────────────────┘\n");
        output
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

/// Throughput benchmark for measuring data processing rates
pub struct ThroughputBench {
    /// Data sizes to test
    pub sizes: Vec<usize>,
    /// Duration per size
    pub duration: Duration,
}

impl ThroughputBench {
    pub fn new(sizes: Vec<usize>, duration: Duration) -> Self {
        ThroughputBench { sizes, duration }
    }

    /// Run throughput benchmark with closure
    pub fn run<F>(&self, name: &str, mut f: F) -> Vec<ThroughputResult>
    where
        F: FnMut(&[u8]) -> usize,
    {
        let mut results = Vec::new();

        for &size in &self.sizes {
            let data = vec![0u8; size];
            let mut ops = 0u64;
            let mut bytes = 0u64;

            let start = Instant::now();
            while start.elapsed() < self.duration {
                let processed = f(&data);
                ops += 1;
                bytes += processed as u64;
            }

            let elapsed = start.elapsed();
            let ops_per_sec = ops as f64 / elapsed.as_secs_f64();
            let mb_per_sec = bytes as f64 / elapsed.as_secs_f64() / 1_000_000.0;

            results.push(ThroughputResult {
                name: format!("{} ({}B)", name, size),
                size,
                ops,
                bytes,
                duration: elapsed,
                ops_per_sec,
                mb_per_sec,
            });
        }

        results
    }
}

impl Default for ThroughputBench {
    fn default() -> Self {
        Self::new(
            vec![64, 256, 1024, 4096, 16384, 65536],
            Duration::from_secs(1),
        )
    }
}

#[derive(Debug, Clone)]
pub struct ThroughputResult {
    pub name: String,
    pub size: usize,
    pub ops: u64,
    pub bytes: u64,
    pub duration: Duration,
    pub ops_per_sec: f64,
    pub mb_per_sec: f64,
}

impl ThroughputResult {
    pub fn format(&self) -> String {
        format!(
            "{}: {} ops in {:.2}s = {:.2} ops/sec, {:.2} MB/s",
            self.name,
            self.ops,
            self.duration.as_secs_f64(),
            self.ops_per_sec,
            self.mb_per_sec,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benchmarker() {
        let bench = Benchmarker::new(10, 100);

        let result = bench.run("test_add", 0, || {
            let _ = 1 + 1;
        });

        assert_eq!(result.iterations, 100);
        assert!(result.avg_time_ns > 0);
    }

    #[test]
    fn test_comparison() {
        let mut comp = BenchmarkComparison::new();

        let bench = Benchmarker::new(10, 100);

        comp.add(bench.run("slow", 0, || {
            std::thread::sleep(Duration::from_micros(10));
        }));

        comp.add(bench.run("fast", 0, || {
            std::thread::sleep(Duration::from_micros(1));
        }));

        let table = comp.format_table();
        assert!(table.contains("slow"));
        assert!(table.contains("fast"));
    }

    #[test]
    fn test_throughput() {
        let bench = ThroughputBench::new(vec![64, 256], Duration::from_millis(100));

        let results = bench.run("copy", |data| {
            let _copy = data.to_vec();
            data.len()
        });

        assert_eq!(results.len(), 2);
        assert!(results[0].ops > 0);
    }
}
