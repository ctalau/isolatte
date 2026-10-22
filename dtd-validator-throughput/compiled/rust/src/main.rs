//! Command-line benchmark for the compiled DITA DTD validator.
//!
//! usage: dita-compiled-validator THREADS < file-list
//!   VERBOSE=1 prints errors; PARSE_ONLY=1 runs quick-xml without validating.

use dita_compiled_validator::{parse_only, validate};
use std::io::{self, BufRead};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

fn main() {
    let nthreads: usize = std::env::args().nth(1).and_then(|a| a.parse().ok()).unwrap_or(1);
    let verbose = std::env::var_os("VERBOSE").is_some();
    let parse_only_mode = std::env::var_os("PARSE_ONLY").is_some();
    let files: Vec<String> = io::stdin().lock().lines().map(Result::unwrap).collect();
    let next = AtomicUsize::new(0);
    let (bytes, invalid, errors) = (AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0));
    let t0 = Instant::now();
    std::thread::scope(|s| {
        for _ in 0..nthreads {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= files.len() {
                    break;
                }
                let data = std::fs::read(&files[i]).unwrap();
                bytes.fetch_add(data.len(), Ordering::Relaxed);
                let (n, msgs) = if parse_only_mode { (parse_only(&data), vec![]) } else { validate(&data, verbose) };
                if n > 0 {
                    invalid.fetch_add(1, Ordering::Relaxed);
                    errors.fetch_add(n, Ordering::Relaxed);
                    println!("INVALID {} {}", files[i], n);
                    for m in msgs {
                        println!("  {m}");
                    }
                }
            });
        }
    });
    let secs = t0.elapsed().as_secs_f64();
    let b = bytes.into_inner();
    println!(
        "validator={} threads={nthreads} files={} bytes={b} invalid_files={} errors={} \
         dtd_load_s=0.000 seconds={secs:.3} files_per_s={:.0} MB_per_s={:.1}",
        if parse_only_mode { "parse-only-rust" } else { "compiled-rust" },
        files.len(),
        invalid.into_inner(),
        errors.into_inner(),
        files.len() as f64 / secs,
        b as f64 / secs / 1e6
    );
}
