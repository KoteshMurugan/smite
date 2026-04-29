//! Walks a directory of fuzz inputs and reports the postcard decode rate
//! for `smite_ir::Program`.
//!
//! Usage:
//!   cargo run --release --bin decode_rate -- <corpus_dir>
//!
//! Mirrors the match in `dual_funding.rs::run()` lines 157-171: every input
//! is fed through `postcard::from_bytes::<smite_ir::Program>` and tallied as
//! Ok (real IR mutation reaches the executor) or Err (harness falls back to
//! the seeded random generator instead).

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let dir = match args.next() {
        Some(d) => PathBuf::from(d),
        None => {
            eprintln!("usage: decode_rate <corpus_dir>");
            return ExitCode::from(2);
        }
    };

    let entries = match fs::read_dir(&dir) {
        Ok(it) => it,
        Err(e) => {
            eprintln!("failed to read {}: {e}", dir.display());
            return ExitCode::from(1);
        }
    };

    let mut ok = 0u64;
    let mut err = 0u64;
    let mut total_bytes = 0u64;
    let mut ok_bytes = 0u64;

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        total_bytes += bytes.len() as u64;
        match postcard::from_bytes::<smite_ir::Program>(&bytes) {
            Ok(_) => {
                ok += 1;
                ok_bytes += bytes.len() as u64;
            }
            Err(_) => {
                err += 1;
            }
        }
    }

    let total = ok + err;
    if total == 0 {
        eprintln!("no inputs found in {}", dir.display());
        return ExitCode::from(1);
    }

    let pct = |n: u64| (n as f64) * 100.0 / (total as f64);
    println!("corpus_dir   : {}", dir.display());
    println!("total inputs : {total}");
    println!("ok  (decoded): {ok} ({:.2}%)", pct(ok));
    println!("err (fallback): {err} ({:.2}%)", pct(err));
    println!("avg input size : {:.1} B", total_bytes as f64 / total as f64);
    if ok > 0 {
        println!("avg ok size    : {:.1} B", ok_bytes as f64 / ok as f64);
    }

    ExitCode::SUCCESS
}
