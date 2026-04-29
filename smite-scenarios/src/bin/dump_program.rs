//! Pretty-print a serialized smite_ir::Program for debugging.
//!
//! Used to inspect AFL-saved inputs (queue entries, hangs, crashes) and
//! understand what message sequence the fuzzer encoded — useful when
//! triaging hangs that result from semantically-wrong-but-structurally-valid
//! mutations.
//!
//! Usage:
//!   cargo run --release --bin dump_program -- <path-to-input.bin>

use smite_ir::Program;

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: dump_program <file>");
    let bytes = std::fs::read(&path).expect("read input");
    println!("bytes: {}", bytes.len());
    match postcard::from_bytes::<Program>(&bytes) {
        Ok(p) => {
            println!("instructions: {}", p.instructions.len());
            print!("{}", p);
        }
        Err(e) => println!("decode failed: {:?}", e),
    }
}
