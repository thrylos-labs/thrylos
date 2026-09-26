//! Not a fuzz target: measures nanoseconds per unit of gas over a few thousand
//! random protocol calls, the number `metering_ratio`'s ceiling is set from.
//!
//! ```text
//! cd fuzz && RUSTFLAGS="-C debug-assertions" cargo run --release --bin measure_ratio
//! ```

mod protocol_support;

fn main() {
    let mut state = 0x9e3779b97f4a7c15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut ratios: Vec<u128> = Vec::new();
    let mut gases: Vec<u64> = Vec::new();
    for _ in 0..3000 {
        let len = 1 + (next() % 96) as usize;
        let input: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        let (executed, elapsed) = protocol_support::execute(&input);
        let gas = u128::from(executed.gas_used.max(1));
        ratios.push(elapsed.as_nanos() / gas);
        gases.push(executed.gas_used);
    }
    ratios.sort_unstable();
    gases.sort_unstable();
    let p = |q: f64| ratios[((ratios.len() - 1) as f64 * q) as usize];
    println!(
        "ns/gas: p50 {} p90 {} p99 {} max {}  | gas: min {} median {} max {}",
        p(0.5), p(0.9), p(0.99), ratios[ratios.len() - 1],
        gases[0], gases[gases.len() / 2], gases[gases.len() - 1]
    );
}
