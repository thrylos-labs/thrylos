#![no_main]

mod protocol_support;

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;

fn limit_ns_per_gas() -> u128 {
    static LIMIT: OnceLock<u128> = OnceLock::new();
    *LIMIT.get_or_init(|| {
        std::env::var("THRYLOS_MAX_NS_PER_GAS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(1_000_000)
    })
}

#[inline(never)]
fn ratio_bucket(bucket: u8) {
    // Branch coverage makes inputs that reach a new, slower ratio bucket
    // interesting to libFuzzer. This turns time per charged gas into the
    // search objective while the hard ceiling remains an ordinary finding.
    match bucket {
        0 => std::hint::black_box(()),
        1 => std::hint::black_box(()),
        2 => std::hint::black_box(()),
        3 => std::hint::black_box(()),
        4 => std::hint::black_box(()),
        5 => std::hint::black_box(()),
        6 => std::hint::black_box(()),
        _ => std::hint::black_box(()),
    }
}

fuzz_target!(|input: &[u8]| {
    let (executed, elapsed) = protocol_support::execute(input);
    let gas = u128::from(executed.gas_used.max(1));
    let ratio = elapsed.as_nanos().saturating_div(gas);
    let bucket = if ratio == 0 {
        0
    } else {
        u8::try_from(ratio.ilog2()).unwrap_or(u8::MAX).min(7)
    };
    ratio_bucket(bucket);
    assert!(
        ratio <= limit_ns_per_gas(),
        "protocol call used {ratio} ns/gas, above the configured {} ns/gas ceiling",
        limit_ns_per_gas()
    );
});
