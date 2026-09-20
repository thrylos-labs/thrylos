#![no_main]

use chain_state::{apply, compute_root, diff, StateKey, StateValue};
use chain_types::collections::BTreeMap;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let mut reference = BTreeMap::new();
    let mut incremental = BTreeMap::new();

    // Each group is one logical block. The reference mutates a full flat
    // state directly; the incremental path applies only StateDiff. Compare
    // both the entries and the derived root after every block, not just at
    // the end of the input sequence.
    for block in input.chunks(32) {
        let before = reference.clone();
        for operation in block.chunks(4) {
            let Some((&tag, rest)) = operation.split_first() else {
                continue;
            };
            let key = StateKey::new(vec![rest.first().copied().unwrap_or(0)]);
            if tag & 1 == 0 {
                let value = StateValue::new(rest.get(1..).unwrap_or_default().to_vec());
                reference.insert(key, value);
            } else {
                reference.remove(&key);
            }
        }

        let changes = diff(&before, &reference);
        apply(&mut incremental, &changes);

        assert_eq!(incremental, reference);
        assert_eq!(compute_root(&incremental), compute_root(&reference));

        // Reapplying a persisted block diff after interrupted recovery must
        // be idempotent at the flat-state and root layers.
        apply(&mut incremental, &changes);
        assert_eq!(incremental, reference);
        assert_eq!(compute_root(&incremental), compute_root(&reference));
    }
});
