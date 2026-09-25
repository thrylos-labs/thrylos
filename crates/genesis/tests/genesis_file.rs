//! The genesis file format: what it accepts, and — as much — what it
//! refuses.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::integer_division,
    clippy::arithmetic_side_effects
)]

use chain_exec::genesis_config::{Allocation, GenesisConfig, GenesisConfigError, GenesisValidator};
use chain_genesis::check::{report, warnings, Warning};
use chain_genesis::{devnet, load, parse, to_json, ParseError, MAX_FILE_BYTES};
use chain_modules::params::GENESIS_PARAM_VALUES;
use chain_types::{Address, ChainId, PublicKey};
use serde_json::{json, Value};

const DEVNET_FILE: &str = include_str!("../examples/devnet.json");

fn devnet_value() -> Value {
    serde_json::from_str(DEVNET_FILE).unwrap()
}

fn parse_value(value: &Value) -> Result<GenesisConfig, ParseError> {
    parse(&value.to_string())
}

fn message(result: Result<GenesisConfig, ParseError>) -> String {
    result.unwrap_err().to_string()
}

// ---- the example is the truth --------------------------------------------

#[test]
fn the_checked_in_devnet_file_is_exactly_what_the_generator_produces() {
    // A golden file: if the format, the canonical order or the devnet
    // parameters change, this fails until the example is regenerated with
    // `cargo run -p chain-genesis -- devnet`.
    let generated = to_json(&devnet::config().unwrap()).unwrap();
    assert_eq!(DEVNET_FILE, format!("{generated}\n"));
}

#[test]
fn the_devnet_file_parses_to_the_devnet_configuration() {
    assert_eq!(parse(DEVNET_FILE).unwrap(), devnet::config().unwrap());
}

#[test]
fn the_devnet_chain_can_be_built_and_reported_on() {
    let config = parse(DEVNET_FILE).unwrap();
    let report = report(&config).unwrap();
    assert_eq!(report.chain_id, devnet::DEVNET_CHAIN_ID);
    assert_eq!(report.genesis_hash, config.hash());
    assert_eq!(report.total_supply, config.total_supply());
    assert_eq!(report.validators.len(), 4);
    assert_eq!(report.allocation_count, 4);
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
}

// ---- round trips -----------------------------------------------------------

#[test]
fn a_configuration_survives_being_written_and_read_back() {
    let config = devnet::config().unwrap();
    let json = to_json(&config).unwrap();
    let back = parse(&json).unwrap();
    assert_eq!(back, config);
    assert_eq!(back.hash(), config.hash());
    assert_eq!(
        to_json(&back).unwrap(),
        json,
        "and writing it again is identical"
    );
}

#[test]
fn the_order_of_entries_in_a_file_does_not_change_the_genesis() {
    let mut value = devnet_value();
    value["allocations"].as_array_mut().unwrap().reverse();
    value["validators"].as_array_mut().unwrap().reverse();
    assert_eq!(
        parse_value(&value).unwrap().hash(),
        devnet::config().unwrap().hash()
    );
}

#[test]
fn hex_may_be_upper_case_and_prefixed() {
    let mut value = devnet_value();
    for allocation in value["allocations"].as_array_mut().unwrap() {
        let key = allocation["public_key"].as_str().unwrap().to_uppercase();
        allocation["public_key"] = json!(format!("0x{key}"));
    }
    assert_eq!(parse_value(&value).unwrap(), devnet::config().unwrap());
}

#[test]
fn amounts_up_to_the_largest_u128_are_accepted_as_strings() {
    // Not a valid genesis (the supply overflows), but the *amount* parses:
    // the refusal is the configuration's, not the parser's.
    let mut value = devnet_value();
    value["allocations"][0]["amount"] = json!(u128::MAX.to_string());
    let err = parse_value(&value).unwrap_err();
    assert!(matches!(
        err,
        ParseError::Genesis(GenesisConfigError::SupplyOverflow)
    ));
}

// ---- strictness: shape -----------------------------------------------------

#[test]
fn an_unknown_field_anywhere_is_refused() {
    for path in [
        vec![],
        vec!["parameters"],
        vec!["allocations", "0"],
        vec!["validators", "0"],
    ] {
        let mut value = devnet_value();
        let mut node = &mut value;
        for step in &path {
            node = match step.parse::<usize>() {
                Ok(index) => &mut node[index],
                Err(_) => &mut node[*step],
            };
        }
        node["surprise"] = json!(1);
        let text = message(parse_value(&value));
        assert!(text.contains("unknown field"), "{path:?}: {text}");
    }
}

#[test]
fn every_field_is_required() {
    let mut top = vec![
        "chain_id",
        "genesis_time_ms",
        "parameters",
        "allocations",
        "validators",
    ];
    top.sort_unstable();
    for field in top {
        let mut value = devnet_value();
        value.as_object_mut().unwrap().remove(field);
        let text = message(parse_value(&value));
        assert!(text.contains("missing field"), "{field}: {text}");
    }
    for field in [
        "max_block_gas",
        "base_fee_change_denominator",
        "min_self_stake",
        "inflation_bps",
        "unbonding_period_ms",
        "quorum_bps",
        "veto_threshold_bps",
        "publish_enabled",
    ] {
        let mut value = devnet_value();
        value["parameters"].as_object_mut().unwrap().remove(field);
        let text = message(parse_value(&value));
        assert!(text.contains("missing field"), "parameters.{field}: {text}");
    }
    for field in ["public_key", "amount"] {
        let mut value = devnet_value();
        value["allocations"][0]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(
            message(parse_value(&value)).contains("missing field"),
            "{field}"
        );
    }
    for field in [
        "operator_public_key",
        "consensus_key",
        "proof_of_possession",
        "self_stake",
    ] {
        let mut value = devnet_value();
        value["validators"][0]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(
            message(parse_value(&value)).contains("missing field"),
            "{field}"
        );
    }
}

#[test]
fn a_repeated_key_is_refused_rather_than_the_last_one_winning() {
    let text = DEVNET_FILE.replacen(
        "\"chain_id\": 1337,",
        "\"chain_id\": 1337,\n  \"chain_id\": 1338,",
        1,
    );
    assert!(parse(&text)
        .unwrap_err()
        .to_string()
        .contains("duplicate field"));
}

#[test]
fn text_that_is_not_exactly_one_json_object_is_refused() {
    for text in [
        "",
        "   ",
        "not json",
        "[]",
        "null",
        "{}",
        &format!("{DEVNET_FILE} trailing"),
        &format!("{DEVNET_FILE}{DEVNET_FILE}"),
        &DEVNET_FILE[..DEVNET_FILE.len() / 2],
    ] {
        assert!(parse(text).is_err(), "accepted: {:.40?}", text);
    }
}

#[test]
fn a_number_too_big_for_its_field_is_refused() {
    // As raw text: a JSON value cannot even hold a number this large.
    let too_big = DEVNET_FILE.replacen(
        "\"genesis_time_ms\": 1700000000000",
        "\"genesis_time_ms\": 18446744073709551616",
        1,
    );
    assert!(parse(&too_big).is_err());
    let largest = DEVNET_FILE.replacen(
        "\"genesis_time_ms\": 1700000000000",
        "\"genesis_time_ms\": 18446744073709551615",
        1,
    );
    assert_eq!(parse(&largest).unwrap().genesis_time_ms(), u64::MAX);
}

#[test]
fn numbers_must_be_integers_of_the_right_kind() {
    for (field, bad) in [
        ("chain_id", json!("1337")),
        ("chain_id", json!(1337.5)),
        ("chain_id", json!(-1)),
        ("chain_id", json!(1e3)),
        ("chain_id", json!(null)),
        ("genesis_time_ms", json!("1700000000000")),
    ] {
        let mut value = devnet_value();
        value[field] = bad.clone();
        assert!(parse_value(&value).is_err(), "{field} = {bad}");
    }
}

// ---- strictness: amounts ---------------------------------------------------

#[test]
fn an_amount_is_base_ten_digits_in_a_string_and_nothing_else() {
    for bad in [
        json!(1000),
        json!(1000.0),
        json!(null),
        json!(""),
        json!("+5"),
        json!("-5"),
        json!(" 5"),
        json!("5 "),
        json!("1_000"),
        json!("1,000"),
        json!("0x10"),
        json!("1e3"),
        json!("007"),
        json!("5.0"),
        json!("340282366920938463463374607431768211456"),
    ] {
        let mut value = devnet_value();
        value["allocations"][0]["amount"] = bad.clone();
        assert!(parse_value(&value).is_err(), "accepted amount {bad}");
    }
    // The reasons an operator reads are specific.
    for (bad, reason) in [
        ("", "an amount is empty"),
        ("+5", "digits only"),
        ("007", "no leading zeros"),
        ("340282366920938463463374607431768211456", "does not fit"),
    ] {
        let mut value = devnet_value();
        value["allocations"][0]["amount"] = json!(bad);
        let text = message(parse_value(&value));
        assert!(text.contains(reason), "{bad:?}: {text}");
    }
    // The good ones, for contrast.
    for good in ["1", "10", "1000000000000"] {
        let mut value = devnet_value();
        value["allocations"][0]["amount"] = json!(good);
        parse_value(&value).unwrap();
    }
}

// ---- strictness: hex and keys ----------------------------------------------

#[test]
fn keys_are_the_exact_length_and_all_hex() {
    let good = devnet_value()["allocations"][0]["public_key"]
        .as_str()
        .unwrap()
        .to_owned();
    for bad in [
        good[..good.len() - 1].to_owned(),
        good[..good.len() - 2].to_owned(),
        format!("{good}00"),
        format!("{good}0"),
        format!("{}g", &good[..good.len() - 1]),
        format!(" {good}"),
        format!("{good}\n"),
        String::new(),
        "0x".to_owned(),
    ] {
        let mut value = devnet_value();
        value["allocations"][0]["public_key"] = json!(bad);
        assert!(parse_value(&value).is_err(), "accepted {bad:?}");
    }
}

/// 32 bytes that are not a valid Ed25519 point.
fn not_a_point() -> [u8; 32] {
    (0u8..=255)
        .map(|b| [b; 32])
        .find(|candidate| PublicKey::from_ed25519_bytes(*candidate).is_err())
        .expect("some repeated byte is off the curve")
}

#[test]
fn a_public_key_that_is_not_a_curve_point_is_refused_and_says_where() {
    let bytes = not_a_point();
    let text = chain_genesis::hex::encode(&bytes);

    let mut value = devnet_value();
    value["allocations"][2]["public_key"] = json!(text.clone());
    assert_eq!(
        message(parse_value(&value)),
        "allocations[2].public_key: not a valid Ed25519 public key"
    );

    let mut value = devnet_value();
    value["validators"][1]["operator_public_key"] = json!(text);
    assert_eq!(
        message(parse_value(&value)),
        "validators[1].operator_public_key: not a valid Ed25519 public key"
    );
}

#[test]
fn a_bls_key_or_proof_that_is_not_valid_is_refused_and_says_where() {
    let mut value = devnet_value();
    value["validators"][0]["consensus_key"] = json!("00".repeat(48));
    assert_eq!(
        message(parse_value(&value)),
        "validators[0].consensus_key: not a valid BLS12-381 public key"
    );

    let mut value = devnet_value();
    value["validators"][3]["proof_of_possession"] = json!("00".repeat(96));
    assert_eq!(
        message(parse_value(&value)),
        "validators[3].proof_of_possession: not a valid BLS12-381 signature"
    );
}

// ---- strictness: what the file describes -----------------------------------

#[test]
fn a_proof_of_possession_belonging_to_another_validator_is_refused_by_account() {
    let mut value = devnet_value();
    let other = value["validators"][1]["proof_of_possession"].clone();
    value["validators"][0]["proof_of_possession"] = other;
    let err = parse_value(&value).unwrap_err();
    assert!(matches!(
        err,
        ParseError::Genesis(GenesisConfigError::InvalidProofOfPossession { .. })
    ));
    let text = err.to_string();
    assert!(text.contains("proof of possession"), "{text}");
    assert!(text.contains("account "), "names the account: {text}");
}

#[test]
fn the_configurations_own_rules_surface_through_the_file() {
    // No validators.
    let mut value = devnet_value();
    value["validators"] = json!([]);
    assert!(matches!(
        parse_value(&value),
        Err(ParseError::Genesis(GenesisConfigError::NoValidators))
    ));

    // A parameter outside its clamp.
    let mut value = devnet_value();
    value["parameters"]["inflation_bps"] = json!(9_999);
    assert!(matches!(
        parse_value(&value),
        Err(ParseError::Genesis(GenesisConfigError::Parameters(_)))
    ));

    // A self-stake under the minimum.
    let mut value = devnet_value();
    value["validators"][0]["self_stake"] = json!("999999");
    assert!(matches!(
        parse_value(&value),
        Err(ParseError::Genesis(
            GenesisConfigError::SelfStakeBelowMinimum { .. }
        ))
    ));

    // The same account allocated to twice.
    let mut value = devnet_value();
    let first = value["allocations"][0].clone();
    value["allocations"].as_array_mut().unwrap().push(first);
    assert!(matches!(
        parse_value(&value),
        Err(ParseError::Genesis(
            GenesisConfigError::DuplicateAllocation { .. }
        ))
    ));

    // An allocation of nothing.
    let mut value = devnet_value();
    value["allocations"][0]["amount"] = json!("0");
    assert!(matches!(
        parse_value(&value),
        Err(ParseError::Genesis(
            GenesisConfigError::ZeroAllocation { .. }
        ))
    ));
}

// ---- load ------------------------------------------------------------------

#[test]
fn a_file_is_read_from_disk() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("genesis.json");
    std::fs::write(&path, DEVNET_FILE).unwrap();
    assert_eq!(load(&path).unwrap(), devnet::config().unwrap());
}

#[test]
fn a_missing_file_or_a_directory_is_an_io_error() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(
        load(&dir.path().join("nope.json")),
        Err(ParseError::Io(_))
    ));
    assert!(matches!(load(dir.path()), Err(ParseError::Io(_))));
}

#[test]
fn a_file_over_the_size_limit_is_refused_without_being_parsed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("huge.json");
    let file = std::fs::File::create(&path).unwrap();
    file.set_len(MAX_FILE_BYTES + 1).unwrap();
    assert!(matches!(load(&path), Err(ParseError::TooLarge)));

    // Exactly at the limit is not too large (though it is not a genesis).
    let file = std::fs::File::create(&path).unwrap();
    file.set_len(MAX_FILE_BYTES).unwrap();
    assert!(matches!(load(&path), Err(ParseError::Json(_))));
}

#[test]
fn a_file_that_is_not_utf8_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("binary.json");
    std::fs::write(&path, [0xFF, 0xFE, 0x00]).unwrap();
    let err = load(&path).unwrap_err();
    assert!(err.to_string().contains("UTF-8"), "{err}");
}

// ---- warnings --------------------------------------------------------------

/// A configuration with validators of the given stakes, in multiples of
/// the minimum self-stake.
fn config_with_stakes(multiples: &[u128]) -> GenesisConfig {
    let min = GENESIS_PARAM_VALUES.min_self_stake;
    let mut validators = Vec::new();
    for (index, multiple) in multiples.iter().enumerate() {
        let seed = u8::try_from(index).unwrap() + 1;
        let (consensus_key, proof_of_possession) = devnet::bls(seed).unwrap();
        validators.push(GenesisValidator {
            operator: devnet::ed25519(seed).unwrap(),
            consensus_key,
            proof_of_possession,
            self_stake: multiple * min,
        });
    }
    GenesisConfig::new(
        ChainId(1),
        0,
        GENESIS_PARAM_VALUES,
        vec![Allocation {
            owner: devnet::ed25519(200).unwrap(),
            amount: 1,
        }],
        validators,
    )
    .unwrap()
}

fn kinds(config: &GenesisConfig) -> (bool, usize, usize) {
    let all = warnings(config);
    (
        all.iter()
            .any(|w| matches!(w, Warning::FewerThanFourValidators { .. })),
        all.iter()
            .filter(|w| matches!(w, Warning::CanHaltTheChain { .. }))
            .count(),
        all.iter()
            .filter(|w| matches!(w, Warning::ControlsFinality { .. }))
            .count(),
    )
}

#[test]
fn four_evenly_staked_validators_draw_no_warning() {
    assert!(warnings(&config_with_stakes(&[1, 1, 1, 1])).is_empty());
}

#[test]
fn a_lone_validator_is_warned_about_on_every_count() {
    assert_eq!(kinds(&config_with_stakes(&[5])), (true, 1, 1));
}

#[test]
fn a_third_of_the_stake_can_halt_the_chain_and_two_thirds_decide_it() {
    // Exactly a third each: three validators, each at the halting line.
    assert_eq!(kinds(&config_with_stakes(&[1, 1, 1])), (true, 3, 0));
    // Just under a third: 99 of 300.
    assert_eq!(kinds(&config_with_stakes(&[99, 100, 101, 100])).1, 0);
    // Over a third but under two thirds.
    assert_eq!(kinds(&config_with_stakes(&[2, 1, 1, 1])), (false, 1, 0));
    // Exactly two thirds: 2 of 3.
    assert_eq!(kinds(&config_with_stakes(&[2, 1])), (true, 2, 1));
    // Just under two thirds: 199 of 299. Neither decides finality alone, and
    // both can halt the chain (the smaller holds 33.4%, over a third).
    let just_under = kinds(&config_with_stakes(&[199, 100]));
    assert_eq!((just_under.1, just_under.2), (2, 0));
}

#[test]
fn the_report_lists_validators_largest_stake_first() {
    let report = report(&config_with_stakes(&[1, 3, 2, 3])).unwrap();
    let stakes: Vec<u128> = report.validators.iter().map(|v| v.self_stake).collect();
    let min = GENESIS_PARAM_VALUES.min_self_stake;
    assert_eq!(stakes, vec![3 * min, 3 * min, 2 * min, min]);
    // Ties are broken by address, ascending, so the order is fixed.
    let tied: Vec<Address> = report.validators[..2].iter().map(|v| v.operator).collect();
    assert!(tied[0] < tied[1]);
    assert_eq!(report.bonded, 9 * min);
}
