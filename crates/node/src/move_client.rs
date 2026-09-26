//! What `thrylos move` builds: signed publish and entry-call transactions, and
//! the command-line spelling of a call's arguments.
//!
//! Presentation and signing only. What a publish or a call may contain is
//! decided by the chain (`chain_exec::publish`, `chain_exec::entry`); the
//! checks here only spare a user a transaction that is certain to abort.

use chain_exec::publish::{publish_gas, MOVE_MODULE_NAME, MOVE_PACKAGE_ADDRESS, PUBLISH};
use chain_text::parse_address;
use chain_types::{
    Address, BlockHeight, ChainId, Encode, GasAmount, GasPrice, MoveCall, PublicKey,
    SequenceNumber, Signature, Transaction, TransactionBody,
};
use ed25519_dalek::{Signer, SigningKey};

/// The gas a call is given unless the user says otherwise: the most nodes accept
/// for a call to a package (`chain_exec::policy`). A call is charged for what it
/// uses, so the full limit costs nothing extra; it only sets the most a runaway
/// function can burn.
pub const DEFAULT_CALL_GAS: u64 = chain_exec::policy::MOVE_CALL_GAS_LIMIT;

#[allow(clippy::too_many_arguments)]
fn sign(
    key: &SigningKey,
    chain_id: u64,
    sequence: u64,
    expiry: u64,
    gas_limit: u64,
    max_fee_per_gas: u64,
    declared_inputs: Vec<Address>,
    call: MoveCall,
) -> Result<Transaction, String> {
    let sender = PublicKey::from_ed25519_bytes(key.verifying_key().to_bytes())
        .map_err(|_| "the signing key is not a valid public key".to_owned())?;
    let body = TransactionBody {
        chain_id: ChainId(chain_id),
        sender,
        sequence_number: SequenceNumber(sequence),
        expiry: BlockHeight(expiry),
        gas_limit: GasAmount(gas_limit),
        max_fee_per_gas: GasPrice(max_fee_per_gas),
        declared_inputs,
        call,
    };
    let mut bytes = Vec::new();
    body.encode(&mut bytes);
    let signature = Signature::from_ed25519_bytes(key.sign(&bytes).to_bytes());
    Ok(Transaction { body, signature })
}

/// A signed publish of `modules` (each one compiled module's bytes), with
/// exactly the gas the chain charges for a package of that size.
pub fn signed_publish(
    key: &SigningKey,
    chain_id: u64,
    sequence: u64,
    expiry: u64,
    modules: Vec<Vec<u8>>,
    max_fee_per_gas: u64,
) -> Result<Transaction, String> {
    let total: usize = modules.iter().map(Vec::len).sum();
    sign(
        key,
        chain_id,
        sequence,
        expiry,
        publish_gas(total),
        max_fee_per_gas,
        Vec::new(),
        MoveCall {
            module_address: Address::from_bytes(MOVE_PACKAGE_ADDRESS),
            module_name: MOVE_MODULE_NAME.as_bytes().to_vec(),
            function_name: PUBLISH.as_bytes().to_vec(),
            type_arguments: Vec::new(),
            arguments: modules,
        },
    )
}

/// A signed call of `package::module::function` with already-encoded arguments.
/// `declared_inputs` are the addresses, besides the sender, whose stored values
/// the call will touch: the chain refuses a call that touches any other.
#[allow(clippy::too_many_arguments)]
pub fn signed_call(
    key: &SigningKey,
    chain_id: u64,
    sequence: u64,
    expiry: u64,
    gas_limit: u64,
    max_fee_per_gas: u64,
    declared_inputs: Vec<Address>,
    package: Address,
    module: &str,
    function: &str,
    arguments: Vec<Vec<u8>>,
) -> Result<Transaction, String> {
    sign(
        key,
        chain_id,
        sequence,
        expiry,
        gas_limit,
        max_fee_per_gas,
        declared_inputs,
        MoveCall {
            module_address: package,
            module_name: module.as_bytes().to_vec(),
            function_name: function.as_bytes().to_vec(),
            type_arguments: Vec::new(),
            arguments,
        },
    )
}

fn uleb128(mut value: usize, out: &mut Vec<u8>) {
    loop {
        let low = u8::try_from(value & 0x7f).unwrap_or(0);
        value >>= 7;
        if value == 0 {
            out.push(low);
            return;
        }
        out.push(low | 0x80);
    }
}

fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    let text = text.strip_prefix("0x").unwrap_or(text);
    if !text.len().is_multiple_of(2) {
        return Err("hex needs an even number of digits".to_owned());
    }
    (0..text.len())
        .step_by(2)
        .map(|at| {
            text.get(at..at.saturating_add(2))
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| "not valid hex".to_owned())
        })
        .collect()
}

/// A decimal number as `width` little-endian bytes, or an error if it does not
/// fit or is not a number.
fn decimal_le(text: &str, width: usize) -> Result<Vec<u8>, String> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("{text:?} is not a whole number"));
    }
    let too_big = || format!("{text} does not fit in {} bits", width.saturating_mul(8));
    let mut bytes = vec![0u8; width];
    for digit in text.bytes() {
        let mut carry = u32::from(digit.saturating_sub(b'0'));
        for byte in &mut bytes {
            // At most 255 * 10 + 9, so this cannot overflow.
            let value = u32::from(*byte).saturating_mul(10).saturating_add(carry);
            *byte = u8::try_from(value & 0xff).unwrap_or(0);
            carry = value >> 8;
        }
        if carry != 0 {
            return Err(too_big());
        }
    }
    Ok(bytes)
}

fn primitive(kind: &str, value: &str) -> Result<Vec<u8>, String> {
    match kind {
        "bool" => match value {
            "true" => Ok(vec![1]),
            "false" => Ok(vec![0]),
            _ => Err("a bool is true or false".to_owned()),
        },
        "u8" => decimal_le(value, 1),
        "u16" => decimal_le(value, 2),
        "u32" => decimal_le(value, 4),
        "u64" => decimal_le(value, 8),
        "u128" => decimal_le(value, 16),
        "u256" => decimal_le(value, 32),
        "address" => parse_address(value)
            .map(|address| address.as_bytes().to_vec())
            .map_err(|error| error.to_string()),
        other => Err(format!(
            "unknown type {other:?}; use bool, u8, u16, u32, u64, u128, u256, address, bytes, string, vec or raw"
        )),
    }
}

/// One argument as written on the command line, `type:value`, encoded the way
/// the chain reads it (BCS):
///
/// - `bool:true`, `u8:7` … `u256:123`, `address:thry1…`
/// - `bytes:0x0a0b` and `string:hello` for a `vector<u8>`
/// - `vec:u64:1,2,3` for a vector of a primitive
/// - `raw:0x…` for bytes you have already encoded
pub fn encode_argument(spec: &str) -> Result<Vec<u8>, String> {
    let (kind, value) = spec
        .split_once(':')
        .ok_or_else(|| format!("{spec:?}: write an argument as type:value, like u64:5"))?;
    let context = |error: String| format!("{spec:?}: {error}");
    match kind {
        "bytes" => {
            let bytes = decode_hex(value).map_err(context)?;
            let mut out = Vec::new();
            uleb128(bytes.len(), &mut out);
            out.extend(bytes);
            Ok(out)
        }
        "string" => {
            let mut out = Vec::new();
            uleb128(value.len(), &mut out);
            out.extend_from_slice(value.as_bytes());
            Ok(out)
        }
        "raw" => decode_hex(value).map_err(context),
        "vec" => {
            let (inner, list) = value
                .split_once(':')
                .ok_or_else(|| context("write a vector as vec:type:a,b,c".to_owned()))?;
            let items: Vec<&str> = if list.is_empty() {
                Vec::new()
            } else {
                list.split(',').collect()
            };
            let mut out = Vec::new();
            uleb128(items.len(), &mut out);
            for item in items {
                out.extend(primitive(inner, item).map_err(context)?);
            }
            Ok(out)
        }
        _ => primitive(kind, value).map_err(context),
    }
}

/// A returned value that could be text: a non-empty list of decimal numbers each
/// under 256 whose bytes are readable UTF-8 (letters, digits, punctuation, spaces and
/// newlines). A `vector<u8>` comes back as such a list, and a person reading a view
/// wants the words; the node does not say which width a vector is, so this is a
/// reading aid, shown beside the list and never instead of it.
pub fn as_text(value: &serde_json::Value) -> Option<String> {
    let items = value.as_array().filter(|items| !items.is_empty())?;
    let bytes = items
        .iter()
        .map(|item| item.as_str()?.parse::<u8>().ok())
        .collect::<Option<Vec<u8>>>()?;
    let text = String::from_utf8(bytes).ok()?;
    text.chars()
        .all(|c| !c.is_control() || c == '\n' || c == '\t')
        .then_some(text)
}

/// A decoded stored value with every `std::string::String` in it shown as its text
/// instead of as a struct holding a list of byte numbers. Anything that is not a
/// readable string is left as it was.
pub fn with_strings_as_text(value: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::Object(fields) => {
            let is_string = fields
                .get("_type")
                .and_then(Value::as_str)
                .is_some_and(|name| name.ends_with("::string::String"));
            if is_string {
                if let Some(text) = fields.get("bytes").and_then(as_text) {
                    return Value::String(text);
                }
            }
            Value::Object(
                fields
                    .iter()
                    .map(|(name, field)| (name.clone(), with_strings_as_text(field)))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.iter().map(with_strings_as_text).collect()),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;
    use chain_text::format_address;

    #[test]
    fn numbers_are_little_endian_at_their_width() {
        assert_eq!(encode_argument("u8:255").unwrap(), [255]);
        assert_eq!(encode_argument("u16:258").unwrap(), [2, 1]);
        assert_eq!(encode_argument("u32:1").unwrap(), [1, 0, 0, 0]);
        assert_eq!(encode_argument("u64:5").unwrap(), 5u64.to_le_bytes());
        assert_eq!(
            encode_argument(&format!("u128:{}", u128::MAX)).unwrap(),
            u128::MAX.to_le_bytes()
        );
        let mut two_to_128 = vec![0u8; 32];
        two_to_128[16] = 1;
        assert_eq!(
            encode_argument("u256:340282366920938463463374607431768211456").unwrap(),
            two_to_128
        );
    }

    #[test]
    fn a_number_that_does_not_fit_or_is_not_a_number_is_refused() {
        for bad in [
            "u8:256",
            "u16:65536",
            "u64:18446744073709551616",
            "u64:-1",
            "u64:",
            "u64:1.5",
            "u64:0x10",
            "u8:one",
        ] {
            assert!(encode_argument(bad).is_err(), "{bad}");
        }
        assert!(encode_argument(&format!("u256:{}0", "9".repeat(78))).is_err());
        assert!(encode_argument(&format!("u256:{}", "9".repeat(77))).is_ok());
    }

    #[test]
    fn booleans_addresses_and_vectors_encode_as_bcs() {
        assert_eq!(encode_argument("bool:true").unwrap(), [1]);
        assert_eq!(encode_argument("bool:false").unwrap(), [0]);
        assert!(encode_argument("bool:yes").is_err());
        let address = Address::from_bytes([7; 32]);
        assert_eq!(
            encode_argument(&format!("address:{}", format_address(&address))).unwrap(),
            vec![7; 32]
        );
        assert!(encode_argument("address:not-an-address").is_err());
        assert_eq!(encode_argument("bytes:0x0a0b").unwrap(), [2, 0x0a, 0x0b]);
        assert_eq!(encode_argument("bytes:").unwrap(), [0]);
        assert!(encode_argument("bytes:abc").is_err());
        assert!(encode_argument("bytes:zz").is_err());
        assert_eq!(encode_argument("string:hi").unwrap(), [2, b'h', b'i']);
        assert_eq!(encode_argument("vec:u8:1,2,3").unwrap(), [3, 1, 2, 3]);
        assert_eq!(encode_argument("vec:u16:").unwrap(), [0]);
        assert_eq!(encode_argument("vec:u16:1,2").unwrap(), [2, 1, 0, 2, 0]);
        assert_eq!(encode_argument("raw:0x0102").unwrap(), [1, 2]);
    }

    #[test]
    fn a_vector_longer_than_127_uses_a_two_byte_length() {
        let list = vec!["1"; 200].join(",");
        let encoded = encode_argument(&format!("vec:u8:{list}")).unwrap();
        assert_eq!(&encoded[..2], [0xc8, 0x01]);
        assert_eq!(encoded.len(), 202);
    }

    #[test]
    fn malformed_specs_are_refused_with_the_spec_in_the_message() {
        for bad in ["5", "u64", "float:1.0", "vec:u64", "vec:nope:1"] {
            let error = encode_argument(bad).unwrap_err();
            assert!(
                error.contains(bad) || error.contains("unknown type"),
                "{bad}: {error}"
            );
        }
    }

    #[test]
    fn a_publish_carries_the_modules_and_exactly_the_gas_it_is_charged() {
        let key = SigningKey::from_bytes(&[3; 32]);
        let modules = vec![vec![1u8; 100], vec![2u8; 50]];
        let tx = signed_publish(&key, 1, 4, 100, modules.clone(), 2).unwrap();
        assert_eq!(tx.body.call.arguments, modules);
        assert_eq!(tx.body.gas_limit.0, publish_gas(150));
        assert_eq!(tx.body.sequence_number.0, 4);
        assert_eq!(
            tx.body.call.module_address.as_bytes(),
            &MOVE_PACKAGE_ADDRESS
        );
        assert!(tx.verify_signature().is_ok());
    }

    #[test]
    fn a_call_names_its_function_and_is_signed() {
        let key = SigningKey::from_bytes(&[3; 32]);
        let package = Address::from_bytes([9; 32]);
        let tx = signed_call(
            &key,
            1,
            0,
            100,
            DEFAULT_CALL_GAS,
            2,
            vec![Address::from_bytes([5; 32])],
            package,
            "demo",
            "run",
            vec![vec![1]],
        )
        .unwrap();
        assert_eq!(tx.body.declared_inputs, vec![Address::from_bytes([5; 32])]);
        assert_eq!(tx.body.call.module_address, package);
        assert_eq!(tx.body.call.module_name, b"demo");
        assert_eq!(tx.body.call.function_name, b"run");
        assert_eq!(tx.body.call.arguments, vec![vec![1u8]]);
        assert!(tx.verify_signature().is_ok());
    }

    #[test]
    fn a_list_of_bytes_that_reads_as_text_is_shown_as_text_and_nothing_else_is() {
        use serde_json::json;
        assert_eq!(as_text(&json!(["72", "105"])).as_deref(), Some("Hi"));
        assert_eq!(
            as_text(&json!(["104", "195", "169"])).as_deref(),
            Some("h\u{e9}")
        );
        assert_eq!(as_text(&json!([])), None, "nothing to read");
        assert_eq!(as_text(&json!(["300"])), None, "not a byte");
        assert_eq!(as_text(&json!(["1", "2"])), None, "control characters");
        assert_eq!(as_text(&json!(["255", "254"])), None, "not UTF-8");
        assert_eq!(as_text(&json!("72")), None, "not a list");
        assert_eq!(as_text(&json!([["72"]])), None, "a list of lists");
    }

    #[test]
    fn a_string_inside_a_stored_value_is_shown_as_its_text() {
        use serde_json::json;
        let stored = json!({
            "_type": "0x9::guestbook::Entry",
            "author": "thry1abc",
            "message": {"_type": "0x1::string::String", "bytes": ["72", "105"]},
            "others": [{"_type": "0x1::string::String", "bytes": ["79", "75"]}],
        });
        let shown = with_strings_as_text(&stored);
        assert_eq!(shown["message"], json!("Hi"));
        assert_eq!(shown["others"][0], json!("OK"));
        assert_eq!(shown["author"], json!("thry1abc"));
        // Bytes that are not text stay as they were.
        let odd = json!({"_type": "0x1::string::String", "bytes": ["1"]});
        assert_eq!(with_strings_as_text(&odd), odd);
    }
}
