//! Bootstrap configuration for creating a singleton AccountStateV1.
//!
//! The state cell is created once and is the root of the account's identity.
//! A configuration mistake here is not recoverable by editing a file later, so
//! these tests pin the checks that must fail closed.

use ckb_account_host::config::AccountStateConfig;
use ckb_account_protocol::*;

fn p256_aux() -> String {
    // profile 0x01 || rp_id_hash[32] || origin_hash[32]
    format!("0x01{}{}", "33".repeat(32), "44".repeat(32))
}

fn config_json(overrides: &str) -> String {
    format!(
        r#"{{
          "flags": 1,
          "sequence": 0,
          "spend_threshold": 1,
          "rotate_threshold": 1,
          "recovery_threshold": 1,
          "recovery_since": 0,
          "authenticators": [
            {{
              "slot": 0,
              "algorithm_id": 1,
              "capabilities": 7,
              "weight": 1,
              "verifier_hash_type": 0,
              "verifier_abi": 1,
              "verifier_code_hash": "0x{code_hash}",
              "key_id": "0x{key_id}",
              "aux": "{aux}"
            }}
          ]
          {overrides}
        }}"#,
        code_hash = "37".repeat(32),
        key_id = "22".repeat(32),
        aux = p256_aux(),
    )
}

fn parse(json: &str) -> Result<AccountStateConfig, String> {
    serde_json::from_str::<AccountStateConfig>(json).map_err(|error| error.to_string())
}

#[test]
fn a_valid_p256_config_encodes_to_state_bytes_the_protocol_accepts() {
    let config = parse(&config_json("")).expect("config parses");
    let encoded = config.encode().expect("config encodes");

    let (header, _) = validate_state(&encoded).expect("encoded state must re-parse");
    assert_eq!(header.sequence, 0);
    assert_eq!(header.spend_threshold, 1);
    assert_eq!(
        header.flags & STATE_FLAG_RECOVERY_ENABLED,
        STATE_FLAG_RECOVERY_ENABLED
    );

    let mut slots = Vec::new();
    parse_authenticators(&encoded, &header, |entry| {
        slots.push(entry.slot);
        Ok(())
    })
    .expect("authenticators parse");
    assert_eq!(slots, vec![0]);
}

#[test]
fn a_spend_threshold_above_total_weight_is_rejected() {
    // An account whose spend threshold can never be met is permanently
    // unspendable, and the state cell cannot be edited after creation.
    let json = config_json("").replace(r#""spend_threshold": 1"#, r#""spend_threshold": 2"#);
    let config = parse(&json).expect("config parses");

    let error = config
        .encode()
        .expect_err("must refuse an unsatisfiable threshold");
    assert!(
        error.to_string().contains("spend"),
        "error should name the offending threshold, got: {error}"
    );
}

#[test]
fn a_rotation_threshold_above_total_rotate_weight_is_rejected() {
    let json = config_json("").replace(r#""rotate_threshold": 1"#, r#""rotate_threshold": 9"#);
    let config = parse(&json).expect("config parses");

    let error = config
        .encode()
        .expect_err("must refuse an unsatisfiable threshold");
    assert!(
        error.to_string().contains("rotate"),
        "error should name the offending threshold, got: {error}"
    );
}

#[test]
fn a_threshold_is_measured_only_against_authenticators_holding_that_capability() {
    // capabilities 0x01 = SPEND only. The rotate threshold of 1 cannot be met
    // even though total weight across all authenticators is 1.
    let json = config_json("").replace(r#""capabilities": 7"#, r#""capabilities": 1"#);
    let config = parse(&json).expect("config parses");

    let error = config
        .encode()
        .expect_err("must refuse an unsatisfiable threshold");
    assert!(
        error.to_string().contains("rotate"),
        "error should name the offending threshold, got: {error}"
    );
}

#[test]
fn a_p256_authenticator_with_wrong_aux_length_is_rejected() {
    // ABI v1 requires exactly 65 aux bytes for algorithm 0x0001.
    let json = config_json("").replace(&p256_aux(), "0x0133");
    let config = parse(&json).expect("config parses");

    let error = config
        .encode()
        .expect_err("must refuse malformed P-256 aux");
    assert!(
        error.to_string().contains("aux"),
        "error should name aux, got: {error}"
    );
}

#[test]
fn recovery_enabled_without_a_recovery_capable_authenticator_is_rejected() {
    let json = config_json("").replace(r#""capabilities": 7"#, r#""capabilities": 3"#);
    let config = parse(&json).expect("config parses");

    let error = config
        .encode()
        .expect_err("must refuse recovery flag with no recovery-capable slot");
    assert!(
        error.to_string().contains("recovery"),
        "error should name recovery, got: {error}"
    );
}

#[test]
fn a_nonzero_initial_sequence_is_rejected() {
    // DEPLOYMENT.md requires the initial state to use sequence 0.
    let json = config_json("").replace(r#""sequence": 0"#, r#""sequence": 5"#);
    let config = parse(&json).expect("config parses");

    let error = config
        .encode()
        .expect_err("must refuse a nonzero initial sequence");
    assert!(
        error.to_string().contains("sequence"),
        "error should name sequence, got: {error}"
    );
}
