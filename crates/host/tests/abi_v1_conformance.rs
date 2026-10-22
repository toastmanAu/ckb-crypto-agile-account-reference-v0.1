//! Cross-package conformance against the frozen `ckb-account-verifier-abi-v1`
//! vector set.
//!
//! The ABI package publishes the consensus-candidate request format as data
//! (one positive structural vector plus sixteen named mutations). Nothing
//! mechanically checked that this implementation still agrees with it, so the
//! two could drift apart silently. These tests close that gap.
//!
//! The vectors are mirrored under `vectors/abi-v1/`; see the `PROVENANCE.md`
//! file there for their origin and update procedure.
//!
//! Scope note: a mutation is only asserted against the layer that actually owns
//! its rejection. Eleven mutations corrupt the request *framing* and are owned
//! by `VerifierRequest::parse`. The remaining five are cross-checks against
//! AccountState or cryptographic facts that the framing parser cannot see; they
//! are enumerated in `DEFERRED_MUTATIONS` with the reason, and
//! `every_negative_vector_is_classified` fails if the published set ever grows
//! a mutation that appears in neither list.

use ckb_account_host::encode_verifier_request;
use ckb_account_protocol::*;
use serde::Deserialize;
use std::{fs, path::PathBuf};

/// Mutations that corrupt request framing. `VerifierRequest::parse` must reject
/// every one of these on bytes alone.
const FRAMING_MUTATIONS: &[&str] = &[
    "magic",
    "abi_version",
    "flags",
    "header_len",
    "reserved0",
    "reserved1",
    "aux_length",
    "proof_length",
    "trailing",
    "operation",
    "eof",
];

/// Mutations the framing parser provably cannot own, with the layer that does.
const DEFERRED_MUTATIONS: &[(&str, &str)] = &[
    (
        "slot",
        "cross-check against the AccountState-selected slot; AccountLock copies \
         AuthenticatorEntryV1::slot into the request, so the parser never sees a \
         mismatch",
    ),
    (
        "algorithm",
        "cross-check against the AccountState entry algorithm_id; requires the \
         resolved authenticator, which the framing parser does not receive",
    ),
    (
        "key",
        "CKB_HASH(public key) != key_id is a verifier-side cryptographic check \
         (ABI exit 5 KEY_ID_MISMATCH)",
    ),
    (
        "digest",
        "a proof valid for a different authorization_digest is structurally \
         well-formed; only signature verification rejects it (ABI exit 1)",
    ),
    (
        "profile",
        "verifier_profile support is defined per algorithm implementation; the \
         framing parser accepts any profile byte by design (ABI exit 4)",
    ),
];

fn vector_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/abi-v1")
}

fn hex_bytes(value: &str) -> Vec<u8> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    hex::decode(trimmed).unwrap_or_else(|error| panic!("decode hex {value}: {error}"))
}

fn operation_code(name: &str) -> u8 {
    match name {
        "SPEND" => OP_SPEND,
        "ROTATE" => OP_ROTATE,
        "RECOVERY" => OP_RECOVERY,
        other => panic!("unknown operation name in vector: {other}"),
    }
}

#[derive(Debug, Deserialize)]
struct StructVector {
    id: String,
    expected: String,
    algorithm_id: String,
    slot: u16,
    operation: String,
    verifier_profile: u8,
    authorization_digest_hex: String,
    key_id_hex: String,
    aux_hex: String,
    proof_hex: String,
    request_hex: String,
    request_len: usize,
}

#[derive(Debug, Deserialize)]
struct NegativeVector {
    id: String,
    base: String,
    mutation: String,
    expected: String,
}

fn read_vector<T: serde::de::DeserializeOwned>(name: &str) -> T {
    let path = vector_dir().join(name);
    let bytes =
        fs::read(&path).unwrap_or_else(|error| panic!("read vector {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("parse vector {}: {error}", path.display()))
}

fn negative_vectors() -> Vec<NegativeVector> {
    let dir = vector_dir();
    let mut names = fs::read_dir(&dir)
        .unwrap_or_else(|error| panic!("read vector dir {}: {error}", dir.display()))
        .map(|entry| entry.expect("vector dir entry").file_name())
        .filter_map(|name| name.to_str().map(str::to_owned))
        .filter(|name| name.starts_with("ABI-V1-NEG-") && name.ends_with(".json"))
        .collect::<Vec<_>>();
    names.sort();
    names.iter().map(|name| read_vector(name)).collect()
}

fn base_vector() -> StructVector {
    read_vector("ABI-V1-STRUCT-001.json")
}

/// Applies the named mutation to the frozen base request.
///
/// Returns `None` for mutations this layer does not own, so a silent typo in a
/// mutation name cannot masquerade as a passing rejection test.
fn apply_framing_mutation(mutation: &str, base: &[u8]) -> Option<Vec<u8>> {
    let mut out = base.to_vec();
    match mutation {
        "magic" => out[0] ^= 0xff,
        "abi_version" => out[4] = 0x02,
        "flags" => out[5] = 0x01,
        "header_len" => out[6..8].copy_from_slice(&97u16.to_le_bytes()),
        "reserved0" => out[14] = 0x01,
        "reserved1" => out[88] = 0x01,
        "aux_length" => {
            let over = u32::try_from(VERIFIER_MAX_AUX_LEN + 1).expect("aux bound fits u32");
            out[80..84].copy_from_slice(&over.to_le_bytes());
        }
        "proof_length" => {
            let over = u32::try_from(VERIFIER_MAX_PROOF_LEN + 1).expect("proof bound fits u32");
            out[84..88].copy_from_slice(&over.to_le_bytes());
        }
        "trailing" => out.push(0x00),
        "operation" => out[12] = 0x09,
        "eof" => {
            out.pop();
        }
        _ => return None,
    }
    Some(out)
}

#[test]
fn host_encoder_reproduces_the_frozen_struct_vector_byte_for_byte() {
    let vector = base_vector();
    assert_eq!(vector.id, "ABI-V1-STRUCT-001");
    assert_eq!(vector.expected, "accept_structure");

    let algorithm_id = u16::from_str_radix(
        vector
            .algorithm_id
            .strip_prefix("0x")
            .unwrap_or(&vector.algorithm_id),
        16,
    )
    .expect("algorithm_id hex");
    let digest: [u8; 32] = hex_bytes(&vector.authorization_digest_hex)
        .try_into()
        .expect("digest is 32 bytes");
    let key_id: [u8; 32] = hex_bytes(&vector.key_id_hex)
        .try_into()
        .expect("key_id is 32 bytes");

    let encoded = encode_verifier_request(
        algorithm_id,
        vector.slot,
        operation_code(&vector.operation),
        vector.verifier_profile,
        &digest,
        &key_id,
        &hex_bytes(&vector.aux_hex),
        &hex_bytes(&vector.proof_hex),
    )
    .expect("host encoder accepts the frozen vector inputs");

    assert_eq!(
        hex::encode(&encoded),
        hex::encode(hex_bytes(&vector.request_hex)),
        "host encoder output diverged from the frozen ABI v1 request bytes"
    );
    assert_eq!(encoded.len(), vector.request_len);
}

#[test]
fn framing_parser_accepts_the_frozen_struct_vector_and_recovers_its_fields() {
    let vector = base_vector();
    let request = hex_bytes(&vector.request_hex);

    let parsed = VerifierRequest::parse(&request).expect("frozen struct vector must parse");

    assert_eq!(parsed.slot, vector.slot);
    assert_eq!(parsed.operation, operation_code(&vector.operation));
    assert_eq!(parsed.verifier_profile, vector.verifier_profile);
    assert_eq!(
        parsed.authorization_digest.as_slice(),
        hex_bytes(&vector.authorization_digest_hex)
    );
    assert_eq!(parsed.key_id.as_slice(), hex_bytes(&vector.key_id_hex));
    assert_eq!(parsed.aux, hex_bytes(&vector.aux_hex));
    assert_eq!(parsed.proof, hex_bytes(&vector.proof_hex));
}

#[test]
fn framing_parser_rejects_every_framing_mutation_vector() {
    let vector = base_vector();
    let base = hex_bytes(&vector.request_hex);
    let mut checked = 0usize;

    for negative in negative_vectors() {
        if !FRAMING_MUTATIONS.contains(&negative.mutation.as_str()) {
            continue;
        }
        assert_eq!(negative.base, "ABI-V1-STRUCT-001", "{}", negative.id);
        assert_eq!(negative.expected, "reject", "{}", negative.id);

        let mutated = apply_framing_mutation(&negative.mutation, &base)
            .unwrap_or_else(|| panic!("{} declares an unhandled mutation", negative.id));
        assert_ne!(
            mutated, base,
            "{} produced no byte change; the rejection below would be vacuous",
            negative.id
        );
        assert!(
            VerifierRequest::parse(&mutated).is_err(),
            "{} ({}) was accepted by the framing parser",
            negative.id,
            negative.mutation
        );
        checked += 1;
    }

    assert_eq!(
        checked,
        FRAMING_MUTATIONS.len(),
        "not every framing mutation was present in the published vector set"
    );
}

#[test]
fn every_negative_vector_is_classified() {
    let negatives = negative_vectors();
    assert_eq!(
        negatives.len(),
        FRAMING_MUTATIONS.len() + DEFERRED_MUTATIONS.len(),
        "published negative-vector count changed; classify the new vectors"
    );

    for negative in &negatives {
        let framing = FRAMING_MUTATIONS.contains(&negative.mutation.as_str());
        let deferred = DEFERRED_MUTATIONS
            .iter()
            .any(|(name, _)| *name == negative.mutation);
        assert!(
            framing ^ deferred,
            "{} mutation '{}' must be classified in exactly one list",
            negative.id,
            negative.mutation
        );
    }
}
