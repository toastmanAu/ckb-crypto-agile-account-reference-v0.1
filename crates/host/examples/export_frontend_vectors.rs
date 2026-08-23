//! Emits deterministic JSON vectors for the browser ABI-v1 implementation.

use ckb_account_host::{
    authorization_digest, ckb_hash, encode_p256_proof, encode_state, encode_witness, group_sighash,
    AccountState, Authenticator, Proof,
};
use ckb_account_protocol::{
    parse_proofs, parse_witness_header, validate_state, ALG_P256_WEBAUTHN, CAP_RECOVERY,
    CAP_ROTATE, CAP_SPEND, OP_SPEND, PROFILE_V1, STATE_FLAG_RECOVERY_ENABLED, VERIFIER_ABI_V1,
};
use ckb_types::{bytes::Bytes, packed, prelude::*, H256};
use serde_json::json;
use std::{env, fs, path::PathBuf};

const ORIGIN: &str = "http://localhost:5173";
const RP_ID_HASH: [u8; 32] = [
    0x49, 0x96, 0x0d, 0xe5, 0x88, 0x0e, 0x8c, 0x68, 0x74, 0x34, 0x17, 0x0f, 0x64, 0x76, 0x60, 0x5b,
    0x8f, 0xe4, 0xae, 0xb9, 0xa2, 0x86, 0x32, 0xc7, 0x99, 0x5c, 0xf3, 0xba, 0x83, 0x1d, 0x97, 0x63,
];
const ORIGIN_HASH: [u8; 32] = [
    0x4e, 0x90, 0xec, 0x8f, 0x9d, 0x9b, 0x8d, 0x5b, 0xd3, 0x87, 0x7a, 0xc0, 0x03, 0x79, 0x77, 0x38,
    0xff, 0x48, 0x41, 0x9f, 0xcf, 0x8f, 0x97, 0x82, 0x1a, 0x87, 0x5e, 0xa4, 0x67, 0x19, 0x55, 0xb6,
];
const VERIFIER_CODE_HASH: [u8; 32] = [
    0x37, 0x6a, 0x3e, 0x1b, 0xfe, 0xfc, 0x57, 0xd6, 0x3c, 0xff, 0x2e, 0x5d, 0x02, 0x22, 0x83, 0x80,
    0x0f, 0xb6, 0xb5, 0xf0, 0x14, 0xb5, 0xed, 0xac, 0x4b, 0xe5, 0x73, 0xd5, 0x8a, 0x7b, 0x12, 0x4a,
];

fn hex(bytes: impl AsRef<[u8]>) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn base64url(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::new();
    for chunk in input.chunks(3) {
        let a = u32::from(chunk[0]);
        let b = u32::from(*chunk.get(1).unwrap_or(&0));
        let c = u32::from(*chunk.get(2).unwrap_or(&0));
        let value = (a << 16) | (b << 8) | c;
        output.push(TABLE[((value >> 18) & 63) as usize] as char);
        output.push(TABLE[((value >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            output.push(TABLE[((value >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            output.push(TABLE[(value & 63) as usize] as char);
        }
    }
    output
}

fn main() {
    let output = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("vectors/frontend-v1.json"));

    let mut public_key = [0x11; 65];
    public_key[0] = 0x04;
    let key_id = ckb_hash(&public_key);
    let mut aux = vec![PROFILE_V1];
    aux.extend_from_slice(&RP_ID_HASH);
    aux.extend_from_slice(&ORIGIN_HASH);

    let state = encode_state(&AccountState {
        flags: STATE_FLAG_RECOVERY_ENABLED,
        sequence: 0,
        spend_threshold: 1,
        rotate_threshold: 1,
        recovery_threshold: 1,
        recovery_since: 0,
        authenticators: vec![Authenticator {
            slot: 0,
            algorithm_id: ALG_P256_WEBAUTHN,
            capabilities: CAP_SPEND | CAP_ROTATE | CAP_RECOVERY,
            weight: 1,
            verifier_hash_type: 0,
            verifier_abi: VERIFIER_ABI_V1,
            verifier_code_hash: VERIFIER_CODE_HASH,
            key_id,
            aux: aux.clone(),
        }],
    })
    .expect("canonical P-256 state");
    validate_state(&state).expect("exported state parses");

    let provisional = encode_witness(
        OP_SPEND,
        0,
        &[Proof {
            slot: 0,
            bytes: vec![1],
        }],
    )
    .expect("provisional witness");
    let provisional_args = packed::WitnessArgs::new_builder()
        .lock(Some(Bytes::from(provisional)).pack())
        .build()
        .as_bytes();
    let tx_hash = H256::from([0x77; 32]);
    let group_hash = group_sighash(&tx_hash, &[provisional_args], &[]).expect("group sighash");
    let account_id = [0x88; 32];
    let digest = authorization_digest(OP_SPEND, &account_id, 0, &state, &group_hash)
        .expect("authorization digest");

    let client_data_json = format!(
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"{}\",\"crossOrigin\":false}}",
        base64url(&digest),
        ORIGIN,
    );
    let mut authenticator_data = RP_ID_HASH.to_vec();
    authenticator_data.extend_from_slice(&[0x05, 0, 0, 0, 1]);
    let signature = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
    let p256_proof = encode_p256_proof(
        &public_key,
        ORIGIN.as_bytes(),
        &authenticator_data,
        client_data_json.as_bytes(),
        &signature,
    )
    .expect("P256ProofV1");
    let account_witness = encode_witness(
        OP_SPEND,
        0,
        &[Proof {
            slot: 0,
            bytes: p256_proof.clone(),
        }],
    )
    .expect("AccountWitnessV1");
    let witness_header = parse_witness_header(&account_witness).expect("witness header");
    parse_proofs(&account_witness, &witness_header, |slot, proof| {
        assert_eq!(slot, 0);
        assert_eq!(proof, p256_proof);
        Ok(())
    })
    .expect("witness proofs");
    let packed_witness_args = packed::WitnessArgs::new_builder()
        .lock(Some(Bytes::from(account_witness.clone())).pack())
        .build()
        .as_bytes();
    packed::WitnessArgs::from_slice(&packed_witness_args).expect("packed WitnessArgs");
    assert_eq!(
        group_sighash(&tx_hash, std::slice::from_ref(&packed_witness_args), &[])
            .expect("final sighash"),
        group_hash,
    );
    assert_eq!(
        authorization_digest(OP_SPEND, &account_id, 0, &state, &group_hash)
            .expect("recomputed digest"),
        digest,
    );

    let vector = json!({
        "schema_version": 1,
        "inputs": {
            "operation": OP_SPEND,
            "sequence": "0",
            "public_key": hex(public_key),
            "origin": hex(ORIGIN.as_bytes()),
            "authenticator_data": hex(&authenticator_data),
            "client_data_json": hex(client_data_json.as_bytes()),
            "signature": hex(signature),
            "tx_hash": hex(tx_hash.as_bytes()),
            "account_id": hex(account_id),
        },
        "state": hex(&state),
        "state_hash": hex(ckb_hash(&state)),
        "p256_proof": hex(&p256_proof),
        "account_witness": hex(&account_witness),
        "packed_witness_args": hex(&packed_witness_args),
        "group_sighash": hex(group_hash),
        "authorization_digest": hex(digest),
    });

    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).expect("vector directory");
    }
    fs::write(
        &output,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&vector).expect("serialize vector")
        ),
    )
    .expect("write vector");
    println!("wrote {}", output.display());
}
