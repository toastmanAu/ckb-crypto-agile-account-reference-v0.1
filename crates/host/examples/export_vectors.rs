use ckb_account_host::{
    authorization_digest, encode_public_key_proof, encode_state, encode_verifier_request,
    encode_witness, AccountState, Authenticator, Proof,
};
use ckb_account_protocol::{ALG_MLDSA65, CAP_ROTATE, CAP_SPEND, OP_SPEND, VERIFIER_ABI_V1};
use std::{env, fs, path::PathBuf};

fn main() {
    let output = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("vectors/conformance-v1.bin"));
    let state = encode_state(&AccountState {
        flags: 0,
        sequence: 7,
        spend_threshold: 1,
        rotate_threshold: 1,
        recovery_threshold: 0,
        recovery_since: 0,
        authenticators: vec![Authenticator {
            slot: 1,
            algorithm_id: ALG_MLDSA65,
            capabilities: CAP_SPEND | CAP_ROTATE,
            weight: 1,
            verifier_hash_type: 0,
            verifier_abi: VERIFIER_ABI_V1,
            verifier_code_hash: [0x22; 32],
            key_id: [0x33; 32],
            aux: vec![1],
        }],
    })
    .expect("canonical state");
    let inner_proof = encode_public_key_proof(&[0x44; 32], &[0x55; 64]).expect("proof");
    let witness = encode_witness(
        OP_SPEND,
        7,
        &[Proof {
            slot: 1,
            bytes: inner_proof.clone(),
        }],
    )
    .expect("witness");
    let digest = authorization_digest(OP_SPEND, &[0x11; 32], 7, &state, &[0x66; 32])
        .expect("authorization digest");
    let request = encode_verifier_request(
        ALG_MLDSA65,
        1,
        OP_SPEND,
        1,
        &digest,
        &[0x33; 32],
        &[1],
        &inner_proof,
    )
    .expect("request");
    let records = [(1u8, state), (2u8, witness), (3u8, request)];
    let mut bytes = b"CKCV\x01\x00\x03\x00".to_vec();
    for (kind, record) in records {
        bytes.push(kind);
        bytes.extend_from_slice(&(record.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&record);
    }
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).expect("vector directory");
    }
    fs::write(&output, bytes).expect("write vector");
    println!("wrote {}", output.display());
}
