use ckb_account_host::*;
use ckb_account_protocol::*;
use ckb_types::{bytes::Bytes, packed, prelude::*, H256};

fn auth(slot: u16) -> Authenticator {
    Authenticator {
        slot,
        algorithm_id: ALG_MLDSA65,
        capabilities: CAP_SPEND | CAP_ROTATE,
        weight: 1,
        verifier_hash_type: 0,
        verifier_abi: 1,
        verifier_code_hash: [2; 32],
        key_id: [3; 32],
        aux: vec![1],
    }
}

#[test]
fn host_encoders_round_trip_through_consensus_parsers() {
    let state = encode_state(&AccountState {
        flags: 0,
        sequence: 9,
        spend_threshold: 1,
        rotate_threshold: 1,
        recovery_threshold: 0,
        recovery_since: 0,
        authenticators: vec![auth(1)],
    })
    .unwrap();
    assert_eq!(validate_state(&state).unwrap().0.sequence, 9);

    let witness = encode_witness(
        OP_SPEND,
        9,
        &[Proof {
            slot: 1,
            bytes: vec![8],
        }],
    )
    .unwrap();
    let header = parse_witness_header(&witness).unwrap();
    parse_proofs(&witness, &header, |slot, proof| {
        assert_eq!((slot, proof), (1, &[8][..]));
        Ok(())
    })
    .unwrap();

    let request =
        encode_verifier_request(ALG_MLDSA65, 1, OP_SPEND, 1, &[4; 32], &[3; 32], &[1], &[8])
            .unwrap();
    assert_eq!(VerifierRequest::parse(&request).unwrap().proof, &[8]);
}

#[test]
fn sighash_uses_present_empty_lock_and_preserves_other_fields() {
    let args = packed::WitnessArgs::new_builder()
        .lock(Some(Bytes::from_static(b"signature")).pack())
        .input_type(Some(Bytes::from_static(b"input")).pack())
        .output_type(Some(Bytes::from_static(b"output")).pack())
        .build();
    let canonical = args
        .clone()
        .as_builder()
        .lock(Some(Bytes::new()).pack())
        .build()
        .as_bytes();
    let hash = group_sighash(
        &H256::from([7; 32]),
        &[args.as_bytes(), Bytes::from_static(b"second")],
        &[Bytes::from_static(b"extra")],
    )
    .unwrap();

    let mut material = vec![7; 32];
    for witness in [&canonical[..], b"second", b"extra"] {
        material.extend_from_slice(&(witness.len() as u64).to_le_bytes());
        material.extend_from_slice(witness);
    }
    assert_eq!(hash, ckb_hash(&material));
}

#[test]
fn authorization_digest_is_domain_and_state_bound() {
    let base = authorization_digest(OP_SPEND, &[1; 32], 2, b"state", &[3; 32]).unwrap();
    assert_ne!(
        base,
        authorization_digest(OP_ROTATE, &[1; 32], 2, b"state", &[3; 32]).unwrap()
    );
    assert_ne!(
        base,
        authorization_digest(OP_SPEND, &[1; 32], 3, b"state", &[3; 32]).unwrap()
    );
    assert_ne!(
        base,
        authorization_digest(OP_SPEND, &[1; 32], 2, b"State", &[3; 32]).unwrap()
    );
}
