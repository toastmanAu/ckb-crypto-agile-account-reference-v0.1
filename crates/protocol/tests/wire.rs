use ckb_account_protocol::*;

fn authenticator(slot: u16, algorithm: u16, capabilities: u16, weight: u16) -> Vec<u8> {
    let aux: &[u8] = if algorithm == ALG_P256_WEBAUTHN {
        &[1; 65]
    } else {
        &[1]
    };
    let entry_len = 48 + 32 + aux.len();
    let mut out = Vec::new();
    out.extend_from_slice(&(entry_len as u16).to_le_bytes());
    out.extend_from_slice(&slot.to_le_bytes());
    out.extend_from_slice(&algorithm.to_le_bytes());
    out.extend_from_slice(&capabilities.to_le_bytes());
    out.extend_from_slice(&weight.to_le_bytes());
    out.push(0);
    out.push(VERIFIER_ABI_V1);
    out.extend_from_slice(&[9; 32]);
    out.extend_from_slice(&32u16.to_le_bytes());
    out.extend_from_slice(&(aux.len() as u16).to_le_bytes());
    out.extend_from_slice(&[7; 32]);
    out.extend_from_slice(aux);
    out
}

fn state(entries: &[Vec<u8>], thresholds: (u16, u16, u16), flags: u8) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"CKAS");
    out.push(1);
    out.push(flags);
    out.extend_from_slice(&32u16.to_le_bytes());
    out.extend_from_slice(&42u64.to_le_bytes());
    out.extend_from_slice(&thresholds.0.to_le_bytes());
    out.extend_from_slice(&thresholds.1.to_le_bytes());
    out.extend_from_slice(&thresholds.2.to_le_bytes());
    out.push(entries.len() as u8);
    out.push(0);
    out.extend_from_slice(
        &(if flags & STATE_FLAG_RECOVERY_ENABLED != 0 {
            99u64
        } else {
            0u64
        })
        .to_le_bytes(),
    );
    for entry in entries {
        out.extend_from_slice(entry);
    }
    out
}

#[test]
fn validates_canonical_weighted_state() {
    let bytes = state(
        &[
            authenticator(1, ALG_P256_WEBAUTHN, CAP_SPEND | CAP_ROTATE, 1),
            authenticator(2, ALG_MLDSA65, CAP_SPEND | CAP_ROTATE | CAP_RECOVERY, 2),
        ],
        (2, 3, 2),
        STATE_FLAG_RECOVERY_ENABLED,
    );
    let (header, weights) = validate_state(&bytes).expect("valid state");
    assert_eq!(header.sequence, 42);
    assert_eq!(weights.spend_weight, 3);
    assert_eq!(weights.rotate_weight, 3);
    assert_eq!(weights.recovery_weight, 2);
}

#[test]
fn rejects_state_mutation_corpus_without_panics() {
    let valid = state(
        &[authenticator(
            1,
            ALG_P256_WEBAUTHN,
            CAP_SPEND | CAP_ROTATE,
            1,
        )],
        (1, 1, 0),
        0,
    );
    for end in 0..valid.len() {
        assert!(
            validate_state(&valid[..end]).is_err(),
            "accepted truncation {end}"
        );
    }
    let mutations = [
        (0, 0),
        (4, 2),
        (5, 0x80),
        (6, 31),
        (7, 1),
        (22, 0),
        (23, 1),
        (38, 0),
        (40, 0),
    ];
    for (offset, value) in mutations {
        let mut malformed = valid.clone();
        malformed[offset] = value;
        assert!(
            validate_state(&malformed).is_err(),
            "accepted mutation at {offset}"
        );
    }
    let mut duplicate = state(
        &[
            authenticator(1, ALG_P256_WEBAUTHN, CAP_SPEND | CAP_ROTATE, 1),
            authenticator(1, ALG_MLDSA65, CAP_SPEND | CAP_ROTATE, 1),
        ],
        (1, 1, 0),
        0,
    );
    assert!(validate_state(&duplicate).is_err());
    let second_entry = 32 + (48 + 32 + 65);
    duplicate[second_entry + 2] = 2;
    assert!(validate_state(&duplicate).is_ok());
}

fn request() -> Vec<u8> {
    let aux = [1u8; 65];
    let proof = b"proof";
    let mut out = Vec::new();
    out.extend_from_slice(b"CKVR");
    out.extend_from_slice(&[1, 0]);
    out.extend_from_slice(&96u16.to_le_bytes());
    out.extend_from_slice(&ALG_P256_WEBAUTHN.to_le_bytes());
    out.extend_from_slice(&7u16.to_le_bytes());
    out.extend_from_slice(&[OP_SPEND, 1, 0, 0]);
    out.extend_from_slice(&[3; 32]);
    out.extend_from_slice(&[4; 32]);
    out.extend_from_slice(&(aux.len() as u32).to_le_bytes());
    out.extend_from_slice(&(proof.len() as u32).to_le_bytes());
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(&aux);
    out.extend_from_slice(proof);
    out
}

#[test]
fn verifier_request_rejects_every_framing_class() {
    let valid = request();
    let parsed = VerifierRequest::parse(&valid).expect("valid request");
    assert_eq!(parsed.slot, 7);
    assert_eq!(parsed.proof, b"proof");
    for end in 0..valid.len() {
        assert!(VerifierRequest::parse(&valid[..end]).is_err());
    }
    for offset in [0, 4, 5, 6, 7, 12, 14, 15, 88, 95] {
        let mut malformed = valid.clone();
        malformed[offset] ^= 0xff;
        assert!(
            VerifierRequest::parse(&malformed).is_err(),
            "accepted offset {offset}"
        );
    }
    let mut trailing = valid.clone();
    trailing.push(0);
    assert!(VerifierRequest::parse(&trailing).is_err());
    let mut too_much_aux = valid;
    too_much_aux[80..84].copy_from_slice(&4097u32.to_le_bytes());
    assert!(VerifierRequest::parse(&too_much_aux).is_err());
}

#[test]
fn witness_requires_sorted_unique_nonempty_proofs() {
    let mut witness = Vec::new();
    witness.extend_from_slice(b"CKAW");
    witness.extend_from_slice(&[1, OP_SPEND, 2, 0]);
    witness.extend_from_slice(&8u64.to_le_bytes());
    for slot in [1u16, 2] {
        witness.extend_from_slice(&slot.to_le_bytes());
        witness.extend_from_slice(&[0, 0]);
        witness.extend_from_slice(&1u32.to_le_bytes());
        witness.push(slot as u8);
    }
    let header = parse_witness_header(&witness).unwrap();
    parse_proofs(&witness, &header, |_, _| Ok(())).unwrap();
    witness[25] = 1;
    assert!(parse_proofs(&witness, &header, |_, _| Ok(())).is_err());
}
