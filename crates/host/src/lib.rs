//! Host-side, consensus-byte-exact construction and hashing helpers.

use ckb_account_protocol::*;
use ckb_hash::new_blake2b;
use ckb_types::{bytes::Bytes, packed, prelude::*, H256};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Authenticator {
    pub slot: u16,
    pub algorithm_id: u16,
    pub capabilities: u16,
    pub weight: u16,
    pub verifier_hash_type: u8,
    pub verifier_abi: u8,
    pub verifier_code_hash: [u8; 32],
    pub key_id: [u8; 32],
    pub aux: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountState {
    pub flags: u8,
    pub sequence: u64,
    pub spend_threshold: u16,
    pub rotate_threshold: u16,
    pub recovery_threshold: u16,
    pub recovery_since: u64,
    pub authenticators: Vec<Authenticator>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof {
    pub slot: u16,
    pub bytes: Vec<u8>,
}

fn u16_len(value: usize) -> Result<u16, ProtocolError> {
    u16::try_from(value).map_err(|_| ProtocolError::LengthOverflow)
}

fn u32_len(value: usize) -> Result<u32, ProtocolError> {
    u32::try_from(value).map_err(|_| ProtocolError::LengthOverflow)
}

pub fn encode_state(state: &AccountState) -> Result<Vec<u8>, ProtocolError> {
    let count =
        u8::try_from(state.authenticators.len()).map_err(|_| ProtocolError::InvalidState)?;
    let capacity = ACCOUNT_STATE_HEADER_LEN
        .checked_add(state.authenticators.iter().try_fold(0usize, |sum, auth| {
            sum.checked_add(48)
                .and_then(|v| v.checked_add(auth.key_id.len()))
                .and_then(|v| v.checked_add(auth.aux.len()))
                .ok_or(ProtocolError::LengthOverflow)
        })?)
        .ok_or(ProtocolError::LengthOverflow)?;
    if capacity > ACCOUNT_STATE_MAX_LEN {
        return Err(ProtocolError::InvalidState);
    }
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(&ACCOUNT_STATE_MAGIC);
    out.push(ACCOUNT_STATE_VERSION);
    out.push(state.flags);
    out.extend_from_slice(&(ACCOUNT_STATE_HEADER_LEN as u16).to_le_bytes());
    out.extend_from_slice(&state.sequence.to_le_bytes());
    out.extend_from_slice(&state.spend_threshold.to_le_bytes());
    out.extend_from_slice(&state.rotate_threshold.to_le_bytes());
    out.extend_from_slice(&state.recovery_threshold.to_le_bytes());
    out.push(count);
    out.push(0);
    out.extend_from_slice(&state.recovery_since.to_le_bytes());
    for auth in &state.authenticators {
        let entry_len = 48usize
            .checked_add(auth.key_id.len())
            .and_then(|v| v.checked_add(auth.aux.len()))
            .ok_or(ProtocolError::LengthOverflow)?;
        out.extend_from_slice(&u16_len(entry_len)?.to_le_bytes());
        out.extend_from_slice(&auth.slot.to_le_bytes());
        out.extend_from_slice(&auth.algorithm_id.to_le_bytes());
        out.extend_from_slice(&auth.capabilities.to_le_bytes());
        out.extend_from_slice(&auth.weight.to_le_bytes());
        out.push(auth.verifier_hash_type);
        out.push(auth.verifier_abi);
        out.extend_from_slice(&auth.verifier_code_hash);
        out.extend_from_slice(&u16_len(auth.key_id.len())?.to_le_bytes());
        out.extend_from_slice(&u16_len(auth.aux.len())?.to_le_bytes());
        out.extend_from_slice(&auth.key_id);
        out.extend_from_slice(&auth.aux);
    }
    validate_state(&out)?;
    Ok(out)
}

pub fn encode_witness(
    operation: u8,
    state_sequence: u64,
    proofs: &[Proof],
) -> Result<Vec<u8>, ProtocolError> {
    capability_for_operation(operation)?;
    let count = u8::try_from(proofs.len()).map_err(|_| ProtocolError::InvalidWitness)?;
    if proofs.len() > AUTHENTICATOR_MAX_COUNT {
        return Err(ProtocolError::InvalidWitness);
    }
    let mut out = Vec::with_capacity(ACCOUNT_WITNESS_HEADER_LEN);
    out.extend_from_slice(&ACCOUNT_WITNESS_MAGIC);
    out.push(ACCOUNT_WITNESS_VERSION);
    out.push(operation);
    out.push(count);
    out.push(0);
    out.extend_from_slice(&state_sequence.to_le_bytes());
    for proof in proofs {
        if proof.bytes.is_empty() {
            return Err(ProtocolError::InvalidWitness);
        }
        out.extend_from_slice(&proof.slot.to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&u32_len(proof.bytes.len())?.to_le_bytes());
        out.extend_from_slice(&proof.bytes);
    }
    let header = parse_witness_header(&out)?;
    parse_proofs(&out, &header, |_, _| Ok(()))?;
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
pub fn encode_verifier_request(
    algorithm_id: u16,
    slot: u16,
    operation: u8,
    verifier_profile: u8,
    authorization_digest: &[u8; 32],
    key_id: &[u8; 32],
    aux: &[u8],
    proof: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    capability_for_operation(operation)?;
    if aux.len() > VERIFIER_MAX_AUX_LEN || proof.len() > VERIFIER_MAX_PROOF_LEN {
        return Err(ProtocolError::InvalidRequest);
    }
    let total = VERIFIER_REQUEST_HEADER_LEN
        .checked_add(aux.len())
        .and_then(|v| v.checked_add(proof.len()))
        .ok_or(ProtocolError::LengthOverflow)?;
    if total > VERIFIER_MAX_REQUEST_LEN {
        return Err(ProtocolError::InvalidRequest);
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&VERIFIER_MAGIC);
    out.push(VERIFIER_ABI_V1);
    out.push(0);
    out.extend_from_slice(&(VERIFIER_REQUEST_HEADER_LEN as u16).to_le_bytes());
    out.extend_from_slice(&algorithm_id.to_le_bytes());
    out.extend_from_slice(&slot.to_le_bytes());
    out.push(operation);
    out.push(verifier_profile);
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(authorization_digest);
    out.extend_from_slice(key_id);
    out.extend_from_slice(&u32_len(aux.len())?.to_le_bytes());
    out.extend_from_slice(&u32_len(proof.len())?.to_le_bytes());
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(aux);
    out.extend_from_slice(proof);
    VerifierRequest::parse(&out)?;
    Ok(out)
}

pub fn encode_public_key_proof(
    public_key: &[u8],
    signature: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    if public_key.is_empty() || signature.is_empty() {
        return Err(ProtocolError::InvalidProof);
    }
    let mut out = Vec::with_capacity(5 + public_key.len() + signature.len());
    out.push(1);
    out.extend_from_slice(&u16_len(public_key.len())?.to_le_bytes());
    out.extend_from_slice(&u16_len(signature.len())?.to_le_bytes());
    out.extend_from_slice(public_key);
    out.extend_from_slice(signature);
    parse_public_key_proof(&out)?;
    Ok(out)
}

pub fn ckb_hash(data: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut hasher = new_blake2b();
    hasher.update(data);
    hasher.finalize(&mut output);
    output
}

pub fn authorization_digest(
    operation: u8,
    account_id: &[u8; 32],
    sequence: u64,
    state_data: &[u8],
    group_sighash: &[u8; 32],
) -> Result<[u8; 32], ProtocolError> {
    capability_for_operation(operation)?;
    let mut output = [0u8; 32];
    let mut hasher = new_blake2b();
    hasher.update(AUTH_DOMAIN);
    hasher.update(&[operation]);
    hasher.update(account_id);
    hasher.update(&sequence.to_le_bytes());
    hasher.update(&ckb_hash(state_data));
    hasher.update(group_sighash);
    hasher.finalize(&mut output);
    Ok(output)
}

fn update_witness(hasher: &mut ckb_hash::Blake2b, witness: &[u8]) -> Result<(), ProtocolError> {
    let len = u64::try_from(witness.len()).map_err(|_| ProtocolError::LengthOverflow)?;
    hasher.update(&len.to_le_bytes());
    hasher.update(witness);
    Ok(())
}

/// Computes CKB lock-group sighash from the transaction hash, group witnesses,
/// and witnesses beyond the transaction input count.
pub fn group_sighash(
    tx_hash: &H256,
    group_witnesses: &[Bytes],
    extra_witnesses: &[Bytes],
) -> Result<[u8; 32], ProtocolError> {
    let first = group_witnesses
        .first()
        .ok_or(ProtocolError::InvalidWitness)?;
    let args = packed::WitnessArgs::from_slice(first).map_err(|_| ProtocolError::InvalidWitness)?;
    let canonical = args
        .as_builder()
        .lock(Some(Bytes::new()).pack())
        .build()
        .as_bytes();
    let mut hasher = new_blake2b();
    hasher.update(tx_hash.as_bytes());
    update_witness(&mut hasher, &canonical)?;
    for witness in &group_witnesses[1..] {
        update_witness(&mut hasher, witness)?;
    }
    for witness in extra_witnesses {
        update_witness(&mut hasher, witness)?;
    }
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    Ok(output)
}
