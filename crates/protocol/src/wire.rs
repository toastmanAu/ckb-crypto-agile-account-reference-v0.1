use crate::*;

fn le_u16(b: &[u8]) -> Result<u16, ProtocolError> {
    if b.len() != 2 {
        return Err(ProtocolError::InvalidState);
    }
    Ok(u16::from_le_bytes([b[0], b[1]]))
}
fn le_u32(b: &[u8]) -> Result<u32, ProtocolError> {
    if b.len() != 4 {
        return Err(ProtocolError::InvalidWitness);
    }
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
fn le_u64(b: &[u8]) -> Result<u64, ProtocolError> {
    if b.len() != 8 {
        return Err(ProtocolError::InvalidState);
    }
    Ok(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

fn checked_end(offset: usize, len: usize, total: usize) -> Result<usize, ProtocolError> {
    offset
        .checked_add(len)
        .filter(|end| *end <= total)
        .ok_or(ProtocolError::LengthOverflow)
}

pub fn is_supported_algorithm(algorithm_id: u16) -> bool {
    matches!(
        algorithm_id,
        ALG_P256_WEBAUTHN | ALG_MLDSA44 | ALG_MLDSA65 | ALG_MLDSA87 | ALG_SLHDSA
    )
}

pub fn capability_for_operation(operation: u8) -> Result<u16, ProtocolError> {
    match operation {
        OP_SPEND => Ok(CAP_SPEND),
        OP_ROTATE => Ok(CAP_ROTATE),
        OP_RECOVERY => Ok(CAP_RECOVERY),
        _ => Err(ProtocolError::InvalidOperation),
    }
}

#[derive(Clone, Copy, Debug)]
pub struct AccountLockArgs<'a> {
    pub version: u8,
    pub account_id: &'a [u8; 32],
}

impl<'a> AccountLockArgs<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, ProtocolError> {
        if data.len() != ACCOUNT_LOCK_ARGS_LEN {
            return Err(ProtocolError::InvalidArgs);
        }
        if data[0] != ACCOUNT_LOCK_VERSION {
            return Err(ProtocolError::UnsupportedVersion);
        }
        let account_id: &'a [u8; 32] = data[1..33]
            .try_into()
            .map_err(|_| ProtocolError::InvalidArgs)?;
        Ok(Self {
            version: data[0],
            account_id,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub struct StateHeader {
    pub flags: u8,
    pub sequence: u64,
    pub spend_threshold: u16,
    pub rotate_threshold: u16,
    pub recovery_threshold: u16,
    pub authenticator_count: u8,
    pub recovery_since: u64,
}

impl StateHeader {
    pub fn parse(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < ACCOUNT_STATE_HEADER_LEN || data.len() > ACCOUNT_STATE_MAX_LEN {
            return Err(ProtocolError::InvalidState);
        }
        if data[0..4] != ACCOUNT_STATE_MAGIC {
            return Err(ProtocolError::InvalidState);
        }
        if data[4] != ACCOUNT_STATE_VERSION {
            return Err(ProtocolError::UnsupportedVersion);
        }
        if data[5] & !STATE_FLAGS_KNOWN_MASK != 0 {
            return Err(ProtocolError::InvalidState);
        }
        if le_u16(&data[6..8])? as usize != ACCOUNT_STATE_HEADER_LEN {
            return Err(ProtocolError::InvalidState);
        }
        if data[23] != 0 {
            return Err(ProtocolError::InvalidState);
        }
        let count = data[22];
        if count == 0 || count as usize > AUTHENTICATOR_MAX_COUNT {
            return Err(ProtocolError::InvalidState);
        }
        Ok(Self {
            flags: data[5],
            sequence: le_u64(&data[8..16])?,
            spend_threshold: le_u16(&data[16..18])?,
            rotate_threshold: le_u16(&data[18..20])?,
            recovery_threshold: le_u16(&data[20..22])?,
            authenticator_count: count,
            recovery_since: le_u64(&data[24..32])?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateSummary {
    pub spend_weight: u32,
    pub rotate_weight: u32,
    pub recovery_weight: u32,
}

pub fn validate_state(state: &[u8]) -> Result<(StateHeader, StateSummary), ProtocolError> {
    let header = StateHeader::parse(state)?;
    let mut summary = StateSummary {
        spend_weight: 0,
        rotate_weight: 0,
        recovery_weight: 0,
    };
    parse_authenticators(state, &header, |entry| {
        if !is_supported_algorithm(entry.algorithm_id) {
            return Err(ProtocolError::UnsupportedAlgorithm);
        }
        if entry.key_id.len() != 32 || entry.aux.is_empty() {
            return Err(ProtocolError::InvalidState);
        }
        let weight = u32::from(entry.weight);
        if entry.capabilities & CAP_SPEND != 0 {
            summary.spend_weight = summary
                .spend_weight
                .checked_add(weight)
                .ok_or(ProtocolError::LengthOverflow)?;
        }
        if entry.capabilities & CAP_ROTATE != 0 {
            summary.rotate_weight = summary
                .rotate_weight
                .checked_add(weight)
                .ok_or(ProtocolError::LengthOverflow)?;
        }
        if entry.capabilities & CAP_RECOVERY != 0 {
            summary.recovery_weight = summary
                .recovery_weight
                .checked_add(weight)
                .ok_or(ProtocolError::LengthOverflow)?;
        }
        Ok(())
    })?;
    if header.spend_threshold == 0
        || header.rotate_threshold == 0
        || u32::from(header.spend_threshold) > summary.spend_weight
        || u32::from(header.rotate_threshold) > summary.rotate_weight
    {
        return Err(ProtocolError::UnsatisfiableThreshold);
    }
    let recovery_enabled = header.flags & STATE_FLAG_RECOVERY_ENABLED != 0;
    if recovery_enabled {
        if header.recovery_threshold == 0
            || u32::from(header.recovery_threshold) > summary.recovery_weight
        {
            return Err(ProtocolError::UnsatisfiableThreshold);
        }
    } else if header.recovery_threshold != 0 || header.recovery_since != 0 {
        return Err(ProtocolError::InvalidState);
    }
    Ok((header, summary))
}

#[derive(Clone, Copy, Debug)]
pub struct AuthenticatorEntry<'a> {
    pub slot: u16,
    pub algorithm_id: u16,
    pub capabilities: u16,
    pub weight: u16,
    pub verifier_hash_type: u8,
    pub verifier_abi: u8,
    pub verifier_code_hash: &'a [u8; 32],
    pub key_id: &'a [u8],
    pub aux: &'a [u8],
}

pub fn parse_authenticators<'a>(
    state: &'a [u8],
    header: &StateHeader,
    mut f: impl FnMut(AuthenticatorEntry<'a>) -> Result<(), ProtocolError>,
) -> Result<(), ProtocolError> {
    let mut off = ACCOUNT_STATE_HEADER_LEN;
    let mut prev_slot: Option<u16> = None;
    for _ in 0..header.authenticator_count {
        checked_end(off, 48, state.len()).map_err(|_| ProtocolError::InvalidState)?;
        let entry_len = le_u16(&state[off..off + 2])? as usize;
        let slot = le_u16(&state[off + 2..off + 4])?;
        let algorithm_id = le_u16(&state[off + 4..off + 6])?;
        let capabilities = le_u16(&state[off + 6..off + 8])?;
        let weight = le_u16(&state[off + 8..off + 10])?;
        let verifier_hash_type = state[off + 10];
        let verifier_abi = state[off + 11];
        let verifier_code_hash: &'a [u8; 32] = state[off + 12..off + 44]
            .try_into()
            .map_err(|_| ProtocolError::InvalidState)?;
        let key_len = le_u16(&state[off + 44..off + 46])? as usize;
        let aux_len = le_u16(&state[off + 46..off + 48])? as usize;
        if entry_len
            != 48usize
                .checked_add(key_len)
                .and_then(|v| v.checked_add(aux_len))
                .ok_or(ProtocolError::InvalidState)?
        {
            return Err(ProtocolError::InvalidState);
        }
        checked_end(off, entry_len, state.len()).map_err(|_| ProtocolError::InvalidState)?;
        if let Some(p) = prev_slot {
            if slot <= p {
                return Err(ProtocolError::InvalidState);
            }
        }
        prev_slot = Some(slot);
        if weight == 0 || capabilities & !CAP_KNOWN_MASK != 0 {
            return Err(ProtocolError::InvalidState);
        }
        if verifier_hash_type > 1 || verifier_abi != VERIFIER_ABI_V1 {
            return Err(ProtocolError::InvalidVerifierRef);
        }
        let key_start = off + 48;
        let aux_start = key_start + key_len;
        let entry = AuthenticatorEntry {
            slot,
            algorithm_id,
            capabilities,
            weight,
            verifier_hash_type,
            verifier_abi,
            verifier_code_hash,
            key_id: &state[key_start..aux_start],
            aux: &state[aux_start..off + entry_len],
        };
        f(entry)?;
        off += entry_len;
    }
    if off != state.len() {
        return Err(ProtocolError::InvalidState);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub struct AccountWitnessHeader {
    pub operation: u8,
    pub proof_count: u8,
    pub state_sequence: u64,
}

pub fn parse_witness_header(data: &[u8]) -> Result<AccountWitnessHeader, ProtocolError> {
    if data.len() < ACCOUNT_WITNESS_HEADER_LEN || data.len() > ACCOUNT_WITNESS_MAX_LOCK_LEN {
        return Err(ProtocolError::InvalidWitness);
    }
    if data[0..4] != ACCOUNT_WITNESS_MAGIC || data[4] != ACCOUNT_WITNESS_VERSION || data[7] != 0 {
        return Err(ProtocolError::InvalidWitness);
    }
    match data[5] {
        OP_SPEND | OP_ROTATE | OP_RECOVERY => {}
        _ => return Err(ProtocolError::InvalidWitness),
    }
    Ok(AccountWitnessHeader {
        operation: data[5],
        proof_count: data[6],
        state_sequence: le_u64(&data[8..16]).map_err(|_| ProtocolError::InvalidWitness)?,
    })
}

pub fn parse_proofs<'a>(
    data: &'a [u8],
    header: &AccountWitnessHeader,
    mut f: impl FnMut(u16, &'a [u8]) -> Result<(), ProtocolError>,
) -> Result<(), ProtocolError> {
    let mut off = ACCOUNT_WITNESS_HEADER_LEN;
    let mut prev: Option<u16> = None;
    for _ in 0..header.proof_count {
        checked_end(off, 8, data.len()).map_err(|_| ProtocolError::InvalidWitness)?;
        let slot = le_u16(&data[off..off + 2]).map_err(|_| ProtocolError::InvalidWitness)?;
        if data[off + 2] != 0 || data[off + 3] != 0 {
            return Err(ProtocolError::InvalidWitness);
        }
        let len = le_u32(&data[off + 4..off + 8])? as usize;
        let payload = off.checked_add(8).ok_or(ProtocolError::InvalidWitness)?;
        let end =
            checked_end(payload, len, data.len()).map_err(|_| ProtocolError::InvalidWitness)?;
        if len == 0 {
            return Err(ProtocolError::InvalidWitness);
        }
        if let Some(p) = prev {
            if slot <= p {
                return Err(ProtocolError::InvalidWitness);
            }
        }
        prev = Some(slot);
        f(slot, &data[payload..end])?;
        off = end;
    }
    if off != data.len() {
        return Err(ProtocolError::InvalidWitness);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub struct VerifierRequest<'a> {
    pub algorithm_id: u16,
    pub slot: u16,
    pub operation: u8,
    pub verifier_profile: u8,
    pub authorization_digest: &'a [u8; 32],
    pub key_id: &'a [u8; 32],
    pub aux: &'a [u8],
    pub proof: &'a [u8],
}

impl<'a> VerifierRequest<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, ProtocolError> {
        if data.len() < VERIFIER_REQUEST_HEADER_LEN || data.len() > VERIFIER_MAX_REQUEST_LEN {
            return Err(ProtocolError::InvalidRequest);
        }
        if data[0..4] != VERIFIER_MAGIC {
            return Err(ProtocolError::InvalidRequest);
        }
        if data[4] != VERIFIER_ABI_V1 {
            return Err(ProtocolError::UnsupportedVersion);
        }
        if data[5] != 0 || le_u16(&data[6..8])? as usize != VERIFIER_REQUEST_HEADER_LEN {
            return Err(ProtocolError::InvalidRequest);
        }
        let algorithm_id = le_u16(&data[8..10])?;
        let slot = le_u16(&data[10..12])?;
        let operation = data[12];
        capability_for_operation(operation)?;
        if data[14] != 0 || data[15] != 0 || data[88..96].iter().any(|byte| *byte != 0) {
            return Err(ProtocolError::InvalidRequest);
        }
        let aux_len = le_u32(&data[80..84]).map_err(|_| ProtocolError::InvalidRequest)? as usize;
        let proof_len = le_u32(&data[84..88]).map_err(|_| ProtocolError::InvalidRequest)? as usize;
        if aux_len > VERIFIER_MAX_AUX_LEN || proof_len > VERIFIER_MAX_PROOF_LEN {
            return Err(ProtocolError::InvalidRequest);
        }
        let aux_end = VERIFIER_REQUEST_HEADER_LEN
            .checked_add(aux_len)
            .ok_or(ProtocolError::LengthOverflow)?;
        let total = aux_end
            .checked_add(proof_len)
            .ok_or(ProtocolError::LengthOverflow)?;
        if total != data.len() {
            return Err(ProtocolError::InvalidRequest);
        }
        Ok(Self {
            algorithm_id,
            slot,
            operation,
            verifier_profile: data[13],
            authorization_digest: data[16..48]
                .try_into()
                .map_err(|_| ProtocolError::InvalidRequest)?,
            key_id: data[48..80]
                .try_into()
                .map_err(|_| ProtocolError::InvalidRequest)?,
            aux: &data[VERIFIER_REQUEST_HEADER_LEN..aux_end],
            proof: &data[aux_end..total],
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PublicKeyProof<'a> {
    pub public_key: &'a [u8],
    pub signature: &'a [u8],
}

pub fn parse_public_key_proof(data: &[u8]) -> Result<PublicKeyProof<'_>, ProtocolError> {
    if data.len() < 5 || data[0] != 1 {
        return Err(ProtocolError::InvalidProof);
    }
    let public_key_len = le_u16(&data[1..3])? as usize;
    let signature_len = le_u16(&data[3..5])? as usize;
    if public_key_len == 0 || signature_len == 0 {
        return Err(ProtocolError::InvalidProof);
    }
    let key_end = 5usize
        .checked_add(public_key_len)
        .ok_or(ProtocolError::LengthOverflow)?;
    let total = key_end
        .checked_add(signature_len)
        .ok_or(ProtocolError::LengthOverflow)?;
    if total != data.len() {
        return Err(ProtocolError::InvalidProof);
    }
    Ok(PublicKeyProof {
        public_key: &data[5..key_end],
        signature: &data[key_end..total],
    })
}
