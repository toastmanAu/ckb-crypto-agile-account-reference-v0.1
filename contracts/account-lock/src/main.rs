#![no_std]
#![no_main]

use alloc::{vec, vec::Vec};
use ckb_account_protocol::*;
use ckb_hash::new_blake2b;
use ckb_std::{
    ckb_constants::{CellField, Source},
    default_alloc, entry,
    error::SysError,
    syscalls::{self, SpawnArgs},
};

default_alloc!();
entry!(program_entry);

const MAX_CELL_DATA: usize = ACCOUNT_STATE_MAX_LEN;
const MAX_WITNESS: usize = ACCOUNT_WITNESS_MAX_LOCK_LEN + 1024;
const MAX_TYPE_SCRIPT: usize = 512;
const MAX_SCRIPT: usize = 512;

fn code(error: ProtocolError) -> i8 {
    error as i8
}

fn load_bounded(
    cap: usize,
    loader: impl Fn(&mut [u8], usize) -> Result<usize, SysError>,
) -> Result<Vec<u8>, ProtocolError> {
    let mut initial = [0u8; 256];
    match loader(&mut initial, 0) {
        Ok(len) => Ok(initial[..len].to_vec()),
        Err(SysError::LengthNotEnough(actual)) if actual <= cap => {
            let mut output = vec![0u8; actual];
            let loaded = loader(&mut output, 0).map_err(|_| ProtocolError::InvalidState)?;
            if loaded != actual {
                return Err(ProtocolError::InvalidState);
            }
            Ok(output)
        }
        Err(_) => Err(ProtocolError::InvalidState),
    }
}

fn load_cell_data(index: usize, source: Source) -> Result<Vec<u8>, ProtocolError> {
    load_bounded(MAX_CELL_DATA, |buffer, offset| {
        syscalls::load_cell_data(buffer, offset, index, source)
    })
}

fn load_witness(index: usize, source: Source) -> Result<Vec<u8>, ProtocolError> {
    load_bounded(MAX_WITNESS, |buffer, offset| {
        syscalls::load_witness(buffer, offset, index, source)
    })
    .map_err(|_| ProtocolError::InvalidWitness)
}

fn le_u32(bytes: &[u8]) -> Result<usize, ProtocolError> {
    let value: [u8; 4] = bytes
        .try_into()
        .map_err(|_| ProtocolError::InvalidWitness)?;
    Ok(u32::from_le_bytes(value) as usize)
}

fn table3_fields(data: &[u8]) -> Result<[&[u8]; 3], ProtocolError> {
    if data.len() < 16 || le_u32(&data[0..4])? != data.len() {
        return Err(ProtocolError::InvalidWitness);
    }
    let first = le_u32(&data[4..8])?;
    let second = le_u32(&data[8..12])?;
    let third = le_u32(&data[12..16])?;
    if first != 16 || first > second || second > third || third > data.len() {
        return Err(ProtocolError::InvalidWitness);
    }
    Ok([&data[first..second], &data[second..third], &data[third..]])
}

fn molecule_bytes(field: &[u8]) -> Result<&[u8], ProtocolError> {
    if field.len() < 4 {
        return Err(ProtocolError::InvalidWitness);
    }
    let length = le_u32(&field[..4])?;
    if length != field.len() - 4 {
        return Err(ProtocolError::InvalidWitness);
    }
    Ok(&field[4..])
}

fn witness_lock(witness: &[u8]) -> Result<&[u8], ProtocolError> {
    let fields = table3_fields(witness)?;
    if fields[0].is_empty() {
        return Err(ProtocolError::InvalidWitness);
    }
    molecule_bytes(fields[0])
}

fn canonical_witness(witness: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let fields = table3_fields(witness)?;
    let total = 20usize
        .checked_add(fields[1].len())
        .and_then(|value| value.checked_add(fields[2].len()))
        .ok_or(ProtocolError::LengthOverflow)?;
    let second = 20usize;
    let third = second
        .checked_add(fields[1].len())
        .ok_or(ProtocolError::LengthOverflow)?;
    let mut output = Vec::with_capacity(total);
    output.extend_from_slice(&(total as u32).to_le_bytes());
    output.extend_from_slice(&16u32.to_le_bytes());
    output.extend_from_slice(&(second as u32).to_le_bytes());
    output.extend_from_slice(&(third as u32).to_le_bytes());
    output.extend_from_slice(&0u32.to_le_bytes());
    output.extend_from_slice(fields[1]);
    output.extend_from_slice(fields[2]);
    Ok(output)
}

fn script_args(script: &[u8]) -> Result<&[u8], ProtocolError> {
    let fields = table3_fields(script).map_err(|_| ProtocolError::InvalidArgs)?;
    molecule_bytes(fields[2]).map_err(|_| ProtocolError::InvalidArgs)
}

fn load_current_script() -> Result<Vec<u8>, ProtocolError> {
    load_bounded(MAX_SCRIPT, |buffer, offset| {
        syscalls::load_script(buffer, offset)
    })
    .map_err(|_| ProtocolError::InvalidArgs)
}

fn load_type_script(index: usize, source: Source) -> Result<Option<Vec<u8>>, ProtocolError> {
    let result = load_bounded(MAX_TYPE_SCRIPT, |buffer, offset| {
        syscalls::load_cell_by_field(buffer, offset, index, source, CellField::Type)
    });
    match result {
        Ok(script) => Ok(Some(script)),
        Err(_) => {
            let mut probe = [0u8; 1];
            match syscalls::load_cell_by_field(&mut probe, 0, index, source, CellField::Type) {
                Err(SysError::ItemMissing) => Ok(None),
                _ => Err(ProtocolError::InvalidState),
            }
        }
    }
}

fn cell_type_hash(index: usize, source: Source) -> Result<Option<[u8; 32]>, SysError> {
    let mut hash = [0u8; 32];
    match syscalls::load_cell_by_field(&mut hash, 0, index, source, CellField::TypeHash) {
        Ok(32) => Ok(Some(hash)),
        Ok(_) => Err(SysError::Encoding),
        Err(SysError::ItemMissing) => Ok(None),
        Err(error) => Err(error),
    }
}

fn matching_type_indices(
    source: Source,
    account_id: &[u8; 32],
) -> Result<Vec<usize>, ProtocolError> {
    let mut matches = Vec::new();
    for index in 0usize.. {
        match cell_type_hash(index, source) {
            Ok(Some(hash)) if hash == *account_id => matches.push(index),
            Ok(_) => {}
            Err(SysError::IndexOutOfBound) => break,
            Err(_) => return Err(ProtocolError::InvalidState),
        }
    }
    Ok(matches)
}

struct ResolvedState {
    current: Vec<u8>,
    successor: Option<Vec<u8>>,
    state_input: Option<usize>,
}

fn resolve_state(operation: u8, account_id: &[u8; 32]) -> Result<ResolvedState, ProtocolError> {
    let inputs = matching_type_indices(Source::Input, account_id)?;
    match operation {
        OP_SPEND => {
            if !inputs.is_empty() {
                return Err(ProtocolError::StateConsumedOnSpend);
            }
            let deps = matching_type_indices(Source::CellDep, account_id)?;
            if deps.len() != 1 {
                return Err(if deps.is_empty() {
                    ProtocolError::StateNotFound
                } else {
                    ProtocolError::DuplicateState
                });
            }
            Ok(ResolvedState {
                current: load_cell_data(deps[0], Source::CellDep)?,
                successor: None,
                state_input: None,
            })
        }
        OP_ROTATE | OP_RECOVERY => {
            if inputs.len() != 1 {
                return Err(if inputs.is_empty() {
                    ProtocolError::StateNotFound
                } else {
                    ProtocolError::DuplicateState
                });
            }
            let outputs = matching_type_indices(Source::Output, account_id)?;
            if outputs.len() != 1 {
                return Err(ProtocolError::InvalidTransition);
            }
            let input_type = load_type_script(inputs[0], Source::Input)?
                .ok_or(ProtocolError::InvalidTransition)?;
            let output_type = load_type_script(outputs[0], Source::Output)?
                .ok_or(ProtocolError::InvalidTransition)?;
            if input_type != output_type {
                return Err(ProtocolError::InvalidTransition);
            }
            Ok(ResolvedState {
                current: load_cell_data(inputs[0], Source::Input)?,
                successor: Some(load_cell_data(outputs[0], Source::Output)?),
                state_input: Some(inputs[0]),
            })
        }
        _ => Err(ProtocolError::InvalidOperation),
    }
}

fn validate_transition(
    operation: u8,
    resolved: &ResolvedState,
    current_header: &StateHeader,
) -> Result<(), ProtocolError> {
    if operation == OP_SPEND {
        return Ok(());
    }
    let successor = resolved
        .successor
        .as_deref()
        .ok_or(ProtocolError::InvalidTransition)?;
    let (next, _) = validate_state(successor)?;
    let expected = current_header
        .sequence
        .checked_add(1)
        .ok_or(ProtocolError::InvalidSequence)?;
    if next.sequence != expected {
        return Err(ProtocolError::InvalidSequence);
    }
    if operation == OP_RECOVERY {
        if current_header.flags & STATE_FLAG_RECOVERY_ENABLED == 0 {
            return Err(ProtocolError::InvalidCapability);
        }
        let index = resolved
            .state_input
            .ok_or(ProtocolError::InvalidTransition)?;
        let mut since = [0u8; 8];
        syscalls::load_input_by_field(
            &mut since,
            0,
            index,
            Source::Input,
            ckb_std::ckb_constants::InputField::Since,
        )
        .map_err(|_| ProtocolError::RecoveryLocked)?;
        if u64::from_le_bytes(since) < current_header.recovery_since {
            return Err(ProtocolError::RecoveryLocked);
        }
    }
    Ok(())
}

fn hash_witness(hasher: &mut ckb_hash::Blake2b, witness: &[u8]) -> Result<(), ProtocolError> {
    let length = u64::try_from(witness.len()).map_err(|_| ProtocolError::LengthOverflow)?;
    hasher.update(&length.to_le_bytes());
    hasher.update(witness);
    Ok(())
}

fn input_count() -> Result<usize, ProtocolError> {
    for index in 0usize.. {
        let mut since = [0u8; 8];
        match syscalls::load_input_by_field(
            &mut since,
            0,
            index,
            Source::Input,
            ckb_std::ckb_constants::InputField::Since,
        ) {
            Ok(_) => {}
            Err(SysError::IndexOutOfBound) => return Ok(index),
            Err(_) => return Err(ProtocolError::InvalidWitness),
        }
    }
    Err(ProtocolError::LengthOverflow)
}

fn canonical_group_sighash() -> Result<[u8; 32], ProtocolError> {
    let first = load_witness(0, Source::GroupInput)?;
    let canonical = canonical_witness(&first)?;
    let mut hasher = new_blake2b();
    let mut tx_hash = [0u8; 32];
    if syscalls::load_tx_hash(&mut tx_hash, 0).map_err(|_| ProtocolError::InvalidWitness)? != 32 {
        return Err(ProtocolError::InvalidWitness);
    }
    hasher.update(&tx_hash);
    hash_witness(&mut hasher, &canonical)?;
    for index in 1usize.. {
        let mut probe = [0u8; 1];
        match syscalls::load_witness(&mut probe, 0, index, Source::GroupInput) {
            Ok(_) | Err(SysError::LengthNotEnough(_)) => {
                let witness = load_witness(index, Source::GroupInput)?;
                hash_witness(&mut hasher, &witness)?;
            }
            Err(SysError::IndexOutOfBound) => break,
            Err(_) => return Err(ProtocolError::InvalidWitness),
        }
    }
    let inputs = input_count()?;
    for index in inputs.. {
        let mut probe = [0u8; 1];
        match syscalls::load_witness(&mut probe, 0, index, Source::Input) {
            Ok(_) | Err(SysError::LengthNotEnough(_)) => {
                let witness = load_witness(index, Source::Input)?;
                hash_witness(&mut hasher, &witness)?;
            }
            Err(SysError::IndexOutOfBound) => break,
            Err(_) => return Err(ProtocolError::InvalidWitness),
        }
    }
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    Ok(output)
}

fn authorization_digest(
    operation: u8,
    account_id: &[u8; 32],
    sequence: u64,
    state: &[u8],
    group_sighash: &[u8; 32],
) -> [u8; 32] {
    let mut state_hash = [0u8; 32];
    let mut state_hasher = new_blake2b();
    state_hasher.update(state);
    state_hasher.finalize(&mut state_hash);
    let mut output = [0u8; 32];
    let mut hasher = new_blake2b();
    hasher.update(AUTH_DOMAIN);
    hasher.update(&[operation]);
    hasher.update(account_id);
    hasher.update(&sequence.to_le_bytes());
    hasher.update(&state_hash);
    hasher.update(group_sighash);
    hasher.finalize(&mut output);
    output
}

fn find_authenticator<'a>(
    state: &'a [u8],
    header: &StateHeader,
    slot: u16,
) -> Result<AuthenticatorEntry<'a>, ProtocolError> {
    let mut found = None;
    parse_authenticators(state, header, |entry| {
        if entry.slot == slot {
            found = Some(entry);
        }
        Ok(())
    })?;
    found.ok_or(ProtocolError::InvalidWitness)
}

fn resolve_verifier(auth: &AuthenticatorEntry<'_>) -> Result<usize, ProtocolError> {
    let field = if auth.verifier_hash_type == 0 {
        CellField::DataHash
    } else {
        CellField::TypeHash
    };
    let mut found = None;
    for index in 0usize.. {
        let mut hash = [0u8; 32];
        match syscalls::load_cell_by_field(&mut hash, 0, index, Source::CellDep, field) {
            Ok(32) if hash == *auth.verifier_code_hash => {
                if found.replace(index).is_some() {
                    return Err(ProtocolError::InvalidVerifierRef);
                }
            }
            Ok(_) | Err(SysError::ItemMissing) => {}
            Err(SysError::IndexOutOfBound) => break,
            Err(_) => return Err(ProtocolError::InvalidVerifierRef),
        }
    }
    found.ok_or(ProtocolError::InvalidVerifierRef)
}

fn encode_request(
    auth: &AuthenticatorEntry<'_>,
    operation: u8,
    digest: &[u8; 32],
    proof: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    if auth.key_id.len() != 32 || auth.aux.is_empty() || proof.len() > VERIFIER_MAX_PROOF_LEN {
        return Err(ProtocolError::InvalidRequest);
    }
    let total = VERIFIER_REQUEST_HEADER_LEN
        .checked_add(auth.aux.len())
        .and_then(|v| v.checked_add(proof.len()))
        .filter(|v| *v <= VERIFIER_MAX_REQUEST_LEN)
        .ok_or(ProtocolError::LengthOverflow)?;
    let mut output = Vec::with_capacity(total);
    output.extend_from_slice(&VERIFIER_MAGIC);
    output.extend_from_slice(&[VERIFIER_ABI_V1, 0]);
    output.extend_from_slice(&(VERIFIER_REQUEST_HEADER_LEN as u16).to_le_bytes());
    output.extend_from_slice(&auth.algorithm_id.to_le_bytes());
    output.extend_from_slice(&auth.slot.to_le_bytes());
    output.extend_from_slice(&[operation, auth.aux[0], 0, 0]);
    output.extend_from_slice(digest);
    output.extend_from_slice(auth.key_id);
    output.extend_from_slice(&(auth.aux.len() as u32).to_le_bytes());
    output.extend_from_slice(&(proof.len() as u32).to_le_bytes());
    output.extend_from_slice(&[0u8; 8]);
    output.extend_from_slice(auth.aux);
    output.extend_from_slice(proof);
    VerifierRequest::parse(&output)?;
    Ok(output)
}

fn spawn_verifier(index: usize, request: &[u8]) -> Result<bool, ProtocolError> {
    let (read_fd, write_fd) = syscalls::pipe().map_err(|_| ProtocolError::VerifierFailure)?;
    let inherited = [read_fd, 0];
    let mut process_id = 0u64;
    let mut spawn_args = SpawnArgs {
        argc: 0,
        argv: core::ptr::null(),
        process_id: &mut process_id,
        inherited_fds: inherited.as_ptr(),
    };
    let pid = syscalls::spawn(index, Source::CellDep, 0, 0, &mut spawn_args)
        .map_err(|_| ProtocolError::VerifierFailure)?;
    match syscalls::close(read_fd) {
        Ok(()) | Err(SysError::InvalidFd) => {}
        Err(_) => return Err(ProtocolError::VerifierFailure),
    }
    let mut offset = 0usize;
    while offset < request.len() {
        let written = syscalls::write(write_fd, &request[offset..])
            .map_err(|_| ProtocolError::VerifierFailure)?;
        if written == 0 {
            return Err(ProtocolError::VerifierFailure);
        }
        offset = offset
            .checked_add(written)
            .ok_or(ProtocolError::LengthOverflow)?;
    }
    syscalls::close(write_fd).map_err(|_| ProtocolError::VerifierFailure)?;
    Ok(syscalls::wait(pid).map_err(|_| ProtocolError::VerifierFailure)? == 0)
}

fn run() -> Result<(), ProtocolError> {
    let script = load_current_script()?;
    let lock_args = AccountLockArgs::parse(script_args(&script)?)?;
    let first_witness = load_witness(0, Source::GroupInput)?;
    let lock = witness_lock(&first_witness)?;
    let witness_header = parse_witness_header(lock)?;
    if usize::from(witness_header.proof_count) > AUTHENTICATOR_MAX_COUNT {
        return Err(ProtocolError::InvalidWitness);
    }
    let resolved = resolve_state(witness_header.operation, lock_args.account_id)?;
    let (state_header, _) = validate_state(&resolved.current)?;
    if witness_header.state_sequence != state_header.sequence {
        return Err(ProtocolError::InvalidSequence);
    }
    validate_transition(witness_header.operation, &resolved, &state_header)?;
    let sighash = canonical_group_sighash()?;
    let digest = authorization_digest(
        witness_header.operation,
        lock_args.account_id,
        state_header.sequence,
        &resolved.current,
        &sighash,
    );
    let capability = capability_for_operation(witness_header.operation)?;
    let threshold = match witness_header.operation {
        OP_SPEND => state_header.spend_threshold,
        OP_ROTATE => state_header.rotate_threshold,
        OP_RECOVERY => state_header.recovery_threshold,
        _ => return Err(ProtocolError::InvalidOperation),
    };
    let mut weight = 0u32;
    parse_proofs(lock, &witness_header, |slot, proof| {
        let auth = find_authenticator(&resolved.current, &state_header, slot)?;
        if auth.capabilities & capability == 0 {
            return Err(ProtocolError::InvalidCapability);
        }
        let verifier_index = resolve_verifier(&auth)?;
        let request = encode_request(&auth, witness_header.operation, &digest, proof)?;
        if spawn_verifier(verifier_index, &request)? {
            weight = weight
                .checked_add(u32::from(auth.weight))
                .ok_or(ProtocolError::LengthOverflow)?;
        }
        Ok(())
    })?;
    if weight < u32::from(threshold) {
        return Err(ProtocolError::ThresholdUnsatisfied);
    }
    Ok(())
}

fn program_entry() -> i8 {
    match run() {
        Ok(()) => 0,
        Err(error) => code(error),
    }
}
