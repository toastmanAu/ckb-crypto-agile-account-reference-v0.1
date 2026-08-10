#![no_std]
#![no_main]

use alloc::{vec, vec::Vec};
use ckb_account_protocol::{
    parse_public_key_proof, VerifierRequest, ALG_MLDSA65, PROFILE_V1, VERIFIER_MAX_REQUEST_LEN,
    VERIFIER_REQUEST_HEADER_LEN,
};
use ckb_hash::new_blake2b;
use ckb_std::{default_alloc, entry, error::SysError, syscalls};
use ml_dsa::{EncodedVerifyingKey, MlDsa65, Signature, Verifier, VerifyingKey};

default_alloc!();
entry!(program_entry);

mod exit {
    pub const VALID: i8 = 0;
    pub const INVALID_PROOF: i8 = 1;
    pub const MALFORMED_REQUEST: i8 = 2;
    pub const UNSUPPORTED_ALGORITHM: i8 = 3;
    pub const UNSUPPORTED_PROFILE: i8 = 4;
    pub const KEY_ID_MISMATCH: i8 = 5;
    pub const MALFORMED_KEY: i8 = 6;
    pub const MALFORMED_PROOF: i8 = 7;
    pub const AUX_MISMATCH: i8 = 9;
    pub const INTERNAL_ERROR: i8 = 10;
}

fn read_exact(fd: u64, output: &mut [u8]) -> Result<(), ()> {
    let mut offset = 0usize;
    while offset < output.len() {
        let read = syscalls::read(fd, &mut output[offset..]).map_err(|_| ())?;
        if read == 0 {
            return Err(());
        }
        offset = offset.checked_add(read).ok_or(())?;
    }
    Ok(())
}

fn read_request() -> Result<Vec<u8>, i8> {
    let mut fds = [0u64; 2];
    if syscalls::inherited_fds(&mut fds) != 1 {
        return Err(exit::MALFORMED_REQUEST);
    }
    let fd = fds[0];
    let mut header = [0u8; VERIFIER_REQUEST_HEADER_LEN];
    read_exact(fd, &mut header).map_err(|_| exit::MALFORMED_REQUEST)?;
    let aux_len = u32::from_le_bytes(
        header[80..84]
            .try_into()
            .map_err(|_| exit::MALFORMED_REQUEST)?,
    ) as usize;
    let proof_len = u32::from_le_bytes(
        header[84..88]
            .try_into()
            .map_err(|_| exit::MALFORMED_REQUEST)?,
    ) as usize;
    let total = VERIFIER_REQUEST_HEADER_LEN
        .checked_add(aux_len)
        .and_then(|v| v.checked_add(proof_len))
        .filter(|v| *v <= VERIFIER_MAX_REQUEST_LEN)
        .ok_or(exit::MALFORMED_REQUEST)?;
    let mut request = vec![0u8; total];
    request[..VERIFIER_REQUEST_HEADER_LEN].copy_from_slice(&header);
    read_exact(fd, &mut request[VERIFIER_REQUEST_HEADER_LEN..])
        .map_err(|_| exit::MALFORMED_REQUEST)?;
    let mut extra = [0u8; 1];
    if !matches!(
        syscalls::read(fd, &mut extra),
        Ok(0) | Err(SysError::OtherEndClosed)
    ) {
        return Err(exit::MALFORMED_REQUEST);
    }
    syscalls::close(fd).map_err(|_| exit::INTERNAL_ERROR)?;
    Ok(request)
}

fn hash(data: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut hasher = new_blake2b();
    hasher.update(data);
    hasher.finalize(&mut output);
    output
}

fn verify(request: &[u8]) -> Result<(), i8> {
    let request = VerifierRequest::parse(request).map_err(|_| exit::MALFORMED_REQUEST)?;
    if request.algorithm_id != ALG_MLDSA65 {
        return Err(exit::UNSUPPORTED_ALGORITHM);
    }
    if request.verifier_profile != PROFILE_V1 {
        return Err(exit::UNSUPPORTED_PROFILE);
    }
    if request.aux != [PROFILE_V1] {
        return Err(exit::AUX_MISMATCH);
    }
    let proof = parse_public_key_proof(request.proof).map_err(|_| exit::MALFORMED_PROOF)?;
    if hash(proof.public_key) != *request.key_id {
        return Err(exit::KEY_ID_MISMATCH);
    }
    let encoded = EncodedVerifyingKey::<MlDsa65>::try_from(proof.public_key)
        .map_err(|_| exit::MALFORMED_KEY)?;
    let key = VerifyingKey::<MlDsa65>::decode(&encoded);
    let signature =
        Signature::<MlDsa65>::try_from(proof.signature).map_err(|_| exit::MALFORMED_PROOF)?;
    key.verify(request.authorization_digest, &signature)
        .map_err(|_| exit::INVALID_PROOF)
}

fn program_entry() -> i8 {
    match read_request().and_then(|request| verify(&request)) {
        Ok(()) => exit::VALID,
        Err(code) => code,
    }
}
