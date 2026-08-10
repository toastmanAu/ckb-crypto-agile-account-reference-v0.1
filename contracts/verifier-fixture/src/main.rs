#![no_std]
#![no_main]

use alloc::{vec, vec::Vec};
use ckb_account_protocol::{
    VerifierRequest, VERIFIER_MAX_REQUEST_LEN, VERIFIER_REQUEST_HEADER_LEN,
};
use ckb_std::{default_alloc, entry, error::SysError, syscalls};

default_alloc!();
entry!(program_entry);

fn read_exact(fd: u64, output: &mut [u8]) -> Result<(), ()> {
    let mut offset = 0usize;
    while offset < output.len() {
        let count = syscalls::read(fd, &mut output[offset..]).map_err(|_| ())?;
        if count == 0 {
            return Err(());
        }
        offset = offset.checked_add(count).ok_or(())?;
    }
    Ok(())
}

fn request() -> Result<Vec<u8>, i8> {
    let mut fds = [0u64; 2];
    if syscalls::inherited_fds(&mut fds) != 1 {
        return Err(2);
    }
    let fd = fds[0];
    let mut header = [0u8; VERIFIER_REQUEST_HEADER_LEN];
    read_exact(fd, &mut header).map_err(|_| 3)?;
    let aux = u32::from_le_bytes(header[80..84].try_into().map_err(|_| 4)?) as usize;
    let proof = u32::from_le_bytes(header[84..88].try_into().map_err(|_| 4)?) as usize;
    let total = VERIFIER_REQUEST_HEADER_LEN
        .checked_add(aux)
        .and_then(|value| value.checked_add(proof))
        .filter(|value| *value <= VERIFIER_MAX_REQUEST_LEN)
        .ok_or(5)?;
    let mut bytes = vec![0u8; total];
    bytes[..VERIFIER_REQUEST_HEADER_LEN].copy_from_slice(&header);
    read_exact(fd, &mut bytes[VERIFIER_REQUEST_HEADER_LEN..]).map_err(|_| 6)?;
    let mut extra = [0u8; 1];
    if !matches!(
        syscalls::read(fd, &mut extra),
        Ok(0) | Err(SysError::OtherEndClosed)
    ) {
        return Err(7);
    }
    syscalls::close(fd).map_err(|_| 8)?;
    Ok(bytes)
}

fn program_entry() -> i8 {
    let bytes = match request() {
        Ok(bytes) => bytes,
        Err(code) => return code,
    };
    let request = match VerifierRequest::parse(&bytes) {
        Ok(request) => request,
        Err(_) => return 3,
    };
    if request.verifier_profile == 1 && request.aux == [1] && request.proof == b"fixture-valid" {
        0
    } else {
        1
    }
}
