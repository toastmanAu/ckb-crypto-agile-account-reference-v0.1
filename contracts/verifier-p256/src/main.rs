#![no_std]
#![no_main]

use alloc::{vec, vec::Vec};
use ckb_account_protocol::{
    VerifierRequest, ALG_P256_WEBAUTHN, PROFILE_V1, VERIFIER_MAX_REQUEST_LEN,
    VERIFIER_REQUEST_HEADER_LEN,
};
use ckb_hash::new_blake2b;
use ckb_std::{default_alloc, entry, error::SysError, syscalls};
use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};

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
    pub const DIGEST_BINDING_FAILURE: i8 = 8;
    pub const AUX_MISMATCH: i8 = 9;
    pub const INTERNAL_ERROR: i8 = 10;
}

struct PasskeyProof<'a> {
    public_key: &'a [u8],
    origin: &'a [u8],
    authenticator_data: &'a [u8],
    client_data_json: &'a [u8],
    signature: &'a [u8],
}

fn take<'a>(data: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8], i8> {
    let end = offset.checked_add(len).ok_or(exit::MALFORMED_PROOF)?;
    let value = data.get(*offset..end).ok_or(exit::MALFORMED_PROOF)?;
    *offset = end;
    Ok(value)
}

fn take_u16(data: &[u8], offset: &mut usize) -> Result<usize, i8> {
    let bytes = take(data, offset, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]) as usize)
}

fn parse_proof(data: &[u8]) -> Result<PasskeyProof<'_>, i8> {
    let mut offset = 0usize;
    let public_key = take(data, &mut offset, 65)?;
    let origin_len = usize::from(
        *take(data, &mut offset, 1)?
            .first()
            .ok_or(exit::MALFORMED_PROOF)?,
    );
    let origin = take(data, &mut offset, origin_len)?;
    let authenticator_len = take_u16(data, &mut offset)?;
    let authenticator_data = take(data, &mut offset, authenticator_len)?;
    let client_len = take_u16(data, &mut offset)?;
    let client_data_json = take(data, &mut offset, client_len)?;
    let signature_len = take_u16(data, &mut offset)?;
    let signature = take(data, &mut offset, signature_len)?;
    if offset != data.len()
        || origin.is_empty()
        || authenticator_data.len() < 37
        || client_data_json.is_empty()
        || signature.is_empty()
    {
        return Err(exit::MALFORMED_PROOF);
    }
    Ok(PasskeyProof {
        public_key,
        origin,
        authenticator_data,
        client_data_json,
        signature,
    })
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

fn ckb_hash(data: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut hasher = new_blake2b();
    hasher.update(data);
    hasher.finalize(&mut output);
    output
}

fn base64url_digest(input: &[u8; 32]) -> [u8; 43] {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = [0u8; 43];
    let mut source = 0usize;
    let mut target = 0usize;
    while source + 3 <= input.len() {
        let value = (u32::from(input[source]) << 16)
            | (u32::from(input[source + 1]) << 8)
            | u32::from(input[source + 2]);
        output[target] = TABLE[((value >> 18) & 63) as usize];
        output[target + 1] = TABLE[((value >> 12) & 63) as usize];
        output[target + 2] = TABLE[((value >> 6) & 63) as usize];
        output[target + 3] = TABLE[(value & 63) as usize];
        source += 3;
        target += 4;
    }
    let value = (u32::from(input[30]) << 16) | (u32::from(input[31]) << 8);
    output[40] = TABLE[((value >> 18) & 63) as usize];
    output[41] = TABLE[((value >> 12) & 63) as usize];
    output[42] = TABLE[((value >> 6) & 63) as usize];
    output
}

fn whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\n' | b'\r' | b'\t')
}

fn skip_ws(json: &[u8], offset: &mut usize) {
    while json.get(*offset).is_some_and(|byte| whitespace(*byte)) {
        *offset += 1;
    }
}

fn json_string<'a>(json: &'a [u8], offset: &mut usize) -> Result<&'a [u8], i8> {
    if json.get(*offset) != Some(&b'"') {
        return Err(exit::DIGEST_BINDING_FAILURE);
    }
    *offset += 1;
    let start = *offset;
    while let Some(byte) = json.get(*offset) {
        if *byte == b'"' {
            let value = &json[start..*offset];
            *offset += 1;
            return Ok(value);
        }
        if *byte == b'\\' || *byte < 0x20 {
            return Err(exit::DIGEST_BINDING_FAILURE);
        }
        *offset += 1;
    }
    Err(exit::DIGEST_BINDING_FAILURE)
}

fn skip_primitive(json: &[u8], offset: &mut usize) -> Result<(), i8> {
    let start = *offset;
    while let Some(byte) = json.get(*offset) {
        if matches!(byte, b',' | b'}') || whitespace(*byte) {
            break;
        }
        *offset += 1;
    }
    if *offset == start {
        Err(exit::DIGEST_BINDING_FAILURE)
    } else {
        Ok(())
    }
}

fn validate_client_data(json: &[u8], challenge: &[u8; 43], origin: &[u8]) -> Result<(), i8> {
    let mut offset = 0usize;
    let mut found_type = false;
    let mut found_challenge = false;
    let mut found_origin = false;
    skip_ws(json, &mut offset);
    if json.get(offset) != Some(&b'{') {
        return Err(exit::DIGEST_BINDING_FAILURE);
    }
    offset += 1;
    loop {
        skip_ws(json, &mut offset);
        if json.get(offset) == Some(&b'}') {
            offset += 1;
            break;
        }
        let key = json_string(json, &mut offset)?;
        skip_ws(json, &mut offset);
        if json.get(offset) != Some(&b':') {
            return Err(exit::DIGEST_BINDING_FAILURE);
        }
        offset += 1;
        skip_ws(json, &mut offset);
        if matches!(key, b"type" | b"challenge" | b"origin") {
            let value = json_string(json, &mut offset)?;
            let (found, expected): (&mut bool, &[u8]) = match key {
                b"type" => (&mut found_type, b"webauthn.get"),
                b"challenge" => (&mut found_challenge, challenge),
                _ => (&mut found_origin, origin),
            };
            if *found || value != expected {
                return Err(exit::DIGEST_BINDING_FAILURE);
            }
            *found = true;
        } else if json.get(offset) == Some(&b'"') {
            json_string(json, &mut offset)?;
        } else {
            skip_primitive(json, &mut offset)?;
        }
        skip_ws(json, &mut offset);
        match json.get(offset) {
            Some(b',') => offset += 1,
            Some(b'}') => continue,
            _ => return Err(exit::DIGEST_BINDING_FAILURE),
        }
    }
    skip_ws(json, &mut offset);
    if offset != json.len() || !found_type || !found_challenge || !found_origin {
        return Err(exit::DIGEST_BINDING_FAILURE);
    }
    Ok(())
}

fn verify(request: &[u8]) -> Result<(), i8> {
    let request = VerifierRequest::parse(request).map_err(|_| exit::MALFORMED_REQUEST)?;
    if request.algorithm_id != ALG_P256_WEBAUTHN {
        return Err(exit::UNSUPPORTED_ALGORITHM);
    }
    if request.verifier_profile != PROFILE_V1 {
        return Err(exit::UNSUPPORTED_PROFILE);
    }
    if request.aux.len() != 65 || request.aux[0] != PROFILE_V1 {
        return Err(exit::AUX_MISMATCH);
    }
    let proof = parse_proof(request.proof)?;
    if ckb_hash(proof.public_key) != *request.key_id {
        return Err(exit::KEY_ID_MISMATCH);
    }
    if ckb_hash(proof.origin) != request.aux[33..65] {
        return Err(exit::AUX_MISMATCH);
    }
    if proof.authenticator_data[..32] != request.aux[1..33]
        || proof.authenticator_data[32] & 0x05 != 0x05
    {
        return Err(exit::AUX_MISMATCH);
    }
    validate_client_data(
        proof.client_data_json,
        &base64url_digest(request.authorization_digest),
        proof.origin,
    )?;
    if proof.public_key[0] != 4 {
        return Err(exit::MALFORMED_KEY);
    }
    let key = VerifyingKey::from_sec1_bytes(proof.public_key).map_err(|_| exit::MALFORMED_KEY)?;
    if key.to_sec1_point(false).as_bytes() != proof.public_key {
        return Err(exit::MALFORMED_KEY);
    }
    let signature = Signature::from_der(proof.signature).map_err(|_| exit::MALFORMED_PROOF)?;
    if signature.to_der().as_bytes() != proof.signature {
        return Err(exit::MALFORMED_PROOF);
    }
    let client_hash = Sha256::digest(proof.client_data_json);
    let mut signed = Sha256::new();
    signed.update(proof.authenticator_data);
    signed.update(client_hash);
    key.verify_prehash(&signed.finalize(), &signature)
        .map_err(|_| exit::INVALID_PROOF)
}

fn program_entry() -> i8 {
    match read_request().and_then(|request| verify(&request)) {
        Ok(()) => exit::VALID,
        Err(code) => code,
    }
}
