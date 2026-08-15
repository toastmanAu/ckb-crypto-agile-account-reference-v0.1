//! Bootstrap configuration for a singleton AccountStateV1.
//!
//! The initial state cell is created once and roots the account's identity. It
//! cannot be edited afterwards — only rotated, and rotation itself requires
//! meeting a threshold this file is responsible for making satisfiable. Every
//! check here therefore fails closed.

use serde::Deserialize;

use crate::{encode_state, AccountState, Authenticator};
use ckb_account_protocol::*;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{0}")]
    Invalid(String),
    #[error("the encoded state was rejected by the protocol parser: {0:?}")]
    Protocol(ProtocolError),
}

fn invalid(message: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(message.into())
}

fn parse_hex(field: &str, value: &str) -> Result<Vec<u8>, ConfigError> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    hex::decode(trimmed).map_err(|error| invalid(format!("invalid hex in {field}: {error}")))
}

fn parse_hash(field: &str, value: &str) -> Result<[u8; 32], ConfigError> {
    let bytes = parse_hex(field, value)?;
    bytes
        .try_into()
        .map_err(|_| invalid(format!("{field} must be exactly 32 bytes")))
}

#[derive(Debug, Deserialize)]
pub struct AuthenticatorConfig {
    pub slot: u16,
    pub algorithm_id: u16,
    pub capabilities: u16,
    pub weight: u16,
    pub verifier_hash_type: u8,
    pub verifier_abi: u8,
    pub verifier_code_hash: String,
    pub key_id: String,
    pub aux: String,
}

#[derive(Debug, Deserialize)]
pub struct AccountStateConfig {
    pub flags: u8,
    pub sequence: u64,
    pub spend_threshold: u16,
    pub rotate_threshold: u16,
    pub recovery_threshold: u16,
    pub recovery_since: u64,
    pub authenticators: Vec<AuthenticatorConfig>,
}

impl AuthenticatorConfig {
    fn to_authenticator(&self) -> Result<Authenticator, ConfigError> {
        if self.verifier_abi != VERIFIER_ABI_V1 {
            return Err(invalid(format!(
                "slot {}: verifier_abi must be {VERIFIER_ABI_V1:#04x} for ABI v1, got {:#04x}",
                self.slot, self.verifier_abi
            )));
        }
        if self.verifier_hash_type > 1 {
            return Err(invalid(format!(
                "slot {}: verifier_hash_type must be 0 (data) or 1 (type)",
                self.slot
            )));
        }
        if self.capabilities & !CAP_KNOWN_MASK != 0 {
            return Err(invalid(format!(
                "slot {}: capabilities {:#06x} set bits outside the known mask {CAP_KNOWN_MASK:#06x}",
                self.slot, self.capabilities
            )));
        }
        if self.weight == 0 {
            return Err(invalid(format!(
                "slot {}: weight 0 can never contribute to a threshold",
                self.slot
            )));
        }

        let aux = parse_hex("aux", &self.aux)?;
        if aux.is_empty() {
            return Err(invalid(format!(
                "slot {}: aux must not be empty",
                self.slot
            )));
        }
        // ABI v1 fixes the P-256/WebAuthn aux layout at profile || rp_id_hash ||
        // origin_hash. A short aux would be accepted by the framing parser and
        // then rejected by the verifier at spend time, when the account already
        // holds assets.
        if self.algorithm_id == ALG_P256_WEBAUTHN && aux.len() != 65 {
            return Err(invalid(format!(
                "slot {}: P-256 aux must be exactly 65 bytes (profile || rp_id_hash || origin_hash), got {}",
                self.slot,
                aux.len()
            )));
        }

        Ok(Authenticator {
            slot: self.slot,
            algorithm_id: self.algorithm_id,
            capabilities: self.capabilities,
            weight: self.weight,
            verifier_hash_type: self.verifier_hash_type,
            verifier_abi: self.verifier_abi,
            verifier_code_hash: parse_hash("verifier_code_hash", &self.verifier_code_hash)?,
            key_id: parse_hash("key_id", &self.key_id)?,
            aux,
        })
    }
}

/// Total weight of authenticators holding `capability`.
fn available_weight(authenticators: &[Authenticator], capability: u16) -> u32 {
    authenticators
        .iter()
        .filter(|entry| entry.capabilities & capability != 0)
        .map(|entry| u32::from(entry.weight))
        .sum()
}

fn require_satisfiable(
    label: &str,
    threshold: u16,
    authenticators: &[Authenticator],
    capability: u16,
) -> Result<(), ConfigError> {
    if threshold == 0 {
        return Err(invalid(format!(
            "{label} threshold must be at least 1; a zero threshold authorizes with no proof"
        )));
    }
    let available = available_weight(authenticators, capability);
    if available < u32::from(threshold) {
        return Err(invalid(format!(
            "{label} threshold {threshold} exceeds the total weight {available} of \
             authenticators holding the {label} capability; the account would be \
             permanently unusable for that operation"
        )));
    }
    Ok(())
}

impl AccountStateConfig {
    /// Validates the configuration and returns consensus-exact
    /// AccountStateV1 bytes.
    pub fn encode(&self) -> Result<Vec<u8>, ConfigError> {
        if self.sequence != 0 {
            return Err(invalid(format!(
                "initial state sequence must be 0, got {}",
                self.sequence
            )));
        }
        if self.flags & !STATE_FLAGS_KNOWN_MASK != 0 {
            return Err(invalid(format!(
                "flags {:#04x} set bits outside the known mask {STATE_FLAGS_KNOWN_MASK:#04x}",
                self.flags
            )));
        }
        if self.authenticators.is_empty() {
            return Err(invalid("at least one authenticator is required"));
        }
        if self.authenticators.len() > AUTHENTICATOR_MAX_COUNT {
            return Err(invalid(format!(
                "at most {AUTHENTICATOR_MAX_COUNT} authenticators are allowed, got {}",
                self.authenticators.len()
            )));
        }

        let authenticators = self
            .authenticators
            .iter()
            .map(AuthenticatorConfig::to_authenticator)
            .collect::<Result<Vec<_>, _>>()?;

        // The protocol requires strictly increasing slots; an unsorted or
        // duplicated list is rejected on chain rather than here, so catch it
        // before the cell exists.
        for pair in authenticators.windows(2) {
            if pair[1].slot <= pair[0].slot {
                return Err(invalid(format!(
                    "authenticator slots must be strictly increasing, got {} after {}",
                    pair[1].slot, pair[0].slot
                )));
            }
        }

        require_satisfiable("spend", self.spend_threshold, &authenticators, CAP_SPEND)?;
        require_satisfiable("rotate", self.rotate_threshold, &authenticators, CAP_ROTATE)?;
        if self.flags & STATE_FLAG_RECOVERY_ENABLED != 0 {
            require_satisfiable(
                "recovery",
                self.recovery_threshold,
                &authenticators,
                CAP_RECOVERY,
            )?;
        }

        let state = AccountState {
            flags: self.flags,
            sequence: self.sequence,
            spend_threshold: self.spend_threshold,
            rotate_threshold: self.rotate_threshold,
            recovery_threshold: self.recovery_threshold,
            recovery_since: self.recovery_since,
            authenticators,
        };

        let encoded = encode_state(&state).map_err(ConfigError::Protocol)?;
        // Fail closed: the bytes that will become the state cell must parse
        // under the same validator the on-chain lock uses.
        validate_state(&encoded).map_err(ConfigError::Protocol)?;
        Ok(encoded)
    }
}
