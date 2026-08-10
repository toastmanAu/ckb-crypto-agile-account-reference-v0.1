pub const ACCOUNT_LOCK_VERSION: u8 = 0x01;
pub const ACCOUNT_LOCK_ARGS_LEN: usize = 33;

pub const ACCOUNT_STATE_MAGIC: [u8; 4] = *b"CKAS";
pub const ACCOUNT_STATE_VERSION: u8 = 0x01;
pub const ACCOUNT_STATE_HEADER_LEN: usize = 32;
pub const ACCOUNT_STATE_MAX_LEN: usize = 16_384;
pub const AUTHENTICATOR_MAX_COUNT: usize = 16;

pub const ACCOUNT_WITNESS_MAGIC: [u8; 4] = *b"CKAW";
pub const ACCOUNT_WITNESS_VERSION: u8 = 0x01;
pub const ACCOUNT_WITNESS_HEADER_LEN: usize = 16;
pub const ACCOUNT_WITNESS_MAX_LOCK_LEN: usize = 131_072;

pub const VERIFIER_MAGIC: [u8; 4] = *b"CKVR";
pub const VERIFIER_ABI_V1: u8 = 0x01;
pub const VERIFIER_REQUEST_HEADER_LEN: usize = 96;
pub const VERIFIER_MAX_AUX_LEN: usize = 4_096;
pub const VERIFIER_MAX_PROOF_LEN: usize = 65_536;
pub const VERIFIER_MAX_REQUEST_LEN: usize = 69_728;

pub const AUTH_DOMAIN: &[u8; 19] = b"CKB_ACCOUNT_LOCK_V1";

pub const OP_SPEND: u8 = 0x01;
pub const OP_ROTATE: u8 = 0x02;
pub const OP_RECOVERY: u8 = 0x03;

pub const CAP_SPEND: u16 = 0x0001;
pub const CAP_ROTATE: u16 = 0x0002;
pub const CAP_RECOVERY: u16 = 0x0004;
pub const CAP_SESSION_ISSUE: u16 = 0x0008;
pub const CAP_KNOWN_MASK: u16 = CAP_SPEND | CAP_ROTATE | CAP_RECOVERY | CAP_SESSION_ISSUE;

pub const STATE_FLAG_RECOVERY_ENABLED: u8 = 0x01;
pub const STATE_FLAG_SESSION_ENABLED: u8 = 0x02;
pub const STATE_FLAGS_KNOWN_MASK: u8 = STATE_FLAG_RECOVERY_ENABLED | STATE_FLAG_SESSION_ENABLED;

pub const ALG_P256_WEBAUTHN: u16 = 0x0001;
pub const ALG_MLDSA44: u16 = 0x0101;
pub const ALG_MLDSA65: u16 = 0x0102;
pub const ALG_MLDSA87: u16 = 0x0103;
pub const ALG_SLHDSA: u16 = 0x0201;
pub const ALG_FALCON512_EXPERIMENTAL: u16 = 0x0301;
pub const ALG_FALCON1024_EXPERIMENTAL: u16 = 0x0302;

pub const PROFILE_V1: u8 = 0x01;
pub const SLH_DSA_SHA2_128S: u8 = 0x01;
