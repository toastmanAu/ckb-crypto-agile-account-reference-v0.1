//! Account identity derivation.
//!
//! `account_id` is the script hash of the singleton Type ID script, and the
//! AccountLock args are `0x01 || account_id`. Those args are never executed at
//! creation time — a lock script only runs when its cell is consumed — so an
//! error here produces cells that look correct on chain and can never be
//! unlocked. These vectors are the cross-language oracle for the deployment
//! tool, which must reproduce them exactly.

use ckb_account_host::{
    account_id_from_type_id_args, account_lock_args, type_id_script, TYPE_ID_CODE_HASH,
};
use ckb_account_protocol::{ACCOUNT_LOCK_ARGS_LEN, ACCOUNT_LOCK_VERSION};
use ckb_types::prelude::*;

/// A fixed, arbitrary Type ID args value. Any change to the expectations below
/// is a change to account identity itself.
const TYPE_ID_ARGS: [u8; 32] = [0x11; 32];

#[test]
fn the_builtin_type_id_code_hash_is_ascii_type_id_left_padded() {
    assert_eq!(
        format!("0x{}", hex::encode(TYPE_ID_CODE_HASH)),
        "0x00000000000000000000000000000000000000000000000000545950455f4944"
    );
}

#[test]
fn the_type_id_script_uses_the_builtin_code_hash_with_type_hash_type() {
    let script = type_id_script(&TYPE_ID_ARGS);

    assert_eq!(
        script.code_hash().raw_data().as_ref(),
        &TYPE_ID_CODE_HASH[..]
    );
    // hash_type "type" is 0x01
    assert_eq!(script.hash_type().as_slice(), &[0x01]);
    assert_eq!(script.args().raw_data().as_ref(), &TYPE_ID_ARGS[..]);
}

#[test]
fn account_id_is_the_type_id_script_hash() {
    let account_id = account_id_from_type_id_args(&TYPE_ID_ARGS);
    let expected: [u8; 32] = type_id_script(&TYPE_ID_ARGS).calc_script_hash().unpack();

    assert_eq!(account_id, expected);
    // Printed so the deployment tool can pin the same bytes.
    println!("GOLDEN account_id 0x{}", hex::encode(account_id));
}

#[test]
fn account_lock_args_are_the_version_byte_followed_by_the_account_id() {
    let account_id = account_id_from_type_id_args(&TYPE_ID_ARGS);
    let args = account_lock_args(&account_id);

    assert_eq!(args.len(), ACCOUNT_LOCK_ARGS_LEN);
    assert_eq!(args[0], ACCOUNT_LOCK_VERSION);
    assert_eq!(&args[1..], &account_id[..]);
    println!("GOLDEN lock_args 0x{}", hex::encode(args));
}
