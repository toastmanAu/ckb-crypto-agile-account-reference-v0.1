//! Emits consensus-exact AccountStateV1 bytes for a bootstrap configuration.
//!
//! The transaction builder in `tools/deploy` consumes the output as opaque
//! bytes. State serialization stays here, in the crate the VM suite already
//! exercises, so the wire format is never reimplemented in a second language.
//!
//! Usage:
//!
//!   cargo run -p ckb-account-host --example export_account_state -- \
//!     deploy/account-state.example.json /tmp/account-state.bin

use ckb_account_host::{ckb_hash, config::AccountStateConfig};
use std::{env, fs, path::PathBuf, process};

fn main() {
    let mut args = env::args_os().skip(1);
    let (Some(config_path), Some(output_path)) = (args.next(), args.next()) else {
        eprintln!("usage: export_account_state CONFIG_JSON OUTPUT_BIN");
        process::exit(2);
    };
    let config_path = PathBuf::from(config_path);
    let output_path = PathBuf::from(output_path);

    let source = fs::read_to_string(&config_path)
        .unwrap_or_else(|error| fatal(format!("read {}: {error}", config_path.display())));
    let config: AccountStateConfig = serde_json::from_str(&source)
        .unwrap_or_else(|error| fatal(format!("parse {}: {error}", config_path.display())));

    let encoded = config
        .encode()
        .unwrap_or_else(|error| fatal(format!("invalid account state configuration: {error}")));

    fs::write(&output_path, &encoded)
        .unwrap_or_else(|error| fatal(format!("write {}: {error}", output_path.display())));

    println!("wrote {} ({} bytes)", output_path.display(), encoded.len());
    println!("state hash 0x{}", hex::encode(ckb_hash(&encoded)));
    println!("authenticators {}", config.authenticators.len());
    println!(
        "thresholds spend={} rotate={} recovery={}",
        config.spend_threshold, config.rotate_threshold, config.recovery_threshold
    );
}

fn fatal(message: String) -> ! {
    eprintln!("{message}");
    process::exit(1);
}
