use ckb_account_host::ckb_hash;
use serde::Serialize;
use std::{env, fs, path::PathBuf};

#[derive(Serialize)]
struct Artifact {
    file: String,
    bytes: usize,
    ckb_data_hash: String,
}

fn main() {
    let mut args = env::args_os().skip(1);
    let output = PathBuf::from(args.next().expect("usage: OUTPUT ARTIFACT..."));
    let paths = args.map(PathBuf::from).collect::<Vec<_>>();
    assert!(!paths.is_empty(), "at least one artifact is required");

    let artifacts = paths
        .iter()
        .map(|path| {
            let data =
                fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
            Artifact {
                file: path
                    .file_name()
                    .expect("artifact file name")
                    .to_string_lossy()
                    .into_owned(),
                bytes: data.len(),
                ckb_data_hash: format!("0x{}", hex::encode(ckb_hash(&data))),
            }
        })
        .collect::<Vec<_>>();
    let encoded = serde_json::to_vec_pretty(&artifacts).expect("serialize artifact manifest");
    fs::write(&output, encoded)
        .unwrap_or_else(|error| panic!("write {}: {error}", output.display()));
    println!("wrote {}", output.display());
}
