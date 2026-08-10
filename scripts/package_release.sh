#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 VERSION OUTPUT_DIRECTORY" >&2
  exit 2
fi

release_version=$1
output_directory=$2
if [[ ! $release_version =~ ^v?[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "invalid release version: $release_version" >&2
  exit 2
fi

repository_root=$(cd "$(dirname "$0")/.." && pwd)
release_name="ckb-crypto-agile-account-${release_version#v}"
staging_directory="$output_directory/$release_name"
archive="$output_directory/$release_name.tar.gz"

if [[ -e $staging_directory || -e $archive ]]; then
  echo "release output already exists: $staging_directory or $archive" >&2
  exit 2
fi

cd "$repository_root"
if [[ -n $(git status --porcelain=v1 --untracked-files=all) ]]; then
  echo "refusing to package a dirty worktree" >&2
  exit 2
fi

mkdir -p "$staging_directory/contracts" "$staging_directory/vectors" "$staging_directory/docs"

cargo build --locked --release --target riscv64imac-unknown-none-elf \
  -p account-lock \
  -p verifier-fixture \
  -p verifier-p256 \
  -p verifier-mldsa-adapter \
  -p verifier-slhdsa-adapter

contract_directory=target/riscv64imac-unknown-none-elf/release
contract_paths=(
  "$contract_directory/account-lock"
  "$contract_directory/verifier-p256"
  "$contract_directory/verifier-mldsa-adapter"
  "$contract_directory/verifier-slhdsa-adapter"
  "$contract_directory/verifier-fixture"
)
cp "${contract_paths[@]}" "$staging_directory/contracts/"
cp vectors/conformance-v1.bin vectors/fixture-spend.json "$staging_directory/vectors/"
cp README.md SECURITY.md CYCLES.md LICENSE Cargo.lock rust-toolchain.toml \
  "$staging_directory/"
cp docs/REFERENCE_IMPLEMENTATION_SPEC.md docs/DEPLOYMENT.md \
  docs/REPRODUCIBLE_BUILDS.md docs/THREAT_MODEL.md docs/AUDIT_SCOPE.md \
  docs/AUDITOR_SHORTLIST.md docs/AUDIT_REQUEST.md \
  "$staging_directory/docs/"
cp deploy/reference-deployments.json "$staging_directory/"

{
  echo "version=$release_version"
  echo "source_commit=$(git rev-parse HEAD)"
  echo "rustc=$(rustc --version)"
  echo "cargo=$(cargo --version)"
} > "$staging_directory/BUILD_INFO.txt"

cargo run --locked -p ckb-account-host --example export_artifact_manifest -- \
  "$staging_directory/CKB_DATA_HASHES.json" "${contract_paths[@]}"

(
  cd "$staging_directory"
  find . -type f ! -name SHA256SUMS -print0 \
    | sort -z \
    | xargs -0 sha256sum > SHA256SUMS
)

tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
  -czf "$archive" -C "$output_directory" "$release_name"
(
  cd "$output_directory"
  sha256sum "$(basename "$archive")" > "$(basename "$archive").sha256"
)

echo "release archive: $archive"
echo "archive digest: $archive.sha256"
