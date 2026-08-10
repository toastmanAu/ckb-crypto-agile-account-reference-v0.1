use ckb_account_host::{
    authorization_digest, ckb_hash, encode_public_key_proof, encode_state, encode_witness,
    group_sighash, AccountState, Authenticator, Proof,
};
use ckb_account_protocol::{
    ALG_MLDSA65, ALG_P256_WEBAUTHN, ALG_SLHDSA, CAP_RECOVERY, CAP_ROTATE, CAP_SPEND, OP_RECOVERY,
    OP_ROTATE, OP_SPEND, STATE_FLAG_RECOVERY_ENABLED, VERIFIER_ABI_V1,
};
use ckb_hash::new_blake2b;
use ckb_testtool::{
    ckb_types::{
        bytes::Bytes,
        core::{ScriptHashType, TransactionBuilder, TransactionView},
        packed::{CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgs},
        prelude::*,
    },
    context::Context,
};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

const MAX_CYCLES: u64 = 3_500_000_000;
const ORIGIN: &[u8] = b"https://account.example";

#[derive(Clone, Copy)]
enum Kind {
    P256,
    MlDsa65,
    SlhDsaSha2_128s,
}

impl Kind {
    fn algorithm_id(self) -> u16 {
        match self {
            Self::P256 => ALG_P256_WEBAUTHN,
            Self::MlDsa65 => ALG_MLDSA65,
            Self::SlhDsaSha2_128s => ALG_SLHDSA,
        }
    }

    fn public_key(self) -> Vec<u8> {
        match self {
            Self::P256 => {
                use p256::ecdsa::SigningKey;
                SigningKey::from_slice(&[7u8; 32])
                    .expect("P-256 key")
                    .verifying_key()
                    .to_sec1_point(false)
                    .as_bytes()
                    .to_vec()
            }
            Self::MlDsa65 => {
                use ml_dsa::{KeyExport, Keypair, MlDsa65, Seed, SigningKey};
                let seed = Seed::try_from(&[0x42u8; 32][..]).expect("ML-DSA seed");
                SigningKey::<MlDsa65>::from_seed(&seed)
                    .verifying_key()
                    .to_bytes()
                    .to_vec()
            }
            Self::SlhDsaSha2_128s => {
                use slh_dsa::{signature::Keypair, Sha2_128s, SigningKey};
                SigningKey::<Sha2_128s>::slh_keygen_internal(&[0x11; 16], &[0x22; 16], &[0x33; 16])
                    .verifying_key()
                    .to_bytes()
                    .to_vec()
            }
        }
    }

    fn aux(self) -> Vec<u8> {
        match self {
            Self::P256 => {
                let rp_id_hash: [u8; 32] = Sha256::digest(b"account.example").into();
                let mut aux = vec![1];
                aux.extend_from_slice(&rp_id_hash);
                aux.extend_from_slice(&ckb_hash(ORIGIN));
                aux
            }
            Self::MlDsa65 => vec![1],
            Self::SlhDsaSha2_128s => vec![1, 1],
        }
    }

    fn proof(self, digest: &[u8; 32]) -> Vec<u8> {
        let public_key = self.public_key();
        match self {
            Self::P256 => p256_proof(digest, &public_key),
            Self::MlDsa65 => {
                use ml_dsa::{MlDsa65, Seed, SignatureEncoding, Signer, SigningKey};
                let seed = Seed::try_from(&[0x42u8; 32][..]).expect("ML-DSA seed");
                let signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
                let signature = signing_key.sign(digest);
                encode_public_key_proof(&public_key, signature.to_bytes().as_ref())
                    .expect("ML-DSA proof")
            }
            Self::SlhDsaSha2_128s => {
                use slh_dsa::{signature::Signer, Sha2_128s, SigningKey};
                let signing_key = SigningKey::<Sha2_128s>::slh_keygen_internal(
                    &[0x11; 16],
                    &[0x22; 16],
                    &[0x33; 16],
                );
                let signature = signing_key.sign(digest);
                encode_public_key_proof(&public_key, signature.to_bytes().as_ref())
                    .expect("SLH-DSA proof")
            }
        }
    }
}

#[derive(Clone)]
struct StoryAuth {
    slot: u16,
    kind: Kind,
    verifier_hash: [u8; 32],
}

impl StoryAuth {
    fn state_entry(&self) -> Authenticator {
        let public_key = self.kind.public_key();
        Authenticator {
            slot: self.slot,
            algorithm_id: self.kind.algorithm_id(),
            capabilities: CAP_SPEND | CAP_ROTATE | CAP_RECOVERY,
            weight: 1,
            verifier_hash_type: 0,
            verifier_abi: VERIFIER_ABI_V1,
            verifier_code_hash: self.verifier_hash,
            key_id: ckb_hash(&public_key),
            aux: self.kind.aux(),
        }
    }
}

fn binary(name: &str) -> Bytes {
    let target = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../target/riscv64imac-unknown-none-elf/release")
        .join(name);
    fs::read(&target)
        .unwrap_or_else(|error| panic!("read {}: {error}", target.display()))
        .into()
}

fn base64url(input: &[u8; 32]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = Vec::with_capacity(43);
    for chunk in input[..30].chunks_exact(3) {
        let value = (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);
        output.push(TABLE[((value >> 18) & 63) as usize]);
        output.push(TABLE[((value >> 12) & 63) as usize]);
        output.push(TABLE[((value >> 6) & 63) as usize]);
        output.push(TABLE[(value & 63) as usize]);
    }
    let value = (u32::from(input[30]) << 16) | (u32::from(input[31]) << 8);
    output.push(TABLE[((value >> 18) & 63) as usize]);
    output.push(TABLE[((value >> 12) & 63) as usize]);
    output.push(TABLE[((value >> 6) & 63) as usize]);
    String::from_utf8(output).expect("base64url ASCII")
}

fn p256_proof(digest: &[u8; 32], public_key: &[u8]) -> Vec<u8> {
    use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};

    let signing_key = SigningKey::from_slice(&[7u8; 32]).expect("P-256 key");
    let rp_id_hash: [u8; 32] = Sha256::digest(b"account.example").into();
    let client_data = format!(
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"{}\",\"crossOrigin\":false}}",
        base64url(digest),
        core::str::from_utf8(ORIGIN).expect("origin")
    )
    .into_bytes();
    let mut authenticator_data = Vec::with_capacity(37);
    authenticator_data.extend_from_slice(&rp_id_hash);
    authenticator_data.push(0x05);
    authenticator_data.extend_from_slice(&0u32.to_be_bytes());
    let client_hash = Sha256::digest(&client_data);
    let mut signed = Sha256::new();
    signed.update(&authenticator_data);
    signed.update(client_hash);
    let signature: Signature = signing_key
        .sign_prehash(&signed.finalize())
        .expect("P-256 signature");
    let der = signature.to_der();
    let mut proof = Vec::new();
    proof.extend_from_slice(public_key);
    proof.push(u8::try_from(ORIGIN.len()).expect("origin length"));
    proof.extend_from_slice(ORIGIN);
    proof.extend_from_slice(
        &u16::try_from(authenticator_data.len())
            .expect("authenticator data length")
            .to_le_bytes(),
    );
    proof.extend_from_slice(&authenticator_data);
    proof.extend_from_slice(
        &u16::try_from(client_data.len())
            .expect("client data length")
            .to_le_bytes(),
    );
    proof.extend_from_slice(&client_data);
    proof.extend_from_slice(
        &u16::try_from(der.as_bytes().len())
            .expect("DER length")
            .to_le_bytes(),
    );
    proof.extend_from_slice(der.as_bytes());
    proof
}

struct StoryEnv {
    context: Context,
    account_out_point: OutPoint,
    always_success_out_point: OutPoint,
    funding_out_point: OutPoint,
    verifier_out_points: Vec<OutPoint>,
    account_lock: Script,
    state_type: Script,
    account_id: [u8; 32],
    lock_args: Bytes,
    p256_hash: [u8; 32],
    ml_hash: [u8; 32],
    upgraded_ml_hash: [u8; 32],
    slh_hash: [u8; 32],
}

impl StoryEnv {
    fn new() -> Self {
        let mut context = Context::new_with_deterministic_rng();
        let account_out_point = context.deploy_cell(binary("account-lock"));
        let always_success_out_point =
            context.deploy_cell(ckb_testtool::builtin::ALWAYS_SUCCESS.clone());
        let always_success_lock = context
            .build_script_with_hash_type(
                &always_success_out_point,
                ScriptHashType::Data2,
                Bytes::new(),
            )
            .expect("always-success lock");
        let funding_out_point = context.create_cell(
            CellOutput::new_builder()
                .capacity(120_000_000_000u64)
                .lock(always_success_lock)
                .build(),
            Bytes::new(),
        );
        let p256 = binary("verifier-p256");
        let ml = binary("verifier-mldsa-adapter");
        let slh = binary("verifier-slhdsa-adapter");
        let p256_hash = CellOutput::calc_data_hash(&p256).unpack();
        let ml_hash = CellOutput::calc_data_hash(&ml).unpack();
        let slh_hash = CellOutput::calc_data_hash(&slh).unpack();
        let p256_out_point = context.deploy_cell(p256);
        let ml_out_point = context.deploy_cell(ml.clone());
        let slh_out_point = context.deploy_cell(slh);
        let mut upgraded_ml = ml.to_vec();
        upgraded_ml.push(0);
        let upgraded_ml = Bytes::from(upgraded_ml);
        let upgraded_ml_hash = CellOutput::calc_data_hash(&upgraded_ml).unpack();
        let upgraded_ml_out_point = context.deploy_cell(upgraded_ml);
        let creation_input = CellInput::new_builder()
            .previous_output(funding_out_point.clone())
            .build();
        let mut type_id_args = [0u8; 32];
        let mut hasher = new_blake2b();
        hasher.update(creation_input.as_slice());
        hasher.update(&0u64.to_le_bytes());
        hasher.finalize(&mut type_id_args);
        let state_type = Script::new_builder()
            .code_hash(ckb_testtool::ckb_chain_spec::consensus::TYPE_ID_CODE_HASH.pack())
            .hash_type(ScriptHashType::Type)
            .args(type_id_args.as_slice().pack())
            .build();
        let account_id: [u8; 32] = state_type.calc_script_hash().unpack();
        let mut args = vec![1];
        args.extend_from_slice(&account_id);
        let lock_args = Bytes::from(args);
        let account_lock = context
            .build_script_with_hash_type(
                &account_out_point,
                ScriptHashType::Data2,
                lock_args.clone(),
            )
            .expect("account lock");
        Self {
            context,
            account_out_point,
            always_success_out_point,
            funding_out_point,
            verifier_out_points: vec![
                p256_out_point,
                ml_out_point,
                upgraded_ml_out_point,
                slh_out_point,
            ],
            account_lock,
            state_type,
            account_id,
            lock_args,
            p256_hash,
            ml_hash,
            upgraded_ml_hash,
            slh_hash,
        }
    }

    fn state(
        &self,
        sequence: u64,
        spend_threshold: u16,
        rotate_threshold: u16,
        recovery_since: u64,
        authenticators: &[StoryAuth],
    ) -> AccountState {
        AccountState {
            flags: STATE_FLAG_RECOVERY_ENABLED,
            sequence,
            spend_threshold,
            rotate_threshold,
            recovery_threshold: 1,
            recovery_since,
            authenticators: authenticators.iter().map(StoryAuth::state_entry).collect(),
        }
    }

    fn register_output(&mut self, transaction: &TransactionView, index: usize) -> OutPoint {
        let out_point = OutPoint::new_builder()
            .tx_hash(transaction.hash())
            .index(u32::try_from(index).expect("output index"))
            .build();
        let output = transaction.output(index).expect("registered output");
        let data = transaction
            .outputs_data()
            .get(index)
            .expect("registered output data")
            .raw_data();
        self.context
            .create_cell_with_out_point(out_point.clone(), output, data);
        out_point
    }

    fn create_account(&mut self, state: &AccountState) -> (OutPoint, OutPoint) {
        let state_data = encode_state(state).expect("initial state");
        let transaction = TransactionBuilder::default()
            .input(
                CellInput::new_builder()
                    .previous_output(self.funding_out_point.clone())
                    .build(),
            )
            .output(
                CellOutput::new_builder()
                    .capacity(100_000_000_000u64)
                    .lock(self.account_lock.clone())
                    .type_(Some(self.state_type.clone()).pack())
                    .build(),
            )
            .output(
                CellOutput::new_builder()
                    .capacity(20_000_000_000u64)
                    .lock(self.account_lock.clone())
                    .build(),
            )
            .output_data(Bytes::from(state_data).pack())
            .output_data(Bytes::from_static(b"asset").pack())
            .cell_dep(
                CellDep::new_builder()
                    .out_point(self.always_success_out_point.clone())
                    .build(),
            )
            .build();
        self.context
            .verify_tx(&transaction, MAX_CYCLES)
            .expect("Type ID account creation in CKB-VM");
        for output in transaction.outputs() {
            assert_eq!(output.lock().args().raw_data(), self.lock_args);
        }
        let state_out_point = self.register_output(&transaction, 0);
        let asset_out_point = self.register_output(&transaction, 1);
        (state_out_point, asset_out_point)
    }

    fn code_deps(&self, mut builder: TransactionBuilder) -> TransactionBuilder {
        builder = builder.cell_dep(
            CellDep::new_builder()
                .out_point(self.account_out_point.clone())
                .build(),
        );
        for out_point in &self.verifier_out_points {
            builder = builder.cell_dep(CellDep::new_builder().out_point(out_point.clone()).build());
        }
        builder
    }

    fn signed_witness(
        &self,
        transaction: &TransactionView,
        provisional: Bytes,
        operation: u8,
        state: &AccountState,
        state_data: &[u8],
        signers: &[StoryAuth],
    ) -> Bytes {
        let tx_hash = transaction.hash().unpack();
        let sighash = group_sighash(&tx_hash, &[provisional], &[]).expect("group sighash");
        let digest = authorization_digest(
            operation,
            &self.account_id,
            state.sequence,
            state_data,
            &sighash,
        )
        .expect("authorization digest");
        let proofs = signers
            .iter()
            .map(|auth| Proof {
                slot: auth.slot,
                bytes: auth.kind.proof(&digest),
            })
            .collect::<Vec<_>>();
        WitnessArgs::new_builder()
            .lock(
                Some(Bytes::from(
                    encode_witness(operation, state.sequence, &proofs).expect("signed witness"),
                ))
                .pack(),
            )
            .build()
            .as_bytes()
    }

    fn provisional_witness(operation: u8, state: &AccountState, signers: &[StoryAuth]) -> Bytes {
        let proofs = signers
            .iter()
            .map(|auth| Proof {
                slot: auth.slot,
                bytes: vec![1],
            })
            .collect::<Vec<_>>();
        WitnessArgs::new_builder()
            .lock(
                Some(Bytes::from(
                    encode_witness(operation, state.sequence, &proofs)
                        .expect("provisional witness"),
                ))
                .pack(),
            )
            .build()
            .as_bytes()
    }

    fn spend(
        &mut self,
        state: &AccountState,
        state_out_point: &OutPoint,
        asset_out_point: &OutPoint,
        signers: &[StoryAuth],
        should_pass: bool,
    ) -> OutPoint {
        let state_data = encode_state(state).expect("state");
        let provisional = Self::provisional_witness(OP_SPEND, state, signers);
        let builder = TransactionBuilder::default()
            .input(
                CellInput::new_builder()
                    .previous_output(asset_out_point.clone())
                    .build(),
            )
            .output(
                CellOutput::new_builder()
                    .capacity(20_000_000_000u64)
                    .lock(self.account_lock.clone())
                    .build(),
            )
            .output_data(Bytes::from_static(b"asset").pack())
            .cell_dep(
                CellDep::new_builder()
                    .out_point(state_out_point.clone())
                    .build(),
            )
            .witness(provisional.clone().pack());
        let transaction = self.code_deps(builder).build();
        let witness = self.signed_witness(
            &transaction,
            provisional,
            OP_SPEND,
            state,
            &state_data,
            signers,
        );
        let transaction = transaction
            .as_advanced_builder()
            .set_witnesses(vec![witness.pack()])
            .build();
        assert_eq!(
            transaction
                .output(0)
                .expect("asset output")
                .lock()
                .args()
                .raw_data(),
            self.lock_args
        );
        let result = self.context.verify_tx(&transaction, MAX_CYCLES);
        assert_eq!(result.is_ok(), should_pass);
        if should_pass {
            self.register_output(&transaction, 0)
        } else {
            asset_out_point.clone()
        }
    }

    fn transition(
        &mut self,
        operation_and_since: (u8, u64),
        current: &AccountState,
        current_out_point: &OutPoint,
        successor: &AccountState,
        signers: &[StoryAuth],
        should_pass: bool,
    ) -> OutPoint {
        let (operation, since) = operation_and_since;
        let current_data = encode_state(current).expect("current state");
        let successor_data = encode_state(successor).expect("successor state");
        let provisional = Self::provisional_witness(operation, current, signers);
        let builder = TransactionBuilder::default()
            .input(
                CellInput::new_builder()
                    .since(since)
                    .previous_output(current_out_point.clone())
                    .build(),
            )
            .output(
                CellOutput::new_builder()
                    .capacity(100_000_000_000u64)
                    .lock(self.account_lock.clone())
                    .type_(Some(self.state_type.clone()).pack())
                    .build(),
            )
            .output_data(Bytes::from(successor_data).pack())
            .witness(provisional.clone().pack());
        let transaction = self.code_deps(builder).build();
        let witness = self.signed_witness(
            &transaction,
            provisional,
            operation,
            current,
            &current_data,
            signers,
        );
        let transaction = transaction
            .as_advanced_builder()
            .set_witnesses(vec![witness.pack()])
            .build();
        assert_eq!(
            transaction
                .output(0)
                .expect("state output")
                .lock()
                .args()
                .raw_data(),
            self.lock_args
        );
        let result = self.context.verify_tx(&transaction, MAX_CYCLES);
        assert_eq!(result.is_ok(), should_pass);
        if should_pass {
            self.register_output(&transaction, 0)
        } else {
            current_out_point.clone()
        }
    }
}

#[test]
fn complete_crypto_migration_recovery_and_verifier_upgrade_story_runs_in_ckb_vm() {
    let mut env = StoryEnv::new();
    let p256 = StoryAuth {
        slot: 1,
        kind: Kind::P256,
        verifier_hash: env.p256_hash,
    };
    let ml = StoryAuth {
        slot: 2,
        kind: Kind::MlDsa65,
        verifier_hash: env.ml_hash,
    };
    let slh = StoryAuth {
        slot: 3,
        kind: Kind::SlhDsaSha2_128s,
        verifier_hash: env.slh_hash,
    };

    let state0 = env.state(0, 1, 1, 100, core::slice::from_ref(&p256));
    let (mut state_out_point, mut asset_out_point) = env.create_account(&state0);
    asset_out_point = env.spend(
        &state0,
        &state_out_point,
        &asset_out_point,
        core::slice::from_ref(&p256),
        true,
    );

    let state1 = env.state(1, 2, 2, 100, &[p256.clone(), ml.clone()]);
    state_out_point = env.transition(
        (OP_ROTATE, 0),
        &state0,
        &state_out_point,
        &state1,
        core::slice::from_ref(&p256),
        true,
    );
    env.spend(
        &state1,
        &state_out_point,
        &asset_out_point,
        core::slice::from_ref(&p256),
        false,
    );
    env.spend(
        &state1,
        &state_out_point,
        &asset_out_point,
        core::slice::from_ref(&ml),
        false,
    );
    asset_out_point = env.spend(
        &state1,
        &state_out_point,
        &asset_out_point,
        &[p256.clone(), ml.clone()],
        true,
    );

    let state2 = env.state(2, 1, 2, 100, &[ml.clone(), slh.clone()]);
    state_out_point = env.transition(
        (OP_ROTATE, 0),
        &state1,
        &state_out_point,
        &state2,
        &[p256.clone(), ml.clone()],
        true,
    );
    asset_out_point = env.spend(
        &state2,
        &state_out_point,
        &asset_out_point,
        core::slice::from_ref(&ml),
        true,
    );
    asset_out_point = env.spend(
        &state2,
        &state_out_point,
        &asset_out_point,
        core::slice::from_ref(&slh),
        true,
    );

    let upgraded_ml = StoryAuth {
        verifier_hash: env.upgraded_ml_hash,
        ..ml.clone()
    };
    let state3 = env.state(3, 1, 2, 100, &[upgraded_ml.clone(), slh.clone()]);
    env.transition(
        (OP_ROTATE, 0),
        &state2,
        &state_out_point,
        &state3,
        core::slice::from_ref(&ml),
        false,
    );
    state_out_point = env.transition(
        (OP_ROTATE, 0),
        &state2,
        &state_out_point,
        &state3,
        &[ml.clone(), slh.clone()],
        true,
    );
    asset_out_point = env.spend(
        &state3,
        &state_out_point,
        &asset_out_point,
        core::slice::from_ref(&upgraded_ml),
        true,
    );

    let recovered = env.state(4, 1, 1, 100, core::slice::from_ref(&p256));
    env.transition(
        (OP_RECOVERY, 99),
        &state3,
        &state_out_point,
        &recovered,
        core::slice::from_ref(&slh),
        false,
    );
    state_out_point = env.transition(
        (OP_RECOVERY, 100),
        &state3,
        &state_out_point,
        &recovered,
        core::slice::from_ref(&slh),
        true,
    );
    env.spend(
        &recovered,
        &state_out_point,
        &asset_out_point,
        core::slice::from_ref(&p256),
        true,
    );
}
