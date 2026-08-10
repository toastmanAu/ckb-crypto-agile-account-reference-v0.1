#[cfg(test)]
mod vm {
    use ckb_account_host::{
        authorization_digest, ckb_hash, encode_public_key_proof, encode_state, encode_witness,
        group_sighash, AccountState, Authenticator, Proof,
    };
    use ckb_account_protocol::{
        ALG_MLDSA65, ALG_P256_WEBAUTHN, ALG_SLHDSA, CAP_RECOVERY, CAP_ROTATE, CAP_SPEND,
        OP_RECOVERY, OP_ROTATE, OP_SPEND, STATE_FLAG_RECOVERY_ENABLED, VERIFIER_ABI_V1,
    };
    use ckb_testtool::{
        ckb_types::{
            bytes::Bytes,
            core::{DepType, ScriptHashType, TransactionBuilder},
            packed::{CellDep, CellInput, CellOutput, Script, WitnessArgs},
            prelude::*,
        },
        context::Context,
    };
    use std::{fs, path::PathBuf};

    const MAX_CYCLES: u64 = 500_000_000;

    fn type_id_script() -> Script {
        Script::new_builder()
            .code_hash(ckb_testtool::ckb_chain_spec::consensus::TYPE_ID_CODE_HASH.pack())
            .hash_type(ScriptHashType::Type)
            .args([0xa5u8; 32].as_slice().pack())
            .build()
    }

    fn binary(name: &str) -> Bytes {
        let target = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../target/riscv64imac-unknown-none-elf/release")
            .join(name);
        let path = if target.exists() {
            target
        } else {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../target/riscv64imac-unknown-none-elf/debug")
                .join(name)
        };
        fs::read(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
            .into()
    }

    struct SpendFixture {
        context: Context,
        tx: ckb_testtool::ckb_types::core::TransactionView,
        lock_args: Bytes,
    }

    fn write_debug_vector(name: &str, fixture: &SpendFixture) {
        if std::env::var_os("CKB_UPDATE_DEBUG_VECTORS").is_none() {
            return;
        }
        let dump = fixture
            .context
            .dump_tx(&fixture.tx)
            .expect("dump transaction");
        let vectors = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vectors");
        fs::create_dir_all(&vectors).expect("create vectors directory");
        fs::write(
            vectors.join(name),
            serde_json::to_vec_pretty(&dump).expect("serialize transaction"),
        )
        .expect("write transaction vector");
    }

    fn spend_fixture(proof: &[u8]) -> SpendFixture {
        let mut context = Context::new_with_deterministic_rng();
        let account_out_point = context.deploy_cell(binary("account-lock"));
        let verifier_binary = binary("verifier-fixture");
        let verifier_hash = CellOutput::calc_data_hash(&verifier_binary);
        let verifier_out_point = context.deploy_cell(verifier_binary);

        let state_type = type_id_script();
        let account_id: [u8; 32] = state_type.calc_script_hash().unpack();
        let mut args = Vec::with_capacity(33);
        args.push(1);
        args.extend_from_slice(&account_id);
        let lock_args = Bytes::from(args);
        let account_lock = context
            .build_script_with_hash_type(
                &account_out_point,
                ScriptHashType::Data2,
                lock_args.clone(),
            )
            .expect("account lock");

        let state_data = encode_state(&AccountState {
            flags: 0,
            sequence: 0,
            spend_threshold: 1,
            rotate_threshold: 1,
            recovery_threshold: 0,
            recovery_since: 0,
            authenticators: vec![Authenticator {
                slot: 1,
                algorithm_id: ALG_P256_WEBAUTHN,
                capabilities: CAP_SPEND | CAP_ROTATE,
                weight: 1,
                verifier_hash_type: 0,
                verifier_abi: VERIFIER_ABI_V1,
                verifier_code_hash: verifier_hash.unpack(),
                key_id: [3; 32],
                aux: vec![if proof == b"fixture-valid" { 1 } else { 2 }],
            }],
        })
        .expect("state");
        let state_out_point = context.create_cell(
            CellOutput::new_builder()
                .capacity(10_000u64)
                .lock(account_lock.clone())
                .type_(Some(state_type).pack())
                .build(),
            Bytes::from(state_data),
        );
        let asset_out_point = context.create_cell(
            CellOutput::new_builder()
                .capacity(10_000u64)
                .lock(account_lock.clone())
                .build(),
            Bytes::from_static(b"asset"),
        );
        let output = CellOutput::new_builder()
            .capacity(10_000u64)
            .lock(account_lock)
            .build();
        let account_witness = encode_witness(
            OP_SPEND,
            0,
            &[Proof {
                slot: 1,
                bytes: proof.to_vec(),
            }],
        )
        .expect("witness");
        let witness = WitnessArgs::new_builder()
            .lock(Some(Bytes::from(account_witness)).pack())
            .build()
            .as_bytes();
        let tx = TransactionBuilder::default()
            .input(
                CellInput::new_builder()
                    .previous_output(asset_out_point)
                    .build(),
            )
            .output(output)
            .output_data(Bytes::from_static(b"asset").pack())
            .cell_dep(
                CellDep::new_builder()
                    .out_point(state_out_point)
                    .dep_type(DepType::Code)
                    .build(),
            )
            .cell_dep(
                CellDep::new_builder()
                    .out_point(verifier_out_point)
                    .dep_type(DepType::Code)
                    .build(),
            )
            .witness(witness.pack())
            .build();
        let tx = context.complete_tx(tx);
        SpendFixture {
            context,
            tx,
            lock_args,
        }
    }

    #[test]
    fn fixture_verifier_runs_through_ckb2023_spawn_pipe() {
        let fixture = spend_fixture(b"fixture-valid");
        write_debug_vector("fixture-spend.json", &fixture);
        let output_args = fixture.tx.output(0).unwrap().lock().args().raw_data();
        assert_eq!(output_args, fixture.lock_args);
        let cycles = fixture
            .context
            .verify_tx(&fixture.tx, MAX_CYCLES)
            .expect("CKB-VM spend with child verifier");
        println!("fixture spend cycles: {cycles}");
        assert!(cycles > 0);
    }

    #[test]
    fn nonzero_child_exit_contributes_no_weight() {
        let fixture = spend_fixture(b"fixture-invalid");
        write_debug_vector("fixture-invalid-spend.json", &fixture);
        assert!(fixture.context.verify_tx(&fixture.tx, MAX_CYCLES).is_err());
    }

    #[test]
    fn foreign_type_id_state_substitution_fails_in_ckb_vm() {
        let mut fixture = spend_fixture(b"fixture-valid");
        let mut deps = fixture.tx.cell_deps().into_iter().collect::<Vec<_>>();
        let state_dep_index = deps
            .iter()
            .position(|dep| {
                fixture
                    .context
                    .get_cell(&dep.out_point())
                    .is_some_and(|(_, data)| data.starts_with(b"CKAS"))
            })
            .expect("state cell dep");
        let state_out_point = deps[state_dep_index].out_point();
        let (state_cell, state_data) = fixture
            .context
            .get_cell(&state_out_point)
            .expect("state cell");
        let foreign_type = Script::new_builder()
            .code_hash(ckb_testtool::ckb_chain_spec::consensus::TYPE_ID_CODE_HASH.pack())
            .hash_type(ScriptHashType::Type)
            .args([0x5au8; 32].as_slice().pack())
            .build();
        let foreign_out_point = fixture.context.create_cell(
            state_cell
                .as_builder()
                .type_(Some(foreign_type).pack())
                .build(),
            state_data,
        );
        deps[state_dep_index] = CellDep::new_builder().out_point(foreign_out_point).build();
        let substituted = fixture.tx.as_advanced_builder().set_cell_deps(deps).build();
        assert!(fixture.context.verify_tx(&substituted, MAX_CYCLES).is_err());
    }

    #[test]
    fn unknown_state_flags_algorithm_and_verifier_abi_fail_in_ckb_vm() {
        let mut fixture = spend_fixture(b"fixture-valid");
        let original_deps = fixture.tx.cell_deps().into_iter().collect::<Vec<_>>();
        let state_dep_index = original_deps
            .iter()
            .position(|dep| {
                fixture
                    .context
                    .get_cell(&dep.out_point())
                    .is_some_and(|(_, data)| data.starts_with(b"CKAS"))
            })
            .expect("state cell dep");
        let (state_cell, state_data) = fixture
            .context
            .get_cell(&original_deps[state_dep_index].out_point())
            .expect("state cell");

        let mut unknown_flags = state_data.to_vec();
        unknown_flags[5] = 0x80;
        let mut unknown_algorithm = state_data.to_vec();
        unknown_algorithm[36..38].copy_from_slice(&0xffffu16.to_le_bytes());
        let mut unknown_abi = state_data.to_vec();
        unknown_abi[43] = 2;

        for (family, invalid_state) in [
            ("flags", unknown_flags),
            ("algorithm", unknown_algorithm),
            ("verifier ABI", unknown_abi),
        ] {
            let invalid_out_point = fixture
                .context
                .create_cell(state_cell.clone(), Bytes::from(invalid_state));
            let mut deps = original_deps.clone();
            deps[state_dep_index] = CellDep::new_builder().out_point(invalid_out_point).build();
            let transaction = fixture.tx.as_advanced_builder().set_cell_deps(deps).build();
            assert!(
                fixture.context.verify_tx(&transaction, MAX_CYCLES).is_err(),
                "accepted unknown {family}"
            );
        }
    }

    fn cryptographic_spend(
        verifier_name: &str,
        algorithm_id: u16,
        aux: Vec<u8>,
        public_key: &[u8],
        sign: impl FnOnce(&[u8; 32]) -> Vec<u8>,
    ) -> (
        Context,
        ckb_testtool::ckb_types::core::TransactionView,
        Bytes,
    ) {
        let mut context = Context::new_with_deterministic_rng();
        let account_out_point = context.deploy_cell(binary("account-lock"));
        let verifier_binary = binary(verifier_name);
        let verifier_hash = CellOutput::calc_data_hash(&verifier_binary);
        let verifier_out_point = context.deploy_cell(verifier_binary);
        let state_type = type_id_script();
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
        let state_data = encode_state(&AccountState {
            flags: 0,
            sequence: 0,
            spend_threshold: 1,
            rotate_threshold: 1,
            recovery_threshold: 0,
            recovery_since: 0,
            authenticators: vec![Authenticator {
                slot: 1,
                algorithm_id,
                capabilities: CAP_SPEND | CAP_ROTATE,
                weight: 1,
                verifier_hash_type: 0,
                verifier_abi: 1,
                verifier_code_hash: verifier_hash.unpack(),
                key_id: ckb_hash(public_key),
                aux,
            }],
        })
        .expect("state");
        let state_out_point = context.create_cell(
            CellOutput::new_builder()
                .capacity(10_000u64)
                .lock(account_lock.clone())
                .type_(Some(state_type).pack())
                .build(),
            Bytes::from(state_data.clone()),
        );
        let asset_out_point = context.create_cell(
            CellOutput::new_builder()
                .capacity(10_000u64)
                .lock(account_lock.clone())
                .build(),
            Bytes::from_static(b"asset"),
        );
        let provisional_witness = encode_witness(
            OP_SPEND,
            0,
            &[Proof {
                slot: 1,
                bytes: vec![1],
            }],
        )
        .unwrap();
        let provisional_args = WitnessArgs::new_builder()
            .lock(Some(Bytes::from(provisional_witness)).pack())
            .build()
            .as_bytes();
        let tx = TransactionBuilder::default()
            .input(
                CellInput::new_builder()
                    .previous_output(asset_out_point)
                    .build(),
            )
            .output(
                CellOutput::new_builder()
                    .capacity(10_000u64)
                    .lock(account_lock)
                    .build(),
            )
            .output_data(Bytes::from_static(b"asset").pack())
            .cell_dep(CellDep::new_builder().out_point(state_out_point).build())
            .cell_dep(CellDep::new_builder().out_point(verifier_out_point).build())
            .witness(provisional_args.pack())
            .build();
        let tx = context.complete_tx(tx);
        let tx_hash = tx.hash().unpack();
        let sighash = group_sighash(&tx_hash, &[provisional_args], &[]).unwrap();
        let digest = authorization_digest(OP_SPEND, &account_id, 0, &state_data, &sighash).unwrap();
        let proof = sign(&digest);
        let witness = encode_witness(
            OP_SPEND,
            0,
            &[Proof {
                slot: 1,
                bytes: proof,
            }],
        )
        .unwrap();
        let witness_args = WitnessArgs::new_builder()
            .lock(Some(Bytes::from(witness)).pack())
            .build()
            .as_bytes();
        let tx = tx
            .as_advanced_builder()
            .set_witnesses(vec![witness_args.pack()])
            .build();
        (context, tx, lock_args)
    }

    #[test]
    fn mldsa65_signature_is_verified_inside_ckb_vm() {
        use ml_dsa::{KeyExport, Keypair, MlDsa65, Seed, SignatureEncoding, Signer, SigningKey};

        let seed = Seed::try_from(&[0x42u8; 32][..]).unwrap();
        let signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
        let public_key = signing_key.verifying_key().to_bytes().to_vec();
        let (context, tx, args) = cryptographic_spend(
            "verifier-mldsa-adapter",
            ALG_MLDSA65,
            vec![1],
            &public_key,
            |digest| {
                let signature = signing_key.sign(digest);
                encode_public_key_proof(&public_key, signature.to_bytes().as_ref()).unwrap()
            },
        );
        assert_eq!(tx.output(0).unwrap().lock().args().raw_data(), args);
        let cycles = context
            .verify_tx(&tx, 3_500_000_000)
            .expect("ML-DSA-65 verification in CKB-VM");
        println!("ML-DSA-65 spend cycles: {cycles}");
    }

    #[test]
    fn slhdsa_sha2_128s_signature_is_verified_inside_ckb_vm() {
        use slh_dsa::{
            signature::{Keypair, Signer},
            Sha2_128s, SigningKey,
        };

        let signing_key =
            SigningKey::<Sha2_128s>::slh_keygen_internal(&[0x11; 16], &[0x22; 16], &[0x33; 16]);
        let public_key = signing_key.verifying_key().to_bytes().to_vec();
        let (context, tx, args) = cryptographic_spend(
            "verifier-slhdsa-adapter",
            ALG_SLHDSA,
            vec![1, 1],
            &public_key,
            |digest| {
                let signature = signing_key.sign(digest);
                encode_public_key_proof(&public_key, signature.to_bytes().as_ref()).unwrap()
            },
        );
        assert_eq!(tx.output(0).unwrap().lock().args().raw_data(), args);
        let cycles = context
            .verify_tx(&tx, 3_500_000_000)
            .expect("SLH-DSA SHA2-128s verification in CKB-VM");
        println!("SLH-DSA SHA2-128s spend cycles: {cycles}");
    }

    fn base64url(input: &[u8; 32]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut output = Vec::with_capacity(43);
        for chunk in input[..30].chunks_exact(3) {
            let value =
                (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);
            output.push(TABLE[((value >> 18) & 63) as usize]);
            output.push(TABLE[((value >> 12) & 63) as usize]);
            output.push(TABLE[((value >> 6) & 63) as usize]);
            output.push(TABLE[(value & 63) as usize]);
        }
        let value = (u32::from(input[30]) << 16) | (u32::from(input[31]) << 8);
        output.push(TABLE[((value >> 18) & 63) as usize]);
        output.push(TABLE[((value >> 12) & 63) as usize]);
        output.push(TABLE[((value >> 6) & 63) as usize]);
        String::from_utf8(output).unwrap()
    }

    fn webauthn_spend_fixture() -> (
        Context,
        ckb_testtool::ckb_types::core::TransactionView,
        Bytes,
    ) {
        use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
        use sha2::{Digest, Sha256};

        let signing_key = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let public_key = signing_key
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        let origin = b"https://account.example";
        let rp_id_hash: [u8; 32] = Sha256::digest(b"account.example").into();
        let mut aux = vec![1];
        aux.extend_from_slice(&rp_id_hash);
        aux.extend_from_slice(&ckb_hash(origin));
        cryptographic_spend(
            "verifier-p256",
            ALG_P256_WEBAUTHN,
            aux,
            &public_key,
            |digest| {
                let client_data = format!(
                    "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"{}\",\"crossOrigin\":false}}",
                    base64url(digest),
                    core::str::from_utf8(origin).unwrap()
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
                let signature: Signature = signing_key.sign_prehash(&signed.finalize()).unwrap();
                let der = signature.to_der();
                let mut proof = Vec::new();
                proof.extend_from_slice(&public_key);
                proof.push(origin.len() as u8);
                proof.extend_from_slice(origin);
                proof.extend_from_slice(&(authenticator_data.len() as u16).to_le_bytes());
                proof.extend_from_slice(&authenticator_data);
                proof.extend_from_slice(&(client_data.len() as u16).to_le_bytes());
                proof.extend_from_slice(&client_data);
                proof.extend_from_slice(&(der.as_bytes().len() as u16).to_le_bytes());
                proof.extend_from_slice(der.as_bytes());
                proof
            },
        )
    }

    #[test]
    fn webauthn_es256_signature_is_verified_inside_ckb_vm() {
        let (context, tx, args) = webauthn_spend_fixture();
        assert_eq!(tx.output(0).unwrap().lock().args().raw_data(), args);
        let cycles = context
            .verify_tx(&tx, 500_000_000)
            .expect("WebAuthn ES256 verification in CKB-VM");
        println!("WebAuthn ES256 spend cycles: {cycles}");
    }

    #[test]
    fn signed_transaction_mutation_families_fail_in_ckb_vm() {
        let (context, tx, _) = webauthn_spend_fixture();

        let mut inputs = tx.inputs().into_iter().collect::<Vec<_>>();
        inputs[0] = inputs[0].clone().as_builder().since(1u64).build();
        let changed_input = tx.as_advanced_builder().set_inputs(inputs).build();

        let mut outputs = tx.outputs().into_iter().collect::<Vec<_>>();
        outputs[0] = outputs[0].clone().as_builder().capacity(10_001u64).build();
        let changed_output = tx.as_advanced_builder().set_outputs(outputs).build();

        let changed_output_data = tx
            .as_advanced_builder()
            .set_outputs_data(vec![Bytes::from_static(b"mutated-asset").pack()])
            .build();

        let first_witness =
            WitnessArgs::from_slice(&tx.witnesses().get(0).unwrap().raw_data()).unwrap();
        let changed_first_witness = first_witness
            .as_builder()
            .input_type(Some(Bytes::from_static(b"mutation")).pack())
            .build()
            .as_bytes();
        let changed_witness_field = tx
            .as_advanced_builder()
            .set_witnesses(vec![changed_first_witness.pack()])
            .build();

        let mut witnesses = tx.witnesses().into_iter().collect::<Vec<_>>();
        witnesses.push(Bytes::from_static(b"extra-witness").pack());
        let added_extra_witness = tx.as_advanced_builder().set_witnesses(witnesses).build();

        for (family, transaction) in [
            ("input", changed_input),
            ("output", changed_output),
            ("output data", changed_output_data),
            ("first witness field", changed_witness_field),
            ("extra witness", added_extra_witness),
        ] {
            assert!(
                context.verify_tx(&transaction, MAX_CYCLES).is_err(),
                "accepted signed {family} mutation"
            );
        }
    }

    fn transition_fixture(
        operation: u8,
        since: u64,
        rotate_threshold: u16,
        supplied_slots: &[u16],
        include_successor: bool,
        upgrade_verifier: bool,
    ) -> (
        Context,
        ckb_testtool::ckb_types::core::TransactionView,
        Bytes,
    ) {
        let mut context = Context::new_with_deterministic_rng();
        let account_out_point = context.deploy_cell(binary("account-lock"));
        let verifier_binary = binary("verifier-fixture");
        let verifier_hash = CellOutput::calc_data_hash(&verifier_binary);
        let verifier_out_point = context.deploy_cell(verifier_binary);
        let state_type = type_id_script();
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
        let authenticator = |slot| Authenticator {
            slot,
            algorithm_id: ALG_P256_WEBAUTHN,
            capabilities: CAP_SPEND | CAP_ROTATE | CAP_RECOVERY,
            weight: 1,
            verifier_hash_type: 0,
            verifier_abi: VERIFIER_ABI_V1,
            verifier_code_hash: verifier_hash.unpack(),
            key_id: [slot as u8; 32],
            aux: vec![1],
        };
        let current = AccountState {
            flags: STATE_FLAG_RECOVERY_ENABLED,
            sequence: 7,
            spend_threshold: 1,
            rotate_threshold,
            recovery_threshold: 1,
            recovery_since: 100,
            authenticators: vec![authenticator(1), authenticator(2)],
        };
        let mut next = AccountState {
            sequence: 8,
            ..current.clone()
        };
        if upgrade_verifier {
            let upgraded_hash =
                CellOutput::calc_data_hash(&binary("verifier-mldsa-adapter")).unpack();
            for auth in &mut next.authenticators {
                auth.algorithm_id = ALG_MLDSA65;
                auth.verifier_code_hash = upgraded_hash;
                auth.key_id = [0x55; 32];
            }
        }
        let state_input = context.create_cell(
            CellOutput::new_builder()
                .capacity(10_000u64)
                .lock(account_lock.clone())
                .type_(Some(state_type.clone()).pack())
                .build(),
            Bytes::from(encode_state(&current).expect("current state")),
        );
        let witness = encode_witness(
            operation,
            current.sequence,
            &supplied_slots
                .iter()
                .map(|slot| Proof {
                    slot: *slot,
                    bytes: b"fixture-valid".to_vec(),
                })
                .collect::<Vec<_>>(),
        )
        .expect("transition witness");
        let witness_args = WitnessArgs::new_builder()
            .lock(Some(Bytes::from(witness)).pack())
            .build()
            .as_bytes();
        let mut builder = TransactionBuilder::default()
            .input(
                CellInput::new_builder()
                    .since(since)
                    .previous_output(state_input)
                    .build(),
            )
            .cell_dep(CellDep::new_builder().out_point(account_out_point).build())
            .cell_dep(CellDep::new_builder().out_point(verifier_out_point).build())
            .witness(witness_args.pack());
        if include_successor {
            builder = builder
                .output(
                    CellOutput::new_builder()
                        .capacity(10_000u64)
                        .lock(account_lock)
                        .type_(Some(state_type).pack())
                        .build(),
                )
                .output_data(Bytes::from(encode_state(&next).expect("successor state")).pack());
        }
        let tx = builder.build();
        (context, tx, lock_args)
    }

    #[test]
    fn rotation_threshold_two_requires_both_proofs_in_ckb_vm() {
        let (context, tx, _) = transition_fixture(OP_ROTATE, 0, 2, &[1], true, false);
        assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());

        let (context, tx, args) = transition_fixture(OP_ROTATE, 0, 2, &[1, 2], true, false);
        assert_eq!(tx.output(0).unwrap().lock().args().raw_data(), args);
        context
            .verify_tx(&tx, MAX_CYCLES)
            .expect("two rotation proofs satisfy threshold two");
    }

    #[test]
    fn delayed_recovery_and_state_deletion_are_enforced_in_ckb_vm() {
        let (context, tx, _) = transition_fixture(OP_RECOVERY, 99, 1, &[1], true, false);
        assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());

        let (context, tx, args) = transition_fixture(OP_RECOVERY, 100, 1, &[1], true, false);
        assert_eq!(tx.output(0).unwrap().lock().args().raw_data(), args);
        context
            .verify_tx(&tx, MAX_CYCLES)
            .expect("recovery at the configured since value");

        let (context, tx, _) = transition_fixture(OP_ROTATE, 0, 1, &[1], false, false);
        assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
    }

    #[test]
    fn rotation_can_upgrade_verifier_reference_without_changing_lock_args() {
        let (context, tx, args) = transition_fixture(OP_ROTATE, 0, 1, &[1], true, true);
        assert_eq!(tx.output(0).unwrap().lock().args().raw_data(), args);
        context
            .verify_tx(&tx, MAX_CYCLES)
            .expect("authenticated verifier reference upgrade");
    }
}

#[cfg(test)]
mod story;
