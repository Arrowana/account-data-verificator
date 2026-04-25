use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::OnceLock,
};

use account_data_verificator::{
    build_verify_slice_instruction_data, VerifierError, VerifySliceArgs,
};
use litesvm::LiteSVM;
use sha2::{Digest, Sha256};
use solana_account::Account;
use solana_address::Address;
use solana_compute_budget::compute_budget_limits::MAX_COMPUTE_UNIT_LIMIT;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::{account_meta::AccountMeta, error::InstructionError, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;

const TEST_LAMPORTS: u64 = 10_000_000_000;
const PREFIX_LEN: usize = 8;
const MAX_TEST_OFFSET: usize = 0;
const MAX_SEARCH_BYTES: usize = 8 * 1024 * 1024;
const SHA256_BASE_COST: u64 = 85;
const SHA256_BYTES_PER_COMPUTE_UNIT: usize = 2;

static PROGRAM_SO_PATH: OnceLock<PathBuf> = OnceLock::new();

#[test]
fn verifies_a_slice_and_rejects_a_tampered_hash() {
    let (mut svm, payer) = test_vm();
    let target = Address::new_unique();

    let mut account_data = b"header--payload-for-sha256".to_vec();
    let expected_hash = sha256(&account_data[PREFIX_LEN..]);

    svm.set_account(
        target,
        Account {
            lamports: 1_000_000,
            data: account_data.clone(),
            owner: Address::new_unique(),
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();

    let ok_meta = send_verify_slice(
        &mut svm,
        &payer,
        target,
        PREFIX_LEN as u32,
        expected_hash,
        None,
    )
    .unwrap();
    assert!(ok_meta.compute_units_consumed > 0);

    let extra_data_payer = Keypair::new();
    svm.airdrop(&extra_data_payer.pubkey(), TEST_LAMPORTS)
        .unwrap();
    account_data.push(0xff);
    svm.set_account(
        target,
        Account {
            lamports: 1_000_000,
            data: account_data.clone(),
            owner: Address::new_unique(),
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();

    let extra_data_err = send_verify_slice(
        &mut svm,
        &extra_data_payer,
        target,
        PREFIX_LEN as u32,
        expected_hash,
        None,
    )
    .unwrap_err();

    assert_eq!(
        extra_data_err.err,
        TransactionError::InstructionError(
            0,
            InstructionError::Custom(VerifierError::HashMismatch as u32),
        )
    );

    account_data[PREFIX_LEN] ^= 1;
    let tamper_payer = Keypair::new();
    svm.airdrop(&tamper_payer.pubkey(), TEST_LAMPORTS).unwrap();
    svm.set_account(
        target,
        Account {
            lamports: 1_000_000,
            data: account_data,
            owner: Address::new_unique(),
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();

    let err = send_verify_slice(
        &mut svm,
        &tamper_payer,
        target,
        PREFIX_LEN as u32,
        expected_hash,
        None,
    )
    .unwrap_err();

    assert_eq!(
        err.err,
        TransactionError::InstructionError(
            0,
            InstructionError::Custom(VerifierError::HashMismatch as u32),
        )
    );
}

#[test]
fn finds_the_largest_hashable_payload_within_max_compute_budget() {
    let (mut svm, payer) = test_vm();
    let target = Address::new_unique();

    let mut low = 1usize;
    let mut high = 1024usize;
    let mut best = run_size(&mut svm, &payer, target, low);

    if !matches!(best, RunResult::Success { .. }) {
        panic!("expected a 1-byte payload to fit within the compute budget");
    }

    loop {
        match run_size(&mut svm, &payer, target, high) {
            RunResult::Success {
                compute_units_consumed,
            } => {
                low = high;
                best = RunResult::Success {
                    compute_units_consumed,
                };

                if high == MAX_SEARCH_BYTES {
                    panic!(
                        "search cap of {MAX_SEARCH_BYTES} bytes was reached before compute exhaustion"
                    );
                }

                high = high.saturating_mul(2).min(MAX_SEARCH_BYTES);
            }
            RunResult::ComputeBudgetExceeded => break,
            RunResult::OtherError(err) => panic!("unexpected transaction failure: {err:?}"),
        }
    }

    while low + 1 < high {
        let mid = low + ((high - low) / 2);

        match run_size(&mut svm, &payer, target, mid) {
            RunResult::Success {
                compute_units_consumed,
            } => {
                low = mid;
                best = RunResult::Success {
                    compute_units_consumed,
                };
            }
            RunResult::ComputeBudgetExceeded => {
                high = mid;
            }
            RunResult::OtherError(err) => panic!("unexpected transaction failure: {err:?}"),
        }
    }

    let RunResult::Success {
        compute_units_consumed,
    } = best
    else {
        panic!("expected a successful run after search");
    };

    println!(
        "max verified payload at {MAX_COMPUTE_UNIT_LIMIT} CU: {low} bytes, consumed {compute_units_consumed} CU"
    );
    let sha256_math_limit = theoretical_sha256_payload_limit();
    let sha256_overhead_bytes = sha256_math_limit - low;
    println!(
        "LiteSVM matches the SHA-256 syscall math: pure hash cost allows about {sha256_math_limit} bytes, and the remaining {sha256_overhead_bytes} bytes are consumed by fixed instruction overhead"
    );

    assert!(compute_units_consumed <= u64::from(MAX_COMPUTE_UNIT_LIMIT));
    assert!(low <= sha256_math_limit);
    assert!(
        sha256_overhead_bytes < 1024,
        "expected the LiteSVM boundary to stay within 1 KiB of the SHA-256-only limit"
    );
    let boundary_probe_payer = Keypair::new();
    svm.airdrop(&boundary_probe_payer.pubkey(), TEST_LAMPORTS)
        .unwrap();
    assert!(matches!(
        run_size(&mut svm, &boundary_probe_payer, target, high),
        RunResult::ComputeBudgetExceeded
    ));
}

enum RunResult {
    Success { compute_units_consumed: u64 },
    ComputeBudgetExceeded,
    OtherError(litesvm::types::FailedTransactionMetadata),
}

fn run_size(svm: &mut LiteSVM, payer: &Keypair, target: Address, payload_len: usize) -> RunResult {
    let mut data = vec![0u8; MAX_TEST_OFFSET + payload_len];
    for (index, byte) in data[MAX_TEST_OFFSET..].iter_mut().enumerate() {
        *byte = (index % 251) as u8;
    }

    let expected_hash = sha256(&data[MAX_TEST_OFFSET..]);

    svm.set_account(
        target,
        Account {
            lamports: 1_000_000,
            data,
            owner: Address::new_unique(),
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();

    match send_verify_slice(
        svm,
        payer,
        target,
        MAX_TEST_OFFSET as u32,
        expected_hash,
        Some(MAX_COMPUTE_UNIT_LIMIT),
    ) {
        Ok(meta) => RunResult::Success {
            compute_units_consumed: meta.compute_units_consumed,
        },
        Err(err) if is_compute_budget_exceeded(&err) => RunResult::ComputeBudgetExceeded,
        Err(err) => RunResult::OtherError(err),
    }
}

fn send_verify_slice(
    svm: &mut LiteSVM,
    payer: &Keypair,
    target: Address,
    start_offset: u32,
    expected_hash: [u8; 32],
    compute_unit_limit: Option<u32>,
) -> litesvm::types::TransactionResult {
    let mut instructions = Vec::new();

    if let Some(limit) = compute_unit_limit {
        instructions.push(ComputeBudgetInstruction::set_compute_unit_limit(limit));
    }

    let data = build_verify_slice_instruction_data(&VerifySliceArgs {
        start_offset,
        expected_sha256: expected_hash,
    });

    instructions.push(Instruction {
        program_id: program_id(),
        accounts: vec![AccountMeta {
            pubkey: target,
            is_signer: false,
            is_writable: false,
        }],
        data: data.to_vec(),
    });

    let tx = Transaction::new(
        &[payer],
        Message::new(&instructions, Some(&payer.pubkey())),
        svm.latest_blockhash(),
    );

    svm.send_transaction(tx)
}

fn test_vm() -> (LiteSVM, Keypair) {
    let program_id = program_id();
    let mut svm = LiteSVM::new();
    let payer = Keypair::new();

    svm.add_program_from_file(program_id, program_so_path())
        .unwrap();
    svm.airdrop(&payer.pubkey(), TEST_LAMPORTS).unwrap();

    (svm, payer)
}

fn program_id() -> Address {
    Address::new_from_array([
        0x61, 0x63, 0x63, 0x74, 0x2d, 0x76, 0x65, 0x72, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x6f,
        0x72, 0x2d, 0x70, 0x69, 0x6e, 0x6f, 0x63, 0x63, 0x68, 0x69, 0x6f, 0x2d, 0x73, 0x62, 0x66,
        0x2d, 0x31,
    ])
}

fn program_so_path() -> &'static Path {
    PROGRAM_SO_PATH
        .get_or_init(|| {
            let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let status = Command::new("cargo")
                .current_dir(&manifest_dir)
                .args(["build-sbf", "--features", "bpf-entrypoint"])
                .status()
                .expect("failed to invoke cargo build-sbf");

            assert!(status.success(), "cargo build-sbf failed");

            manifest_dir.join("target/deploy/account_data_verificator.so")
        })
        .as_path()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn theoretical_sha256_payload_limit() -> usize {
    ((u64::from(MAX_COMPUTE_UNIT_LIMIT) - SHA256_BASE_COST) * SHA256_BYTES_PER_COMPUTE_UNIT as u64)
        as usize
}

fn is_compute_budget_exceeded(error: &litesvm::types::FailedTransactionMetadata) -> bool {
    match error.err {
        TransactionError::InstructionError(_, InstructionError::ComputationalBudgetExceeded) => {
            true
        }
        TransactionError::InstructionError(_, InstructionError::ProgramFailedToComplete) => {
            error.meta.logs.iter().any(|log| {
                log.contains("exceeded CUs meter") || log.contains("Computational budget exceeded")
            })
        }
        _ => false,
    }
}
