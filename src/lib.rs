#![cfg_attr(feature = "bpf-entrypoint", no_std)]

use core::convert::TryInto;

use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use solana_sha256_hasher::hash as sha256_hash;

pub const VERIFY_SLICE_DISCRIMINATOR: u8 = 0;
pub const VERIFY_SLICE_INSTRUCTION_LEN: usize = 1 + VerifySliceArgs::PACKED_LEN;
pub const SHA256_BYTES: usize = 32;

#[cfg(feature = "bpf-entrypoint")]
pinocchio::program_entrypoint!(process_instruction);
#[cfg(feature = "bpf-entrypoint")]
pinocchio::default_allocator!();
#[cfg(feature = "bpf-entrypoint")]
pinocchio::nostd_panic_handler!();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifySliceArgs {
    pub start_offset: u32,
    pub expected_sha256: [u8; SHA256_BYTES],
}

impl VerifySliceArgs {
    pub const PACKED_LEN: usize = 4 + SHA256_BYTES;

    pub fn pack(&self) -> [u8; Self::PACKED_LEN] {
        let mut bytes = [0u8; Self::PACKED_LEN];
        bytes[0..4].copy_from_slice(&self.start_offset.to_le_bytes());
        bytes[4..].copy_from_slice(&self.expected_sha256);
        bytes
    }

    pub fn unpack(input: &[u8]) -> Result<Self, ProgramError> {
        if input.len() != Self::PACKED_LEN {
            return Err(ProgramError::InvalidInstructionData);
        }

        let start_offset = u32::from_le_bytes(
            input[0..4]
                .try_into()
                .map_err(|_| ProgramError::InvalidInstructionData)?,
        );
        let expected_sha256 = input[4..]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;

        Ok(Self {
            start_offset,
            expected_sha256,
        })
    }
}

pub fn build_verify_slice_instruction_data(
    args: &VerifySliceArgs,
) -> [u8; VERIFY_SLICE_INSTRUCTION_LEN] {
    let mut bytes = [0u8; VERIFY_SLICE_INSTRUCTION_LEN];
    bytes[0] = VERIFY_SLICE_DISCRIMINATOR;
    bytes[1..].copy_from_slice(&args.pack());
    bytes
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifierError {
    SliceOutOfBounds = 0,
    HashMismatch = 1,
}

impl From<VerifierError> for ProgramError {
    fn from(value: VerifierError) -> Self {
        ProgramError::Custom(value as u32)
    }
}

impl TryFrom<u32> for VerifierError {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::SliceOutOfBounds),
            1 => Ok(Self::HashMismatch),
            _ => Err(()),
        }
    }
}

pub fn process_instruction(
    _program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    match instruction_data.split_first() {
        Some((&VERIFY_SLICE_DISCRIMINATOR, data)) => process_verify_slice(accounts, data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn process_verify_slice(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [target_account, _remaining @ ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    let args = VerifySliceArgs::unpack(data)?;
    let account_data = target_account.try_borrow()?;

    let start = args.start_offset as usize;
    let data_slice = account_data
        .get(start..)
        .ok_or(VerifierError::SliceOutOfBounds)?;

    if sha256(data_slice) != args.expected_sha256 {
        return Err(VerifierError::HashMismatch.into());
    }

    Ok(())
}

fn sha256(data: &[u8]) -> [u8; SHA256_BYTES] {
    sha256_hash(data).to_bytes()
}
