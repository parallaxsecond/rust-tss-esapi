// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod argument_number;

use crate::{constants::return_code::TpmFormatOneError, Error, Result};
pub use argument_number::ArgumentNumber;
use bitfield::bitfield;
use std::convert::TryFrom;

/// Type representing the TPM format one response code.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct TpmFormatOneResponseCode {
    error_number: TpmFormatOneError,
    argument_number: ArgumentNumber,
}

impl TpmFormatOneResponseCode {
    /// Creates a new tpm format one response code
    pub const fn new(error_number: TpmFormatOneError, argument_number: ArgumentNumber) -> Self {
        TpmFormatOneResponseCode {
            error_number,
            argument_number,
        }
    }

    /// Returns the error number.
    pub const fn error_number(&self) -> TpmFormatOneError {
        self.error_number
    }

    /// Returns the argument number
    pub const fn argument_number(&self) -> ArgumentNumber {
        self.argument_number
    }
}

impl TryFrom<u16> for TpmFormatOneResponseCode {
    type Error = Error;
    fn try_from(value: u16) -> Result<Self> {
        let structure = TpmFormatOneResponseCodeStructure(value);
        Ok(TpmFormatOneResponseCode {
            error_number: TpmFormatOneError::try_from(structure.error_number())?,
            argument_number: ArgumentNumber::from(structure.argument_number()),
        })
    }
}

impl From<TpmFormatOneResponseCode> for u16 {
    fn from(tpm_format_one_response_code: TpmFormatOneResponseCode) -> u16 {
        let mut structure = TpmFormatOneResponseCodeStructure(0);
        structure.set_error_number(tpm_format_one_response_code.error_number().into());
        structure.set_argument_number(tpm_format_one_response_code.argument_number().into());
        structure.0
    }
}

impl std::error::Error for TpmFormatOneResponseCode {}

impl std::fmt::Display for TpmFormatOneResponseCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.error_number {
            TpmFormatOneError::Asymmetric => write!(f, "Asymmetric algorithm not supported or not correct ({}).", self.argument_number()),
            TpmFormatOneError::Attributes => write!(f, "Inconsistent attributes ({}).", self.argument_number()),
            TpmFormatOneError::Hash => write!(f, "Hash algorithm not supported or not appropriate ({}).", self.argument_number()),
            TpmFormatOneError::Value => write!(f, "Value is out of range or is not correct for the context ({}).", self.argument_number()),
            TpmFormatOneError::Hierarchy => write!(f, "Hierarchy is not enabled or is not correct for the use ({}).", self.argument_number()),
            TpmFormatOneError::KeySize => write!(f, "Key size is not supported ({}).", self.argument_number()),
            TpmFormatOneError::Mgf => write!(f, "Mask generation function not supported ({}).", self.argument_number()),
            TpmFormatOneError::Mode => write!(f, "Mode of operation not supported ({}).", self.argument_number()),
            TpmFormatOneError::Type => write!(f, "The type of the value is not appropriate for the use ({}).", self.argument_number()),
            TpmFormatOneError::Handle => write!(f, "The handle is not correct for the use ({}).", self.argument_number()),
            TpmFormatOneError::Kdf => write!(f, "Unsupported key derivation function or function not appropriate for use ({}).", self.argument_number()),
            TpmFormatOneError::Range => write!(f, "Value was out of allowed range ({}).", self.argument_number()),
            TpmFormatOneError::AuthFail => write!(f, "The authorization HMAC check failed and DA counter incremented ({}).", self.argument_number()),
            TpmFormatOneError::Nonce => write!(f, "Invalid nonce size or nonce value mismatch ({}).", self.argument_number()),
            TpmFormatOneError::Pp => write!(f, "Authorization requires assertion of PP ({}).", self.argument_number()),
            TpmFormatOneError::Scheme => write!(f, "Unsupported or incompatible scheme ({}).", self.argument_number()),
            TpmFormatOneError::Size => write!(f, "Structure is the wrong size ({}).", self.argument_number()),
            TpmFormatOneError::Symmetric => write!(f, "Unsupported symmetric algorithm or key size, or not appropriate for instance ({}).", self.argument_number()),
            TpmFormatOneError::Tag => write!(f, "Incorrect structure tag ({}).", self.argument_number()),
            TpmFormatOneError::Selector => write!(f, "Union selector is incorrect ({}).", self.argument_number()),
            TpmFormatOneError::Insufficient => write!(f, "The TPM was unable to unmarshal a value because there were not enough octets in the input buffer ({}).", self.argument_number()),
            TpmFormatOneError::Signature => write!(f, "The signature is not valid ({}).", self.argument_number()),
            TpmFormatOneError::Key => write!(f, "Key fields are not compatible with the selected use ({}).", self.argument_number()),
            TpmFormatOneError::PolicyFail => write!(f, "A policy check failed ({}).", self.argument_number()),
            TpmFormatOneError::Integrity => write!(f, "Integrity check failed ({}).", self.argument_number()),
            TpmFormatOneError::Ticket => write!(f, "Invalid ticket ({}).", self.argument_number()),
            TpmFormatOneError::ReservedBits => write!(f, "Reserved bits not set to zero as required ({}).", self.argument_number()),
            TpmFormatOneError::BadAuth => write!(f, "Authorization failure without DA implications ({}).", self.argument_number()),
            TpmFormatOneError::Expired => write!(f, "The policy has expired ({}).", self.argument_number()),
            TpmFormatOneError::PolicyCc => write!(f, "The `commandCode` in the policy is not the `commandCode` of the command or the command code in a policy command references a command that is not implemented ({}).", self.argument_number()),
            TpmFormatOneError::Binding => write!(f, "Public and sensitive portions of an object are not cryptographically bound ({}).", self.argument_number()),
            TpmFormatOneError::Curve => write!(f, "Curve not supported ({}).", self.argument_number()),
            TpmFormatOneError::EccPoint => write!(f, "Point is not on the required curve ({}).", self.argument_number()),
        }
    }
}

bitfield! {
    /// A struct representing the format one
    /// TPM retrun code.
    #[derive(PartialEq, Copy, Clone)]
    struct TpmFormatOneResponseCodeStructure(u16);
    impl Debug;
    u8, error_number, set_error_number: 5, 0;
    u8, argument_number, set_argument_number: 11, 6;
}
