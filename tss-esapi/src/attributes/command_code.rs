// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{tss2_esys::TPMA_CC, Error, Result, WrapperErrorKind};
use bitfield::bitfield;
use std::convert::TryFrom;

bitfield! {
    /// Bitfield representing the command code attributes.
    #[derive(Copy, Clone, Eq, PartialEq)]
    pub struct CommandCodeAttributes(TPMA_CC);
    impl Debug;
    pub command_index, _: 15, 0;
    reserved, _: 21, 16; // shall be zero
    pub nv, _: 22;
    pub extensive, _: 23;
    pub flushed, _: 24;
    pub c_handles, _: 27, 25;
    pub r_handle, _: 28;
    pub v, _: 29;
    res, _: 31, 30; // shall be zero
}

impl TryFrom<TPMA_CC> for CommandCodeAttributes {
    type Error = Error;

    fn try_from(tpma_cc: TPMA_CC) -> Result<Self> {
        let command_code_attributes = CommandCodeAttributes(tpma_cc);
    }
}

impl From<CommandCodeAttributes> for TPMA_CC {
    fn from(command_code_attributes: CommandCodeAttributes) -> Self {
        command_code_attributes.0
    }
}
