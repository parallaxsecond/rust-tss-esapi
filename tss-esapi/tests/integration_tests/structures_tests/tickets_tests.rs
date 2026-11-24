// Copyright 2026 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::common::{check_marshall_unmarshall, check_marshall_unmarshall_offset};
use std::convert::TryFrom;
use tss_esapi::{
    constants::StructureTag,
    constants::tss::{
        TPM2_RH_ENDORSEMENT, TPM2_RH_NULL, TPM2_RH_OWNER, TPM2_ST_AUTH_SECRET, TPM2_ST_CREATION,
        TPM2_ST_HASHCHECK, TPM2_ST_VERIFIED,
    },
    structures::{AuthTicket, CreationTicket, HashcheckTicket, Ticket, VerifiedTicket},
    traits::{Marshall, UnMarshall},
    tss2_esys::{
        TPM2B_DIGEST, TPMT_TK_AUTH, TPMT_TK_CREATION, TPMT_TK_HASHCHECK, TPMT_TK_VERIFIED,
    },
};

fn digest(bytes: &[u8]) -> TPM2B_DIGEST {
    let mut buffer = [0u8; 64];
    buffer[..bytes.len()].copy_from_slice(bytes);
    TPM2B_DIGEST {
        size: bytes.len() as u16,
        buffer,
    }
}

const DIGEST: [u8; 32] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];

#[test]
fn test_auth_ticket_marshall_unmarshall() {
    let ticket = AuthTicket::try_from(TPMT_TK_AUTH {
        tag: TPM2_ST_AUTH_SECRET,
        hierarchy: TPM2_RH_ENDORSEMENT,
        digest: digest(&DIGEST),
    })
    .expect("Failed to convert TPMT_TK_AUTH to AuthTicket");

    check_marshall_unmarshall(&ticket);
    check_marshall_unmarshall_offset(&ticket);
}

#[test]
fn test_hashcheck_ticket_marshall_unmarshall() {
    let ticket = HashcheckTicket::try_from(TPMT_TK_HASHCHECK {
        tag: TPM2_ST_HASHCHECK,
        hierarchy: TPM2_RH_OWNER,
        digest: digest(&DIGEST),
    })
    .expect("Failed to convert TPMT_TK_HASHCHECK to HashcheckTicket");

    check_marshall_unmarshall(&ticket);
    check_marshall_unmarshall_offset(&ticket);
}

#[test]
fn test_null_hashcheck_ticket_marshall_unmarshall() {
    // The default hashcheck ticket is the NULL ticket, which has an empty digest.
    let ticket = HashcheckTicket::default();

    check_marshall_unmarshall(&ticket);
    check_marshall_unmarshall_offset(&ticket);
}

#[test]
fn test_verified_ticket_marshall_unmarshall() {
    let ticket = VerifiedTicket::try_from(TPMT_TK_VERIFIED {
        tag: TPM2_ST_VERIFIED,
        hierarchy: TPM2_RH_OWNER,
        digest: digest(&DIGEST),
    })
    .expect("Failed to convert TPMT_TK_VERIFIED to VerifiedTicket");

    check_marshall_unmarshall(&ticket);
    check_marshall_unmarshall_offset(&ticket);
}

#[test]
fn test_creation_ticket_marshall_unmarshall() {
    let ticket = CreationTicket::try_from(TPMT_TK_CREATION {
        tag: TPM2_ST_CREATION,
        hierarchy: TPM2_RH_NULL,
        digest: digest(&DIGEST),
    })
    .expect("Failed to convert TPMT_TK_CREATION to CreationTicket");

    check_marshall_unmarshall(&ticket);
    check_marshall_unmarshall_offset(&ticket);
}

#[test]
fn test_verified_ticket_marshalled_format() {
    let ticket = VerifiedTicket::try_from(TPMT_TK_VERIFIED {
        tag: TPM2_ST_VERIFIED,
        hierarchy: TPM2_RH_OWNER,
        digest: digest(&DIGEST[..4]),
    })
    .expect("Failed to convert TPMT_TK_VERIFIED to VerifiedTicket");

    // tag (u16), hierarchy (u32), digest size (u16), digest, all big endian.
    let expected: Vec<u8> = vec![
        0x80, 0x22, // TPM_ST_VERIFIED
        0x40, 0x00, 0x00, 0x01, // TPM_RH_OWNER
        0x00, 0x04, // digest size
        0x01, 0x23, 0x45, 0x67, // digest
    ];
    assert_eq!(expected, ticket.marshall().expect("Failed to marshall"));

    let unmarshalled =
        VerifiedTicket::unmarshall(&expected).expect("Failed to unmarshall verified ticket");
    assert_eq!(StructureTag::Verified, unmarshalled.tag());
    assert_eq!(&DIGEST[..4], unmarshalled.digest());
}

#[test]
fn test_verified_ticket_unmarshall_wrong_tag() {
    // A marshalled hashcheck ticket must not be accepted as a verified ticket.
    let marshalled = HashcheckTicket::default()
        .marshall()
        .expect("Failed to marshall");
    VerifiedTicket::unmarshall(&marshalled)
        .expect_err("A hashcheck ticket should not unmarshall into a verified ticket");
}

#[test]
fn test_verified_ticket_unmarshall_truncated() {
    let ticket = VerifiedTicket::try_from(TPMT_TK_VERIFIED {
        tag: TPM2_ST_VERIFIED,
        hierarchy: TPM2_RH_OWNER,
        digest: digest(&DIGEST),
    })
    .expect("Failed to convert TPMT_TK_VERIFIED to VerifiedTicket");
    let marshalled = ticket.marshall().expect("Failed to marshall");

    VerifiedTicket::unmarshall(&marshalled[..marshalled.len() - 1])
        .expect_err("Truncated data should not unmarshall");
}
