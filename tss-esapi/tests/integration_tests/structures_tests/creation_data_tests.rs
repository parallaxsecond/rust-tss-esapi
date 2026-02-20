use tss_esapi::{constants::tss::TPM2_ALG_SHA256, structures::CreationData};
use tss_esapi_sys::{
    TPM2B_DATA, TPM2B_DIGEST, TPM2B_NAME, TPML_PCR_SELECTION, TPMS_CREATION_DATA,
    TPMS_PCR_SELECTION,
};

use crate::common::check_marshall_unmarshall;

#[test]
fn test_marshall_unmarshall() {
    let tpms_creation_data = TPMS_CREATION_DATA {
        pcrSelect: TPML_PCR_SELECTION {
            count: 1,
            pcrSelections: [TPMS_PCR_SELECTION {
                hash: TPM2_ALG_SHA256,
                sizeofSelect: 1,
                pcrSelect: [0; 4],
            }; 16],
        },
        pcrDigest: TPM2B_DIGEST {
            size: 1,
            buffer: [0; 64],
        },
        locality: 1,
        parentNameAlg: TPM2_ALG_SHA256,
        parentName: TPM2B_NAME {
            size: 1,
            name: [0; 68],
        },
        parentQualifiedName: TPM2B_NAME {
            size: 1,
            name: [0; 68],
        },
        outsideInfo: TPM2B_DATA {
            size: 1,
            buffer: [0; 64],
        },
    };

    let creation_data =
        CreationData::try_from(tpms_creation_data).expect("can't generate creation ddata");

    check_marshall_unmarshall(&creation_data);
}
