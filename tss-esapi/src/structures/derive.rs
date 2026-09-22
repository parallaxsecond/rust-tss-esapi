use crate::tss2_esys::{TPM2B_SENSITIVE_DATA, TPMS_DERIVE};
use crate::{
    Error, Result,
    structures::{SensitiveData, buffers::label::Label},
};

/// Structure holding key derivation parameters
///
/// # Details
/// This corresponds to TPMS_DERIVE
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Derive {
    label: Label,
    context: Label,
}

impl Derive {
    pub fn from_bytes(label: &[u8], context: &[u8]) -> Result<Self> {
        let label = Label::from_bytes(label)?;
        let context = Label::from_bytes(context)?;

        Ok(Self { label, context })
    }
}

impl From<Derive> for TPMS_DERIVE {
    fn from(derive: Derive) -> Self {
        TPMS_DERIVE {
            label: derive.label.into(),
            context: derive.context.into(),
        }
    }
}

impl TryFrom<Derive> for SensitiveData {
    type Error = Error;

    fn try_from(derive: Derive) -> Result<Self> {
        // There are actually no marshalling functions for this, so we have to hand roll it.
        // Yes, I hate this as much as you do.
        let Derive { label, context } = derive;

        let label_bytes: &[u8] = label.as_ref();
        let label_len = label_bytes.len().to_be_bytes();
        let context_bytes: &[u8] = context.as_ref();
        let context_len = context_bytes.len().to_be_bytes();

        let size = label_len.len() + label_bytes.len() + context_len.len() + context_bytes.len();
        let mut stage_buffer = Vec::with_capacity(256);

        stage_buffer.extend(label_len);
        stage_buffer.extend(label_bytes);
        stage_buffer.extend(context_len);
        stage_buffer.extend(context_bytes);

        let mut buffer: [u8; 256] = [0; 256];

        let buffer_view = &mut buffer[..size];

        buffer_view.copy_from_slice(&stage_buffer);

        let tpm2b_sensitive_data = TPM2B_SENSITIVE_DATA {
            size: size as u16,
            buffer,
        };

        SensitiveData::try_from(tpm2b_sensitive_data)
    }
}
