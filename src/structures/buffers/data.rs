use crate::response_code::{Error, Result, WrapperErrorKind};
use crate::tss2_esys::TPM2B_DATA;
use log::error;
use std::convert::TryFrom;
/// Struct holding a data value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Data {
    value: Vec<u8>,
}

impl Data {
    const MAX_SIZE: usize = 64;
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

impl Default for Data {
    fn default() -> Self {
        Data {
            value: Vec::<u8>::new(),
        }
    }
}

impl TryFrom<Vec<u8>> for Data {
    type Error = Error;
    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() > Data::MAX_SIZE {
            error!("Error: Invalid Vec<u8> size(> {})", Data::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        Ok(Data { value: bytes })
    }
}

impl TryFrom<TPM2B_DATA> for Data {
    type Error = Error;
    fn try_from(tss_data: TPM2B_DATA) -> Result<Self> {
        let size = tss_data.size as usize;
        if size > Data::MAX_SIZE {
            error!("Error: Invalid TPM2B_DATA size(> {})", Data::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        Ok(Data {
            value: tss_data.buffer[..size].to_vec(),
        })
    }
}

impl TryFrom<Data> for TPM2B_DATA {
    type Error = Error;
    fn try_from(data: Data) -> Result<Self> {
        if data.value().len() > Data::MAX_SIZE {
            error!("Error: Invalid data size(> {}) in Data", Data::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        let mut tss_data: TPM2B_DATA = Default::default();
        if !data.value.is_empty() {
            tss_data.size = data.value().len() as u16;
            tss_data.buffer[..data.value().len()].copy_from_slice(&data.value());
        }
        Ok(tss_data)
    }
}
