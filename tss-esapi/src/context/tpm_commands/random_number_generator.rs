use crate::{
    structures::Digest, tss2_esys::*, Context, Error, Result, WrapperErrorKind as ErrorKind,
};
use log::error;
use mbox::MBox;
use std::convert::{TryFrom, TryInto};
use std::ptr::null_mut;

impl Context {
    /// Get a number of random bytes from the TPM and return them.
    ///
    /// # Errors
    /// * if converting `num_bytes` to `u16` fails, a `WrongParamSize` will be returned
    pub fn get_random(&mut self, num_bytes: usize) -> Result<Digest> {
        let mut buffer = null_mut();
        let ret = unsafe {
            Esys_GetRandom(
                self.mut_context(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                num_bytes
                    .try_into()
                    .map_err(|_| Error::local_error(ErrorKind::WrongParamSize))?,
                &mut buffer,
            )
        };

        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            let buffer = unsafe { MBox::from_raw(buffer) };
            let mut random = buffer.buffer.to_vec();
            random.truncate(buffer.size.try_into().unwrap()); // should not panic given the TryInto above
            Ok(Digest::try_from(random)?)
        } else {
            error!("Error in getting random bytes: {}", ret);
            Err(ret)
        }
    }

    // Missing function: StirRandom
}
