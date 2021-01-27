use crate::{
    constants::{
        algorithm::{Cipher, HashingAlgorithm},
        types::session::SessionType,
    },
    context::handle_manager::HandleDropAction,
    handles::{KeyHandle, ObjectHandle, SessionHandle},
    session::Session,
    structures::Nonce,
    tss2_esys::*,
    Context, Error, Result,
};
use log::error;
use std::ptr::null;

impl Context {
    /// Start new authentication session and return the Session object
    /// associated with the session.
    ///
    /// If the returned session handle from ESYS api is ESYS_TR_NONE then
    /// the value of the option in the result will be None.
    ///
    /// # Example
    ///
    /// ```rust, no_run
    /// use tss_esapi::{Context, Tcti,
    ///     constants::{
    ///         algorithm::{Cipher, HashingAlgorithm},
    ///         types::session::SessionType,
    ///     },
    /// };
    /// // Create context that uses Device TCTI.
    /// let mut context = unsafe {
    ///     Context::new(Tcti::Device(Default::default())).expect("Failed to create Context")
    /// };
    ///
    /// // Create auth session without key_handle, bind_handle
    /// // and Nonce
    /// let session = context
    ///     .start_auth_session(
    ///         None,
    ///         None,
    ///         None,
    ///         SessionType::Hmac,
    ///         Cipher::aes_256_cfb(),
    ///         HashingAlgorithm::Sha256,
    ///     )
    ///     .expect("Failed to create session")
    ///     .expect("Recived invalid handle");
    /// ```
    #[allow(clippy::too_many_arguments)]
    pub fn start_auth_session(
        &mut self,
        tpm_key: Option<KeyHandle>,
        bind: Option<ObjectHandle>,
        nonce: Option<&Nonce>,
        session_type: SessionType,
        symmetric: Cipher,
        auth_hash: HashingAlgorithm,
    ) -> Result<Option<Session>> {
        let nonce_ptr: *const TPM2B_NONCE = match nonce {
            Some(val) => &val.clone().into(),
            None => null(),
        };

        let mut esys_session_handle = ESYS_TR_NONE;

        let ret = unsafe {
            Esys_StartAuthSession(
                self.mut_context(),
                tpm_key.map(|v| v.into()).unwrap_or(ESYS_TR_NONE),
                bind.map(|v| v.into()).unwrap_or(ESYS_TR_NONE),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                nonce_ptr,
                session_type.into(),
                &symmetric.into(),
                auth_hash.into(),
                &mut esys_session_handle,
            )
        };

        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            self.handle_manager.add_handle(
                ObjectHandle::from(esys_session_handle),
                HandleDropAction::Flush,
            )?;
            Ok(Session::create(
                session_type,
                SessionHandle::from(esys_session_handle),
                auth_hash,
            ))
        } else {
            error!("Error when creating a session: {}", ret);
            Err(ret)
        }
    }

    // Missing function: policy_restart
}
