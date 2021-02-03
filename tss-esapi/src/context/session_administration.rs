use crate::{
    session::{Session, SessionAttributes, SessionAttributesMask},
    tss2_esys::{Esys_TRSess_GetAttributes, Esys_TRSess_SetAttributes, TPMA_SESSION},
    Context, Error, Result,
};
use log::error;

impl Context {
    /// Set the given attributes on a given session.
    pub fn tr_sess_set_attributes(
        &mut self,
        session: Session,
        attributes: SessionAttributes,
        mask: SessionAttributesMask,
    ) -> Result<()> {
        let ret = unsafe {
            Esys_TRSess_SetAttributes(
                self.mut_context(),
                session.handle().into(),
                attributes.into(),
                mask.into(),
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            Ok(())
        } else {
            error!("Error when setting session attributes: {}", ret);
            Err(ret)
        }
    }

    /// Get session attribute flags.
    pub fn tr_sess_get_attributes(&mut self, session: Session) -> Result<SessionAttributes> {
        let mut flags: TPMA_SESSION = 0;
        let ret = unsafe {
            Esys_TRSess_GetAttributes(self.mut_context(), session.handle().into(), &mut flags)
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            Ok(SessionAttributes(flags))
        } else {
            error!("Error when getting session attributes: {}", ret);
            Err(ret)
        }
    }

    // Missing function: Esys_TRSess_GetNonceTPM
}
