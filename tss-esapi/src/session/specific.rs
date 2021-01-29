/// Macro for implementing specific session types
use crate::{
    constants::{algorithm::HashingAlgorithm, SessionType},
    handles::SessionHandle,
    session::Session,
    Error, Result, WrapperErrorKind,
};
use log::error;
use std::convert::{From, TryFrom};

macro_rules! impl_specific_session {
    ($specific_session:ident, Session::$session_enum_value:ident, SessionType::$session_type_value:ident) => {
        #[derive(Debug, Copy, Clone, Eq, PartialEq)]
        pub struct $specific_session {
            handle: SessionHandle,
            auth_hash: HashingAlgorithm,
        }

        impl $specific_session {
            pub fn new(handle: SessionHandle, auth_hash: HashingAlgorithm) -> $specific_session {
                $specific_session { handle, auth_hash }
            }

            pub fn handle(&self) -> SessionHandle {
                self.handle
            }

            pub fn auth_hash(&self) -> HashingAlgorithm {
                self.auth_hash
            }

            pub const fn session_type() -> SessionType {
                SessionType::$session_type_value
            }
        }

        impl From<$specific_session> for Session {
            fn from(specific_session: $specific_session) -> Session {
                Session::$session_enum_value(specific_session)
            }
        }

        impl TryFrom<Session> for $specific_session {
            type Error = Error;
            fn try_from(session: Session) -> Result<$specific_session> {
                match session {
                    Session::$session_enum_value(val) => Ok(val),
                    _ => {
                        error!(
                            "Error to convert session into {}",
                            std::stringify!($specific_session)
                        );
                        Err(Error::local_error(WrapperErrorKind::InvalidParam))
                    }
                }
            }
        }
    };
}

// Implmentation of the specific sessions
impl_specific_session!(HmacSession, Session::Hmac, SessionType::Hmac);
impl_specific_session!(PolicySession, Session::Policy, SessionType::Policy);
impl_specific_session!(TrialSession, Session::Trial, SessionType::Trial);
