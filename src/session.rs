use crate::{
    constants::{algorithm::HashingAlgorithm, types::session::SessionType},
    handles::SessionHandle,
    Error, Result, WrapperErrorKind,
};
use log::error;
use std::convert::{From, TryFrom};

/// Enum representing the different types of sessions.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Session {
    Hmac(HmacSession),
    Policy(PolicySession),
    Trial(TrialSession),
}

impl Session {
    pub fn handle(&self) -> SessionHandle {
        match self {
            Session::Hmac(session_object) => session_object.handle(),
            Session::Policy(session_object) => session_object.handle(),
            Session::Trial(session_object) => session_object.handle(),
        }
    }

    pub fn auth_hash(&self) -> HashingAlgorithm {
        match self {
            Session::Hmac(session_object) => session_object.auth_hash(),
            Session::Policy(session_object) => session_object.auth_hash(),
            Session::Trial(session_object) => session_object.auth_hash(),
        }
    }

    pub fn session_type(&self) -> SessionType {
        match self {
            Session::Hmac(_) => HmacSession::session_type(),
            Session::Policy(_) => PolicySession::session_type(),
            Session::Trial(_) => TrialSession::session_type(),
        }
    }
}

/// Macro for implementing specific session types
macro_rules! impl_session_data_type {
    ($specific_session_type:ident, Session::$session_enum_value:ident, SessionType::$session_type_value:ident) => {
        #[derive(Debug, Copy, Clone, Eq, PartialEq)]
        pub struct $specific_session_type {
            handle: SessionHandle,
            auth_hash: HashingAlgorithm,
        }

        impl $specific_session_type {
            pub fn new(
                handle: SessionHandle,
                auth_hash: HashingAlgorithm,
            ) -> $specific_session_type {
                $specific_session_type { handle, auth_hash }
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

        impl From<$specific_session_type> for Session {
            fn from(specific_session: $specific_session_type) -> Session {
                Session::$session_enum_value(specific_session)
            }
        }

        impl TryFrom<Session> for $specific_session_type {
            type Error = Error;
            fn try_from(session: Session) -> Result<$specific_session_type> {
                match session {
                    Session::$session_enum_value(val) => Ok(val),
                    _ => {
                        error!(
                            "Error to convert session into {}",
                            std::stringify!($specific_session_type)
                        );
                        Err(Error::local_error(WrapperErrorKind::InvalidParam))
                    }
                }
            }
        }
    };
}

impl_session_data_type!(HmacSession, Session::Hmac, SessionType::Hmac);
impl_session_data_type!(PolicySession, Session::Policy, SessionType::Policy);
impl_session_data_type!(TrialSession, Session::Trial, SessionType::Trial);
