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
    Password,
}

impl Session {
    ///
    /// Function that creates a Option<Session>.
    ///
    /// If a Session is created from the NoneHandle
    /// then the returned value from the function will be None.
    ///
    pub fn create(
        session_type: SessionType,
        session_handle: SessionHandle,
        auth_hash: HashingAlgorithm,
    ) -> Option<Session> {
        if session_handle != SessionHandle::NoneHandle {
            Some(match session_type {
                SessionType::Hmac => Session::Hmac(HmacSession::new(session_handle, auth_hash)),
                SessionType::Policy => {
                    Session::Policy(PolicySession::new(session_handle, auth_hash))
                }
                SessionType::Trial => Session::Trial(TrialSession::new(session_handle, auth_hash)),
            })
        } else {
            None
        }
    }
    ///
    /// Function for retrieving the SessionHandle from Option<Session>
    ///
    pub fn handle_from_option(session: Option<Session>) -> SessionHandle {
        session
            .map(|v| v.handle())
            .unwrap_or(SessionHandle::NoneHandle)
    }
    ///
    /// Function for retrieving the session handle associated with
    /// the session.
    ///
    pub fn handle(&self) -> SessionHandle {
        match self {
            Session::Hmac(session_object) => session_object.handle(),
            Session::Policy(session_object) => session_object.handle(),
            Session::Trial(session_object) => session_object.handle(),
            Session::Password => SessionHandle::PasswordHandle,
        }
    }
    ///
    /// Function for retrieving the auth hash associated with the
    /// session.
    ///
    pub fn auth_hash(&self) -> Option<HashingAlgorithm> {
        match self {
            Session::Hmac(session_object) => Some(session_object.auth_hash()),
            Session::Policy(session_object) => Some(session_object.auth_hash()),
            Session::Trial(session_object) => Some(session_object.auth_hash()),
            Session::Password => None,
        }
    }
    ///
    /// Function for retrieving the session type associated with the
    /// session.
    ///
    pub fn session_type(&self) -> Option<SessionType> {
        match self {
            Session::Hmac(_) => Some(HmacSession::session_type()),
            Session::Policy(_) => Some(PolicySession::session_type()),
            Session::Trial(_) => Some(TrialSession::session_type()),
            Session::Password => None,
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
