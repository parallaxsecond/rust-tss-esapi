mod specific;

use crate::{
    constants::SessionType, handles::SessionHandle, interface_types::algorithm::HashingAlgorithm,
};

pub use specific::{HmacSession, PolicySession, TrialSession};

/// Enum representing the different types of sessions.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Session {
    Hmac(HmacSession),
    Policy(PolicySession),
    Trial(TrialSession),
    Password,
}

impl Session {
    /// Function that creates a Option<Session>.
    ///
    /// If a Session is created from the NoneHandle
    /// then the returned value from the function will be None.
    pub fn create(
        session_type: SessionType,
        session_handle: SessionHandle,
        auth_hash: HashingAlgorithm,
    ) -> Option<Session> {
        if session_handle != SessionHandle::None {
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

    /// Function for retrieving the SessionHandle from Option<Session>
    pub fn handle_from_option(session: Option<Session>) -> SessionHandle {
        session.map(|v| v.handle()).unwrap_or(SessionHandle::None)
    }

    /// Function for retrieving the session handle associated with
    /// the session.
    pub fn handle(&self) -> SessionHandle {
        match self {
            Session::Hmac(session_object) => session_object.handle(),
            Session::Policy(session_object) => session_object.handle(),
            Session::Trial(session_object) => session_object.handle(),
            Session::Password => SessionHandle::Password,
        }
    }

    /// Function for retrieving the auth hash associated with the
    /// session.
    pub fn auth_hash(&self) -> Option<HashingAlgorithm> {
        match self {
            Session::Hmac(session_object) => Some(session_object.auth_hash()),
            Session::Policy(session_object) => Some(session_object.auth_hash()),
            Session::Trial(session_object) => Some(session_object.auth_hash()),
            Session::Password => None,
        }
    }

    /// Function for retrieving the session type associated with the
    /// session.
    pub fn session_type(&self) -> Option<SessionType> {
        match self {
            Session::Hmac(_) => Some(HmacSession::session_type()),
            Session::Policy(_) => Some(PolicySession::session_type()),
            Session::Trial(_) => Some(TrialSession::session_type()),
            Session::Password => None,
        }
    }
}
