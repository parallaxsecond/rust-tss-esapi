// Copyright 2026 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! Per-test swtpm instance management for isolated, parallel integration tests.
//!
//! Each test gets its own `SwtpmSession` which spawns a dedicated swtpm process
//! communicating over a Unix domain socket in a temporary directory. The session
//! is cleaned up automatically on drop.

use assert_fs::TempDir;
use socket2::{Domain, SockAddr, Socket, Type};
use std::ops::{Deref, DerefMut};
use std::process::{Child, Stdio};
use std::time::Duration;
use tss_esapi::{
    Context, attributes::SessionAttributesBuilder, constants::SessionType,
    interface_types::algorithm::HashingAlgorithm, structures::SymmetricDefinition,
    tcti_ldr::TctiNameConf,
};

/// Maximum number of swtpm startup attempts before giving up.
const MAX_SWTPM_RETRIES: usize = 5;

/// An active swtpm session with a temporary directory for state and sockets.
///
/// On drop, the swtpm process is killed and the temp directory is cleaned up.
pub struct SwtpmSession {
    _process: Child,
    sock_path: String,
    _tmp: TempDir,
}

impl SwtpmSession {
    /// Start a new swtpm instance using a Unix domain socket.
    pub fn new() -> Self {
        for attempt in 0..MAX_SWTPM_RETRIES {
            let tmp = TempDir::new().expect("failed to create temp dir");
            let sock_path = tmp.path().join("swtpm.sock");
            let ctrl_path = tmp.path().join("swtpm.sock.ctrl");

            let mut process = std::process::Command::new("swtpm")
                .args([
                    "socket",
                    "--tpm2",
                    "--tpmstate",
                    &format!("dir={}", tmp.path().display()),
                    "--server",
                    &format!("type=unixio,path={}", sock_path.display()),
                    "--ctrl",
                    &format!("type=unixio,path={}", ctrl_path.display()),
                    "--flags",
                    "startup-clear",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("failed to start swtpm — is it installed?");

            // Wait for swtpm to be ready by polling the socket.
            let mut connected = false;
            for _ in 0..40 {
                if let Ok(addr) = SockAddr::unix(&sock_path) {
                    if let Ok(sock) = Socket::new(Domain::UNIX, Type::STREAM, None) {
                        if sock.connect(&addr).is_ok() {
                            connected = true;
                            break;
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(50));
            }

            if !connected {
                let _ = process.kill();
                let _ = process.wait();
                if attempt + 1 < MAX_SWTPM_RETRIES {
                    continue;
                }
                panic!("swtpm failed to start after {MAX_SWTPM_RETRIES} attempts");
            }

            return Self {
                _process: process,
                sock_path: sock_path.to_string_lossy().into_owned(),
                _tmp: tmp,
            };
        }
        unreachable!()
    }

    /// Return the TCTI name/configuration for connecting to this swtpm instance.
    pub fn tcti(&self) -> TctiNameConf {
        use std::str::FromStr;
        TctiNameConf::from_str(&format!("swtpm:path={}", self.sock_path))
            .expect("failed to parse swtpm TCTI string")
    }

    /// Create an ESAPI `Context` with an HMAC session against this swtpm instance.
    pub fn create_session_context(&self) -> Context {
        let mut ctx = Context::new(self.tcti()).unwrap();
        let session = ctx
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )
            .unwrap();
        let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
            .with_decrypt(true)
            .with_encrypt(true)
            .build();
        ctx.tr_sess_set_attributes(
            session.unwrap(),
            session_attributes,
            session_attributes_mask,
        )
        .unwrap();
        ctx.set_sessions((session, None, None));
        ctx
    }
}

impl Drop for SwtpmSession {
    fn drop(&mut self) {
        let _ = self._process.kill();
        let _ = self._process.wait();
    }
}

/// A test context that bundles a `SwtpmSession` with an ESAPI `Context`.
///
/// Implements `Deref` and `DerefMut` targeting `Context`, so existing test code
/// that calls methods on `Context` works transparently. The swtpm process stays
/// alive as long as this struct is held.
///
/// Field order matters: `context` is listed first so it is dropped before
/// `_swtpm`, ensuring the ESAPI context can flush handles while swtpm is
/// still alive.
pub struct TestContext {
    context: Context,
    _swtpm: SwtpmSession,
}

impl TestContext {
    /// Get a reference to the underlying `SwtpmSession`.
    #[allow(dead_code)]
    pub fn swtpm(&self) -> &SwtpmSession {
        &self._swtpm
    }
}

impl Deref for TestContext {
    type Target = Context;
    fn deref(&self) -> &Context {
        &self.context
    }
}

impl DerefMut for TestContext {
    fn deref_mut(&mut self) -> &mut Context {
        &mut self.context
    }
}

/// Spawn a fresh swtpm and create an ESAPI `Context` without any session.
pub fn create_ctx_without_session() -> TestContext {
    super::setup_logging();
    let swtpm = SwtpmSession::new();
    let context = Context::new(swtpm.tcti()).unwrap();
    TestContext {
        context,
        _swtpm: swtpm,
    }
}

/// Spawn a fresh swtpm and create an ESAPI `Context` with an HMAC session.
pub fn create_ctx_with_session() -> TestContext {
    super::setup_logging();
    let swtpm = SwtpmSession::new();
    let context = swtpm.create_session_context();
    TestContext {
        _swtpm: swtpm,
        context,
    }
}

/// Spawn a fresh swtpm and return the session along with its TCTI configuration.
///
/// This is for code that needs the raw `TctiNameConf` (e.g.
/// `TransientKeyContextBuilder::with_tcti()`). The caller must keep the
/// returned `SwtpmSession` alive for the duration of TPM usage.
pub fn create_tcti() -> (SwtpmSession, TctiNameConf) {
    super::setup_logging();
    let swtpm = SwtpmSession::new();
    let tcti = swtpm.tcti();
    (swtpm, tcti)
}
