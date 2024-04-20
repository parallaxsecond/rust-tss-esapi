// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! Wrapper around the TCTI Loader Library interface.
//! See section 3.5 of the TCG TSS 2.0 TPM Command Transmission Interface(TCTI) API
//! Specification.

use crate::{Error, Result, ReturnCode, WrapperErrorKind};
use log::error;
use regex::Regex;
use std::convert::TryFrom;
use std::env;
use std::ffi::CStr;
use std::ffi::CString;
use std::net::IpAddr;
use std::path::PathBuf;
use std::ptr::null_mut;
use std::str::FromStr;

const DEVICE: &str = "device";
const MSSIM: &str = "mssim";
const SWTPM: &str = "swtpm";
const TABRMD: &str = "tabrmd";
const TBS: &str = "tbs";

/// TCTI Context created via a TCTI Loader Library.
/// Wrapper around the TSS2_TCTI_CONTEXT structure.
#[derive(Debug)]
#[allow(missing_copy_implementations)]
pub struct TctiContext {
    tcti_context: *mut tss_esapi_sys::TSS2_TCTI_CONTEXT,
}

impl TctiContext {
    /// Allocate and initialize a new TctiContext structure.
    pub fn initialize(name_conf: TctiNameConf) -> Result<Self> {
        let mut tcti_context = null_mut();

        let tcti_name_conf = CString::try_from(name_conf)?;

        ReturnCode::ensure_success(
            unsafe {
                tss_esapi_sys::Tss2_TctiLdr_Initialize(tcti_name_conf.as_ptr(), &mut tcti_context)
            },
            |ret| {
                error!("Error when creating a TCTI context: {}", ret);
            },
        )?;

        Ok(TctiContext { tcti_context })
    }

    /// Get access to the inner C pointer
    pub(crate) fn tcti_context_ptr(&mut self) -> *mut tss_esapi_sys::TSS2_TCTI_CONTEXT {
        self.tcti_context
    }
}

impl Drop for TctiContext {
    fn drop(&mut self) {
        unsafe {
            tss_esapi_sys::Tss2_TctiLdr_Finalize(&mut self.tcti_context);
        }
    }
}

// `Send` and `Sync` are implemented to allow `TctiContext` to be thread-safe.
// This is necessary because `*mut TSS2_TCTI_CONTEXT` is not thread-safe by
// default. We can confirm the safety as the pointer can only be accessed
// in a thread-safe way (i.e. in methods that require a `&mut self`).
unsafe impl Send for TctiContext {}
unsafe impl Sync for TctiContext {}

/// Wrapper around the TSS2_TCTI_INFO structure.
#[derive(Debug)]
#[allow(missing_copy_implementations)]
pub struct TctiInfo {
    tcti_info: *mut tss_esapi_sys::TSS2_TCTI_INFO,
}

impl TctiInfo {
    /// Query the TCTI loading mechanism
    pub fn get_info(name_conf: TctiNameConf) -> Result<Self> {
        let mut tcti_info = null_mut();

        let tcti_name_conf = CString::try_from(name_conf)?;

        ReturnCode::ensure_success(
            unsafe { tss_esapi_sys::Tss2_TctiLdr_GetInfo(tcti_name_conf.as_ptr(), &mut tcti_info) },
            |ret| {
                error!("Error when getting the TCTI_INFO structure: {}", ret);
            },
        )?;

        Ok(TctiInfo { tcti_info })
    }

    /// Get the version field
    pub fn version(&self) -> u32 {
        unsafe { (*(self.tcti_info)).version }
    }

    /// Get the name field
    pub fn name(&self) -> &CStr {
        unsafe { CStr::from_ptr((*(self.tcti_info)).name) }
    }

    /// Get the description field
    pub fn description(&self) -> &CStr {
        unsafe { CStr::from_ptr((*(self.tcti_info)).description) }
    }

    /// Get the config_help field
    pub fn config_help(&self) -> &CStr {
        unsafe { CStr::from_ptr((*(self.tcti_info)).config_help) }
    }
}

impl Drop for TctiInfo {
    fn drop(&mut self) {
        unsafe {
            tss_esapi_sys::Tss2_TctiLdr_FreeInfo(&mut self.tcti_info);
        }
    }
}

/// Placeholder TCTI types that can be used when initialising a `Context` to determine which
/// interface will be used to communicate with the TPM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TctiNameConf {
    /// Connect to a TPM available as a device node on the system
    ///
    /// For more information about configuration, see [this page](https://www.mankier.com/3/Tss2_Tcti_Device_Init)
    Device(DeviceConfig),
    /// Connect to a TPM (simulator) available as a network device via the MSSIM protocol
    ///
    /// For more information about configuration, see [this page](https://www.mankier.com/3/Tss2_Tcti_Mssim_Init)
    Mssim(TpmSimulatorConfig),
    /// Connect to a TPM (simulator) available as a network device via the SWTPM protocol
    ///
    /// For more information about configuration, see [this page](https://www.mankier.com/3/Tss2_Tcti_Mssim_Init)
    Swtpm(TpmSimulatorConfig),
    /// Connect to a TPM through an Access Broker/Resource Manager daemon
    ///
    /// For more information about configuration, see [this page](https://www.mankier.com/3/Tss2_Tcti_Tabrmd_Init)
    Tabrmd(TabrmdConfig),
    /// Connect to a TPM using windows services
    Tbs,
}

impl TctiNameConf {
    /// Gets a TCTI from the following environment variables, in order:
    /// - TPM2TOOLS_TCTI
    /// - TCTI
    /// - TEST_TCTI
    ///
    /// # Examples
    /// ```
    /// # use tss_esapi::tcti_ldr::TctiNameConf;
    /// // Create context
    /// let tcti_name_conf = TctiNameConf::from_environment_variable().expect("Failed to get TCTI");
    pub fn from_environment_variable() -> Result<Self> {
        env::var("TPM2TOOLS_TCTI")
            .or_else(|_| env::var("TCTI"))
            .or_else(|_| env::var("TEST_TCTI"))
            .map_err(|_| Error::WrapperError(WrapperErrorKind::ParamsMissing))
            .and_then(|val| TctiNameConf::from_str(&val))
    }
}

impl TryFrom<TctiNameConf> for CString {
    type Error = Error;

    fn try_from(tcti: TctiNameConf) -> Result<Self> {
        let tcti_name = match tcti {
            TctiNameConf::Device(..) => DEVICE,
            TctiNameConf::Mssim(..) => MSSIM,
            TctiNameConf::Swtpm(..) => SWTPM,
            TctiNameConf::Tabrmd(..) => TABRMD,
            TctiNameConf::Tbs => TBS,
        };

        let tcti_conf = match tcti {
            TctiNameConf::Mssim(TpmSimulatorConfig::Tcp { host, port }) => {
                if let ServerAddress::Hostname(name) = &host {
                    if !hostname_validator::is_valid(name) {
                        return Err(Error::WrapperError(WrapperErrorKind::InvalidParam));
                    }
                }
                format!("host={},port={}", host, port)
            }
            TctiNameConf::Swtpm(TpmSimulatorConfig::Tcp { host, port }) => {
                if let ServerAddress::Hostname(name) = &host {
                    if !hostname_validator::is_valid(name) {
                        return Err(Error::WrapperError(WrapperErrorKind::InvalidParam));
                    }
                }
                format!("host={},port={}", host, port)
            }
            TctiNameConf::Mssim(TpmSimulatorConfig::Unix { path })
            | TctiNameConf::Swtpm(TpmSimulatorConfig::Unix { path }) => {
                format!("path={}", path)
            }
            TctiNameConf::Device(DeviceConfig { path }) => path
                .to_str()
                .ok_or(Error::WrapperError(WrapperErrorKind::InvalidParam))?
                .to_owned(),
            TctiNameConf::Tabrmd(config) => {
                format!("bus_name={},bus_type={}", config.bus_name, config.bus_type)
            }
            TctiNameConf::Tbs => String::new(),
        };

        if tcti_conf.is_empty() {
            CString::new(tcti_name).or(Err(Error::WrapperError(WrapperErrorKind::InvalidParam)))
        } else {
            CString::new(format!("{}:{}", tcti_name, tcti_conf))
                .or(Err(Error::WrapperError(WrapperErrorKind::InvalidParam)))
        }
    }
}

impl FromStr for TctiNameConf {
    type Err = Error;

    fn from_str(config_str: &str) -> Result<Self> {
        let device_pattern = Regex::new(r"^device(:(.*))?$").unwrap(); //should not fail
        if let Some(captures) = device_pattern.captures(config_str) {
            return Ok(TctiNameConf::Device(DeviceConfig::from_str(
                captures.get(2).map_or("", |m| m.as_str()),
            )?));
        }

        let mssim_pattern = Regex::new(r"^mssim(:(.*))?$").unwrap(); //should not fail
        if let Some(captures) = mssim_pattern.captures(config_str) {
            return Ok(TctiNameConf::Mssim(TpmSimulatorConfig::from_str(
                captures.get(2).map_or("", |m| m.as_str()),
            )?));
        }

        let swtpm_pattern = Regex::new(r"^swtpm(:(.*))?$").unwrap(); //should not fail
        if let Some(captures) = swtpm_pattern.captures(config_str) {
            return Ok(TctiNameConf::Swtpm(TpmSimulatorConfig::from_str(
                captures.get(2).map_or("", |m| m.as_str()),
            )?));
        }

        let tabrmd_pattern = Regex::new(r"^tabrmd(:(.*))?$").unwrap(); //should not fail
        if let Some(captures) = tabrmd_pattern.captures(config_str) {
            return Ok(TctiNameConf::Tabrmd(TabrmdConfig::from_str(
                captures.get(2).map_or("", |m| m.as_str()),
            )?));
        }

        Err(Error::WrapperError(WrapperErrorKind::InvalidParam))
    }
}

#[test]
fn validate_from_str_tcti() {
    let tcti = TctiNameConf::from_str("mssim:port=1234,host=168.0.0.1").unwrap();
    assert_eq!(
        tcti,
        TctiNameConf::Mssim(TpmSimulatorConfig::Tcp {
            port: 1234,
            host: ServerAddress::Ip(IpAddr::V4(std::net::Ipv4Addr::new(168, 0, 0, 1)))
        })
    );

    let tcti = TctiNameConf::from_str("mssim").unwrap();
    assert_eq!(
        tcti,
        TctiNameConf::Mssim(TpmSimulatorConfig::Tcp {
            port: TpmSimulatorConfig::DEFAULT_PORT_CONFIG,
            host: Default::default()
        })
    );

    let tcti = TctiNameConf::from_str("mssim:path=/foo/bar").unwrap();
    assert_eq!(
        tcti,
        TctiNameConf::Mssim(TpmSimulatorConfig::Unix {
            path: "/foo/bar".to_string(),
        })
    );

    let tcti = TctiNameConf::from_str("swtpm:port=1234,host=168.0.0.1").unwrap();
    assert_eq!(
        tcti,
        TctiNameConf::Swtpm(TpmSimulatorConfig::Tcp {
            port: 1234,
            host: ServerAddress::Ip(IpAddr::V4(std::net::Ipv4Addr::new(168, 0, 0, 1)))
        })
    );

    let tcti = TctiNameConf::from_str("swtpm").unwrap();
    assert_eq!(
        tcti,
        TctiNameConf::Swtpm(TpmSimulatorConfig::Tcp {
            port: TpmSimulatorConfig::DEFAULT_PORT_CONFIG,
            host: Default::default()
        })
    );

    let tcti = TctiNameConf::from_str("swtpm:path=/foo/bar").unwrap();
    assert_eq!(
        tcti,
        TctiNameConf::Swtpm(TpmSimulatorConfig::Unix {
            path: "/foo/bar".to_string(),
        })
    );

    let tcti = TctiNameConf::from_str("device:/try/this/path").unwrap();
    assert_eq!(
        tcti,
        TctiNameConf::Device(DeviceConfig {
            path: PathBuf::from("/try/this/path"),
        })
    );

    let tcti = TctiNameConf::from_str("device").unwrap();
    assert_eq!(tcti, TctiNameConf::Device(Default::default()));

    let tcti = TctiNameConf::from_str("tabrmd:bus_name=some.bus.Name2,bus_type=session").unwrap();
    assert_eq!(
        tcti,
        TctiNameConf::Tabrmd(TabrmdConfig {
            bus_name: String::from("some.bus.Name2"),
            bus_type: BusType::Session
        })
    );

    let tcti = TctiNameConf::from_str("tabrmd").unwrap();
    assert_eq!(tcti, TctiNameConf::Tabrmd(Default::default()));
}

/// Configuration for a Device TCTI context
///
/// The default configuration uses the library default of
/// `/dev/tpm0`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceConfig {
    /// Path to the device node to connect to
    ///
    /// If set to `None`, the default location is used
    path: PathBuf,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        DeviceConfig {
            path: PathBuf::from("/dev/tpm0"),
        }
    }
}

impl FromStr for DeviceConfig {
    type Err = Error;

    fn from_str(config_str: &str) -> Result<Self> {
        if config_str.is_empty() {
            return Ok(Default::default());
        }

        Ok(DeviceConfig {
            path: PathBuf::from(config_str),
        })
    }
}

#[test]
fn validate_from_str_device_config() {
    let config = DeviceConfig::from_str("").unwrap();
    assert_eq!(config, Default::default());

    let config = DeviceConfig::from_str("/dev/tpm0").unwrap();
    assert_eq!(config.path, PathBuf::from("/dev/tpm0"));
}

/// Configuration for an Mssim or Swtpm TCTI context
///
/// The default configuration will point to `localhost:2321`
///
/// Examples:
///  - Use of a TCP connection: `swtpm:host=localhost,port=2321`
///  - Use of a unix socket: `swtpm:path=/path/to/sock`
///    Available on tpm2-tss >= 3.2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TpmSimulatorConfig {
    /// Connects to tpm over TCP
    Tcp {
        /// Address of the server to connect to
        ///
        /// Defaults to `localhost`
        host: ServerAddress,
        /// Port used by the server at the address given in `host`
        ///
        /// Defaults to `2321`
        port: u16,
    },
    /// Connects to tpm over Unix socket
    ///
    /// If used with a library without unix socket support (< 3.2.0),
    /// a [`Error::TssError`] error will be returned.
    /// `base_error()` of which will be a `BaseError::BadValue`.
    Unix { path: String },
}

impl TpmSimulatorConfig {
    const DEFAULT_PORT_CONFIG: u16 = 2321;
}

impl Default for TpmSimulatorConfig {
    fn default() -> Self {
        TpmSimulatorConfig::Tcp {
            host: Default::default(),
            port: TpmSimulatorConfig::DEFAULT_PORT_CONFIG,
        }
    }
}

impl FromStr for TpmSimulatorConfig {
    type Err = Error;

    fn from_str(config_str: &str) -> Result<Self> {
        if config_str.is_empty() {
            return Ok(Default::default());
        }

        let path_pattern = Regex::new(r"(,|^)path=(.*?)(,|$)").unwrap(); // should not fail
        if let Some(path) = path_pattern
            .captures(config_str)
            .and_then(|c| c.get(2))
            .map(|m| m.as_str())
        {
            return Ok(TpmSimulatorConfig::Unix {
                path: path.to_string(),
            });
        }

        let host_pattern = Regex::new(r"(,|^)host=(.*?)(,|$)").unwrap(); // should not fail
        let host = host_pattern
            .captures(config_str)
            .map_or(Ok(Default::default()), |captures| {
                ServerAddress::from_str(captures.get(2).map_or("", |m| m.as_str()))
            })?;

        let port_pattern = Regex::new(r"(,|^)port=(.*?)(,|$)").unwrap(); // should not fail
        let port = port_pattern.captures(config_str).map_or(
            Ok(TpmSimulatorConfig::DEFAULT_PORT_CONFIG),
            |captures| {
                u16::from_str(captures.get(2).map_or("", |m| m.as_str()))
                    .or(Err(Error::WrapperError(WrapperErrorKind::InvalidParam)))
            },
        )?;

        Ok(TpmSimulatorConfig::Tcp { host, port })
    }
}

#[test]
fn validate_from_str_networktpm_config() {
    let config = TpmSimulatorConfig::from_str("").unwrap();
    assert_eq!(config, Default::default());

    let config = TpmSimulatorConfig::from_str("fjshd89943r=joishdf894u9r,sio0983=9u98jj").unwrap();
    assert_eq!(config, Default::default());

    let config = TpmSimulatorConfig::from_str("host=127.0.0.1,random=value").unwrap();
    assert_eq!(
        config,
        TpmSimulatorConfig::Tcp {
            host: ServerAddress::Ip(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
            port: TpmSimulatorConfig::DEFAULT_PORT_CONFIG
        }
    );

    let config = TpmSimulatorConfig::from_str("port=1234,random=value").unwrap();
    assert_eq!(
        config,
        TpmSimulatorConfig::Tcp {
            host: Default::default(),
            port: 1234
        }
    );

    let config = TpmSimulatorConfig::from_str("host=localhost,port=1234").unwrap();
    assert_eq!(
        config,
        TpmSimulatorConfig::Tcp {
            host: ServerAddress::Hostname(String::from("localhost")),
            port: 1234
        }
    );

    let config = TpmSimulatorConfig::from_str("port=1234,host=localhost").unwrap();
    assert_eq!(
        config,
        TpmSimulatorConfig::Tcp {
            host: ServerAddress::Hostname(String::from("localhost")),
            port: 1234
        }
    );

    let config = TpmSimulatorConfig::from_str("port=1234,host=localhost,random=value").unwrap();
    assert_eq!(
        config,
        TpmSimulatorConfig::Tcp {
            host: "localhost".parse::<ServerAddress>().unwrap(),
            port: 1234
        }
    );

    let config = TpmSimulatorConfig::from_str("host=1234.1234.1234.1234.12445.111").unwrap();
    assert_eq!(
        config,
        TpmSimulatorConfig::Tcp {
            host: ServerAddress::Hostname(String::from("1234.1234.1234.1234.12445.111")),
            port: TpmSimulatorConfig::DEFAULT_PORT_CONFIG
        }
    );

    let _ = TpmSimulatorConfig::from_str("port=abdef").unwrap_err();
    let _ = TpmSimulatorConfig::from_str("host=-timey-wimey").unwrap_err();
    let _ = TpmSimulatorConfig::from_str("host=abc@def").unwrap_err();
    let _ = TpmSimulatorConfig::from_str("host=").unwrap_err();
    let _ = TpmSimulatorConfig::from_str("port=").unwrap_err();
    let _ = TpmSimulatorConfig::from_str("port=,host=,yas").unwrap_err();
}

/// Address of a TPM server
///
/// The default value is `localhost`
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerAddress {
    /// IPv4 or IPv6 address
    Ip(IpAddr),
    /// Hostname
    ///
    /// The string is checked for compatibility with DNS hostnames
    /// before the context is created
    Hostname(String),
}

impl FromStr for ServerAddress {
    type Err = Error;

    fn from_str(config_str: &str) -> Result<Self> {
        if let Ok(addr) = IpAddr::from_str(config_str) {
            return Ok(ServerAddress::Ip(addr));
        }

        if !hostname_validator::is_valid(config_str) {
            return Err(Error::WrapperError(WrapperErrorKind::InvalidParam));
        }

        Ok(ServerAddress::Hostname(config_str.to_owned()))
    }
}

impl std::fmt::Display for ServerAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerAddress::Ip(addr) => addr.fmt(f),
            ServerAddress::Hostname(name) => name.fmt(f),
        }
    }
}

impl Default for ServerAddress {
    fn default() -> Self {
        ServerAddress::Hostname(String::from("localhost"))
    }
}

/// Configuration for a TABRMD TCTI context
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TabrmdConfig {
    /// Bus name to be used by TABRMD
    ///
    /// Defaults tp `com.intel.tss2.Tabrmd`
    // TODO: this could be changed to use the `dbus` crate, which has some
    // more dependencies, though
    bus_name: String,
    /// Bus type to be used by TABRMD
    ///
    /// Defaults to `System`
    bus_type: BusType,
}

const DEFAULT_BUS_NAME: &str = "com.intel.tss2.Tabrmd";

impl Default for TabrmdConfig {
    fn default() -> Self {
        TabrmdConfig {
            bus_name: String::from(DEFAULT_BUS_NAME),
            bus_type: Default::default(),
        }
    }
}

impl FromStr for TabrmdConfig {
    type Err = Error;

    fn from_str(config_str: &str) -> Result<Self> {
        if config_str.is_empty() {
            return Ok(Default::default());
        }
        let bus_name_pattern = Regex::new(r"(,|^)bus_name=(.*?)(,|$)").unwrap(); // should not fail
        let bus_name = bus_name_pattern.captures(config_str).map_or(
            Ok(DEFAULT_BUS_NAME.to_owned()),
            |captures| {
                let valid_bus_name_pattern =
                    Regex::new(r"^[a-zA-Z0-9\-_]+(\.[a-zA-Z0-9\-_]+)+$").unwrap(); //should not fail
                if !valid_bus_name_pattern.is_match(captures.get(2).map_or("", |m| m.as_str())) {
                    return Err(Error::WrapperError(WrapperErrorKind::InvalidParam));
                }
                Ok(captures.get(2).map_or("", |m| m.as_str()).to_owned())
            },
        )?;

        let bus_type_pattern = Regex::new(r"(,|^)bus_type=(.*?)(,|$)").unwrap(); // should not fail
        let bus_type = bus_type_pattern
            .captures(config_str)
            .map_or(Ok(Default::default()), |captures| {
                BusType::from_str(captures.get(2).map_or("", |m| m.as_str()))
            })?;

        Ok(TabrmdConfig { bus_name, bus_type })
    }
}

/// DBus type for usage with TABRMD
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum BusType {
    #[default]
    System,
    Session,
}

impl FromStr for BusType {
    type Err = Error;

    fn from_str(config_str: &str) -> Result<Self> {
        match config_str {
            "session" => Ok(BusType::Session),
            "system" => Ok(BusType::System),
            _ => Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        }
    }
}

impl std::fmt::Display for BusType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BusType::Session => write!(f, "session"),
            BusType::System => write!(f, "system"),
        }
    }
}

#[test]
fn validate_from_str_tabrmd_config() {
    let config = TabrmdConfig::from_str("").unwrap();
    assert_eq!(config, Default::default());

    let config = TabrmdConfig::from_str("fjshd89943r=joishdf894u9r,sio0983=9u98jj").unwrap();
    assert_eq!(config, Default::default());

    let config = TabrmdConfig::from_str("bus_name=one.true.bus.Name,random=value").unwrap();
    assert_eq!(&config.bus_name, "one.true.bus.Name");
    assert_eq!(config.bus_type, Default::default());

    let config = TabrmdConfig::from_str("bus_type=session,random=value").unwrap();
    assert_eq!(&config.bus_name, DEFAULT_BUS_NAME);
    assert_eq!(config.bus_type, BusType::Session);

    let config = TabrmdConfig::from_str("bus_name=one.true.bus.Name,bus_type=system").unwrap();
    assert_eq!(&config.bus_name, "one.true.bus.Name");
    assert_eq!(config.bus_type, BusType::System);

    let config = TabrmdConfig::from_str("bus_type=system,bus_name=one.true.bus.Name").unwrap();
    assert_eq!(&config.bus_name, "one.true.bus.Name");
    assert_eq!(config.bus_type, BusType::System);

    let config =
        TabrmdConfig::from_str("bus_type=system,bus_name=one.true.bus.Name,random=value").unwrap();
    assert_eq!(&config.bus_name, "one.true.bus.Name");
    assert_eq!(config.bus_type, BusType::System);

    let _ = TabrmdConfig::from_str("bus_name=abc&.bcd").unwrap_err();
    let _ = TabrmdConfig::from_str("bus_name=adfsdgdfg4gf4").unwrap_err();
    let _ = TabrmdConfig::from_str("bus_name=,bus_type=,bla?").unwrap_err();
    let _ = TabrmdConfig::from_str("bus_type=randooom").unwrap_err();
}
