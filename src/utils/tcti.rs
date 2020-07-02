// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::response_code::{Error, WrapperErrorKind};
use regex::Regex;
use std::convert::TryFrom;
use std::ffi::CString;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

const DEVICE: &str = "device";
const MSSIM: &str = "mssim";
const TABRMD: &str = "tabrmd";

// Possible TCTI to use with the ESYS API.
/// Placeholder TCTI types that can be used when initialising a `Context` to determine which
/// interface will be used to communicate with the TPM.
#[derive(Clone, Debug, PartialEq)]
pub enum Tcti {
    /// Connect to a TPM available as a device node on the system
    ///
    /// For more information about configuration, see [this page](https://www.mankier.com/3/Tss2_Tcti_Device_Init)
    Device(DeviceConfig),
    /// Connect to a TPM (simulator) available as a network device
    ///
    /// For more information about configuration, see [this page](https://www.mankier.com/3/Tss2_Tcti_Mssim_Init)
    Mssim(MssimConfig),
    /// Connect to a TPM through an Access Broker/Resource Manager daemon
    ///
    /// For more information about configuration, see [this page](https://www.mankier.com/3/Tss2_Tcti_Tabrmd_Init)
    Tabrmd(TabrmdConfig),
}

impl TryFrom<Tcti> for CString {
    type Error = Error;

    fn try_from(tcti: Tcti) -> Result<Self, Error> {
        let tcti_name = match tcti {
            Tcti::Device(..) => DEVICE,
            Tcti::Mssim(..) => MSSIM,
            Tcti::Tabrmd(..) => TABRMD,
        };

        let tcti_conf = match tcti {
            Tcti::Mssim(config) => {
                if let ServerAddress::Hostname(name) = &config.host {
                    if !hostname_validator::is_valid(name) {
                        return Err(Error::WrapperError(WrapperErrorKind::InvalidParam));
                    }
                }
                format!("host={},port={}", config.host, config.port)
            }
            Tcti::Device(DeviceConfig { path }) => path
                .to_str()
                .ok_or(Error::WrapperError(WrapperErrorKind::InvalidParam))?
                .to_owned(),
            Tcti::Tabrmd(config) => {
                format!("bus_name={},bus_type={}", config.bus_name, config.bus_type)
            }
        };

        if tcti_conf.is_empty() {
            CString::new(tcti_name).or(Err(Error::WrapperError(WrapperErrorKind::InvalidParam)))
        } else {
            CString::new(format!("{}:{}", tcti_name, tcti_conf))
                .or(Err(Error::WrapperError(WrapperErrorKind::InvalidParam)))
        }
    }
}

impl FromStr for Tcti {
    type Err = Error;

    fn from_str(config_str: &str) -> Result<Self, Self::Err> {
        let device_pattern = Regex::new(r"^device(:(.*))?$").unwrap(); //should not fail
        if let Some(captures) = device_pattern.captures(config_str) {
            return Ok(Tcti::Device(DeviceConfig::from_str(
                captures.get(2).map_or("", |m| m.as_str()),
            )?));
        }

        let mssim_pattern = Regex::new(r"^mssim(:(.*))?$").unwrap(); //should not fail
        if let Some(captures) = mssim_pattern.captures(config_str) {
            return Ok(Tcti::Mssim(MssimConfig::from_str(
                captures.get(2).map_or("", |m| m.as_str()),
            )?));
        }

        let tabrmd_pattern = Regex::new(r"^tabrmd(:(.*))?$").unwrap(); //should not fail
        if let Some(captures) = tabrmd_pattern.captures(config_str) {
            return Ok(Tcti::Tabrmd(TabrmdConfig::from_str(
                captures.get(2).map_or("", |m| m.as_str()),
            )?));
        }

        Err(Error::WrapperError(WrapperErrorKind::InvalidParam))
    }
}

#[test]
fn validate_from_str_tcti() {
    let tcti = Tcti::from_str("mssim:port=1234,host=168.0.0.1").unwrap();
    assert_eq!(
        tcti,
        Tcti::Mssim(MssimConfig {
            port: 1234,
            host: ServerAddress::Ip(IpAddr::V4(std::net::Ipv4Addr::new(168, 0, 0, 1)))
        })
    );

    let tcti = Tcti::from_str("mssim").unwrap();
    assert_eq!(
        tcti,
        Tcti::Mssim(MssimConfig {
            port: DEFAULT_SERVER_PORT,
            host: Default::default()
        })
    );

    let tcti = Tcti::from_str("device:/try/this/path").unwrap();
    assert_eq!(
        tcti,
        Tcti::Device(DeviceConfig {
            path: PathBuf::from("/try/this/path"),
        })
    );

    let tcti = Tcti::from_str("device").unwrap();
    assert_eq!(tcti, Tcti::Device(Default::default()));

    let tcti = Tcti::from_str("tabrmd:bus_name=some.bus.Name2,bus_type=session").unwrap();
    assert_eq!(
        tcti,
        Tcti::Tabrmd(TabrmdConfig {
            bus_name: String::from("some.bus.Name2"),
            bus_type: BusType::Session
        })
    );

    let tcti = Tcti::from_str("tabrmd").unwrap();
    assert_eq!(tcti, Tcti::Tabrmd(Default::default()));
}

/// Configuration for a Device TCTI context
///
/// The default configuration uses the library default of
/// `/dev/tpm0`.
#[derive(Clone, Debug, PartialEq)]
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

    fn from_str(config_str: &str) -> Result<Self, Self::Err> {
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

/// Configuration for an Mssim TCTI context
///
/// The default configuration will point to `localhost:2321`
#[derive(Clone, Debug, PartialEq)]
pub struct MssimConfig {
    /// Address of the server to connect to
    ///
    /// Defaults to `localhost`
    host: ServerAddress,
    /// Port used by the server at the address given in `host`
    ///
    /// Defaults to `2321`
    port: u16,
}

const DEFAULT_SERVER_PORT: u16 = 2321;

impl Default for MssimConfig {
    fn default() -> Self {
        MssimConfig {
            host: Default::default(),
            port: DEFAULT_SERVER_PORT,
        }
    }
}

impl FromStr for MssimConfig {
    type Err = Error;

    fn from_str(config_str: &str) -> Result<Self, Self::Err> {
        if config_str.is_empty() {
            return Ok(Default::default());
        }
        let host_pattern = Regex::new(r"(,|^)host=(.*?)(,|$)").unwrap(); // should not fail
        let host = host_pattern
            .captures(config_str)
            .map_or(Ok(Default::default()), |captures| {
                ServerAddress::from_str(captures.get(2).map_or("", |m| m.as_str()))
            })?;

        let port_pattern = Regex::new(r"(,|^)port=(.*?)(,|$)").unwrap(); // should not fail
        let port =
            port_pattern
                .captures(config_str)
                .map_or(Ok(DEFAULT_SERVER_PORT), |captures| {
                    u16::from_str(captures.get(2).map_or("", |m| m.as_str()))
                        .or(Err(Error::WrapperError(WrapperErrorKind::InvalidParam)))
                })?;
        Ok(MssimConfig { host, port })
    }
}

#[test]
fn validate_from_str_mssim_config() {
    let config = MssimConfig::from_str("").unwrap();
    assert_eq!(config, Default::default());

    let config = MssimConfig::from_str("fjshd89943r=joishdf894u9r,sio0983=9u98jj").unwrap();
    assert_eq!(config, Default::default());

    let config = MssimConfig::from_str("host=127.0.0.1,random=value").unwrap();
    assert_eq!(
        config.host,
        ServerAddress::Ip(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)))
    );
    assert_eq!(config.port, DEFAULT_SERVER_PORT);

    let config = MssimConfig::from_str("port=1234,random=value").unwrap();
    assert_eq!(config.host, Default::default());
    assert_eq!(config.port, 1234);

    let config = MssimConfig::from_str("host=localhost,port=1234").unwrap();
    assert_eq!(
        config.host,
        ServerAddress::Hostname(String::from("localhost"))
    );
    assert_eq!(config.port, 1234);

    let config = MssimConfig::from_str("port=1234,host=localhost").unwrap();
    assert_eq!(config.host, "localhost".parse::<ServerAddress>().unwrap());
    assert_eq!(config.port, 1234);

    let config = MssimConfig::from_str("port=1234,host=localhost,random=value").unwrap();
    assert_eq!(config.host, "localhost".parse::<ServerAddress>().unwrap());
    assert_eq!(config.port, 1234);

    let _ = MssimConfig::from_str("port=abdef").unwrap_err();
    let _ = MssimConfig::from_str("host=-timey-wimey").unwrap_err();
    let _ = MssimConfig::from_str("host=1234.1234.1234.1234.12445.111").unwrap_err();
    let _ = MssimConfig::from_str("host=").unwrap_err();
    let _ = MssimConfig::from_str("port=").unwrap_err();
    let _ = MssimConfig::from_str("port=,host=,yas").unwrap_err();
}

/// Address of a TPM server
///
/// The default value is `localhost`
#[derive(Clone, Debug, PartialEq)]
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

    fn from_str(config_str: &str) -> Result<Self, Self::Err> {
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
#[derive(Clone, Debug, PartialEq)]
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

    fn from_str(config_str: &str) -> Result<Self, Self::Err> {
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
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum BusType {
    System,
    Session,
}

impl Default for BusType {
    fn default() -> Self {
        BusType::System
    }
}

impl FromStr for BusType {
    type Err = Error;

    fn from_str(config_str: &str) -> Result<Self, Self::Err> {
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
