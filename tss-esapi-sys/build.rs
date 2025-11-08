// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

fn main() {
    if std::env::var("DOCS_RS").is_ok() {
        // Nothing to be done for docs.rs builds.
        return;
    }

    cfg_if::cfg_if! {
        // If `TPM2_TSS_SOURCE_PATH` is set when using bundled then the code
        // is expected to be located in that path and will not be downloaded from
        // github.
        // N.B. On windows it might be necessary to add the VERSION file
        // manually because tpm2-tss does not create it when compiling.

        if #[cfg(all(feature = "bundled", feature = "generate-bindings"))] {
            // Bundled and generate bindings for the case when
            // it should be bundled with a non minimal version
            // of tpm2-tss.
            // Library source code will be either downloaded or read from a path, built and
            // statically linked in the build step.
            let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
            let installation = tpm2_tss::Installation::bundled(out_dir.as_path());
            installation.generate_bindings(&out_dir.join("tss_esapi_bindings.rs"));
        } else if #[cfg(all(feature = "bundled", not(feature = "generate-bindings")))] {
            // Bundled with the minimum supported version of tpm2-tss and the pre generated
            // bindings will be used.
            // Library source code will be either downloaded or read from a path, built and
            // statically linked in the build step.
            target::ensure_supported();
            let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
            let installation = tpm2_tss::Installation::bundled(out_dir.as_path());
        } else if #[cfg(all(not(feature = "bundled"), feature = "generate-bindings"))] {
            // Not bundled only generate the bindings and build against them.
            // The library files are expected to exist locally.
            let installation = tpm2_tss::Installation::probe(true);
            let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
            installation.generate_bindings(&out_dir.join("tss_esapi_bindings.rs"));
        } else {
            // Not bundled and using the pre generated bindings and build against them.
            // Library files are expected to exist locally.
            target::ensure_supported();
            let _ = tpm2_tss::Installation::probe(false);
        }
    }
}

pub mod target {
    use std::str::FromStr;
    use target_lexicon::{Architecture, OperatingSystem, Triple};
    const TARGET_ENV_VAR_NAME: &str = "TARGET";

    /// Ensures that the `TARGET` is valid for cross compilation.
    pub fn ensure_supported() {
        let target = Triple::from_str(&std::env::var(TARGET_ENV_VAR_NAME).unwrap_or_else(|_| {
            panic!("Missing environment variable `{TARGET_ENV_VAR_NAME}`.");
        }))
        .expect("Failed to parse target triple.");
        match (target.architecture, target.operating_system) {
            (Architecture::Arm(_), OperatingSystem::Linux)
            | (Architecture::Aarch64(_), OperatingSystem::Linux)
            | (Architecture::X86_64, OperatingSystem::Darwin(_))
            | (Architecture::X86_64, OperatingSystem::Linux) => {}
            (arch, os) => {
                panic!(
                    "Compilation target (architecture, OS) tuple ({arch}, {os}) is not part of the \
                     supported tuples. Please compile with the \"generate-bindings\" feature or \
                     add support for your platform."
                );
            }
        }
    }
}

pub mod tpm2_tss {
    use semver::{Version, VersionReq};
    use std::{
        fs::read_dir,
        path::{Path, PathBuf},
    };

    // General constants
    const MINIMUM_VERSION: &str = "4.1.3";
    const INSTALLATION_PATH_ENV_VAR_NAME: &str = "TPM2_TSS_PATH";

    /// The installed tpm2-tss libraries that are of
    /// interest.
    pub struct Installation {
        _tss2_sys: Library,
        #[allow(unused)]
        tss2_esys: Library,
        #[allow(unused)]
        tss2_tctildr: Library,
        #[allow(unused)]
        tss2_mu: Library,
        #[allow(unused)]
        tss2_tcti_tbs: Option<Library>,
    }

    impl Installation {
        #[cfg(feature = "bundled")]
        /// Uses a bundled build for the installation.
        pub fn bundled(out_path: &Path) -> Self {
            let version = Self::version();
            let source_path = Self::source(out_path, &version);
            Self::compile(&source_path);
            Self {
                _tss2_sys: Library::bundled_required("tss2-sys", &source_path, &version, false),
                tss2_esys: Library::bundled_required("tss2-esys", &source_path, &version, true),
                tss2_tctildr: Library::bundled_required(
                    "tss2-tctildr",
                    &source_path,
                    &version,
                    false,
                ),
                tss2_mu: Library::bundled_required("tss2-mu", &source_path, &version, false),
                tss2_tcti_tbs: Library::bundled_optional("tss2-tcti-tbs", &source_path, &version),
            }
        }

        /// Probes the system for an installation.
        pub fn probe(with_header_files: bool) -> Self {
            let install_path = Installation::installation_path_from_env_var();
            Installation {
                _tss2_sys: Library::probe_required(
                    "tss2-sys",
                    install_path.as_ref(),
                    with_header_files,
                    false,
                ),
                tss2_esys: Library::probe_required(
                    "tss2-esys",
                    install_path.as_ref(),
                    with_header_files,
                    true,
                ),
                tss2_tctildr: Library::probe_required(
                    "tss2-tctildr",
                    install_path.as_ref(),
                    with_header_files,
                    false,
                ),
                tss2_mu: Library::probe_required(
                    "tss2-mu",
                    install_path.as_ref(),
                    with_header_files,
                    false,
                ),
                tss2_tcti_tbs: Library::probe_optional(
                    "tss2-tcti-tbs",
                    install_path.as_ref(),
                    with_header_files,
                ),
            }
        }

        /// Generates bindings for the Installation.
        #[cfg(feature = "generate-bindings")]
        pub fn generate_bindings(&self, esapi_out: &Path) {
            self.bindgen_builder()
                .generate()
                .expect("Unable to generate bindings to TSS2 ESYS APIs.")
                .write_to_file(esapi_out)
                .expect("Couldn't write ESYS bindings!");
        }

        /// The bindgen builder to use.
        #[cfg(feature = "generate-bindings")]
        fn bindgen_builder(&self) -> bindgen::Builder {
            // Creates the general builder.
            let builder = bindgen::Builder::default()
                .size_t_is_usize(false)
                .rust_target(
                    bindgen::RustTarget::stable(73, 0)
                        .expect("Rust version 1.73.0 should be a stable release"),
                ) // lower or equal to MSRV.
                .clang_arg(self.tss2_esys.include_dir_arg())
                .clang_arg(self.tss2_tctildr.include_dir_arg())
                .clang_arg(self.tss2_mu.include_dir_arg())
                .formatter(bindgen::Formatter::Rustfmt)
                .header(self.tss2_esys.header_file_arg())
                .header(self.tss2_tctildr.header_file_arg())
                .header(self.tss2_mu.header_file_arg())
                //See this issue: https://github.com/parallaxsecond/rust-cryptoki/issues/12
                .generate_comments(false)
                .blocklist_type("max_align_t")
                .derive_default(true);
            // Add platform specific args.
            self.add_platform_args(builder)
        }

        /// Adds arguments to the bindgen builder that are platform specific.
        #[cfg(feature = "generate-bindings")]
        fn add_platform_args(&self, builder: bindgen::Builder) -> bindgen::Builder {
            cfg_if::cfg_if! {
                if #[cfg(windows)] {
                    self.add_windows_platform_args(builder)
                } else {
                    builder
                }
            }
        }

        // Adds arguments to the bindgen builder that are specific for Windows.
        #[cfg(all(windows, feature = "generate-bindings"))]
        fn add_windows_platform_args(&self, mut builder: bindgen::Builder) -> bindgen::Builder {
            if let Some(tss2_tcti_tbs) = &self.tss2_tcti_tbs {
                builder = builder
                    .clang_arg(tss2_tcti_tbs.include_dir_arg())
                    .header(tss2_tcti_tbs.header_file_arg());
            }

            const MINIMUM_WIN_SDK_VERSION: &str = "10.0.17134.0";

            let min_sdk_version = Some(
                msbuild::win_sdk::WinSdkVersion::parse(MINIMUM_WIN_SDK_VERSION)
                    .expect("Could not parse the Win SDK version."),
            );

            let win_sdk = msbuild::win_sdk::WinSdk::find_in_range(None, min_sdk_version)
                .expect("Unable to find a Win SDK in version range.");

            builder
                .clang_arg(format!("-I{}", win_sdk.include_dirs().ucrt_dir().display()))
                .clang_arg(format!("-I{}", win_sdk.include_dirs().um_dir().display()))
                .clang_arg(format!(
                    "-I{}",
                    win_sdk.include_dirs().shared_dir().display()
                ))
                .blocklist_type("IMAGE_TLS_DIRECTORY")
                .blocklist_type("PIMAGE_TLS_DIRECTORY")
                .blocklist_type("IMAGE_TLS_DIRECTORY64")
                .blocklist_type("PIMAGE_TLS_DIRECTORY64")
                .blocklist_type("_IMAGE_TLS_DIRECTORY64")
                .blocklist_type("MONITORINFOEX")
                .blocklist_type("MONITORINFOEXA")
                .blocklist_type("MONITORINFOEXW")
                .blocklist_type("tagMONITORINFOEXA")
                .blocklist_type("tagMONITORINFOEXW")
                .blocklist_type("LPMONITORINFOEX")
                .blocklist_type("LPMONITORINFOEXA")
                .blocklist_type("LPMONITORINFOEXW")
        }

        /// Retrieves the installation path from the environment variable and validates it.
        fn installation_path_from_env_var() -> Option<(PathBuf, String)> {
            std::env::var(INSTALLATION_PATH_ENV_VAR_NAME).map_or_else(
                |e| match e {
                    std::env::VarError::NotUnicode(invalid_value) => {
                        panic!(
                            "Invalid `{INSTALLATION_PATH_ENV_VAR_NAME}` env var: `{invalid_value:?}`."
                        );
                    }
                    std::env::VarError::NotPresent => None,
                },
                |var| Some(Installation::ensure_valid_installation_path(var)),
            )
        }

        /// Ensures that the installation path is valid.
        ///
        /// # Details
        /// In order to be considered valid the following
        /// requirements needs to be full filled:
        /// 1. The directory must exist.
        /// 2. Sub directories `include` and `lib` must exist.
        /// 3. A `VERSION` file must be present in the directory and it needs to be
        ///    be specifying a version that is greater then the minimum supported version.
        ///
        /// The function is also responsible for reporting the library search path the rust compiler
        /// should use.
        ///
        /// # Arguments
        /// env_var - The value of the environment variable that contains the installation path.
        ///
        /// # Returns
        /// A tuple containing the validated installation path and the version associated with it.
        fn ensure_valid_installation_path(env_var: String) -> (PathBuf, String) {
            let install_path = PathBuf::from(env_var);
            if !install_path.is_dir() {
                panic!(
                    "The tpm2-tss installation path `{INSTALLATION_PATH_ENV_VAR_NAME}` specifies an existing directory (`{}`).",
                    install_path.to_string_lossy()
                );
            }
            if !install_path.join("include").is_dir() {
                panic!(
                    "The tpm2-tss installation path `{INSTALLATION_PATH_ENV_VAR_NAME}` specifies a path `{}`, that does not \
                     contain an `include` directory",
                    install_path.to_string_lossy()
                );
            }
            if !install_path.join("lib").is_dir() {
                panic!(
                    "The tpm2-tss installation path `{INSTALLATION_PATH_ENV_VAR_NAME}` specifies a path `{}`, that does not \
                     contain an `lib` directory",
                    install_path.to_string_lossy()
                );
            }
            let version_str =
                std::fs::read_to_string(install_path.join("VERSION")).unwrap_or_else(|e| {
                    panic!(
                        "The tpm2-tss installation path `{INSTALLATION_PATH_ENV_VAR_NAME}` specifies a path `{}`, that does not \
                         contain a readable VERSION file: {e}.",
                        install_path.to_string_lossy()
                    );
                });
            let version = Version::parse(version_str.trim()).unwrap_or_else(|e| {
                panic!(
                    "The tpm2-tss installation path `{INSTALLATION_PATH_ENV_VAR_NAME}` specifies a path `{}`, contains a \
                     VERSION file that cannot be parsed: {e}.",
                    install_path.to_string_lossy(),
                );
            });

            let min_version_req_str = format!(">={MINIMUM_VERSION}");
            let min_version_req = VersionReq::parse(&min_version_req_str).unwrap_or_else(|e| {
                panic!(
                    "[Internal Error]: Failed to parse minimum tpm2-tss library version \
                     requirement. Error: `{e}`. Please report this."
                );
            });
            if !min_version_req.matches(&version) {
                panic!(
                    "The tpm2-tss installation path `{INSTALLATION_PATH_ENV_VAR_NAME}` specifies a path `{}`, contains a \
                     VERSION file that specifies a version `{version_str}` that does not meet the minimum \
                     version requirement `{MINIMUM_VERSION}`.",
                    install_path.to_string_lossy(),
                );
            }
            println!(
                "cargo:rustc-link-search=native={}",
                install_path.join("lib").to_string_lossy()
            );
            (install_path, version_str)
        }

        /// Compiles the tpm2-tss source code.
        ///
        /// # Details
        /// Tries to detect the appropriate way to build the source
        /// code.
        #[cfg(feature = "bundled")]
        fn compile(source_path: &Path) {
            cfg_if::cfg_if! {
                if #[cfg(windows)] {
                    let msbuild_max_version = None;
                    let msbuild_min_version = Some(msbuild::ProductLineVersion::Vs2017.installation_version_min());
                    let msbuild = msbuild::MsBuild::find_msbuild_in_range(msbuild_max_version, msbuild_min_version)
                        .expect("Failed to find an installed version of msbuild in the necessary version range.");
                    let profile = std::env::var("PROFILE").unwrap();
                    let build_string = match profile.as_str() {
                        "debug" => "",
                        "release" => "/p:Configuration=Release",
                        _ => panic!("Unknown cargo profile:"),
                    };

                    msbuild.run(source_path, &[
                        build_string,
                        "tpm2-tss.sln"]).unwrap_or_else(|e| {panic!("Failed to run msbuild: {e:?}")});

                    // This should be done by tpm2-tss when building it but it does not
                    // happen on windows (yet..?).
                    use std::io::Write;
                    let version_file_path = source_path.join("VERSION");
                    if !version_file_path.is_file() {
                        let mut version_file = std::fs::File::create(version_file_path)
                            .expect("Unable to create version file for tpm2-tss");
                        write!(version_file, "{}", Self::version())
                            .unwrap_or_else(|e| panic!("Failed to write version file: {e}"));
            }
                }
                else {
                    let install_path = Self::compile_with_autotools(source_path);
                    std::env::set_var(
                        "PKG_CONFIG_PATH",
                        format!("{}", install_path.join("lib").join("pkgconfig").display()),
                    );
                }
            }
        }

        #[cfg(all(feature = "bundled", not(windows)))]
        fn compile_with_autotools(p: &Path) -> PathBuf {
            let output1 = std::process::Command::new("./bootstrap")
                .current_dir(p)
                .output()
                .expect("bootstrap script failed");
            let status = output1.status;
            if !status.success() {
                panic!("{p:?}/bootstrap script failed with {status}:\n{output1:?}");
            }

            let mut config = autotools::Config::new(p);
            config
                // Force configuration of the autotools env
                .reconf("-fiv")
                // skip ./configure if no parameter changes are made
                .fast_build(true)
                .enable("esys", None)
                // Disable fapi as we only use esys
                .disable("fapi", None)
                .disable("fapi-async-tests", None)
                // Disable integration tests
                .disable("integration", None)
                // Don't allow weak crypto
                .disable("weakcrypto", None)
                .build()
        }

        /// Fetch version to use.
        ///
        /// Tries to retrieve a version to use for bundled builds
        /// from en environment variable. If it does not exist then
        /// it defaults to the minimum version.
        ///
        /// # Returns
        /// The version of tpm2-tss to be used when building bundled.
        #[cfg(feature = "bundled")]
        fn version() -> String {
            const VERSION_ENV_VAR_NAME: &str = "TPM2_TSS_SOURCE_VERSION";
            std::env::var(VERSION_ENV_VAR_NAME).unwrap_or_else(|e| match e {
                std::env::VarError::NotUnicode(invalid_value) => {
                    panic!("Invalid `{VERSION_ENV_VAR_NAME}` env var: `{invalid_value:?}`.");
                }
                std::env::VarError::NotPresent => MINIMUM_VERSION.to_string(),
            })
        }

        /// Fetch the source code path.
        ///
        /// # Returns
        /// The path to tpm2-tss source code to be used.
        #[cfg(feature = "bundled")]
        fn source(out_path: &Path, version: &str) -> std::path::PathBuf {
            const REPO: &str = "https://github.com/tpm2-software/tpm2-tss.git";
            const NAME: &str = "tpm2-tss";
            Self::source_path_from_env_var()
                .unwrap_or_else(|| Self::fetch_source(out_path, NAME, REPO, version))
        }

        /// Fetch the given source repo using git
        ///
        /// # Details
        /// Uses a the git application that is installed locally in order
        /// to execute git commands.
        ///
        /// # Args
        ///     `dest_path` - The destination to where the source should be downloaded.
        ///     `name`      - The name of of the repository.
        ///     `repo`      - The path to the repository (web or local).
        ///     `branch`    - The branch to fetch.
        ///
        /// # Returns
        /// The path to the downloaded repository in the form of a PathBuf.
        #[cfg(feature = "bundled")]
        fn fetch_source(
            dest_path: &Path,
            name: &str,
            repo: &str,
            branch: &str,
        ) -> std::path::PathBuf {
            let repo_path = dest_path.join(name);
            if !repo_path.join("Makefile.am").exists() {
                let output = std::process::Command::new("git")
                    .args(["clone", repo, "--depth", "1", "--branch", branch])
                    .current_dir(dest_path)
                    .output()
                    .unwrap_or_else(|_| panic!("git clone for {name} failed"));
                let status = output.status;
                if !status.success() {
                    panic!("git clone for {name} returned failure status {status}:\n{output:?}");
                }
            }
            repo_path
        }

        /// Extracts the source path from the environment variable.
        ///
        /// # Details
        /// Extracts the source code path from the environment variable,
        /// if it exits, and checks that it is valid.
        ///
        /// # Returns
        /// The source code path if the environment variable was
        /// set, else None.
        #[cfg(feature = "bundled")]
        fn source_path_from_env_var() -> Option<PathBuf> {
            const SOURCE_PATH_ENV_VAR_NAME: &str = "TPM2_TSS_SOURCE_PATH";
            std::env::var(SOURCE_PATH_ENV_VAR_NAME).map_or_else(
                |e| match e {
                    std::env::VarError::NotUnicode(invalid_value) => {
                        panic!(
                            "Invalid `{SOURCE_PATH_ENV_VAR_NAME}` env var: `{invalid_value:?}`."
                        );
                    }
                    std::env::VarError::NotPresent => None,
                },
                |var| {
                    let source_path = PathBuf::from(var.as_str());
                    if !source_path.is_dir() {
                        panic!(
                            "Invalid `{SOURCE_PATH_ENV_VAR_NAME}` env var. `{:?}` is not a directory.",
                            var.as_str()
                        );
                    }
                    let is_empty_dir = source_path
                        .read_dir()
                        .unwrap_or_else(|e| {
                            panic!(
                                "Invalid `{SOURCE_PATH_ENV_VAR_NAME}` env var. Unable to read dir `{:?}`. \n {e:?}",
                                var.as_str(),
                            )
                        })
                        .next()
                        .is_none();
                    if is_empty_dir {
                        panic!(
                            "Invalid `{SOURCE_PATH_ENV_VAR_NAME}` env var. `{:?}` is an empty directory.",
                            var.as_str()
                        );
                    }
                    Some(source_path)
                },
            )
        }
    }

    /// Struct holding the information for a library.
    struct Library {
        #[allow(unused)]
        header_file: Option<PathBuf>,
        version: String,
        #[allow(unused)]
        name: String,
    }

    impl Library {
        /// Probes the different options for a required library.
        ///
        /// # Arguments
        ///     `lib_name`          - The name of the library.
        ///     `install_path`      - Optional path and version of installation.
        ///     `with_header_files` - Flag indicating if header files are required.
        ///     `report_version`    - Flag indicating if the version of the library should
        ///                           be reported to Cargo.
        ///
        /// # Returns
        ///     The detected installed library.
        /// # Panics
        ///     - If the library is not found.
        pub fn probe_required(
            lib_name: &str,
            install_path: Option<&(PathBuf, String)>,
            with_header_files: bool,
            report_version: bool,
        ) -> Self {
            Self::probe_optional(lib_name, install_path, with_header_files).map_or_else(
                || {
                    panic!(
                        "Failed to find {lib_name} library of version {MINIMUM_VERSION} or greater."
                    )
                },
                |lib| {
                    if report_version {
                        Self::report_version(&lib.version);
                    }
                    lib
                },
            )
        }

        /// Probes the different options for an optional library.
        ///
        /// # Arguments
        ///     `lib_name`          - The name of the library.
        ///     `install_path`      - Optional path and version of installation.
        ///     `with_header_files` - Flag indicating if header files are required.
        ///
        /// # Returns
        ///     The detected installed library or None if no library was found.
        pub fn probe_optional(
            lib_name: &str,
            install_path: Option<&(PathBuf, String)>,
            with_header_files: bool,
        ) -> Option<Self> {
            if let Some((path, version)) = install_path {
                return Self::probe_install_path_optional(
                    lib_name,
                    path,
                    version,
                    with_header_files,
                );
            }
            Self::probe_pkg_config_optional(lib_name, with_header_files, MINIMUM_VERSION)
        }

        /// Creates a bundled required library.
        ///
        /// # Arguments
        ///     `lib_name`          - The name of the library.
        ///     `source_path`       - Path to the source code.
        ///     `lib_version`       - The version of the library.
        ///     `report_to_cargo`   - Flag indicating if the version and linking information
        ///                           of the library should be reported to Cargo.
        ///
        /// # Returns
        ///     The bundled library.
        #[cfg(feature = "bundled")]
        pub fn bundled_required(
            lib_name: &str,
            source_path: &Path,
            lib_version: &str,
            report_to_cargo: bool,
        ) -> Self {
            let lib =
                Self::bundled_optional(lib_name, source_path, lib_version).unwrap_or_else(|| {
                    panic!("Failed to find {lib_name} library of version {lib_version} or greater.")
                });

            if report_to_cargo {
                Self::report_version(&lib.version);
                Self::report_search_paths(source_path);
            }
            lib
        }

        /// Creates a bundled optional library.
        ///
        /// # Arguments
        ///     `lib_name`      - The name of the library.
        ///     `source_path`   - Path to the source code.
        ///     `lib_version`   - The version of the library.
        ///
        /// # Returns
        ///     The bundled library if it was found else None.      
        #[cfg(feature = "bundled")]
        pub fn bundled_optional(
            lib_name: &str,
            _source_path: &Path,
            lib_version: &str,
        ) -> Option<Self> {
            cfg_if::cfg_if! {
                if #[cfg(windows)] {
                    let include_path = _source_path.join("include").join("tss2");
                    println!("cargo:rustc-link-lib=dylib={lib_name}");
                    Some(Self {
                        header_file: Self::header_file(lib_name, &include_path, true),
                        version: lib_version.to_string(),
                        name: lib_name.to_string(),
                    })
                } else {
                    // PKG_CONFIG_PATH is setup in the compile step for bundled.
                    Self::probe_pkg_config_optional(lib_name, true, lib_version)
                }
            }
        }

        /// The include dir `clang_arg` bindgen builder argument.
        ///
        /// # Panics
        ///     - If the library was probed without requiring header files.
        ///     - If the library specifies a header file does not have a parent directory.
        ///     - If the library specifies a header file path that contain invalid utf-8 characters.
        #[allow(unused)]
        pub fn include_dir_arg(&self) -> String {
            self.header_file
                .as_ref()
                .unwrap_or_else(|| panic!("No header file present for `{}`.", self.name))
                .parent()
                .unwrap_or_else(|| panic!("Inconsistent `{}` header file path.", self.name))
                .as_os_str()
                .to_str()
                .map_or_else(
                    || {
                        panic!(
                            "Error converting OsString to &str when processing `{}` include dir.",
                            self.name
                        );
                    },
                    |v| format!("-I{v}"),
                )
        }

        /// The header file path to a `header` bindgen argument.
        ///
        /// # Panics
        ///     - If the library specifies a header file path that contain invalid utf-8 characters.
        #[allow(unused)]
        pub fn header_file_arg(&self) -> &str {
            self.header_file.as_ref().map_or_else(
                || {
                    panic!("No header file present for `{}`.", self.name);
                },
                |v| {
                    v.as_os_str().to_str().unwrap_or_else(|| {
                        panic!(
                            "Error converting OsString to &str when processing `{}` include dir.",
                            self.name
                        )
                    })
                },
            )
        }

        /// Probe the system for an optional library using pkg-config.
        ///
        /// # Args
        /// `lib_name`          - The name of the library.
        /// `with_header_files` - Flag indicating if header files are required.
        fn probe_pkg_config_optional(
            lib_name: &str,
            with_header_files: bool,
            lib_version: &str,
        ) -> Option<Self> {
            pkg_config::Config::new()
                .atleast_version(lib_version)
                .probe(lib_name)
                .ok()
                .map(|pkg_config| {
                    if !with_header_files {
                        return Self {
                            header_file: None,
                            version: pkg_config.version,
                            name: lib_name.to_string(),
                        };
                    }
                    let include_path = pkg_config.include_paths[0].join("tss2");
                    let header_file = Self::header_file(lib_name, &include_path, with_header_files);
                    Self {
                        header_file,
                        version: pkg_config.version,
                        name: lib_name.to_string(),
                    }
                })
        }

        /// Probe the install path for a library.
        ///
        /// # Details
        /// Will report then name of the library to Cargo for
        /// static linking purposes.
        ///
        /// # Arguments
        /// `lib_name`      - The name of the library to probe for.
        /// `path`          - The path to probe for the library.
        /// `lib_version`   - The version of the library.
        ///
        /// # Returns
        /// A `Library` object containing the information retrieved if one
        /// was found that matched the library name.
        ///
        /// # Panics
        ///     - If no `.lib` or `.so` file for the library was found.
        ///     - If no `.h` file for the library was found.
        fn probe_install_path_optional(
            lib_name: &str,
            path: &Path,
            lib_version: &str,
            with_header_files: bool,
        ) -> Option<Self> {
            let lib_path = path.join("lib");
            Self::lib_file(lib_name, &lib_path)?;
            // If the lib file was found then the name is reported to Cargo.
            println!("cargo:rustc-link-lib={lib_name}");

            let include_path = path.join("include/tss2");
            Some(Self {
                header_file: Self::header_file(lib_name, &include_path, with_header_files),
                version: lib_version.to_string(),
                name: lib_name.to_string(),
            })
        }

        /// Finds the path for the lib file.
        ///
        /// # Arguments
        /// `lib_name` - The name of the library to probe for.
        /// `lib_path` - The path to probe for the library.
        ///
        /// # Returns
        ///     The lib file path if it was found.
        ///
        /// # Panics
        ///     - If the `lib_path` cannot be read using `read_dir`.
        ///     - If more then one file matches the lib_name.
        fn lib_file(lib_name: &str, lib_path: &Path) -> Option<PathBuf> {
            let mut hit_iter = read_dir(lib_path)
                .expect("The call to read_dir failed.")
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|file| {
                    file.extension()
                        .and_then(|ext| ext.to_str())
                        .is_some_and(|file_ext| ["so", "lib"].contains(&file_ext))
                        && file
                            .file_stem()
                            .and_then(|stem| stem.to_str())
                            .is_some_and(|file_name| file_name.contains(lib_name))
                })
                .peekable();

            let result = hit_iter.next();
            // Ensure it is a unique hit
            if let Some(hit) = result.as_ref() {
                if hit_iter.peek().is_some() {
                    let mut associated_files = hit_iter.collect::<Vec<PathBuf>>();
                    associated_files.push(hit.clone());
                    panic!(
                        "More then one match found for library `{lib_name}`: {associated_files:?}",
                    );
                }
            }
            result
        }

        /// Creates a PathBuf object for the header file.
        ///
        /// # Args
        /// `lib_name`          - Name of the library.
        /// `include_path`      - The include path to the header file.
        /// `with_header_files` - Flag indicating if header files are required.
        ///
        /// # Returns
        ///     An optional PathBuf object.
        ///
        /// # Panics
        ///     - If `with_header_files` but the combination of `file_name` and `include_path`
        ///       does not point to an existing file.
        fn header_file(
            lib_name: &str,
            include_path: &Path,
            with_header_files: bool,
        ) -> Option<PathBuf> {
            if !with_header_files {
                return None;
            }
            let file_name = PathBuf::from(lib_name.replace('-', "_"));
            let header_file = include_path.join(file_name.with_extension("h"));
            if !header_file.is_file() {
                panic!(
                    "Header file `{}`, does not exist.",
                    header_file.to_string_lossy()
                );
            }
            Some(header_file)
        }

        /// Reports the library version to Cargo.
        ///
        /// # Arguments
        /// `lib_version`   - The version of the library.
        fn report_version(lib_version: &str) {
            println!("cargo:version={lib_version}");
        }

        /// Reports search paths too Cargo.
        ///
        /// # Arguments
        ///     `source_path`   - Path to the source code.
        #[cfg(feature = "bundled")]
        fn report_search_paths(_source_path: &Path) {
            cfg_if::cfg_if! {
                if #[cfg(windows)] {
                    let profile = std::env::var("PROFILE").unwrap();
                    let build_string = match profile.as_str() {
                        "debug" => "Debug",
                        "release" => "Release",
                        _ => panic!("Unknown cargo profile: {}", profile),
                    };
                    let lib_out_path: PathBuf = _source_path.join("x64").join(build_string);
                    println!("cargo:rustc-link-search=all={}", lib_out_path.display());
                }
            }
        }
    }
}
