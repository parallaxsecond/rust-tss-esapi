// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

fn main() {
    if std::env::var("DOCS_RS").is_ok() {
        // Nothing to be done for docs.rs builds.
        return;
    }

    cfg_if::cfg_if! {
        if #[cfg(feature = "generate-bindings")] {
            #[cfg(feature = "bundled")]
            let installation = tpm2_tss::Installation::bundled();
            #[cfg(not(feature = "bundled"))]
            let installation = tpm2_tss::Installation::probe(true);
            let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
            installation.generate_bindings(&out_dir.join("tss_esapi_bindings.rs"));
            installation.output_linker_arguments();
        } else {
            target::ensure_supported();
            #[cfg(feature = "bundled")]
            {
                let installation = tpm2_tss::Installation::bundled();
                installation.pkg_config();
            }
            #[cfg(not(feature = "bundled"))]
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
            panic!("Missing environment variable `{}`.", TARGET_ENV_VAR_NAME);
        }))
        .expect("Failed to parse target triple.");
        match (target.architecture, target.operating_system) {
            (Architecture::Arm(_), OperatingSystem::Linux)
            | (Architecture::Aarch64(_), OperatingSystem::Linux)
            | (Architecture::X86_64, OperatingSystem::Darwin)
            | (Architecture::X86_64, OperatingSystem::Linux) => {}
            (arch, os) => {
                panic!(
                    "Compilation target (architecture, OS) tuple ({}, {}) is not part of the \
                     supported tuples. Please compile with the \"generate-bindings\" feature or \
                     add support for your platform.",
                    arch, os
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
    const MINIMUM_VERSION: &str = "3.2.2";
    const PATH_ENV_VAR_NAME: &str = "TPM2_TSS_PATH";

    /// The installed tpm2-tss libraries that are of
    /// interest.
    pub struct Installation {
        tss2_sys: Library,
        tss2_esys: Library,
        tss2_tctildr: Library,
        tss2_mu: Library,
        tss2_tcti_tbs: Option<Library>,
    }

    impl Installation {
        /// Return an optional list of clang arguments that are platform specific
        #[cfg(feature = "bundled")]
        fn platform_args() -> Option<Vec<String>> {
            cfg_if::cfg_if! {
                if #[cfg(windows)] {
                    let mut clang_args: Vec<String> = Vec::new();
                    let hklm = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE);
                    // Find the windows sdk path from the windows registry
                    let sdk_entry = hklm.open_subkey("SOFTWARE\\WOW6432Node\\Microsoft\\Microsoft SDKs\\Windows\\v10.0").unwrap();
                    // add relevant paths to get to the windows 10.0.17134.0 sdk, which tpm2-tss uses on windows.
                    let installation_path: String = sdk_entry.get_value("InstallationFolder").unwrap();
                    let ip_pb = PathBuf::from(installation_path).join("Include");
                    let windows_sdk = ip_pb.join("10.0.17134.0");
                    // Add paths required for bindgen to find all required headers
                    clang_args.push(format!("-I{}", windows_sdk.join("ucrt").display()));
                    clang_args.push(format!("-I{}", windows_sdk.join("um").display()));
                    clang_args.push(format!("-I{}", windows_sdk.join("shared").display()));
                    Some(clang_args)
                }
                else {
                    None
                }
            }
        }

        #[cfg(feature = "bundled")]
        /// Fetch the given source repo using git
        fn fetch_source(
            dest_path: impl AsRef<std::path::Path>,
            name: &str,
            repo: &str,
            branch: &str,
        ) -> std::path::PathBuf {
            let parent_path = dest_path.as_ref();
            let repo_path = parent_path.join(name);
            if !repo_path.join("Makefile.am").exists() {
                let output = std::process::Command::new("git")
                    .args(["clone", repo, "--depth", "1", "--branch", branch])
                    .current_dir(parent_path)
                    .output()
                    .unwrap_or_else(|_| panic!("git clone for {} failed", name));
                let status = output.status;
                if !status.success() {
                    panic!(
                        "git clone for {} returned failure status {}:\n{:?}",
                        name, status, output
                    );
                }
            }

            repo_path
        }

        #[cfg(all(feature = "bundled",not(windows)))]
        fn compile_with_autotools(p: PathBuf) -> PathBuf {
            let output1 = std::process::Command::new("./bootstrap")
                .current_dir(&p)
                .output()
                .expect("bootstrap script failed");
            let status = output1.status;
            if !status.success() {
                panic!("bootstrap script failed with {}:\n{:?}", status, output1);
            }

            let mut config = autotools::Config::new(p);
            config.fast_build(true).reconf("-ivf").build()
        }

        #[cfg(feature = "bundled")]
        /// Uses a bundled build for an installation
        pub fn bundled() -> Self {
            use std::io::Write;
            let out_path = std::env::var("OUT_DIR").expect("No output directory given");
            let source_path = Self::fetch_source(
                out_path,
                "tpm2-tss",
                "https://github.com/tpm2-software/tpm2-tss.git",
                MINIMUM_VERSION,
            );
            let version_file_name = source_path.join("VERSION");
            let mut version_file = std::fs::File::create(version_file_name)
                .expect("Unable to create version file for tpm2-tss");
            write!(version_file, "{}", MINIMUM_VERSION)
                .unwrap_or_else(|e| panic!("Failed to write version file: {}", e));

            cfg_if::cfg_if! {
                if #[cfg(windows)] {
                    let mut msbuild = msbuild::MsBuild::find_msbuild(Some("2017")).unwrap();
                    let profile = std::env::var("PROFILE").unwrap();
                    let build_string = match profile.as_str() {
                        "debug" => "",
                        "release" => "/p:Configuration=Release",
                        _ => panic!("Unknown cargo profile:"),
                    };

                    msbuild.run(source_path.clone(), &[
                        build_string,
                        "tpm2-tss.sln"]);
                }
                else {
                    let install_path = Self::compile_with_autotools(source_path.clone());
                    std::env::set_var(
                        "PKG_CONFIG_PATH",
                        format!("{}", install_path.join("lib").join("pkgconfig").display()),
                    );
                }
            }
            std::env::set_var(PATH_ENV_VAR_NAME, source_path.clone());

            let include_path = source_path.join("include").join("tss2");

            #[cfg(windows)]
            let tbs = Some(Library {
                header_file: Some(include_path.join("tss2_tcti_tbs.h")),
                version: MINIMUM_VERSION.into(),
                name: "tss2-tbs".into(),
            });
            #[cfg(not(windows))]
            let tbs = None;
            Self {
                tss2_sys: Library {
                    header_file: Some(include_path.join("tss2_sys.h")),
                    version: MINIMUM_VERSION.into(),
                    name: "tss2-sys".into(),
                },
                tss2_esys: Library {
                    header_file: Some(include_path.join("tss2_esys.h")),
                    version: MINIMUM_VERSION.into(),
                    name: "tss2-esys".into(),
                },
                tss2_tctildr: Library {
                    header_file: Some(include_path.join("tss2_tctildr.h")),
                    version: MINIMUM_VERSION.into(),
                    name: "tss2-tctildr".into(),
                },
                tss2_mu: Library {
                    header_file: Some(include_path.join("tss2_mu.h")),
                    version: MINIMUM_VERSION.into(),
                    name: "tss2-mu".into(),
                },
                tss2_tcti_tbs: tbs,
            }
        }

        /// Probes the system for an installation.
        pub fn probe(with_header_files: bool) -> Self {
            let install_path = Installation::installation_path_from_env_var();
            Installation {
                tss2_sys: Library::probe_required(
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

        cfg_if::cfg_if! {
            if #[cfg(feature = "generate-bindings")] {

                /// Generates bindings for the Installation.
                pub fn generate_bindings(&self, esapi_out: &Path) {
                    self.bindgen_builder()
                        .generate()
                        .expect("Unable to generate bindings to TSS2 ESYS APIs.")
                        .write_to_file(esapi_out)
                        .expect("Couldn't write ESYS bindings!");
                }

                /// The bindgen builder to use.
                fn bindgen_builder(&self) -> bindgen::Builder {
                    let mut builder = bindgen::Builder::default()
                        .size_t_is_usize(false)
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
                        // Needed for windows
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
                        .derive_default(true);
                    if let Some(tss2_tcti_tbs) = &self.tss2_tcti_tbs {
                        builder = builder
                            .clang_arg(tss2_tcti_tbs.include_dir_arg())
                            .header(tss2_tcti_tbs.header_file_arg());
                    }
                    if let Some(clang_args) = Self::platform_args() {
                        for arg in clang_args {
                            builder = builder.clang_arg(arg);
                        }
                    }
                    builder
                }
            }
        }

        /// Run pkgconfig for bundled installations
        #[cfg(feature = "bundled")]
        pub fn pkg_config(&self) {
            self.tss2_sys.pkg_config();
            self.tss2_esys.pkg_config();
            self.tss2_tctildr.pkg_config();
            self.tss2_mu.pkg_config();
            if let Some(lib) = &self.tss2_tcti_tbs {
                lib.pkg_config();
            }
        }

        pub fn output_linker_arguments(&self) {
            #[cfg(windows)]
            {
                println!("cargo:rustc-link-lib=dylib=tss2-esys");
                println!("cargo:rustc-link-lib=dylib=tss2-mu");
                println!("cargo:rustc-link-lib=dylib=tss2-sys");
                println!("cargo:rustc-link-lib=dylib=tss2-tctildr");
                println!("cargo:rustc-link-lib=dylib=tss2-tcti-tbs");
                let profile = std::env::var("PROFILE").unwrap();
                let build_string = match profile.as_str() {
                    "debug" => "Debug",
                    "release" => "Release",
                    _ => panic!("Unknown cargo profile: {}", profile),
                };
                let mut source_path = self
                    .tss2_esys
                    .header_file
                    .clone()
                    .expect("Expected a header file path");
                source_path.pop();
                source_path.pop();
                source_path.pop();
                println!(
                    "cargo:rustc-link-search=dylib={}",
                    source_path.join("x64").join(build_string).display()
                );
            }
        }

        /// Retrieves the installation path from the environment variable and validates it.
        fn installation_path_from_env_var() -> Option<(PathBuf, String)> {
            std::env::var(PATH_ENV_VAR_NAME).map_or_else(
                |e| match e {
                    std::env::VarError::NotUnicode(invalid_value) => {
                        panic!(
                            "Invalid `{}` env var: `{:?}`.",
                            PATH_ENV_VAR_NAME, invalid_value
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
                    "The tpm2-tss installation path `{}` specifies an existing directory (`{}`).",
                    PATH_ENV_VAR_NAME,
                    install_path.to_string_lossy(),
                );
            }
            if !install_path.join("include").is_dir() {
                panic!(
                    "The tpm2-tss installation path `{}` specifies a path `{}`, that does not \
                     contain an `include` directory",
                    PATH_ENV_VAR_NAME,
                    install_path.to_string_lossy(),
                );
            }
            if !install_path.join("lib").is_dir() {
                panic!(
                    "The tpm2-tss installation path `{}` specifies a path `{}`, that does not \
                     contain an `lib` directory",
                    PATH_ENV_VAR_NAME,
                    install_path.to_string_lossy(),
                );
            }
            let version_str =
                std::fs::read_to_string(install_path.join("VERSION")).unwrap_or_else(|e| {
                    panic!(
                        "The tpm2-tss installation path `{}` specifies a path `{}`, that does not \
                         contain a readable VERSION file: {}.",
                        PATH_ENV_VAR_NAME,
                        install_path.to_string_lossy(),
                        e,
                    );
                });
            let version = Version::parse(version_str.trim()).unwrap_or_else(|e| {
                panic!(
                    "The tpm2-tss installation path `{}` specifies a path `{}`, contains a \
                     VERSION file that cannot be parsed: {}.",
                    PATH_ENV_VAR_NAME,
                    install_path.to_string_lossy(),
                    e
                );
            });

            let min_version_req_str = format!(">={}", MINIMUM_VERSION);
            let min_version_req = VersionReq::parse(&min_version_req_str).unwrap_or_else(|e| {
                panic!(
                    "[Internal Error]: Failed to parse minimum tpm2-tss library version \
                     requirement. Error: `{}`. Please report this.",
                    e
                );
            });
            if !min_version_req.matches(&version) {
                panic!(
                    "The tpm2-tss installation path `{}` specifies a path `{}`, contains a \
                     VERSION file that specifies a version `{}` that does not meet the minimum \
                     version requirement `{}`.",
                    PATH_ENV_VAR_NAME,
                    install_path.to_string_lossy(),
                    version_str,
                    MINIMUM_VERSION,
                );
            }
            println!(
                "cargo:rustc-link-search=native={}",
                install_path.join("lib").to_string_lossy()
            );
            (install_path, version_str)
        }
    }

    /// Struct holding the information for a library.
    struct Library {
        header_file: Option<PathBuf>,
        version: String,
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
                        "Failed to find {} library of version {MINIMUM_VERSION} or greater.",
                        lib_name
                    )
                },
                |lib| {
                    if report_version {
                        println!("cargo:version={}", lib.version);
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
            Self::probe_pkg_config_optional(lib_name, with_header_files)
        }

        /// The include dir `clang_arg` bindgen builder argument.
        ///
        /// # Panics
        ///     - If the library was probe without requiring header files.
        ///     - If the library specifies a header file does not have a parent directory.
        ///     - If the library specifies a header file path that contain invalid utf-8 characters.
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
                    |v| format!("-I{}", v),
                )
        }

        /// The header file path to a `header` bindgen argument.
        ///
        /// # Panics
        ///     - If the library specifies a header file path that contain invalid utf-8 characters.
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

        /// Use the pkg config file for a bundled installation
        #[cfg(feature = "bundled")]
        fn pkg_config(&self) {
            pkg_config::Config::new()
                .atleast_version(MINIMUM_VERSION)
                .statik(true)
                .probe(&self.name)
                .unwrap_or_else(|_| panic!("Failed to run pkg-config on {}", self.name));
        }

        /// Probe the system for an optional library using pkg-config.
        ///
        /// # Args
        /// `lib_name`          - The name of the library.
        /// `with_header_files` - Flag indicating if header files are required.
        fn probe_pkg_config_optional(lib_name: &str, with_header_files: bool) -> Option<Self> {
            pkg_config::Config::new()
                .atleast_version(MINIMUM_VERSION)
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
        /// `lib_name` - The name of the library to probe for.
        /// `path`     - The path to probe for the library.
        /// `version`  - The version of the library.
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
            version: &str,
            with_header_files: bool,
        ) -> Option<Self> {
            let lib_path = path.join("lib");
            Self::lib_file(lib_name, &lib_path)?;
            // If the lib file was found then the name is reported to Cargo.
            println!("cargo:rustc-link-lib={}", lib_name);

            let include_path = path.join("include/tss2");
            Some(Self {
                header_file: Self::header_file(lib_name, &include_path, with_header_files),
                version: version.to_string(),
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
                        .map_or(false, |file_ext| ["so", "lib"].contains(&file_ext))
                        && file
                            .file_stem()
                            .and_then(|stem| stem.to_str())
                            .map_or(false, |file_name| file_name.contains(lib_name))
                })
                .peekable();

            let result = hit_iter.next();
            // Ensure it is a unique hit
            if let Some(hit) = result.as_ref() {
                if hit_iter.peek().is_some() {
                    let mut associated_files = hit_iter.collect::<Vec<PathBuf>>();
                    associated_files.push(hit.clone());
                    panic!(
                        "More then one match found for library `{}`: {:?}",
                        lib_name, associated_files
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
    }
}
