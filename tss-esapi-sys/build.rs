// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "generate-bindings")]
use std::path::PathBuf;

#[cfg(feature = "bundled")]
use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

const MINIMUM_VERSION: &str = "3.2.2";

#[cfg(feature = "bundled")]
fn fetch_source(dest_path: impl AsRef<Path>, name: &str, repo: &str, branch: &str) -> PathBuf {
    let parent_path = dest_path.as_ref();
    let repo_path = parent_path.join(name);
    let output = if !repo_path.join("Makefile.am").exists() {
        Command::new("git")
            .args(["clone", repo, "--depth", "1", "--branch", branch])
            .current_dir(parent_path)
            .output()
            .expect(&format!("git clone for {} failed", name))
    } else {
        Command::new("git")
            .args(["pull", "--ff-only", "origin", branch])
            .current_dir(&repo_path)
            .output()
            .expect(&format!("git pull for {} failed", name))
    };

    let status = output.status;
    assert!(
        status.success(),
        "git clone/pull for {name} returned failure status {status}:\n{output:?}"
    );

    repo_path
}

#[cfg(feature = "bundled")]
fn compile_with_autotools(p: PathBuf) -> PathBuf {
    let output1 = Command::new("./bootstrap")
        .current_dir(&p)
        .output()
        .expect("bootstrapt script failed");
    let status = output1.status;
    assert!(
        status.success(),
        "bootstrapt script failed with {status}:\n{output1:?}"
    );

    let mut config = autotools::Config::new(p);
    config.fast_build(true).reconf("-ivf").build()
}

#[cfg(feature = "bundled")]
fn use_pkgconfig(
    required_version: &str,
    first_unsupported_version: &str,
    name: &str,
) -> pkg_config::Library {
    // Run pkg-config
    let lib = pkg_config::Config::new()
        .range_version(required_version..first_unsupported_version)
        .statik(true)
        .probe(name)
        .expect("Could not find a suitable version of {name}");

    // As it turns-out, pkg-config does not correctly set up the RPATHs for the
    // transitive dependencies of in static builds. Fix that.
    if cfg!(target_family = "unix") {
        for link_path in &lib.link_paths {
            println!(
                "cargo:rustc-link-arg=-Wl,-rpath,{}",
                link_path
                    .to_str()
                    .expect("Link path is not an UTF-8 string")
            );
        }
    }

    // Forward pkg-config output for futher consumption
    lib
}

fn main() {
    if std::env::var("DOCS_RS").is_ok() {
        // Nothing to be done for docs.rs builds.
        return;
    }

    #[cfg(feature = "generate-bindings")]
    {
        let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
        let esys_path = out_path.join("tss_esapi_bindings.rs");
        generate_from_system(esys_path);
    }

    #[cfg(all(feature = "bundled", not(windows)))]
    {
        let out_path = env::var("OUT_DIR").expect("No output directory given");
        let source_path = fetch_source(
            out_path,
            "tpm2-tss",
            "https://github.com/tpm2-software/tpm2-tss.git",
            "3.2.2",
        );

        let install_path = compile_with_autotools(source_path);
        env::set_var(
            "PKG_CONFIG_PATH",
            format!("{}", install_path.join("lib").join("pkgconfig").display()),
        );
        use_pkgconfig(MINIMUM_VERSION, "4.0.0", "tss2-esys");
    }

    #[cfg(all(feature = "bundled", windows))]
    {
        let out_path = env::var("OUT_DIR").expect("No output directory given");
        let source_path = fetch_source(
            out_path,
            "tpm2-tss",
            "https://github.com/tpm2-software/tpm2-tss.git",
            "3.2.2",
        );

        let mut msbuild = msbuild::MsBuild::find_msbuild().unwrap();
        msbuild.run(source_path, &[
            "-ds",
            "tpm2-tss.sln"]);
    }

    #[cfg(all(not(feature = "generate-bindings"), not(features = "bundled")))]
    {
        use std::str::FromStr;
        use target_lexicon::{Architecture, OperatingSystem, Triple};

        let target = Triple::from_str(&std::env::var("TARGET").unwrap())
            .expect("Failed to parse target triple");
        match (target.architecture, target.operating_system) {
            (Architecture::Arm(_), OperatingSystem::Linux) => {}
            (Architecture::Aarch64(_), OperatingSystem::Linux) => {}
            (Architecture::X86_64, OperatingSystem::Darwin) => {}
            (Architecture::X86_64, OperatingSystem::Linux) => {}
            (arch, os) => {
                panic!("Compilation target (architecture, OS) tuple ({}, {}) is not part of the supported tuples. Please compile with the \"generate-bindings\" feature or add support for your platform :)", arch, os);
            }
        }

        pkg_config::Config::new()
            .atleast_version(MINIMUM_VERSION)
            .probe("tss2-sys")
            .expect("Failed to find tss2-sys library.");
        let tss2_esys = pkg_config::Config::new()
            .atleast_version(MINIMUM_VERSION)
            .probe("tss2-esys")
            .expect("Failed to find tss2-esys library.");
        pkg_config::Config::new()
            .atleast_version(MINIMUM_VERSION)
            .probe("tss2-tctildr")
            .expect("Failed to find tss2-tctildr library.");
        pkg_config::Config::new()
            .atleast_version(MINIMUM_VERSION)
            .probe("tss2-mu")
            .expect("Failed to find tss2-mu library.");

        println!("cargo:version={}", tss2_esys.version);
    }
}

#[cfg(feature = "generate-bindings")]
pub fn generate_from_system(esapi_out: PathBuf) {
    pkg_config::Config::new()
        .atleast_version(MINIMUM_VERSION)
        .probe("tss2-sys")
        .expect("Failed to find tss2-sys library.");
    let tss2_esys = pkg_config::Config::new()
        .atleast_version(MINIMUM_VERSION)
        .probe("tss2-esys")
        .expect("Failed to find tss2-esys");
    let tss2_tctildr = pkg_config::Config::new()
        .atleast_version(MINIMUM_VERSION)
        .probe("tss2-tctildr")
        .expect("Failed to find tss2-tctildr");
    let tss2_mu = pkg_config::Config::new()
        .atleast_version(MINIMUM_VERSION)
        .probe("tss2-mu")
        .expect("Failed to find tss2-mu");

    println!("cargo:version={}", tss2_esys.version);

    // These three pkg-config files should contain only one include/lib path.
    let tss2_esys_include_path = tss2_esys.include_paths[0]
        .clone()
        .into_os_string()
        .into_string()
        .expect("Error converting OsString to String.");
    let tss2_tctildr_include_path = tss2_tctildr.include_paths[0]
        .clone()
        .into_os_string()
        .into_string()
        .expect("Error converting OsString to String.");
    let tss2_mu_include_path = tss2_mu.include_paths[0]
        .clone()
        .into_os_string()
        .into_string()
        .expect("Error converting OsString to String.");

    bindgen::Builder::default()
        .size_t_is_usize(false)
        .clang_arg(format!("-I{}/tss2/", tss2_esys_include_path))
        .clang_arg(format!("-I{}/tss2/", tss2_tctildr_include_path))
        .clang_arg(format!("-I{}/tss2/", tss2_mu_include_path))
        .header(format!("{}/tss2/tss2_esys.h", tss2_esys_include_path))
        .header(format!("{}/tss2/tss2_tctildr.h", tss2_tctildr_include_path))
        .header(format!("{}/tss2/tss2_mu.h", tss2_mu_include_path))
        // See this issue: https://github.com/parallaxsecond/rust-cryptoki/issues/12
        .blocklist_type("max_align_t")
        .generate_comments(false)
        .derive_default(true)
        .generate()
        .expect("Unable to generate bindings to TSS2 ESYS APIs.")
        .write_to_file(esapi_out)
        .expect("Couldn't write ESYS bindings!");
}
