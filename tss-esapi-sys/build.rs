// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "generate-bindings")]
use std::path::PathBuf;

const MINIMUM_VERSION: &str = "2.3.3";

fn main() {
    #[cfg(feature = "generate-bindings")]
    {
        let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
        let esys_path = out_path.join("tss_esapi_bindings.rs");
        generate_from_system(esys_path);
    }

    #[cfg(not(feature = "generate-bindings"))]
    {
        let supported_platforms = vec![String::from("x86_64-unknown-linux-gnu")];
        let target = std::env::var("TARGET").unwrap();

        // check if target is in the list of supported ones or panic with nice message
        if !supported_platforms.contains(&target) {
            panic!(format!("Compilation target ({}) is not part of the supported targets ({:?}). Please compile with the \"generate-bindings\" feature or add support for your platform :)", target, supported_platforms));
        }

        pkg_config::Config::new()
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
    }
}

#[cfg(feature = "generate-bindings")]
pub fn generate_from_system(esapi_out: PathBuf) {
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

    // Check version to automatically set compatability flag.
    match tss2_esys.version.chars().next().unwrap() {
        '2' => println!("cargo:rustc-cfg=tpm2_tss_version=\"2\""),
        '3' => println!("cargo:rustc-cfg=tpm2_tss_version=\"3\""),
        major => panic!("Unsupported TSS version: {}", major),
    }

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
        .clang_arg(format!("-I{}/tss2/", tss2_esys_include_path))
        .clang_arg(format!("-I{}/tss2/", tss2_tctildr_include_path))
        .clang_arg(format!("-I{}/tss2/", tss2_mu_include_path))
        .rustfmt_bindings(true)
        .header(format!("{}/tss2/tss2_esys.h", tss2_esys_include_path))
        .header(format!("{}/tss2/tss2_tctildr.h", tss2_tctildr_include_path))
        .header(format!("{}/tss2/tss2_mu.h", tss2_mu_include_path))
        .generate_comments(false)
        .derive_default(true)
        .generate()
        .expect("Unable to generate bindings to TSS2 ESYS APIs.")
        .write_to_file(esapi_out)
        .expect("Couldn't write ESYS bindings!");
}
