// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use semver::{Version, VersionReq, Prerelease};

const TPM2_TSS_MINIMUM_VERSION: Version = Version::new(4, 1, 3);
const TPM2_TSS_VERSION_IGNORE_PRERELEASE: &str = "TPM2_TSS_VERSION_IGNORE_PRERELEASE";

fn main() {
    println!("cargo:rustc-check-cfg=cfg(hierarchy_is_esys_tr)");
    println!("cargo:rustc-check-cfg=cfg(has_tss_base_rc_values_28_to_51)");
    println!("cargo:rustc-check-cfg=cfg(has_tss_base_rc_values_52_to_53)");
    println!("cargo:rustc-check-cfg=cfg(has_tpmu_sensitive_create)");
    println!("cargo:rustc-check-cfg=cfg(has_esys_tr_get_tpm_handle)");

    // If documentation for Docs.rs is being built then the version is set
    // to the minimum supported tpm2-tss version.
    let mut tss_version = if std::env::var("DOCS_RS").is_ok() {
        TPM2_TSS_MINIMUM_VERSION
    } else {
        let tss_version_string = std::env::var("DEP_TSS2_ESYS_VERSION")
            .expect("Failed to parse ENV variable DEP_TSS2_ESYS_VERSION as string");

        Version::parse(&tss_version_string)
            .map(|mut v| {
                if std::env::var(TPM2_TSS_VERSION_IGNORE_PRERELEASE).is_ok() {
                    v.pre = Prerelease::EMPTY;
                }
                v
            })
            .expect("Failed to parse the DEP_TSS2_ESYS_VERSION variable {tss_version_string} as a semver version")
    };

    // nuke any prerelease info, which probably is just a git repo/dirty flag
    // like: 4.0.1-67-gb7bad346
    tss_version.pre = Prerelease::EMPTY;
    //eprintln!("tss version: {} / {:?}", tss_version_string, tss_version);

    let supported_tss_version =
        VersionReq::parse("<5.0.0, >=2.3.3").expect("Failed to parse supported TSS version");

    //eprintln!("tss version: {} / {:?}", supported_tss_version, tss_version);
    assert!(
        supported_tss_version.matches(&tss_version),
        "Unsupported TSS version {tss_version}, maybe try {TPM2_TSS_VERSION_IGNORE_PRERELEASE}=true"
    );

    let hierarchy_is_esys_tr_req = VersionReq::parse(">=3.0.0").unwrap();
    if hierarchy_is_esys_tr_req.matches(&tss_version) {
        println!("cargo:rustc-cfg=hierarchy_is_esys_tr")
    }

    let has_tss_base_rc_values_28_to_51_req = VersionReq::parse(">=2.4.0").unwrap();
    if has_tss_base_rc_values_28_to_51_req.matches(&tss_version) {
        println!("cargo:rustc-cfg=has_tss_base_rc_values_28_to_51")
    }

    let has_tss_base_rc_values_52_to_53_req = VersionReq::parse(">=3.0.0").unwrap();
    if has_tss_base_rc_values_52_to_53_req.matches(&tss_version) {
        println!("cargo:rustc-cfg=has_tss_base_rc_values_52_to_53")
    }

    let has_tpmu_sensitive_create_req = VersionReq::parse(">=4.0.0").unwrap();
    if has_tpmu_sensitive_create_req.matches(&tss_version) {
        println!("cargo:rustc-cfg=has_tpmu_sensitive_create")
    }

    #[cfg(feature = "generate-bindings")]
    {
        let has_esys_tr_get_tpm_handle_req = VersionReq::parse(">=2.4.0").unwrap();
        if has_esys_tr_get_tpm_handle_req.matches(&tss_version) {
            println!("cargo:rustc-cfg=has_esys_tr_get_tpm_handle")
        }
    }
}
