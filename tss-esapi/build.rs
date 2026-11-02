// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use semver::{Prerelease, Version, VersionReq};

const TPM2_TSS_MINIMUM_VERSION: Version = Version::new(4, 1, 3);
const TPM2_TSS_VERSION_IGNORE_PRERELEASE: &str = "TPM2_TSS_VERSION_IGNORE_PRERELEASE";

fn main() {
    println!("cargo:rustc-check-cfg=cfg(hierarchy_is_esys_tr)");
    println!("cargo:rustc-check-cfg=cfg(has_tss_base_rc_values_28_to_51)");
    println!("cargo:rustc-check-cfg=cfg(has_tss_base_rc_values_52_to_53)");
    println!("cargo:rustc-check-cfg=cfg(has_tpmu_sensitive_create)");
    println!("cargo:rustc-check-cfg=cfg(has_esys_tr_get_tpm_handle)");
    println!("cargo:rustc-check-cfg=cfg(has_esys_set_crypto_callbacks)");
    println!("cargo:rustc-check-cfg=cfg(has_tss_base_rc_value_54)");

    // If documentation for Docs.rs is being built then the version is set
    // to the minimum supported tpm2-tss version.
    let tss_version = if std::env::var("DOCS_RS").is_ok() {
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

    let supported_tss_version =
        VersionReq::parse("<5.0.0, >=2.3.3").expect("Failed to parse supported TSS version");

    assert!(
        supported_tss_version.matches(&tss_version),
        "Unsupported TSS version {tss_version}, maybe try setting the environment variable {TPM2_TSS_VERSION_IGNORE_PRERELEASE}=true"
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

    // Esys_SetCryptoCallbacks arrived in tpm2-tss 4.0.0. The pre-generated
    // x86_64 macOS bindings predate it.
    let pregenerated_lacks_callbacks = cfg!(not(feature = "generate-bindings"))
        && std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos");
    let has_esys_set_crypto_callbacks_req = VersionReq::parse(">=4.0.0").unwrap();
    if has_esys_set_crypto_callbacks_req.matches(&tss_version) && !pregenerated_lacks_callbacks {
        println!("cargo:rustc-cfg=has_esys_set_crypto_callbacks");
        // TSS2_BASE_RC_CALLBACK_NULL arrived with the callbacks.
        println!("cargo:rustc-cfg=has_tss_base_rc_value_54")
    }
}
