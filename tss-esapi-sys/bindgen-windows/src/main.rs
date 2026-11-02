// Copyright 2026 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! Generates the pre-generated Windows bindings in `src/bindings` from a
//! tpm2-tss source tree and an `xwin` SDK/CRT tree, so they can be produced
//! from any host. Uses the same bindgen options as `generate-bindings` on
//! Windows (`Installation::add_windows_platform_args` in build.rs).
//!
//! Usage: bindgen-windows <tpm2-tss>/include/tss2 <xwin dir> <target triple> <out.rs> <tpm2-tss version>
//!
//! `cargo xwin` downloads the SDK/CRT to `~/.cache/cargo-xwin/xwin`.
//! `tss2_tcti.h` includes `<windows.h>`, so the output is restricted to the
//! TSS API with an allowlist: about 12.6k lines instead of 212k.
use std::env::args;

const WINDOWS_BLOCKLIST: &[&str] = &[
    "IMAGE_TLS_DIRECTORY",
    "PIMAGE_TLS_DIRECTORY",
    "IMAGE_TLS_DIRECTORY64",
    "PIMAGE_TLS_DIRECTORY64",
    "_IMAGE_TLS_DIRECTORY64",
    "MONITORINFOEX",
    "MONITORINFOEXA",
    "MONITORINFOEXW",
    "tagMONITORINFOEXA",
    "tagMONITORINFOEXW",
    "LPMONITORINFOEX",
    "LPMONITORINFOEXA",
    "LPMONITORINFOEXW",
];

fn main() {
    let a: Vec<String> = args().collect();
    let (tss2, xwin, target, out, version) = (&a[1], &a[2], &a[3], &a[4], &a[5]);
    let arch = if target.starts_with("aarch64") {
        "aarch64"
    } else {
        "x86_64"
    };
    let mut b = bindgen::Builder::default()
        .size_t_is_usize(false)
        .rust_target(bindgen::RustTarget::stable(85, 0).unwrap())
        .clang_arg(format!("--target={target}"))
        .clang_arg(format!("-I{tss2}"))
        .clang_arg(format!("-isystem{xwin}/crt/include"))
        .clang_arg(format!("-isystem{xwin}/sdk/include/ucrt"))
        .clang_arg(format!("-isystem{xwin}/sdk/include/um"))
        .clang_arg(format!("-isystem{xwin}/sdk/include/shared"))
        .formatter(bindgen::Formatter::Rustfmt)
        .generate_comments(false)
        .blocklist_type("max_align_t")
        .derive_default(true)
        .raw_line(format!("/* TPM2_TSS_VERSION=\"{version}\" */"));
    if arch == "aarch64" {
        // MSVC's intrin.h declares __prefetch with a type that conflicts with
        // clang's ARM64 builtin. The allowlist drops it either way.
        b = b.clang_arg("-D__prefetch=__bindgen_msvc_prefetch");
    }
    for h in [
        "tss2_esys.h",
        "tss2_tctildr.h",
        "tss2_mu.h",
        "tss2_tcti_tbs.h",
    ] {
        b = b.header(format!("{tss2}/{h}"));
    }
    for t in WINDOWS_BLOCKLIST {
        b = b.blocklist_type(t);
    }
    b = b
        .allowlist_function("(Esys|Tss2)_.*")
        // `_PRIVATE` is the one TPM structure named with a leading underscore.
        .allowlist_type(
            "(TSS2|ESYS|IESYS|TPM|TPMA|TPMI|TPML|TPMS|TPMT|TPMU|TPM2|TPM2B)_.*|_PRIVATE",
        )
        .allowlist_var("(TSS2|ESYS|TPM2|TPMA|TPM|TPM2B|TPMI)_.*");
    b.generate()
        .expect("generate")
        .write_to_file(out)
        .expect("write");
}
