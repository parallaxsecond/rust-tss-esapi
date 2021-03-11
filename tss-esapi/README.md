<!--
  -- Copyright 2021 Contributors to the Parsec project.
  -- SPDX-License-Identifier: Apache-2.0
--->

# TPM2 Software Stack Rust Wrapper 

<p align="center">
  <a href="https://crates.io/crates/tss-esapi"><img alt="Crates.io" src="https://img.shields.io/crates/v/tss-esapi"></a>
  <a href="https://docs.rs/tss-esapi"><img src="https://docs.rs/tss-esapi/badge.svg" alt="Code documentation"/></a>
  <a href="https://github.com/parallaxsecond/rust-tss-esapi/actions?query=workflow%3A%22Continuous+Integration%22"><img src="https://github.com/parallaxsecond/rust-tss-esapi/workflows/Continuous%20Integration/badge.svg" alt="CI tests"/></a>
</p>

This is the high-level, Rust idiomatic wrapper crate that exposes an interface 
to [TSS](https://github.com/tpm2-software/tpm2-tss).

This crate depends on the [`tss-esapi-sys`](../tss-esapi-sys/) crate for its
FFI interface. By default, pre-generated bindings are used. If you'd like the
bindings to be generated at build time, please enable either the 
`generate-bindings` feature - the FFI bindings will then be generated at build
time using the headers identified on the system.

Our end-goal is to achieve a fully Rust-native interface that offers strong safety and security guarantees. Check out our [documentation](https://docs.rs/tss-esapi/*/tss_esapi/#notes-on-code-safety) for an overview of our code safety approach.

## Versioning

The `tss-esapi` crate is still under development and thus the interface is not stable (despite the version number). As a rule of thumb, all versions marked `alpha` are expected to be short-lived and superseded by a better, more complete interface that relies on breaking changes.

## Cross compiling

For more information on cross-compiling the `tss-esapi` crate, please see the README of the `tss-esapi-sys` crate.