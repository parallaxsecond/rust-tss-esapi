// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
#![deny(
    nonstandard_style,
    const_err,
    dead_code,
    improper_ctypes,
    non_shorthand_field_patterns,
    no_mangle_generic_items,
    overflowing_literals,
    path_statements,
    patterns_in_fns_without_body,
    private_in_public,
    unconditional_recursion,
    unused,
    unused_allocation,
    unused_comparisons,
    unused_parens,
    while_true,
    missing_debug_implementations,
    //TODO: activate this!
    //missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results,
    missing_copy_implementations
)]
//! # TSS 2.0 Rust Wrapper over Enhanced System API
//! This crate exposes the functionality of the TCG Software Stack Enhanced System API to
//! Rust developers, both directly through FFI bindings and through more Rust-tailored interfaces
//! at varying levels of abstraction.
//! At the moment, the abstracted functionality focuses on creating signing and encryption RSA
//! keys, as well as signing and verifying signatures.
//! Only platforms based on processors with a word size of at least 16 bits are supported.
//!
//! The crate is expected to successfully compile and run using the nightly compiler and any other
//! Rust compiler since 1.38.0.
//!
//! # Disclaimer
//!
//! The current version of the API does not offer any security or code safety guarantees as it has
//! not been tested to a desired level of confidence.
//! The implementation that is provided is suitable for exploratory testing and experimentation only.
//! This test implementation does not offer any tangible security benefits and therefore is not
//! suitable for use in production.
//! Contributions from the developer community are welcome. Please refer to the contribution guidelines.
//!
//! # Code structure
//! The modules comprising the crate expose the following functionalities:
//! * lib/root module - exposes the `Context` structure, the most basic abstraction over the
//! ESAPI, on top of which all other abstraction layers are implemented.
//! * utils - exposes Rust-native versions and/or builders for (some of) the structures defined in
//! the TSS 2.0 specification; it also offers convenience methods for generating very specific
//! parameter structures for use in certain operations.
//! * response_code - implements error code parsing for the formats defined in the TSS spec and
//! exposes it along with wrapper-specific error types.
//! * abstraction - intended to offer abstracted interfaces that focus on providing different
//! kinds of user experience to the developers; at the moment the only implementation allows for a
//! resource-handle-free coding experience by working soloely with object contexts.
//! * tss2_esys - exposes raw FFI bindings to the Enhanced System API.
//! * constants - exposes constants that were ported to Rust manually as bindgen does not support
//! converting them yet.
//!
//! # Notes on code safety:
//! * thread safety is ensured by the required mutability of the `Context` structure within the
//! methods implemented on it; thus, in an otherwise safe app commands cannot be dispatched in
//! parallel for the same context; whether multithreading with multiple context objects is possible
//! depends on the TCTI used and this is the responsability of the crate client to establish.
//! * the `unsafe` keyword is used to denote methods that could panic, crash or cause undefined
//! behaviour. Whenever this is the case, the properties that need to be checked against
//! parameters before passing them in will be stated in the documentation of the method.
//! * `unsafe` blocks within this crate need to be documented through code comments if they
//! are not covered by the points of trust described here.
//! * the TSS2.0 library that this crate links to is trusted to return consistent values and to
//! not crash or lead to undefined behaviour when presented with valid arguments.
//! * the `Mbox` crate is trusted to perform operations safely on the pointers provided to it, if
//! the pointers are trusted to be valid.
//! * methods not marked `unsafe` are trusted to behave safely, potentially returning appropriate
//! erorr messages when encountering any problems.
//! * whenever `unwrap`, `expect`, `panic` or derivatives of these are used, they need to be
//! thoroughly documented and justified - preferably `unwrap` and `expect` should *never* fail
//! during normal operation.
//! * these rules can be broken in test-only code and in tests.

pub use abstraction::transient::TransientKeyContext;
pub use context::Context;
pub use error::{Error, Result, WrapperErrorKind};
pub use tcti::Tcti;

#[allow(
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    clippy::unseparated_literal_suffix,
    // There is an issue where long double become u128 in extern blocks. Check this issue:
    // https://github.com/rust-lang/rust-bindgen/issues/1549
    improper_ctypes,
    missing_debug_implementations,
    trivial_casts,
    clippy::all,
)]
pub mod tss2_esys {
    #[cfg(not(feature = "docs"))]
    include!(concat!(env!("OUT_DIR"), "/tss2_esys_bindings.rs"));

    #[cfg(feature = "docs")]
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/doc_bindings.rs"));
}
pub mod abstraction;
pub mod constants;
mod context;
mod error;
pub mod handles;
pub mod interface_types;
pub mod nv;
pub mod session;
pub mod structures;
mod tcti;
pub mod utils;
