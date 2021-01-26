<!--
  -- Copyright 2021 Contributors to the Parsec project.
  -- SPDX-License-Identifier: Apache-2.0
--->

# TPM2 Software Stack Rust Wrapper

This is the lower-level wrapper that exposes a minimal, low-level C
interface to Rust to [TSS](https://github.com/tpm2-software/tpm2-tss).

## Dependencies

This crate exposes an interface for the TSS Enhanced System API and thus
links to libraries that expose this interface. In order to allow proper use
of the ESAPI, this FFI layer includes bindings to TCTI and MU headers, and 
must therefore link to all of them at build time.

The paths to the libraries are discovered using `pkg-config` - make sure they
are discoverable in this way on your system. Our build script looks for 
`tss2-esys`, `tss2-tctildr` and `tss2-mu`. A minimum version of `2.3.3` is 
required for all of them.

Having installed the open-source implementation libraries at `/usr/local/lib` (by default), it
might happen that `pkg-config` can not find them. Run the following command if that is the
case:
```bash
$ export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
```

The FFI bindings presented by this crate can be either those commited in the
crate under `src/bindings` or generated on the fly from the library headers
found on the system, at build time. For generating the bindings at build time
please enable the `generate-bindings` feature, as it is not enabled by default.
The build script will then identify the header files using `pkg-config` and
generate fresh bindings from them.

NOTE: Only a limited set of bindings are committed and their target triplet
is included in the name of the file - if the triplet you require is not
available, feel free to raise a Pull Request to add it or to use build-time
generation of bindings. All the committed bindings **MUST** be generated from
the library version found under the `vendor` submodule.