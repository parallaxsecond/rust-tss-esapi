<!--
  -- Copyright 2019 Contributors to the Parsec project.
  -- SPDX-License-Identifier: Apache-2.0
--->

# TSS 2.0 Enhanced System API Rust Wrapper 

<p align="center">
  <a href="https://crates.io/crates/tss-esapi"><img alt="Crates.io" src="https://img.shields.io/crates/v/tss-esapi"></a>
  <a href="https://docs.rs/tss-esapi"><img src="https://docs.rs/tss-esapi/badge.svg" alt="Code documentation"/></a>
  <a href="https://github.com/parallaxsecond/rust-tss-esapi/actions?query=workflow%3A%22Continuous+Integration%22"><img src="https://github.com/parallaxsecond/rust-tss-esapi/workflows/Continuous%20Integration/badge.svg" alt="CI tests"/></a>
</p>

The `tss-esapi` Rust crate provides an idiomatic interface to the TCG TSS 2.0 Enhanced System API. We expose both direct FFI bindings and abstracted versions, aimed at improved convenience of using the API.

Our end-goal is to achieve a fully Rust-native interface that offers strong safety and security guarantees. Check out our [documentation](https://docs.rs/tss-esapi/*/tss_esapi/#notes-on-code-safety) for an overview of our code safety approach.

## Versioning

The crate is still under development and thus the interface is not stable (despite the version number). As a rule of thumb, all versions marked `alpha` are expected to be short-lived and superseded by a better, more complete interface that relies on breaking changes.

## Requirements

This crate has currently only been tested with the TSS 2.0
[open-source implementation](https://github.com/tpm2-software/tpm2-tss).
It uses `pkg-config` to find the include and library files for the `tss2-esys` and `tss2-tctildr`
libraries. A minimum version of `2.3.3` is required for both. `pkg-config` tool is needed to build this crate.

Having installed the open-source implementation libraries at `/usr/local/lib` (by default), it
might happen that `pkg-config` can not find them. Run the following command if that is the
case:
```bash
$ export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
```

## Community channel

Come and talk to us in [our Slack channel](https://app.slack.com/client/T0JK1PCN6/CPMQ9D4H1)!
[Here](http://dockr.ly/slack) is how to join the workspace.

## Contributing

We would be happy for you to contribute to the `tss-esapi` crate!
Please check the [**Contribution Guidelines**](https://parallaxsecond.github.io/parsec-book/contributing.html)
to know more about the contribution process.

## License

The software is provided under Apache-2.0. Contributions to this project are accepted under the same license.

This project uses the following third party crates:
* serde (MIT and Apache-2.0)
* bindgen (BSD-3-Clause)
* log (MIT and Apache-2.0)
* env\_logger (MIT and Apache-2.0)
* mbox (MIT)
* bitfield (MIT and Apache-2.0)
* pkg-config (MIT and Apache-2.0)
* enumflags2 (MIT and Apache-2.0)
* num-derive (MIT and Apache-2.0)
* num-traits (MIT and Apache-2.0)
* hostname-validator (MIT)
* regex (MIT and Apache-2.0)
