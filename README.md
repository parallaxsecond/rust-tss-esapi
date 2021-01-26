<!--
  -- Copyright 2019 Contributors to the Parsec project.
  -- SPDX-License-Identifier: Apache-2.0
--->

# TSS 2.0 Enhanced System API Rust Wrapper

The `tss-esapi` Rust crate provides an idiomatic interface to the TCG TSS 2.0 Enhanced System API. We expose both direct FFI bindings (under the `tss-esapi-sys` crate) and abstracted versions, aimed at improved convenience of using the API.

## Minimum Supported Rust Version (MSRV)

At the moment we test (via CI) and support the following Rust compiler versions:

* On Ubuntu we test with the latest stable compiler version, as accessible through `rustup`.
* On Fedora we test with the compiler version included with the Fedora 33 release.

If you need support for other versions of the compiler, get in touch with us to see what we can do!

## Community channel

Come and talk to us in [our Slack channel](https://cloud-native.slack.com/archives/C01EARH2ZB3)!
[Here](https://slack.cncf.io/) is where you can join the workspace.

## Contributing

We would be happy for you to contribute to the `tss-esapi` crate!
Please check the [**Contribution Guidelines**](https://parallaxsecond.github.io/parsec-book/contributing.html)
to know more about the contribution process.

## License

The software is provided under Apache-2.0. Contributions to this project are accepted under the same license.
