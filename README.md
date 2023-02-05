![Codecov](https://img.shields.io/codecov/c/gh/parallaxsecond/rust-tss-esapi)
# TSS 2.0 Enhanced System API Rust Wrapper

The `tss-esapi` Rust crate provides an idiomatic interface to the TCG TSS 2.0 Enhanced System API. We expose both direct FFI bindings (under the `tss-esapi-sys` crate) and abstracted versions, aimed at improved convenience of using the API.

## Minimum Supported Rust Version (MSRV)

At the moment we test (via CI) and support the following Rust compiler versions:

* On Ubuntu we test with:
    - The latest stable compiler version, as accessible through `rustup`.
    - The 1.57 compiler version.
* On Fedora we test with the compiler version included with the Fedora 35 release.

If you need support for other versions of the compiler, get in touch with us to see what we can do!

## Community channel

Come and talk to us in [our Slack channel](https://github.com/parallaxsecond/community#community-channel)!

## Contributing

We would be happy for you to contribute to the `tss-esapi` crate!
Please check the [**Contribution Guidelines**](https://parallaxsecond.github.io/parsec-book/contributing/index.html)
to know more about the contribution process.

## License

The software is provided under Apache-2.0. Contributions to this project are accepted under the same license.

*Copyright 2019 Contributors to the Parsec project.*
