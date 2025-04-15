#[cfg(all(
    any(feature = "p224", feature = "p256", feature = "p384", feature = "rsa"),
    any(feature = "sha1", feature = "sha2",)
))]
mod quote;
#[cfg(all(
    any(feature = "p224", feature = "p256", feature = "p384", feature = "rsa"),
    any(feature = "sha1", feature = "sha2",)
))]
pub use quote::checkquote;
