//! Module for representation of attributes

/// Representation of the attributes defined in the
/// Attribute structures -> TPMA_OBJECT section of
/// the specfication
pub mod object;

/// Representation of the attributes defined in the
/// Attribute structures -> TPMA_OBJECT section of
/// the specfication.
pub mod session;

/// Representation of the attributes defined in the
/// NV Storage -> TPMA_NV section of
/// the specfication.
pub mod nv_index;

pub use nv_index::{NvIndexAttributes, NvIndexAttributesBuilder};
pub use object::{ObjectAttributes, ObjectAttributesBuilder};
pub use session::{SessionAttributes, SessionAttributesBuilder, SessionAttributesMask};
