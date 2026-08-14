//! Platform-neutral foundation for BYO — Before You Open.
//!
//! No analyzers are implemented in this foundation milestone. Future analysis
//! code belongs here only when it remains independent of user interfaces,
//! operating-system integrations, and network access.

#![forbid(unsafe_code)]

/// The product name shared by all BYO frontends.
pub const PRODUCT_NAME: &str = "BYO — Before You Open";

/// The current public project status.
pub const PROJECT_STATUS: &str = "PRE-ALPHA";

#[cfg(test)]
mod tests {
    use super::{PRODUCT_NAME, PROJECT_STATUS};

    #[test]
    fn foundation_identity_is_stable() {
        assert_eq!(PRODUCT_NAME, "BYO — Before You Open");
        assert_eq!(PROJECT_STATUS, "PRE-ALPHA");
    }
}
