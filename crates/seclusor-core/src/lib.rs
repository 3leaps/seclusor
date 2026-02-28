//! seclusor-core
//!
//! Domain types, validation, and core logic for seclusor secrets management.
//! This crate is the foundation layer with no internal seclusor dependencies.

pub mod constants;
pub mod crud;
pub mod env;
pub mod error;
pub mod model;
pub mod validate;

pub use error::{Result, SeclusorError};
pub use model::{Credential, Project, SecretsFile};
