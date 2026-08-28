//! Client-side security boundary.
//!
//! The relay never receives plaintext or MLS private state. This crate owns all
//! OpenMLS interaction so application code cannot accidentally bypass it.

pub mod device;

pub use device::{
    ConversationAddition, ConversationBootstrap, ConversationRemoval, ConversationSafetyCode,
    Device, DeviceError, PendingApplication, PendingApplicationKind, PendingCommit,
    validate_key_package, validate_key_package_for_device,
};
