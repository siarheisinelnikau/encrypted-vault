#[cfg(windows)]
pub mod app;
pub mod capture;
pub mod crypto;
#[cfg(windows)]
pub mod dokan;
pub mod error;
pub mod filesystem;
pub mod i18n;
pub mod preferences;
pub mod store;
#[cfg(windows)]
pub mod ui;
pub mod updates;
