use crate::{error::VaultError, preferences::Language};
use std::{collections::BTreeMap, sync::OnceLock};
static CATALOGS: OnceLock<[BTreeMap<String, String>; 6]> = OnceLock::new();
pub fn text(language: Language, key: &str) -> &'static str {
    let catalogs = CATALOGS.get_or_init(|| {
        [
            include_str!("../locales/en.json"),
            include_str!("../locales/ru.json"),
            include_str!("../locales/fr.json"),
            include_str!("../locales/de.json"),
            include_str!("../locales/es.json"),
            include_str!("../locales/it.json"),
        ]
        .map(|s| serde_json::from_str(s).expect("bundled language catalog"))
    });
    let index = Language::ALL
        .iter()
        .position(|l| *l == language)
        .unwrap_or(0);
    catalogs[index]
        .get(key)
        .or_else(|| catalogs[0].get(key))
        .map(String::as_str)
        .unwrap_or("Encrypted Vault")
}
pub fn error_key(error: &VaultError) -> &'static str {
    match error {
        VaultError::Authentication => "error_auth",
        VaultError::Format => "error_format",
        VaultError::WriterBusy => "error_writer",
        VaultError::InvalidPath => "error_path",
        VaultError::NotFound => "error_notfound",
        VaultError::Exists => "error_exists",
        VaultError::NotDirectory => "error_notdir",
        VaultError::IsDirectory => "error_isdir",
        VaultError::NotEmpty => "error_notempty",
        VaultError::Sharing => "error_sharing",
        VaultError::DeletePending => "error_delete",
        VaultError::OpenHandles => "error_handles",
        VaultError::Locked => "error_locked",
        VaultError::Access => "error_access",
        VaultError::TooLarge => "error_size",
        VaultError::Runtime(_) => "error_runtime",
        VaultError::Mount(_) => "error_mount",
        VaultError::Update(_) => "error_update",
        VaultError::Io(e) if e.kind() == std::io::ErrorKind::AlreadyExists => "error_exists",
        VaultError::Io(_) => "error_storage",
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_languages_have_complete_nonempty_catalogs() {
        text(Language::En, "app_title");
        let catalogs = CATALOGS.get().unwrap();
        let keys: Vec<_> = catalogs[0].keys().collect();
        for catalog in catalogs {
            assert_eq!(catalog.keys().collect::<Vec<_>>(), keys);
            assert!(catalog.values().all(|v| !v.trim().is_empty()));
        }
    }
}
