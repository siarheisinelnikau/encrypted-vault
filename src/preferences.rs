use crate::{
    crypto,
    error::{Result, VaultError},
    store::{atomic_replace, check_backing_path, read_bounded, write_new},
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    #[default]
    En,
    Ru,
    Fr,
    De,
    Es,
    It,
}
impl Language {
    pub const ALL: [Self; 6] = [Self::En, Self::Ru, Self::Fr, Self::De, Self::Es, Self::It];
    pub fn native_name(self) -> &'static str {
        match self {
            Self::En => "English",
            Self::Ru => "Русский",
            Self::Fr => "Français",
            Self::De => "Deutsch",
            Self::Es => "Español",
            Self::It => "Italiano",
        }
    }
    pub fn code(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Ru => "ru",
            Self::Fr => "fr",
            Self::De => "de",
            Self::Es => "es",
            Self::It => "it",
        }
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    #[default]
    Light,
    Dark,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecentVault {
    pub path: PathBuf,
    pub alias: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Preferences {
    pub language: Language,
    pub theme: Theme,
    pub reduced_motion: bool,
    pub startup_updates: bool,
    pub preferred_letter: char,
    pub idle_minutes: u32,
    pub vaults: Vec<RecentVault>,
}
impl Default for Preferences {
    fn default() -> Self {
        Self {
            language: Language::En,
            theme: Theme::Light,
            reduced_motion: false,
            startup_updates: true,
            preferred_letter: 'V',
            idle_minutes: 0,
            vaults: Vec::new(),
        }
    }
}

pub fn config_path() -> Result<PathBuf> {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .map(|p| p.join("EncryptedVault").join("preferences.json"))
        .ok_or_else(|| VaultError::Io(std::io::Error::other("LOCALAPPDATA is unavailable")))
}
impl Preferences {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        check_backing_path(path)?;
        let value: Self = serde_json::from_slice(&read_bounded(path, 512 * 1024)?)
            .map_err(|_| VaultError::Format)?;
        if value.vaults.len() > 100
            || !('D'..='Z').contains(&value.preferred_letter)
            || ![0, 5, 15, 30, 60].contains(&value.idle_minutes)
            || value
                .vaults
                .iter()
                .any(|v| v.alias.len() > 240 || !v.path.is_absolute())
        {
            return Err(VaultError::Format);
        }
        Ok(value)
    }
    pub fn save(&self, path: &Path) -> Result<()> {
        let parent = path.parent().ok_or(VaultError::InvalidPath)?;
        fs::create_dir_all(parent)?;
        check_backing_path(parent)?;
        if path.exists() {
            check_backing_path(path)?;
        }
        let pending = parent.join(format!("preferences-{}.pending", crypto::new_id()?));
        write_new(
            &pending,
            &serde_json::to_vec_pretty(self).map_err(|_| VaultError::Format)?,
        )?;
        atomic_replace(&pending, path)
    }
    pub fn remember(&mut self, path: PathBuf, alias: String) -> Result<()> {
        if let Some(v) = self.vaults.iter_mut().find(|v| v.path == path) {
            v.alias = alias;
            return Ok(());
        }
        if self.vaults.len() >= 100 {
            return Err(VaultError::TooLarge);
        }
        self.vaults.push(RecentVault { path, alias });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preferences_round_trip_and_invalid_settings_are_preserved() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("preferences.json");
        let p = Preferences {
            language: Language::Fr,
            theme: Theme::Dark,
            reduced_motion: true,
            startup_updates: false,
            idle_minutes: 15,
            ..Preferences::default()
        };
        p.save(&path).unwrap();
        let read = Preferences::load(&path).unwrap();
        assert_eq!(read.language, Language::Fr);
        assert_eq!(read.theme, Theme::Dark);
        assert!(!read.startup_updates);
        assert!(read.reduced_motion);
        std::fs::write(&path, b"broken preferences").unwrap();
        assert!(Preferences::load(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"broken preferences");
    }
}
