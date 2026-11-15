use crate::{
    crypto,
    error::{Result, VaultError},
    store::{atomic_replace, check_backing_path, open_existing, read_bounded, write_new},
};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

pub const REPOSITORY: &str = "siarheisinelnikau/encrypted-vault";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_DOWNLOAD: u64 = 128 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Asset {
    pub name: String,
    pub size: u64,
    pub browser_download_url: String,
    pub digest: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Release {
    pub tag_name: String,
    pub draft: bool,
    pub prerelease: bool,
    pub assets: Vec<Asset>,
}
#[derive(Clone, Debug)]
pub struct Available {
    pub version: Version,
    pub asset: Asset,
    pub checksum: [u8; 32],
}
#[derive(Clone, Debug)]
pub struct Staged {
    pub path: PathBuf,
    pub target: PathBuf,
    pub checksum: [u8; 32],
}

pub fn startup_check_enabled(preferences: &crate::preferences::Preferences) -> bool {
    preferences.startup_updates
}
pub fn asset_name(version: &Version) -> String {
    format!("EncryptedVault-v{version}.exe")
}

pub fn select_release(release: Release, installed: &Version) -> Result<Option<Available>> {
    if release.draft || release.prerelease {
        return Ok(None);
    }
    let version = Version::parse(
        release
            .tag_name
            .strip_prefix('v')
            .unwrap_or(&release.tag_name),
    )
    .map_err(|_| VaultError::Update("Invalid release version".into()))?;
    if !version.pre.is_empty() || version <= *installed {
        return Ok(None);
    }
    let expected = asset_name(&version);
    let mut matches = release.assets.into_iter().filter(|a| a.name == expected);
    let asset = matches.next().ok_or_else(|| {
        VaultError::Update("A compatible portable Windows asset is missing".into())
    })?;
    if matches.next().is_some()
        || !(1024..=MAX_DOWNLOAD).contains(&asset.size)
        || asset.browser_download_url
            != format!(
                "https://github.com/{REPOSITORY}/releases/download/{}/{expected}",
                release.tag_name
            )
    {
        return Err(VaultError::Update(
            "Release asset metadata is not valid".into(),
        ));
    }
    let digest = asset
        .digest
        .as_deref()
        .and_then(|s| s.strip_prefix("sha256:"))
        .ok_or_else(|| {
            VaultError::Update(
                "The release has no SHA-256 asset digest; installation is blocked".into(),
            )
        })?;
    let bytes =
        hex::decode(digest).map_err(|_| VaultError::Update("Invalid release digest".into()))?;
    let checksum: [u8; 32] = bytes
        .try_into()
        .map_err(|_| VaultError::Update("Invalid release digest length".into()))?;
    Ok(Some(Available {
        version,
        asset,
        checksum,
    }))
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .user_agent(format!("EncryptedVault/{VERSION}"))
        .build()
        .into()
}

pub fn check() -> Result<Option<Available>> {
    let mut response = agent()
        .get(&format!(
            "https://api.github.com/repos/{REPOSITORY}/releases/latest"
        ))
        .header("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| {
            VaultError::Update(format!(
                "Release check failed (repository unavailable, rate limit, or network error): {e}"
            ))
        })?;
    let bytes = response
        .body_mut()
        .with_config()
        .limit(2 * 1024 * 1024)
        .read_to_vec()
        .map_err(|e| VaultError::Update(e.to_string()))?;
    let release: Release = serde_json::from_slice(&bytes)
        .map_err(|_| VaultError::Update("Invalid release response".into()))?;
    select_release(
        release,
        &Version::parse(VERSION).map_err(|_| VaultError::Format)?,
    )
}

pub fn download(available: &Available, target: &Path, progress: impl FnMut(u8)) -> Result<Staged> {
    if !target.is_absolute() {
        return Err(VaultError::InvalidPath);
    }
    let parent = target.parent().ok_or(VaultError::InvalidPath)?;
    check_backing_path(parent)?;
    let directory = parent.join(format!(".encrypted-vault-update-{}", crypto::new_id()?));
    fs::create_dir(&directory)?;
    let path = directory.join(&available.asset.name);
    let mut response = agent()
        .get(&available.asset.browser_download_url)
        .call()
        .map_err(|e| VaultError::Update(e.to_string()))?;
    let reader = response.body_mut().as_reader();
    stage_reader(
        reader,
        &path,
        available.asset.size,
        &available.checksum,
        progress,
    )?;
    Ok(Staged {
        path,
        target: target.to_path_buf(),
        checksum: available.checksum,
    })
}

pub fn stage_reader(
    mut reader: impl Read,
    path: &Path,
    expected_size: u64,
    expected_hash: &[u8; 32],
    mut progress: impl FnMut(u8),
) -> Result<()> {
    if !(1024..=MAX_DOWNLOAD).contains(&expected_size) {
        return Err(VaultError::TooLarge);
    }
    let pending = path.with_extension("download");
    write_new(&pending, &[])?;
    let result = (|| -> Result<()> {
        let mut output = open_existing(&pending, true)?;
        let mut digest = Sha256::new();
        let mut received = 0u64;
        let mut last_percent = 0;
        let mut buffer = [0u8; 65536];
        progress(0);
        loop {
            let n = reader.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            received += n as u64;
            if received > expected_size {
                return Err(VaultError::Update(
                    "The download is larger than the release asset".into(),
                ));
            }
            output.write_all(&buffer[..n])?;
            digest.update(&buffer[..n]);
            let percent = (received * 95 / expected_size) as u8;
            if percent != last_percent {
                progress(percent);
                last_percent = percent;
            }
        }
        if received != expected_size || digest.finalize().as_slice() != expected_hash {
            return Err(VaultError::Update(
                "The download is incomplete or its SHA-256 digest does not match".into(),
            ));
        }
        output.sync_all()?;
        drop(output);
        verify_pe(&pending)?;
        atomic_replace(&pending, path)?;
        progress(100);
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&pending);
    }
    result
}

fn verify_pe(path: &Path) -> Result<()> {
    let mut header = [0; 4096];
    let mut file = open_existing(path, false)?;
    let count = file.read(&mut header)?;
    if count < 128 || &header[..2] != b"MZ" {
        return Err(VaultError::Update(
            "The downloaded file is not a Windows executable".into(),
        ));
    }
    let position =
        u32::from_le_bytes(header[60..64].try_into().map_err(|_| VaultError::Format)?) as usize;
    if position > count.saturating_sub(26)
        || &header[position..position + 4] != b"PE\0\0"
        || u16::from_le_bytes([header[position + 4], header[position + 5]]) != 0x8664
    {
        return Err(VaultError::Update(
            "The downloaded executable is not a compatible x64 image".into(),
        ));
    }
    Ok(())
}

pub fn replace_with_backup(staged: &Path, target: &Path, checksum: &[u8; 32]) -> Result<PathBuf> {
    check_backing_path(staged)?;
    check_backing_path(target)?;
    let bytes = read_bounded(staged, MAX_DOWNLOAD as usize)?;
    if Sha256::digest(&bytes).as_slice() != checksum {
        return Err(VaultError::Update("The staged executable changed".into()));
    }
    verify_pe(staged)?;
    let parent = target.parent().ok_or(VaultError::InvalidPath)?;
    let backup = parent.join(format!(
        "{}.previous-{}",
        target
            .file_name()
            .ok_or(VaultError::InvalidPath)?
            .to_string_lossy(),
        crypto::new_id()?
    ));
    let replacement = parent.join(format!("EncryptedVault-{}.replacement", crypto::new_id()?));
    // Keep a synced original before atomically publishing the verified replacement.
    let old = read_bounded(target, MAX_DOWNLOAD as usize)?;
    write_new(&backup, &old)?;
    write_new(&replacement, &bytes)?;
    atomic_replace(&replacement, target)?;
    Ok(backup)
}

#[cfg(windows)]
pub fn spawn_installer(staged: &Staged) -> Result<()> {
    use std::os::windows::process::CommandExt;
    std::process::Command::new(&staged.path)
        .arg("--apply-update")
        .arg(&staged.target)
        .arg(std::process::id().to_string())
        .arg(hex::encode(staged.checksum))
        .creation_flags(0x08000000)
        .spawn()?;
    Ok(())
}

#[cfg(windows)]
pub fn apply_update_from_args(args: &[std::ffi::OsString]) -> Result<()> {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, ERROR_INVALID_PARAMETER, GetLastError},
        System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
            QueryFullProcessImageNameW, WaitForSingleObject,
        },
    };
    if args.len() != 5 {
        return Err(VaultError::InvalidPath);
    }
    let self_path = std::env::current_exe()?;
    let target = PathBuf::from(&args[2]);
    let parent = self_path.parent().ok_or(VaultError::InvalidPath)?;
    let parent_name = parent
        .file_name()
        .ok_or(VaultError::InvalidPath)?
        .to_string_lossy();
    let suffix = parent_name
        .strip_prefix(".encrypted-vault-update-")
        .ok_or(VaultError::InvalidPath)?;
    if !crypto::valid_id(suffix)
        || !target.is_absolute()
        || target.parent() != parent.parent()
        || !target.file_name().is_some_and(|n| {
            let n = n.to_string_lossy();
            n == "EncryptedVault.exe" || (n.starts_with("EncryptedVault-v") && n.ends_with(".exe"))
        })
    {
        return Err(VaultError::InvalidPath);
    }
    let pid: u32 = args[3]
        .to_str()
        .ok_or(VaultError::InvalidPath)?
        .parse()
        .map_err(|_| VaultError::InvalidPath)?;
    if pid == std::process::id() {
        return Err(VaultError::InvalidPath);
    }
    let hash: [u8; 32] = hex::decode(args[4].to_str().ok_or(VaultError::InvalidPath)?)
        .map_err(|_| VaultError::InvalidPath)?
        .try_into()
        .map_err(|_| VaultError::InvalidPath)?;
    let process = unsafe {
        OpenProcess(
            PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            pid,
        )
    };
    if !process.is_null() {
        let mut name = [0u16; 32768];
        let mut length = name.len() as u32;
        let matches =
            unsafe { QueryFullProcessImageNameW(process, 0, name.as_mut_ptr(), &mut length) } != 0
                && PathBuf::from(String::from_utf16_lossy(&name[..length as usize]))
                    .eq_ignore_ascii_case_path(&target);
        if !matches {
            unsafe {
                CloseHandle(process);
            }
            return Err(VaultError::Access);
        }
        let waited = unsafe { WaitForSingleObject(process, 30_000) };
        unsafe {
            CloseHandle(process);
        }
        if waited != 0 {
            return Err(VaultError::Update(
                "The application did not exit; no files were replaced".into(),
            ));
        }
    } else if unsafe { GetLastError() } != ERROR_INVALID_PARAMETER {
        return Err(std::io::Error::last_os_error().into());
    }
    let backup = replace_with_backup(&self_path, &target, &hash)?;
    match std::process::Command::new(&target).spawn() {
        Ok(_) => Ok(()),
        Err(e) => {
            atomic_replace(&backup, &target)?;
            let _ = std::process::Command::new(&target).spawn();
            Err(e.into())
        }
    }
}

#[cfg(windows)]
trait PathCase {
    fn eq_ignore_ascii_case_path(&self, other: &Path) -> bool;
}
#[cfg(windows)]
impl PathCase for PathBuf {
    fn eq_ignore_ascii_case_path(&self, other: &Path) -> bool {
        let normalize = |p: &Path| -> String {
            p.to_string_lossy()
                .trim_start_matches("\\\\?\\")
                .to_lowercase()
        };
        normalize(self) == normalize(other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn image() -> Vec<u8> {
        let mut b = vec![0; 4096];
        b[..2].copy_from_slice(b"MZ");
        b[60] = 128;
        b[128..132].copy_from_slice(b"PE\0\0");
        b[132..134].copy_from_slice(&0x8664u16.to_le_bytes());
        b
    }
    #[test]
    fn versions_asset_identity_and_startup_opt_out() {
        let version = Version::parse("0.2.0").unwrap();
        let name = asset_name(&version);
        let release = Release {
            tag_name: "v0.2.0".into(),
            draft: false,
            prerelease: false,
            assets: vec![Asset {
                name: name.clone(),
                size: 4096,
                browser_download_url: format!(
                    "https://github.com/{REPOSITORY}/releases/download/v0.2.0/{name}"
                ),
                digest: Some(format!("sha256:{}", hex::encode([1; 32]))),
            }],
        };
        assert!(
            select_release(release.clone(), &Version::parse("0.1.10").unwrap())
                .unwrap()
                .is_some()
        );
        assert!(select_release(release.clone(), &version).unwrap().is_none());
        let mut invalid = release.clone();
        invalid.assets[0].browser_download_url = "https://example.com/malware.exe".into();
        assert!(select_release(invalid, &Version::parse(VERSION).unwrap()).is_err());
        let mut unsigned = release;
        unsigned.assets[0].digest = None;
        assert!(select_release(unsigned, &Version::parse(VERSION).unwrap()).is_err());
        let p = crate::preferences::Preferences {
            startup_updates: false,
            ..Default::default()
        };
        assert!(!startup_check_enabled(&p));
    }
    #[test]
    fn download_verifies_size_digest_and_replacement_keeps_original() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("new.exe");
        let b = image();
        let digest = Sha256::digest(&b).into();
        assert!(stage_reader(&b[..1000], &path, b.len() as u64, &digest, |_| ()).is_err());
        assert!(!path.exists());
        assert!(stage_reader(&b[..], &path, b.len() as u64, &[0; 32], |_| ()).is_err());
        assert!(!path.exists());
        stage_reader(&b[..], &path, b.len() as u64, &digest, |_| ()).unwrap();
        let target = temp.path().join("EncryptedVault.exe");
        std::fs::write(&target, b"original executable").unwrap();
        let backup = replace_with_backup(&path, &target, &digest).unwrap();
        assert_eq!(std::fs::read(&backup).unwrap(), b"original executable");
        assert_eq!(std::fs::read(&target).unwrap(), b);
    }
}
