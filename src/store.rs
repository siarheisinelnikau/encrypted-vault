use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    crypto::{self, CHUNK_SIZE, Header, Id, Keys, MAX_CATALOG, MAX_FILE_SIZE, MAX_IO},
    error::{Result, VaultError},
};

pub const ROOT: &str = "00000000000000000000000000000000";
pub const ATTR_READONLY: u32 = 1;
pub const ATTR_DIRECTORY: u32 = 0x10;
pub const ATTR_ARCHIVE: u32 = 0x20;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub id: Id,
    pub parent: Id,
    pub name: String,
    pub directory: bool,
    pub size: u64,
    pub attributes: u32,
    pub created: u64,
    pub accessed: u64,
    pub modified: u64,
    pub chunks: BTreeMap<u64, Id>,
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.id.zeroize();
        self.parent.zeroize();
        self.name.zeroize();
        self.size.zeroize();
        self.attributes.zeroize();
        self.created.zeroize();
        self.accessed.zeroize();
        self.modified.zeroize();
        for object in self.chunks.values_mut() {
            object.zeroize();
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    version: u32,
    generation: u64,
    entries: BTreeMap<Id, Entry>,
}

pub struct Store {
    root: PathBuf,
    header: Header,
    keys: Keys,
    catalog: Catalog,
    _writer: File,
    #[cfg(test)]
    fail_before_publish: bool,
}

pub fn now() -> u64 {
    // Windows FILETIME: 100 ns ticks since 1601-01-01.
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .saturating_div(100)
        .saturating_add(116_444_736_000_000_000)
        .min(u64::MAX as u128) as u64
}

impl Store {
    pub fn create(path: &Path, password: &str) -> Result<Self> {
        check_backing_path(path.parent().ok_or(VaultError::InvalidPath)?)?;
        let (header, keys) = Header::create(password)?;
        fs::create_dir(path)?; // Never overwrite or adopt an existing directory.
        fs::create_dir(path.join("objects"))?;
        let root = fs::canonicalize(path)?;
        let writer = writer_lock(&root)?;
        let root_entry = Entry {
            id: ROOT.into(),
            parent: ROOT.into(),
            name: String::new(),
            directory: true,
            size: 0,
            attributes: ATTR_DIRECTORY,
            created: now(),
            accessed: now(),
            modified: now(),
            chunks: BTreeMap::new(),
        };
        let catalog = Catalog {
            version: 1,
            generation: 0,
            entries: [(ROOT.into(), root_entry)].into(),
        };
        write_new(
            &root.join("header.json"),
            &serde_json::to_vec(&header).map_err(|_| VaultError::Format)?,
        )?;
        let mut store = Self {
            root,
            header,
            keys,
            catalog,
            _writer: writer,
            #[cfg(test)]
            fail_before_publish: false,
        };
        store.publish(store.catalog.clone())?;
        Ok(store)
    }

    pub fn open(path: &Path, password: &str) -> Result<Self> {
        check_backing_path(path)?;
        let root = fs::canonicalize(path)?;
        check_backing_path(&root.join("objects"))?;
        let writer = writer_lock(&root)?;
        let header: Header =
            serde_json::from_slice(&read_bounded(&root.join("header.json"), 4096)?)
                .map_err(|_| VaultError::Format)?;
        let keys = header.unlock(password)?;
        let blob = read_bounded(&root.join("catalog.ev"), MAX_CATALOG + 8192)?;
        let aad = crypto::aad(&header.public.vault_id, "catalog", "", 0, "");
        let plain = crypto::open(&keys.catalog, &aad, &blob)?;
        if plain.len() < 8 {
            return Err(VaultError::Format);
        }
        let length =
            u64::from_le_bytes(plain[..8].try_into().map_err(|_| VaultError::Format)?) as usize;
        if length > MAX_CATALOG || length > plain.len() - 8 {
            return Err(VaultError::Format);
        }
        let catalog: Catalog =
            serde_json::from_slice(&plain[8..8 + length]).map_err(|_| VaultError::Format)?;
        validate_catalog(&catalog)?;
        Ok(Self {
            root,
            header,
            keys,
            catalog,
            _writer: writer,
            #[cfg(test)]
            fail_before_publish: false,
        })
    }

    pub fn root_path(&self) -> &Path {
        &self.root
    }
    pub fn generation(&self) -> u64 {
        self.catalog.generation
    }
    pub fn entry(&self, id: &str) -> Result<&Entry> {
        self.catalog.entries.get(id).ok_or(VaultError::NotFound)
    }
    pub fn resolve(&self, path: &str) -> Result<Id> {
        let mut id = ROOT.to_string();
        for name in components(path)? {
            if !self.entry(&id)?.directory {
                return Err(VaultError::NotDirectory);
            }
            id = self
                .catalog
                .entries
                .values()
                .find(|e| e.parent == id && e.id != ROOT && fold(&e.name) == fold(name))
                .map(|e| e.id.clone())
                .ok_or(VaultError::NotFound)?;
        }
        Ok(id)
    }

    pub fn list(&self, id: &str) -> Result<Vec<Entry>> {
        if !self.entry(id)?.directory {
            return Err(VaultError::NotDirectory);
        }
        let mut entries: Vec<_> = self
            .catalog
            .entries
            .values()
            .filter(|e| e.parent == id && e.id != ROOT)
            .cloned()
            .collect();
        entries.sort_by_key(|e| (!e.directory, fold(&e.name)));
        Ok(entries)
    }

    fn destination(&self, path: &str) -> Result<(Id, String)> {
        let parts = components(path)?;
        let (name, parents) = parts.split_last().ok_or(VaultError::InvalidPath)?;
        let parent = self.resolve(&parents.join("\\"))?;
        if !self.entry(&parent)?.directory {
            return Err(VaultError::NotDirectory);
        }
        Ok((parent, name.to_string()))
    }

    pub fn create_entry(&mut self, path: &str, directory: bool, attributes: u32) -> Result<Id> {
        let (parent, name) = self.destination(path)?;
        if self
            .catalog
            .entries
            .values()
            .any(|e| e.parent == parent && fold(&e.name) == fold(&name))
        {
            return Err(VaultError::Exists);
        }
        let id = crypto::new_id()?;
        let mut next = self.catalog.clone();
        next.entries.insert(
            id.clone(),
            Entry {
                id: id.clone(),
                parent,
                name,
                directory,
                size: 0,
                attributes: clean_attributes(attributes, directory),
                created: now(),
                accessed: now(),
                modified: now(),
                chunks: BTreeMap::new(),
            },
        );
        self.publish(next)?;
        Ok(id)
    }

    pub fn read(&self, id: &str, offset: u64, count: usize) -> Result<Zeroizing<Vec<u8>>> {
        if count > MAX_IO {
            return Err(VaultError::TooLarge);
        }
        let entry = self.entry(id)?;
        if entry.directory {
            return Err(VaultError::IsDirectory);
        }
        let length = (entry.size.saturating_sub(offset)).min(count as u64) as usize;
        let mut output = Zeroizing::new(vec![0; length]);
        let mut done = 0;
        while done < length {
            let position = offset + done as u64;
            let index = position / CHUNK_SIZE as u64;
            let start = (position % CHUNK_SIZE as u64) as usize;
            let take = (CHUNK_SIZE - start).min(length - done);
            let chunk = self.read_chunk(entry, index)?;
            output[done..done + take].copy_from_slice(&chunk[start..start + take]);
            done += take;
        }
        Ok(output)
    }

    fn read_chunk(&self, entry: &Entry, index: u64) -> Result<Zeroizing<Vec<u8>>> {
        match entry.chunks.get(&index) {
            None => Ok(Zeroizing::new(vec![0; CHUNK_SIZE])),
            Some(object) => {
                let blob = read_bounded(&self.root.join("objects").join(object), CHUNK_SIZE + 40)?;
                if blob.len() != CHUNK_SIZE + 40 {
                    return Err(VaultError::Authentication);
                }
                let aad = crypto::aad(
                    &self.header.public.vault_id,
                    "chunk",
                    &entry.id,
                    index,
                    object,
                );
                let plain = crypto::open(&self.keys.chunks, &aad, &blob)?;
                if plain.len() != CHUNK_SIZE {
                    return Err(VaultError::Authentication);
                }
                Ok(plain)
            }
        }
    }

    fn write_chunk(&self, entry: &mut Entry, index: u64, plain: &[u8]) -> Result<()> {
        let object = crypto::new_id()?;
        let aad = crypto::aad(
            &self.header.public.vault_id,
            "chunk",
            &entry.id,
            index,
            &object,
        );
        let blob = crypto::seal(&self.keys.chunks, &aad, plain)?;
        write_new(&self.root.join("objects").join(&object), &blob)?;
        entry.chunks.insert(index, object);
        Ok(())
    }

    pub fn write(&mut self, id: &str, offset: u64, data: &[u8]) -> Result<usize> {
        if data.len() > MAX_IO
            || offset
                .checked_add(data.len() as u64)
                .filter(|end| *end <= MAX_FILE_SIZE)
                .is_none()
        {
            return Err(VaultError::TooLarge);
        }
        let original = self.entry(id)?;
        if original.directory {
            return Err(VaultError::IsDirectory);
        }
        if original.attributes & ATTR_READONLY != 0 {
            return Err(VaultError::Access);
        }
        if data.is_empty() {
            return Ok(0);
        }
        let mut changed = original.clone();
        let mut done = 0;
        while done < data.len() {
            let position = offset + done as u64;
            let index = position / CHUNK_SIZE as u64;
            let start = (position % CHUNK_SIZE as u64) as usize;
            let take = (CHUNK_SIZE - start).min(data.len() - done);
            let mut chunk = self.read_chunk(original, index)?;
            chunk[start..start + take].copy_from_slice(&data[done..done + take]);
            self.write_chunk(&mut changed, index, &chunk)?;
            done += take;
        }
        changed.size = changed.size.max(offset + data.len() as u64);
        changed.modified = now();
        changed.attributes |= ATTR_ARCHIVE;
        let mut next = self.catalog.clone();
        next.entries.insert(id.into(), changed);
        self.publish(next)?;
        Ok(data.len())
    }

    pub fn truncate(&mut self, id: &str, size: u64) -> Result<()> {
        if size > MAX_FILE_SIZE {
            return Err(VaultError::TooLarge);
        }
        let original = self.entry(id)?;
        if original.directory {
            return Err(VaultError::IsDirectory);
        }
        if original.attributes & ATTR_READONLY != 0 {
            return Err(VaultError::Access);
        }
        if size == original.size {
            return Ok(());
        }
        let mut changed = original.clone();
        if size < original.size {
            changed
                .chunks
                .retain(|index, _| *index < size.div_ceil(CHUNK_SIZE as u64));
            let tail = (size % CHUNK_SIZE as u64) as usize;
            let index = size / CHUNK_SIZE as u64;
            if tail != 0 && changed.chunks.contains_key(&index) {
                let mut chunk = self.read_chunk(original, index)?;
                chunk[tail..].fill(0);
                self.write_chunk(&mut changed, index, &chunk)?;
            }
        }
        changed.size = size;
        changed.modified = now();
        let mut next = self.catalog.clone();
        next.entries.insert(id.into(), changed);
        self.publish(next)
    }

    pub fn rename(&mut self, id: &str, target: &str, replace: bool) -> Result<Option<Id>> {
        if id == ROOT {
            return Err(VaultError::Access);
        }
        let (parent, name) = self.destination(target)?;
        let source = self.entry(id)?;
        let mut ancestor = parent.clone();
        while ancestor != ROOT {
            if ancestor == id {
                return Err(VaultError::InvalidPath);
            }
            ancestor = self.entry(&ancestor)?.parent.clone();
        }
        let existing = self
            .catalog
            .entries
            .values()
            .find(|e| e.id != id && e.parent == parent && fold(&e.name) == fold(&name));
        let replaced = if let Some(other) = existing {
            if !replace {
                return Err(VaultError::Exists);
            }
            if source.directory || other.directory || other.attributes & ATTR_READONLY != 0 {
                return Err(VaultError::Access);
            }
            Some(other.id.clone())
        } else {
            None
        };
        let mut next = self.catalog.clone();
        if let Some(old) = &replaced {
            next.entries.remove(old);
        }
        let changed = next.entries.get_mut(id).ok_or(VaultError::NotFound)?;
        changed.parent = parent;
        changed.name = name;
        changed.modified = now();
        self.publish(next)?;
        Ok(replaced)
    }

    pub fn check_delete(&self, id: &str) -> Result<()> {
        if id == ROOT {
            return Err(VaultError::Access);
        }
        if self.entry(id)?.attributes & ATTR_READONLY != 0 {
            return Err(VaultError::Access);
        }
        if self.catalog.entries.values().any(|e| e.parent == id) {
            return Err(VaultError::NotEmpty);
        }
        Ok(())
    }

    pub fn remove(&mut self, id: &str) -> Result<()> {
        self.check_delete(id)?;
        let mut next = self.catalog.clone();
        next.entries.remove(id);
        self.publish(next)
    }

    pub fn set_metadata(
        &mut self,
        id: &str,
        attributes: Option<u32>,
        created: Option<u64>,
        accessed: Option<u64>,
        modified: Option<u64>,
    ) -> Result<()> {
        let mut next = self.catalog.clone();
        let entry = next.entries.get_mut(id).ok_or(VaultError::NotFound)?;
        if let Some(a) = attributes {
            entry.attributes = clean_attributes(a, entry.directory);
        }
        if let Some(t) = created {
            entry.created = t;
        }
        if let Some(t) = accessed {
            entry.accessed = t;
        }
        if let Some(t) = modified {
            entry.modified = t;
        }
        self.publish(next)
    }

    pub fn flush(&self) -> Result<()> {
        open_existing(&self.root.join("catalog.ev"), true)?.sync_all()?;
        Ok(())
    }

    fn publish(&mut self, mut next: Catalog) -> Result<()> {
        next.generation = self
            .catalog
            .generation
            .checked_add(1)
            .ok_or(VaultError::TooLarge)?;
        let json = Zeroizing::new(serde_json::to_vec(&next).map_err(|_| VaultError::Format)?);
        if json.len() > MAX_CATALOG {
            return Err(VaultError::TooLarge);
        }
        let length = (json.len() + 8).div_ceil(4096) * 4096;
        let mut plain = Zeroizing::new(vec![0; length]);
        plain[..8].copy_from_slice(&(json.len() as u64).to_le_bytes());
        plain[8..8 + json.len()].copy_from_slice(&json);
        let aad = crypto::aad(&self.header.public.vault_id, "catalog", "", 0, "");
        let encrypted = crypto::seal(&self.keys.catalog, &aad, &plain)?;
        let temporary = self
            .root
            .join(format!("catalog-{}.pending", crypto::new_id()?));
        write_new(&temporary, &encrypted)?;
        #[cfg(test)]
        if self.fail_before_publish {
            return Err(VaultError::Io(std::io::Error::other(
                "Injected interruption before catalog publication",
            )));
        }
        atomic_replace(&temporary, &self.root.join("catalog.ev"))?;
        self.catalog = next;
        Ok(())
    }
}

pub fn fold(name: &str) -> String {
    name.to_lowercase()
}

pub fn components(path: &str) -> Result<Vec<&str>> {
    if path.len() > 32760 || path.starts_with("\\\\") || path.contains('/') {
        return Err(VaultError::InvalidPath);
    }
    let path = path.strip_prefix('\\').unwrap_or(path);
    let path = path.strip_suffix('\\').unwrap_or(path);
    if path.is_empty() {
        return Ok(Vec::new());
    }
    let result: Vec<_> = path.split('\\').collect();
    for part in &result {
        validate_name(part)?;
    }
    Ok(result)
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.encode_utf16().count() > 255
        || name.ends_with([' ', '.'])
        || name.chars().any(|c| c < ' ' || "<>:\"/\\|?*".contains(c))
    {
        return Err(VaultError::InvalidPath);
    }
    let stem = name.split('.').next().unwrap_or_default().to_uppercase();
    if ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"].contains(&stem.as_str())
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.chars().count() == 4
            && "123456789¹²³".contains(stem.chars().last().unwrap_or('0')))
    {
        return Err(VaultError::InvalidPath);
    }
    Ok(())
}

fn clean_attributes(attributes: u32, directory: bool) -> u32 {
    let attributes =
        (attributes & (1 | 2 | 4 | 0x20 | 0x1000)) | if directory { ATTR_DIRECTORY } else { 0 };
    if attributes == 0 { 0x80 } else { attributes }
}

fn validate_catalog(catalog: &Catalog) -> Result<()> {
    if catalog.version != 1 || catalog.entries.len() > 100_000 {
        return Err(VaultError::Format);
    }
    let root = catalog.entries.get(ROOT).ok_or(VaultError::Format)?;
    if !root.directory || root.parent != ROOT || !root.name.is_empty() {
        return Err(VaultError::Format);
    }
    let mut names = BTreeSet::new();
    for (id, entry) in &catalog.entries {
        if id != &entry.id
            || !crypto::valid_id(id)
            || entry.size > MAX_FILE_SIZE
            || entry.chunks.len() > MAX_CATALOG / 32
            || (entry.directory && (entry.size != 0 || !entry.chunks.is_empty()))
        {
            return Err(VaultError::Format);
        }
        if id != ROOT {
            validate_name(&entry.name).map_err(|_| VaultError::Format)?;
            if !names.insert((entry.parent.clone(), fold(&entry.name))) {
                return Err(VaultError::Format);
            }
            let mut parent = &entry.parent;
            for depth in 0..=catalog.entries.len() {
                if depth == catalog.entries.len() {
                    return Err(VaultError::Format);
                }
                let p = catalog.entries.get(parent).ok_or(VaultError::Format)?;
                if !p.directory || parent == id {
                    return Err(VaultError::Format);
                }
                if parent == ROOT {
                    break;
                }
                parent = &p.parent;
            }
        }
        for (index, object) in &entry.chunks {
            if !crypto::valid_id(object) || *index >= entry.size.div_ceil(CHUNK_SIZE as u64) {
                return Err(VaultError::Format);
            }
        }
    }
    Ok(())
}

pub fn check_backing_path(path: &Path) -> Result<()> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut current = PathBuf::new();
    for part in absolute.components() {
        if matches!(part, Component::ParentDir) {
            return Err(VaultError::InvalidPath);
        }
        current.push(part);
        // A verbatim Windows drive prefix (\\?\C:) is not an independently openable path.
        if matches!(part, Component::Prefix(_)) {
            continue;
        }
        let metadata = fs::symlink_metadata(&current)?;
        if metadata.file_type().is_symlink() {
            return Err(VaultError::InvalidPath);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(VaultError::InvalidPath);
            }
        }
    }
    Ok(())
}

pub fn open_existing(path: &Path, write: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(write);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000);
    }
    let file = options.open(path)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if file.metadata()?.file_attributes() & 0x400 != 0 {
            return Err(VaultError::InvalidPath);
        }
    }
    Ok(file)
}

pub fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>> {
    let file = open_existing(path, false)?;
    if file.metadata()?.len() > max as u64 {
        return Err(VaultError::TooLarge);
    }
    let mut bytes = Vec::new();
    file.take(max as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > max {
        return Err(VaultError::TooLarge);
    }
    Ok(bytes)
}

pub fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn writer_lock(root: &Path) -> Result<File> {
    let path = root.join("writer.lock");
    if !path.exists() {
        match write_new(
            &path,
            b"Single writer only. Never unlock two cloud replicas at once.\n",
        ) {
            Ok(()) => (),
            Err(VaultError::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e),
        }
    }
    let file = open_existing(&path, true)?;
    FileExt::try_lock_exclusive(&file).map_err(|_| VaultError::WriterBusy)?;
    Ok(file)
}

pub fn atomic_replace(source: &Path, destination: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
        };
        let src: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
        let dst: Vec<u16> = destination
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        // The source is a synced, newly created sibling file. No plaintext is published.
        if unsafe {
            MoveFileExW(
                src.as_ptr(),
                dst.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    #[cfg(not(windows))]
    {
        fs::rename(source, destination)?;
        File::open(destination.parent().ok_or(VaultError::InvalidPath)?)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interrupted_publication_preserves_committed_catalog() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("vault");
        let mut store = Store::create(&path, "interruption fixture password").unwrap();
        let id = store.create_entry("record.txt", false, 0).unwrap();
        store.write(&id, 0, b"committed").unwrap();
        let generation = store.generation();
        store.fail_before_publish = true;
        assert!(store.write(&id, 0, b"uncommitted replacement").is_err());
        assert_eq!(store.generation(), generation);
        assert_eq!(&*store.read(&id, 0, 100).unwrap(), b"committed");
        drop(store);
        let reopened = Store::open(&path, "interruption fixture password").unwrap();
        assert_eq!(&*reopened.read(&id, 0, 100).unwrap(), b"committed");
        assert_eq!(reopened.generation(), generation);
        assert!(std::fs::read_dir(&path).unwrap().any(|e| {
            e.unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".pending")
        }));
    }
}
