//! Driver-independent Windows handle semantics, shared by Dokany and synthetic tests.
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};
use zeroize::Zeroizing;

use crate::{
    error::{Result, VaultError},
    store::{Entry, ROOT, Store},
};

pub const READ: u8 = 1;
pub const WRITE: u8 = 2;
pub const DELETE: u8 = 4;
pub const SHARE_ALL: u8 = READ | WRITE | DELETE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    Open,
    Create,
    OpenOrCreate,
    Overwrite,
    OverwriteOrCreate,
    Supersede,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Active,
    Quiescing,
    Closed,
}

pub struct OpenRequest<'a> {
    pub path: &'a str,
    pub access: u8,
    pub share: u8,
    pub disposition: Disposition,
    pub directory: Option<bool>,
    pub attributes: u32,
    pub delete_on_close: bool,
}

struct Handle {
    node: String,
    access: u8,
    share: u8,
    cleaned: bool,
    delete_on_close: bool,
}

pub struct FileSystem {
    store: Option<Store>,
    handles: BTreeMap<u64, Handle>,
    pending: BTreeSet<String>,
    next_handle: u64,
    phase: Phase,
    last_activity: Instant,
    deferred_failure: bool,
}

impl FileSystem {
    pub fn new(store: Store) -> Self {
        Self {
            store: Some(store),
            handles: BTreeMap::new(),
            pending: BTreeSet::new(),
            next_handle: 1,
            phase: Phase::Active,
            last_activity: Instant::now(),
            deferred_failure: false,
        }
    }
    fn store(&self) -> Result<&Store> {
        self.store.as_ref().ok_or(VaultError::Locked)
    }
    fn store_mut(&mut self) -> Result<&mut Store> {
        self.store.as_mut().ok_or(VaultError::Locked)
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn backing_path(&self) -> Result<std::path::PathBuf> {
        Ok(self.store()?.root_path().to_path_buf())
    }
    pub fn open_handles(&self) -> usize {
        self.handles.len()
    }
    pub fn idle_for(&self) -> std::time::Duration {
        self.last_activity.elapsed()
    }
    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn open(&mut self, request: OpenRequest<'_>) -> Result<(u64, bool, bool)> {
        if self.phase != Phase::Active {
            return Err(VaultError::Locked);
        }
        if self.handles.len() >= 16_384 {
            return Err(VaultError::TooLarge);
        }
        if request.delete_on_close && request.access & DELETE == 0 {
            return Err(VaultError::Access);
        }
        let existing = self.store()?.resolve(request.path);
        let exists = existing.is_ok();
        let id = match existing {
            Ok(id) => id,
            Err(VaultError::NotFound)
                if matches!(
                    request.disposition,
                    Disposition::Create
                        | Disposition::OpenOrCreate
                        | Disposition::OverwriteOrCreate
                        | Disposition::Supersede
                ) =>
            {
                let parts = crate::store::components(request.path)?;
                if parts.len() > 1 {
                    let parent = self
                        .store()?
                        .resolve(&parts[..parts.len() - 1].join("\\"))?;
                    if self.pending.contains(&parent) {
                        return Err(VaultError::DeletePending);
                    }
                }
                self.store_mut()?.create_entry(
                    request.path,
                    request.directory.unwrap_or(false),
                    request.attributes,
                )?
            }
            Err(e) => return Err(e),
        };
        if exists && request.disposition == Disposition::Create {
            return Err(VaultError::Exists);
        }
        if self.pending.contains(&id) {
            return Err(VaultError::DeletePending);
        }
        let directory = self.store()?.entry(&id)?.directory;
        if request.directory == Some(true) && !directory {
            return Err(VaultError::NotDirectory);
        }
        if request.directory == Some(false) && directory {
            return Err(VaultError::IsDirectory);
        }
        for handle in self.handles.values().filter(|h| h.node == id && !h.cleaned) {
            if request.access & !handle.share != 0 || handle.access & !request.share != 0 {
                return Err(VaultError::Sharing);
            }
        }
        if request.delete_on_close {
            if request.access & DELETE == 0 {
                return Err(VaultError::Access);
            }
            self.store()?.check_delete(&id)?;
        }
        if exists
            && matches!(
                request.disposition,
                Disposition::Overwrite | Disposition::OverwriteOrCreate | Disposition::Supersede
            )
        {
            if request.access & WRITE == 0 {
                return Err(VaultError::Access);
            }
            self.store_mut()?.truncate(&id, 0)?;
        }
        let handle = self.next_handle;
        self.next_handle = handle.checked_add(1).ok_or(VaultError::TooLarge)?;
        self.handles.insert(
            handle,
            Handle {
                node: id,
                access: request.access,
                share: request.share,
                cleaned: false,
                delete_on_close: request.delete_on_close,
            },
        );
        if request.delete_on_close {
            let id = self.node(handle, 0)?;
            self.pending.insert(id);
        }
        self.touch();
        Ok((handle, directory, exists))
    }

    fn node(&self, handle: u64, access: u8) -> Result<String> {
        if self.phase == Phase::Closed {
            return Err(VaultError::Locked);
        }
        let handle = self.handles.get(&handle).ok_or(VaultError::Access)?;
        if handle.access & access != access {
            return Err(VaultError::Access);
        }
        Ok(handle.node.clone())
    }

    pub fn read(&mut self, handle: u64, offset: u64, length: usize) -> Result<Zeroizing<Vec<u8>>> {
        let id = self.node(handle, READ)?;
        let data = self.store()?.read(&id, offset, length)?;
        self.touch();
        Ok(data)
    }

    pub fn write(
        &mut self,
        handle: u64,
        offset: Option<u64>,
        bytes: &[u8],
        paging: bool,
    ) -> Result<usize> {
        let id = self.node(handle, WRITE)?;
        let size = self.store()?.entry(&id)?.size;
        let offset = offset.unwrap_or(size);
        let bytes = if paging {
            &bytes[..bytes.len().min(size.saturating_sub(offset) as usize)]
        } else {
            bytes
        };
        let result = self.store_mut()?.write(&id, offset, bytes)?;
        self.touch();
        Ok(result)
    }

    pub fn truncate(&mut self, handle: u64, size: u64) -> Result<()> {
        let id = self.node(handle, WRITE)?;
        self.store_mut()?.truncate(&id, size)?;
        self.touch();
        Ok(())
    }

    pub fn information(&self, handle: u64, path: &str) -> Result<Entry> {
        let id = if handle != 0 {
            self.node(handle, 0)?
        } else {
            self.store()?.resolve(path)?
        };
        Ok(self.store()?.entry(&id)?.clone())
    }

    pub fn list(&mut self, handle: u64, path: &str) -> Result<Vec<Entry>> {
        let id = if handle != 0 {
            self.node(handle, READ)?
        } else {
            self.store()?.resolve(path)?
        };
        let entries = self
            .store()?
            .list(&id)?
            .into_iter()
            .filter(|e| !self.pending.contains(&e.id))
            .collect();
        // Directory enumeration is activity too; idle locking must not disconnect an active Explorer session.
        self.touch();
        Ok(entries)
    }

    pub fn rename(&mut self, handle: u64, target: &str, replace: bool) -> Result<()> {
        let id = self.node(handle, DELETE)?;
        if self.pending.contains(&id) {
            return Err(VaultError::DeletePending);
        }
        let parts = crate::store::components(target)?;
        if parts.len() > 1 {
            let parent = self
                .store()?
                .resolve(&parts[..parts.len() - 1].join("\\"))?;
            if self.pending.contains(&parent) {
                return Err(VaultError::DeletePending);
            }
        }
        if self
            .handles
            .iter()
            .any(|(key, h)| *key != handle && h.node == id && !h.cleaned && h.share & DELETE == 0)
        {
            return Err(VaultError::Sharing);
        }
        if let Ok(target_id) = self.store()?.resolve(target) {
            if target_id != id && self.handles.values().any(|h| h.node == target_id) {
                return Err(VaultError::Sharing);
            }
            if self.pending.contains(&target_id) {
                return Err(VaultError::DeletePending);
            }
        }
        self.store_mut()?.rename(&id, target, replace)?;
        self.touch();
        Ok(())
    }

    pub fn metadata(
        &mut self,
        handle: u64,
        attributes: Option<u32>,
        created: Option<u64>,
        accessed: Option<u64>,
        modified: Option<u64>,
    ) -> Result<()> {
        let id = self.node(handle, WRITE)?;
        self.store_mut()?
            .set_metadata(&id, attributes, created, accessed, modified)?;
        self.touch();
        Ok(())
    }

    pub fn can_delete(&self, handle: u64, directory: bool) -> Result<()> {
        let id = self.node(handle, DELETE)?;
        if self.store()?.entry(&id)?.directory != directory {
            return Err(if directory {
                VaultError::NotDirectory
            } else {
                VaultError::IsDirectory
            });
        }
        if self
            .handles
            .iter()
            .any(|(key, h)| *key != handle && h.node == id && !h.cleaned && h.share & DELETE == 0)
        {
            return Err(VaultError::Sharing);
        }
        self.store()?.check_delete(&id)
    }

    pub fn set_delete_disposition(
        &mut self,
        handle: u64,
        directory: bool,
        pending: bool,
    ) -> Result<()> {
        let id = self.node(handle, DELETE)?;
        if self.store()?.entry(&id)?.directory != directory {
            return Err(if directory {
                VaultError::NotDirectory
            } else {
                VaultError::IsDirectory
            });
        }
        if pending {
            self.can_delete(handle, directory)?;
            self.handles
                .get_mut(&handle)
                .ok_or(VaultError::Access)?
                .delete_on_close = true;
            self.pending.insert(id);
        } else {
            self.handles
                .get_mut(&handle)
                .ok_or(VaultError::Access)?
                .delete_on_close = false;
            if !self
                .handles
                .values()
                .any(|h| h.node == id && h.delete_on_close)
            {
                self.pending.remove(&id);
            }
        }
        Ok(())
    }

    pub fn cleanup(&mut self, handle: u64, delete_pending: bool) -> Result<()> {
        let id = self.node(handle, 0)?;
        let item = self.handles.get_mut(&handle).ok_or(VaultError::Access)?;
        item.cleaned = true;
        if delete_pending || item.delete_on_close {
            self.pending.insert(id);
        }
        self.touch();
        Ok(())
    }

    pub fn close(&mut self, handle: u64) -> Result<()> {
        let item = self.handles.remove(&handle).ok_or(VaultError::Access)?;
        if self.pending.contains(&item.node) && !self.handles.values().any(|h| h.node == item.node)
        {
            if let Err(e) = self.store_mut()?.remove(&item.node) {
                self.deferred_failure = true;
                return Err(e);
            }
            self.pending.remove(&item.node);
        }
        self.touch();
        Ok(())
    }

    pub fn flush(&self) -> Result<()> {
        if self.deferred_failure {
            return Err(VaultError::Io(std::io::Error::other(
                "A deferred filesystem operation failed; preserve this vault and retry after reopening",
            )));
        }
        self.store()?.flush()
    }

    pub fn begin_lock(&mut self) -> Result<()> {
        if self.phase != Phase::Active {
            return Err(VaultError::Locked);
        }
        self.phase = Phase::Quiescing;
        if !self.handles.is_empty() {
            self.phase = Phase::Active;
            return Err(VaultError::OpenHandles);
        }
        if let Err(e) = self.flush() {
            self.phase = Phase::Active;
            return Err(e);
        }
        Ok(())
    }

    pub fn cancel_lock(&mut self) {
        if self.phase == Phase::Quiescing {
            self.phase = Phase::Active;
        }
    }

    pub fn finish_lock(&mut self) -> Result<()> {
        if self.phase != Phase::Quiescing || !self.handles.is_empty() {
            return Err(VaultError::OpenHandles);
        }
        self.store.take(); // Owned keys/catalog and exclusive writer lock are dropped only after provider acknowledgement.
        self.phase = Phase::Closed;
        Ok(())
    }

    pub fn root_information(&self) -> Result<Entry> {
        Ok(self.store()?.entry(ROOT)?.clone())
    }
}
