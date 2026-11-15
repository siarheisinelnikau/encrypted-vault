//! Dynamic Dokany integration. Loading/mounting occurs only after an explicit Unlock action.
pub mod abi;

use crate::{
    crypto::MAX_IO,
    error::{Result, VaultError},
    filesystem::{DELETE, Disposition, FileSystem, OpenRequest, Phase, READ, WRITE},
    store::{Entry, Store},
};
use abi::*;
use std::{
    ffi::c_void,
    path::PathBuf,
    ptr,
    sync::{Arc, Mutex, OnceLock, Weak},
};
use windows_sys::Win32::{
    Foundation::FILETIME,
    Foundation::{FreeLibrary, HMODULE},
    Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetLogicalDrives, WIN32_FIND_DATAW},
    System::{
        LibraryLoader::{
            GetProcAddress, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
            LoadLibraryExW,
        },
        SystemInformation::GetSystemDirectoryW,
    },
};

type CreateFs = unsafe extern "system" fn(*mut Options, *mut Operations, *mut *mut c_void) -> i32;
type Remove = unsafe extern "system" fn(*const u16) -> i32;
type Wait = unsafe extern "system" fn(*mut c_void, u32) -> u32;
type Close = unsafe extern "system" fn(*mut c_void);
type Lifecycle = unsafe extern "system" fn();
type Version = unsafe extern "system" fn() -> u32;

struct Runtime {
    module: HMODULE,
    create: CreateFs,
    remove: Remove,
    wait: Wait,
    close: Close,
    shutdown: Lifecycle,
}
// Dokany documents thread-safe dispatcher/lifecycle APIs; initialization is serialized below.
unsafe impl Send for Runtime {}
unsafe impl Sync for Runtime {}
static RUNTIME: OnceLock<Mutex<Weak<Runtime>>> = OnceLock::new();

fn runtime_path() -> Result<PathBuf> {
    let mut buffer = vec![0u16; 32768];
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return Err(VaultError::Runtime(
            "Windows system directory unavailable".into(),
        ));
    }
    Ok(PathBuf::from(String::from_utf16_lossy(&buffer[..length])).join("dokan2.dll"))
}

pub fn runtime_present() -> bool {
    runtime_path().is_ok_and(|p| p.is_file())
}

pub fn available_letters() -> Vec<char> {
    let mask = unsafe { GetLogicalDrives() };
    if mask == 0 {
        return Vec::new();
    }
    ('D'..='Z')
        .filter(|letter| mask & (1 << (*letter as u32 - 'A' as u32)) == 0)
        .collect()
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

impl Runtime {
    fn load() -> Result<Arc<Self>> {
        let mut slot = RUNTIME
            .get_or_init(|| Mutex::new(Weak::new()))
            .lock()
            .map_err(|_| VaultError::Access)?;
        if let Some(runtime) = slot.upgrade() {
            return Ok(runtime);
        }
        let path = runtime_path()?;
        if !path.is_file() {
            return Err(VaultError::Runtime("Dokany 2.3.1+ is required. Install its official runtime separately; no driver was installed by Encrypted Vault.".into()));
        }
        let path = wide(&path.to_string_lossy());
        let module = unsafe {
            LoadLibraryExW(
                path.as_ptr(),
                ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if module.is_null() {
            return Err(VaultError::Runtime(
                std::io::Error::last_os_error().to_string(),
            ));
        }
        // Resolve all exports before initialization. No application-directory/PATH DLL search is allowed.
        let result = (|| -> Result<Arc<Self>> {
            macro_rules! symbol {
                ($name:literal, $ty:ty) => {{
                    let function = unsafe { GetProcAddress(module, concat!($name, "\0").as_ptr()) }
                        .ok_or_else(|| {
                            VaultError::Runtime(format!("Missing Dokany export: {}", $name))
                        })?;
                    unsafe {
                        std::mem::transmute::<unsafe extern "system" fn() -> isize, $ty>(function)
                    }
                }};
            }
            let init = symbol!("DokanInit", Lifecycle);
            let shutdown = symbol!("DokanShutdown", Lifecycle);
            let create = symbol!("DokanCreateFileSystem", CreateFs);
            let remove = symbol!("DokanRemoveMountPoint", Remove);
            let wait = symbol!("DokanWaitForFileSystemClosed", Wait);
            let close = symbol!("DokanCloseHandle", Close);
            let version = symbol!("DokanVersion", Version);
            let driver_version = symbol!("DokanDriverVersion", Version);
            let library_version = unsafe { version() };
            let kernel_version = unsafe { driver_version() };
            if !(231..300).contains(&library_version) || !(231..300).contains(&kernel_version) {
                return Err(VaultError::Runtime(format!(
                    "Dokany 2.3.1+ required (library {library_version}, driver {kernel_version})"
                )));
            }
            unsafe {
                init();
            }
            Ok(Arc::new(Self {
                module,
                create,
                remove,
                wait,
                close,
                shutdown,
            }))
        })();
        match result {
            Ok(runtime) => {
                *slot = Arc::downgrade(&runtime);
                Ok(runtime)
            }
            Err(e) => {
                unsafe {
                    FreeLibrary(module);
                }
                Err(e)
            }
        }
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        unsafe {
            (self.shutdown)();
            if !self.module.is_null() {
                FreeLibrary(self.module);
            }
        }
    }
}

struct Context {
    fs: Mutex<FileSystem>,
}

pub struct Mount {
    runtime: Arc<Runtime>,
    context: Box<Context>,
    _options: Box<Options>,
    _operations: Box<Operations>,
    mount_point: Vec<u16>,
    handle: *mut c_void,
    letter: char,
}
// All callbacks synchronize the store through Context; Dokany handle operations are thread safe.
unsafe impl Send for Mount {}

impl Mount {
    pub fn start(store: Store, letter: char) -> Result<Self> {
        if !available_letters().contains(&letter) {
            return Err(VaultError::Mount(
                "The selected drive letter is in use".into(),
            ));
        }
        let runtime = Runtime::load()?;
        let context = Box::new(Context {
            fs: Mutex::new(FileSystem::new(store)),
        });
        let mount_point = wide(&format!("{letter}:\\"));
        let mut options: Box<Options> = Box::new(unsafe { std::mem::zeroed() });
        options.version = 231;
        options.options = 1 << 7; // Current session only. Kernel handles byte-range locks; no alternate streams/reparse points.
        options.global_context = (&*context as *const Context) as u64;
        options.mount_point = mount_point.as_ptr();
        options.timeout = 30_000;
        options.allocation_unit_size = 4096;
        options.sector_size = 512;
        let mut operations = Box::new(operations());
        let mut handle = ptr::null_mut();
        let code = unsafe { (runtime.create)(&mut *options, &mut *operations, &mut handle) };
        if code != 0 || handle.is_null() {
            return Err(VaultError::Mount(format!("Dokany returned {code}")));
        }
        Ok(Self {
            runtime,
            context,
            _options: options,
            _operations: operations,
            mount_point,
            handle,
            letter,
        })
    }

    pub fn letter(&self) -> char {
        self.letter
    }
    pub fn idle_for(&self) -> Result<std::time::Duration> {
        Ok(self
            .context
            .fs
            .lock()
            .map_err(|_| VaultError::Access)?
            .idle_for())
    }

    pub fn lock(&mut self) -> Result<()> {
        if self.handle.is_null() {
            let mut fs = self.context.fs.lock().map_err(|_| VaultError::Access)?;
            return if fs.phase() == Phase::Closed {
                Ok(())
            } else {
                fs.finish_lock()
            };
        }
        let initiate = {
            let mut fs = self.context.fs.lock().map_err(|_| VaultError::Access)?;
            if fs.phase() == Phase::Active {
                fs.begin_lock()?;
                true
            } else {
                false
            }
        };
        if initiate && unsafe { (self.runtime.remove)(self.mount_point.as_ptr()) } == 0 {
            self.context
                .fs
                .lock()
                .map_err(|_| VaultError::Access)?
                .cancel_lock();
            return Err(VaultError::Mount(
                "Windows did not disconnect the drive".into(),
            ));
        }
        if unsafe { (self.runtime.wait)(self.handle, 15_000) } != 0 {
            // Keep handle/context/keys alive: subsequent Lock retries await closure instead of declaring success.
            return Err(VaultError::Mount(
                "Disconnect acknowledgement timed out; the drive is still being closed".into(),
            ));
        }
        unsafe {
            (self.runtime.close)(self.handle);
        }
        self.handle = ptr::null_mut();
        self.context
            .fs
            .lock()
            .map_err(|_| VaultError::Access)?
            .finish_lock()
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // The controller retains Mount on any safe-lock failure. Unexpected process teardown must
            // still stop dispatcher callbacks before freeing their context; it never reports safe lock.
            unsafe {
                (self.runtime.close)(self.handle);
            }
            self.handle = ptr::null_mut();
        }
    }
}

const SUCCESS: i32 = 0;
const INVALID_PARAMETER: i32 = 0xC000000Du32 as i32;
const NOT_IMPLEMENTED: i32 = 0xC0000002u32 as i32;
const COLLISION: i32 = 0xC0000035u32 as i32;

fn status(error: VaultError) -> i32 {
    (match error {
        VaultError::NotFound => 0xC0000034u32,
        VaultError::Exists => 0xC0000035,
        VaultError::NotDirectory => 0xC0000103,
        VaultError::IsDirectory => 0xC00000BA,
        VaultError::NotEmpty => 0xC0000101,
        VaultError::Sharing | VaultError::WriterBusy | VaultError::OpenHandles => 0xC0000043,
        VaultError::DeletePending => 0xC0000056,
        VaultError::InvalidPath => 0xC0000033,
        VaultError::TooLarge => 0xC0000904,
        VaultError::Authentication | VaultError::Format => 0xC000003E,
        VaultError::Io(_) => 0xC0000185,
        _ => 0xC0000022,
    }) as i32
}

unsafe fn name(pointer: Name) -> Result<String> {
    if pointer.is_null() {
        return Err(VaultError::InvalidPath);
    }
    let mut len = 0;
    while len < 32760 && unsafe { *pointer.add(len) } != 0 {
        len += 1;
    }
    if len == 32760 {
        return Err(VaultError::InvalidPath);
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(pointer, len) })
        .map_err(|_| VaultError::InvalidPath)
}

unsafe fn call(
    info: Info,
    operation: impl FnOnce(&mut FileSystem, &mut FileInfo) -> Result<()>,
) -> i32 {
    // No panic may unwind over the provider's C boundary. Poisoned state fails closed.
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
        let info = unsafe { info.as_mut() }.ok_or(VaultError::Access)?;
        let options = unsafe { info.options.as_ref() }.ok_or(VaultError::Access)?;
        let context = unsafe { (options.global_context as *const Context).as_ref() }
            .ok_or(VaultError::Access)?;
        let mut fs = context.fs.lock().map_err(|_| VaultError::Access)?;
        operation(&mut fs, info)
    }))
    .map_or(0xC0000185u32 as i32, |r| r.map_or_else(status, |_| SUCCESS))
}

fn access(mask: u32) -> u8 {
    let mut result = 0;
    if mask & (0x80000000 | 0x10000000 | 1 | 8 | 0x80 | 0x20000) != 0 {
        result |= READ;
    }
    if mask & (0x40000000 | 0x10000000 | 2 | 4 | 0x10 | 0x100) != 0 {
        result |= WRITE;
    }
    if mask & (0x10000000 | 0x10000) != 0 {
        result |= DELETE;
    }
    result
}

unsafe extern "system" fn create(
    path: Name,
    _: *mut c_void,
    desired: u32,
    attributes: u32,
    share: u32,
    disposition: u32,
    options: u32,
    info: Info,
) -> i32 {
    let mut existed = false;
    let code = unsafe {
        call(info, |fs, info| {
            if options & (0x00200000 | 0x00002000) != 0 || attributes & (0x400 | 0x4000) != 0 {
                return Err(VaultError::Access);
            }
            let disposition = match disposition {
                0 => Disposition::Supersede,
                1 => Disposition::Open,
                2 => Disposition::Create,
                3 => Disposition::OpenOrCreate,
                4 => Disposition::Overwrite,
                5 => Disposition::OverwriteOrCreate,
                _ => return Err(VaultError::Access),
            };
            let path = name(path)?;
            let (handle, directory, exists) = fs.open(OpenRequest {
                path: &path,
                access: access(desired),
                share: (share & 7) as u8,
                disposition,
                directory: if options & 1 != 0 {
                    Some(true)
                } else if options & 0x40 != 0 {
                    Some(false)
                } else {
                    None
                },
                attributes,
                delete_on_close: options & 0x1000 != 0,
            })?;
            info.context = handle;
            info.is_directory = directory as u8;
            existed = exists;
            Ok(())
        })
    };
    if code == SUCCESS && existed && matches!(disposition, 0 | 3 | 5) {
        COLLISION
    } else {
        code
    }
}

unsafe extern "system" fn cleanup(_: Name, info: Info) {
    unsafe {
        call(info, |fs, info| {
            fs.cleanup(info.context, info.delete_pending != 0)
        });
    }
}
unsafe extern "system" fn close(_: Name, info: Info) {
    unsafe {
        call(info, |fs, info| {
            let handle = info.context;
            info.context = 0;
            fs.close(handle)
        });
    }
}

unsafe extern "system" fn read(
    _: Name,
    buffer: *mut c_void,
    length: u32,
    read_length: *mut u32,
    offset: i64,
    info: Info,
) -> i32 {
    if offset < 0
        || read_length.is_null()
        || (buffer.is_null() && length != 0)
        || length as usize > MAX_IO
    {
        return INVALID_PARAMETER;
    }
    unsafe {
        *read_length = 0;
        call(info, |fs, info| {
            let data = fs.read(info.context, offset as u64, length as usize)?;
            if !data.is_empty() {
                ptr::copy_nonoverlapping(data.as_ptr(), buffer as *mut u8, data.len());
            }
            *read_length = data.len() as u32;
            Ok(())
        })
    }
}

unsafe extern "system" fn write(
    _: Name,
    buffer: *const c_void,
    length: u32,
    written: *mut u32,
    offset: i64,
    info: Info,
) -> i32 {
    if written.is_null() || (buffer.is_null() && length != 0) || length as usize > MAX_IO {
        return INVALID_PARAMETER;
    }
    unsafe {
        *written = 0;
        call(info, |fs, info| {
            let offset = if info.write_to_end_of_file != 0 {
                None
            } else {
                Some(u64::try_from(offset).map_err(|_| VaultError::InvalidPath)?)
            };
            let bytes = if length == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(buffer as *const u8, length as usize)
            };
            *written = fs.write(info.context, offset, bytes, info.paging_io != 0)? as u32;
            Ok(())
        })
    }
}

unsafe extern "system" fn flush(_: Name, info: Info) -> i32 {
    unsafe { call(info, |fs, _| fs.flush()) }
}
fn filetime(t: u64) -> FILETIME {
    FILETIME {
        dwLowDateTime: t as u32,
        dwHighDateTime: (t >> 32) as u32,
    }
}
fn file_index(entry: &Entry) -> u64 {
    u64::from_str_radix(&entry.id[..16], 16).unwrap_or_default()
}

unsafe extern "system" fn information(
    path: Name,
    buffer: *mut BY_HANDLE_FILE_INFORMATION,
    info: Info,
) -> i32 {
    if buffer.is_null() {
        return INVALID_PARAMETER;
    }
    unsafe {
        call(info, |fs, info| {
            let entry = fs.information(info.context, &name(path)?)?;
            *buffer = BY_HANDLE_FILE_INFORMATION {
                dwFileAttributes: entry.attributes,
                ftCreationTime: filetime(entry.created),
                ftLastAccessTime: filetime(entry.accessed),
                ftLastWriteTime: filetime(entry.modified),
                dwVolumeSerialNumber: 0x45564C54,
                nFileSizeHigh: (entry.size >> 32) as u32,
                nFileSizeLow: entry.size as u32,
                nNumberOfLinks: 1,
                nFileIndexHigh: (file_index(&entry) >> 32) as u32,
                nFileIndexLow: file_index(&entry) as u32,
            };
            Ok(())
        })
    }
}

unsafe extern "system" fn find(path: Name, fill: Fill, info: Info) -> i32 {
    unsafe {
        call(info, |fs, info| {
            let entries = fs.list(info.context, &name(path)?)?;
            for entry in entries {
                let mut data: WIN32_FIND_DATAW = std::mem::zeroed();
                data.dwFileAttributes = entry.attributes;
                data.ftCreationTime = filetime(entry.created);
                data.ftLastAccessTime = filetime(entry.accessed);
                data.ftLastWriteTime = filetime(entry.modified);
                data.nFileSizeHigh = (entry.size >> 32) as u32;
                data.nFileSizeLow = entry.size as u32;
                for (dst, src) in data.cFileName.iter_mut().zip(entry.name.encode_utf16()) {
                    *dst = src;
                }
                if fill(&mut data, info) != 0 {
                    break;
                }
            }
            Ok(())
        })
    }
}

unsafe extern "system" fn attributes(_: Name, attributes: u32, info: Info) -> i32 {
    unsafe {
        call(info, |fs, info| {
            if attributes & (0x400 | 0x4000) != 0 {
                return Err(VaultError::Access);
            }
            fs.metadata(info.context, Some(attributes), None, None, None)
        })
    }
}

unsafe fn time_value(pointer: *const FILETIME) -> Option<u64> {
    let t = unsafe { pointer.as_ref() }?;
    let value = (t.dwHighDateTime as u64) << 32 | t.dwLowDateTime as u64;
    if value == 0 || value == u64::MAX {
        None
    } else {
        Some(value)
    }
}

unsafe extern "system" fn times(
    _: Name,
    creation: *const FILETIME,
    access: *const FILETIME,
    write: *const FILETIME,
    info: Info,
) -> i32 {
    unsafe {
        call(info, |fs, info| {
            fs.metadata(
                info.context,
                None,
                time_value(creation),
                time_value(access),
                time_value(write),
            )
        })
    }
}
unsafe extern "system" fn delete_file(_: Name, info: Info) -> i32 {
    unsafe {
        call(info, |fs, info| {
            fs.set_delete_disposition(info.context, false, info.delete_pending != 0)
        })
    }
}
unsafe extern "system" fn delete_directory(_: Name, info: Info) -> i32 {
    unsafe {
        call(info, |fs, info| {
            fs.set_delete_disposition(info.context, true, info.delete_pending != 0)
        })
    }
}
unsafe extern "system" fn move_file(_: Name, target: Name, replace: i32, info: Info) -> i32 {
    unsafe {
        call(info, |fs, info| {
            fs.rename(info.context, &name(target)?, replace != 0)
        })
    }
}
unsafe extern "system" fn end_of_file(_: Name, length: i64, info: Info) -> i32 {
    if length < 0 {
        return INVALID_PARAMETER;
    }
    unsafe { call(info, |fs, info| fs.truncate(info.context, length as u64)) }
}
unsafe extern "system" fn allocation(_: Name, length: i64, info: Info) -> i32 {
    if length < 0 || length as u64 > crate::crypto::MAX_FILE_SIZE {
        return INVALID_PARAMETER;
    }
    unsafe {
        call(info, |fs, info| {
            // Allocation cannot expose data or change EOF when growing a sparse file.
            if (length as u64) < fs.information(info.context, "")?.size {
                fs.truncate(info.context, length as u64)?;
            }
            Ok(())
        })
    }
}
unsafe extern "system" fn free_space(
    available: *mut u64,
    total: *mut u64,
    free: *mut u64,
    info: Info,
) -> i32 {
    if available.is_null() || total.is_null() || free.is_null() {
        return INVALID_PARAMETER;
    }
    unsafe {
        call(info, |fs, _| {
            let path = fs.backing_path()?;
            *available = fs2::available_space(&path)?;
            *total = fs2::total_space(&path)?;
            *free = fs2::free_space(&path)?;
            Ok(())
        })
    }
}

unsafe fn copy_text(buffer: *mut u16, capacity: u32, value: &str) -> Result<()> {
    let text = wide(value);
    if buffer.is_null() || (capacity as usize) < text.len() {
        return Err(VaultError::TooLarge);
    }
    unsafe {
        ptr::copy_nonoverlapping(text.as_ptr(), buffer, text.len());
    }
    Ok(())
}
unsafe extern "system" fn volume(
    label: *mut u16,
    label_size: u32,
    serial: *mut u32,
    component: *mut u32,
    flags: *mut u32,
    fs_name: *mut u16,
    fs_size: u32,
    info: Info,
) -> i32 {
    if serial.is_null() || component.is_null() || flags.is_null() {
        return INVALID_PARAMETER;
    }
    unsafe {
        call(info, |_, _| {
            copy_text(label, label_size, "Encrypted Vault")?;
            copy_text(fs_name, fs_size, "EVault")?;
            *serial = 0x45564C54;
            *component = 255;
            *flags = 2 | 4;
            Ok(())
        })
    }
}
unsafe extern "system" fn mounted(_: Name, _: Info) -> i32 {
    SUCCESS
}
unsafe extern "system" fn unmounted(_: Info) -> i32 {
    SUCCESS
}
unsafe extern "system" fn security(
    _: Name,
    _: *mut u32,
    _: *mut c_void,
    _: u32,
    _: *mut u32,
    _: Info,
) -> i32 {
    NOT_IMPLEMENTED
}

pub fn operations() -> Operations {
    Operations {
        create: Some(create),
        cleanup: Some(cleanup),
        close: Some(close),
        read: Some(read),
        write: Some(write),
        flush: Some(flush),
        information: Some(information),
        find: Some(find),
        attributes: Some(attributes),
        times: Some(times),
        delete_file: Some(delete_file),
        delete_directory: Some(delete_directory),
        move_file: Some(move_file),
        end_of_file: Some(end_of_file),
        allocation: Some(allocation),
        free_space: Some(free_space),
        volume: Some(volume),
        mounted: Some(mounted),
        unmounted: Some(unmounted),
        get_security: Some(security),
        ..Operations::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
    static REMOVE_RESULT: AtomicI32 = AtomicI32::new(0);
    static WAIT_RESULT: AtomicU32 = AtomicU32::new(258);
    static CLOSE_COUNT: AtomicU32 = AtomicU32::new(0);
    unsafe extern "system" fn fake_create(
        _: *mut Options,
        _: *mut Operations,
        _: *mut *mut c_void,
    ) -> i32 {
        -1
    }
    unsafe extern "system" fn fake_remove(_: Name) -> i32 {
        REMOVE_RESULT.load(Ordering::SeqCst)
    }
    unsafe extern "system" fn fake_wait(_: *mut c_void, _: u32) -> u32 {
        WAIT_RESULT.load(Ordering::SeqCst)
    }
    unsafe extern "system" fn fake_close(_: *mut c_void) {
        CLOSE_COUNT.fetch_add(1, Ordering::SeqCst);
    }
    unsafe extern "system" fn fake_shutdown() {}

    #[test]
    fn lock_retains_keys_on_failure_and_waits_for_unmount_acknowledgement() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("vault");
        let context = Box::new(Context {
            fs: Mutex::new(FileSystem::new(
                Store::create(&path, "unmount fixture password").unwrap(),
            )),
        });
        let options = Box::new(unsafe { std::mem::zeroed() });
        let runtime = Arc::new(Runtime {
            module: ptr::null_mut(),
            create: fake_create,
            remove: fake_remove,
            wait: fake_wait,
            close: fake_close,
            shutdown: fake_shutdown,
        });
        let mut mount = Mount {
            runtime,
            context,
            _options: options,
            _operations: Box::new(operations()),
            mount_point: wide("V:\\"),
            handle: ptr::dangling_mut(),
            letter: 'V',
        };
        assert!(mount.lock().is_err());
        assert_eq!(mount.context.fs.lock().unwrap().phase(), Phase::Active);
        assert!(matches!(
            Store::open(&path, "unmount fixture password"),
            Err(VaultError::WriterBusy)
        ));
        REMOVE_RESULT.store(1, Ordering::SeqCst);
        assert!(mount.lock().is_err());
        assert_eq!(mount.context.fs.lock().unwrap().phase(), Phase::Quiescing);
        assert_eq!(CLOSE_COUNT.load(Ordering::SeqCst), 0);
        WAIT_RESULT.store(0, Ordering::SeqCst);
        mount.lock().unwrap();
        assert_eq!(CLOSE_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(mount.context.fs.lock().unwrap().phase(), Phase::Closed);
        Store::open(&path, "unmount fixture password").unwrap();
    }

    #[test]
    fn callbacks_operate_without_a_runtime_or_mount() {
        let temp = tempfile::tempdir().unwrap();
        let context = Box::new(Context {
            fs: Mutex::new(FileSystem::new(
                Store::create(&temp.path().join("vault"), "callback fixture password").unwrap(),
            )),
        });
        let mut options: Box<Options> = Box::new(unsafe { std::mem::zeroed() });
        options.global_context = (&*context as *const Context) as u64;
        let mut info: FileInfo = unsafe { std::mem::zeroed() };
        info.options = &mut *options;
        let ops = operations();
        let path = wide("\\document.txt");
        let target = wide("\\renamed.txt");
        unsafe {
            assert_eq!(
                ops.create.unwrap()(
                    path.as_ptr(),
                    ptr::null_mut(),
                    0xC0010000,
                    0,
                    7,
                    2,
                    0x40,
                    &mut info
                ),
                SUCCESS
            );
            assert_ne!(info.context, 0);
            let bytes = b"callback secret";
            let mut written = 0;
            assert_eq!(
                ops.write.unwrap()(
                    path.as_ptr(),
                    bytes.as_ptr() as _,
                    bytes.len() as u32,
                    &mut written,
                    1021,
                    &mut info
                ),
                SUCCESS
            );
            assert_eq!(written, bytes.len() as u32);
            assert_eq!(
                ops.move_file.unwrap()(path.as_ptr(), target.as_ptr(), 0, &mut info),
                SUCCESS
            );
            let mut buffer = [0; 15];
            let mut read_length = 0;
            assert_eq!(
                ops.read.unwrap()(
                    target.as_ptr(),
                    buffer.as_mut_ptr() as _,
                    15,
                    &mut read_length,
                    1021,
                    &mut info
                ),
                SUCCESS
            );
            assert_eq!(&buffer, bytes);
            assert_eq!(
                ops.read.unwrap()(
                    target.as_ptr(),
                    ptr::null_mut(),
                    15,
                    &mut read_length,
                    0,
                    &mut info
                ),
                INVALID_PARAMETER
            );
            assert_eq!(
                ops.end_of_file.unwrap()(target.as_ptr(), 4, &mut info),
                SUCCESS
            );
            let mut entry: BY_HANDLE_FILE_INFORMATION = std::mem::zeroed();
            assert_eq!(
                ops.information.unwrap()(target.as_ptr(), &mut entry, &mut info),
                SUCCESS
            );
            assert_eq!(entry.nFileSizeLow, 4);
            assert_eq!(ops.flush.unwrap()(target.as_ptr(), &mut info), SUCCESS);
            assert_eq!(
                ops.delete_file.unwrap()(target.as_ptr(), &mut info),
                SUCCESS
            );
            info.delete_pending = 1;
            ops.cleanup.unwrap()(target.as_ptr(), &mut info);
            ops.close.unwrap()(target.as_ptr(), &mut info);
            assert_eq!(info.context, 0);
        }
        let mut fs = context.fs.lock().unwrap();
        assert!(fs.list(0, "\\").unwrap().is_empty());
        fs.begin_lock().unwrap();
        fs.finish_lock().unwrap();
    }
}
