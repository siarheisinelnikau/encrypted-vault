//! Dokany 2.3.1 C ABI, independently declared from the public API documentation.
//! Reference: dokan-dev/dokany dokan/dokan.h blob bc272fd1856143a75583d2b13cef4e360a6211f3.
use std::ffi::c_void;
use windows_sys::Win32::{
    Foundation::FILETIME,
    Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, WIN32_FIND_DATAW},
};

#[repr(C)]
pub struct Options {
    pub version: u16,
    pub single_thread: u8,
    pub options: u32,
    pub global_context: u64,
    pub mount_point: *const u16,
    pub unc_name: *const u16,
    pub timeout: u32,
    pub allocation_unit_size: u32,
    pub sector_size: u32,
    pub volume_security_descriptor_length: u32,
    pub volume_security_descriptor: [u8; 16384],
}
#[repr(C)]
pub struct FileInfo {
    pub context: u64,
    pub dokan_context: u64,
    pub options: *mut Options,
    pub processing_context: *mut c_void,
    pub process_id: u32,
    pub is_directory: u8,
    pub delete_pending: u8,
    pub paging_io: u8,
    pub synchronous_io: u8,
    pub nocache: u8,
    pub write_to_end_of_file: u8,
}
pub type Status = i32;
pub type Info = *mut FileInfo;
pub type Name = *const u16;
pub type Fill = unsafe extern "system" fn(*mut WIN32_FIND_DATAW, Info) -> i32;
pub type Named = unsafe extern "system" fn(Name, Info) -> Status;
pub type EndOfFile = unsafe extern "system" fn(Name, i64, Info) -> Status;
pub type Security = unsafe extern "system" fn(Name, *mut u32, *mut c_void, u32, Info) -> Status;

#[repr(C)]
#[derive(Default)]
pub struct Operations {
    pub create: Option<
        unsafe extern "system" fn(Name, *mut c_void, u32, u32, u32, u32, u32, Info) -> Status,
    >,
    pub cleanup: Option<unsafe extern "system" fn(Name, Info)>,
    pub close: Option<unsafe extern "system" fn(Name, Info)>,
    pub read:
        Option<unsafe extern "system" fn(Name, *mut c_void, u32, *mut u32, i64, Info) -> Status>,
    pub write:
        Option<unsafe extern "system" fn(Name, *const c_void, u32, *mut u32, i64, Info) -> Status>,
    pub flush: Option<Named>,
    pub information:
        Option<unsafe extern "system" fn(Name, *mut BY_HANDLE_FILE_INFORMATION, Info) -> Status>,
    pub find: Option<unsafe extern "system" fn(Name, Fill, Info) -> Status>,
    pub find_pattern: Option<unsafe extern "system" fn(Name, Name, Fill, Info) -> Status>,
    pub attributes: Option<unsafe extern "system" fn(Name, u32, Info) -> Status>,
    pub times: Option<
        unsafe extern "system" fn(
            Name,
            *const FILETIME,
            *const FILETIME,
            *const FILETIME,
            Info,
        ) -> Status,
    >,
    pub delete_file: Option<Named>,
    pub delete_directory: Option<Named>,
    pub move_file: Option<unsafe extern "system" fn(Name, Name, i32, Info) -> Status>,
    pub end_of_file: Option<EndOfFile>,
    pub allocation: Option<EndOfFile>,
    pub lock: Option<unsafe extern "system" fn(Name, i64, i64, Info) -> Status>,
    pub unlock: Option<unsafe extern "system" fn(Name, i64, i64, Info) -> Status>,
    pub free_space: Option<unsafe extern "system" fn(*mut u64, *mut u64, *mut u64, Info) -> Status>,
    pub volume: Option<
        unsafe extern "system" fn(
            *mut u16,
            u32,
            *mut u32,
            *mut u32,
            *mut u32,
            *mut u16,
            u32,
            Info,
        ) -> Status,
    >,
    pub mounted: Option<Named>,
    pub unmounted: Option<unsafe extern "system" fn(Info) -> Status>,
    pub get_security: Option<
        unsafe extern "system" fn(Name, *mut u32, *mut c_void, u32, *mut u32, Info) -> Status,
    >,
    pub set_security: Option<Security>,
    pub streams:
        Option<unsafe extern "system" fn(Name, *const c_void, *mut c_void, Info) -> Status>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[cfg(target_pointer_width = "64")]
    fn public_x64_layout() {
        assert_eq!(std::mem::size_of::<Options>(), 16432);
        assert_eq!(std::mem::offset_of!(Options, global_context), 8);
        assert_eq!(
            std::mem::offset_of!(Options, volume_security_descriptor),
            48
        );
        assert_eq!(std::mem::size_of::<FileInfo>(), 48);
        assert_eq!(std::mem::offset_of!(FileInfo, is_directory), 36);
        assert_eq!(std::mem::size_of::<Operations>(), 25 * 8);
        assert_eq!(std::mem::offset_of!(Operations, mounted), 20 * 8);
    }
}
