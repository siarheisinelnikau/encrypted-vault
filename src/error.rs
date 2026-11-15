use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("The password is incorrect or encrypted data was changed")]
    Authentication,
    #[error("The vault format is damaged, unsupported, or exceeds safe limits")]
    Format,
    #[error("Another writer already has this vault open")]
    WriterBusy,
    #[error("The path or name is not valid on this drive")]
    InvalidPath,
    #[error("The file or folder does not exist")]
    NotFound,
    #[error("A file or folder with this name already exists")]
    Exists,
    #[error("This operation requires a folder")]
    NotDirectory,
    #[error("This operation requires a file")]
    IsDirectory,
    #[error("The folder is not empty")]
    NotEmpty,
    #[error("The file is open with incompatible sharing permissions")]
    Sharing,
    #[error("The file is waiting to be deleted")]
    DeletePending,
    #[error("Close files and Explorer windows using this drive, then try again")]
    OpenHandles,
    #[error("The drive is locking or locked")]
    Locked,
    #[error("The requested operation is not permitted")]
    Access,
    #[error("The request exceeds the supported size")]
    TooLarge,
    #[error("The filesystem runtime is unavailable: {0}")]
    Runtime(String),
    #[error("The filesystem could not be mounted or safely disconnected: {0}")]
    Mount(String),
    #[error("An update could not be completed: {0}")]
    Update(String),
    #[error("Storage error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, VaultError>;
