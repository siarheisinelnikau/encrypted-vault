//! Background drive controller. This module never draws or owns a native window.
use crate::{
    dokan::Mount,
    error::{Result, VaultError},
    i18n::error_key,
    preferences::Preferences,
    store::{Store, check_backing_path},
    updates,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::{
        Arc,
        mpsc::{self, Receiver, SyncSender},
    },
    time::Duration,
};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct Snapshot {
    pub preferences: Preferences,
    pub mounted: BTreeMap<PathBuf, char>,
}
pub enum Event {
    Finished {
        snapshot: Snapshot,
        message: &'static str,
        error: bool,
    },
    UpdateChecked(Result<Option<updates::Available>>, bool),
    DownloadProgress(u8),
    Downloaded(Result<updates::Staged>),
    QuitAllowed,
}
pub enum Command {
    Create {
        path: PathBuf,
        alias: String,
        password: Zeroizing<String>,
        letter: char,
    },
    Remember {
        path: PathBuf,
        alias: String,
    },
    Unlock {
        path: PathBuf,
        password: Zeroizing<String>,
        letter: char,
    },
    Lock(PathBuf),
    LockAll,
    Save(Preferences),
    Forget(PathBuf),
    Quit,
}
pub struct Backend {
    pub commands: SyncSender<Command>,
    pub events: Receiver<Event>,
    pub emitter: Emitter,
}
#[derive(Clone)]
pub struct Emitter {
    sender: mpsc::Sender<Event>,
    wake: Arc<dyn Fn() + Send + Sync>,
}
impl Emitter {
    pub fn send(&self, event: Event) {
        if self.sender.send(event).is_ok() {
            (self.wake)();
        }
    }
}

struct Controller {
    preferences: Preferences,
    settings: PathBuf,
    mounts: BTreeMap<PathBuf, Mount>,
}
impl Controller {
    fn snapshot(&self) -> Snapshot {
        Snapshot {
            preferences: self.preferences.clone(),
            mounted: self
                .mounts
                .iter()
                .map(|(p, m)| (p.clone(), m.letter()))
                .collect(),
        }
    }
    fn save(&self) -> Result<()> {
        self.preferences.save(&self.settings)
    }
    fn canonical(path: PathBuf) -> Result<PathBuf> {
        check_backing_path(&path)?;
        Ok(std::fs::canonicalize(path)?)
    }
    fn alias(alias: &str) -> Result<()> {
        if alias.trim().is_empty() || alias.chars().count() > 80 {
            Err(VaultError::InvalidPath)
        } else {
            Ok(())
        }
    }
    fn lock_all(&mut self) -> Result<()> {
        let mut closed = Vec::new();
        let mut failure = None;
        for (path, mount) in &mut self.mounts {
            match mount.lock() {
                Ok(()) => closed.push(path.clone()),
                Err(e) => {
                    if failure.is_none() {
                        failure = Some(e)
                    }
                }
            }
        }
        for path in closed {
            self.mounts.remove(&path);
        }
        failure.map_or(Ok(()), Err)
    }
    fn execute(&mut self, command: Command) -> Result<&'static str> {
        match command {
            Command::Create {
                path,
                alias,
                password,
                letter,
            } => {
                Self::alias(&alias)?;
                if !path.is_absolute() || self.preferences.vaults.len() >= 100 {
                    return Err(VaultError::InvalidPath);
                }
                let store = Store::create(&path, &password)?;
                let path = store.root_path().to_path_buf();
                self.preferences.remember(path.clone(), alias)?;
                self.save()?;
                match Mount::start(store, letter) {
                    Ok(mount) => {
                        self.mounts.insert(path, mount);
                        Ok("unlocked_notice")
                    }
                    Err(e) => Err(e), // The newly created encrypted vault remains in the list, locked.
                }
            }
            Command::Remember { path, alias } => {
                Self::alias(&alias)?;
                let path = Self::canonical(path)?;
                if !path.join("header.json").is_file() || !path.join("catalog.ev").is_file() {
                    return Err(VaultError::NotFound);
                }
                self.preferences.remember(path, alias)?;
                self.save()?;
                Ok("added")
            }
            Command::Unlock {
                path,
                password,
                letter,
            } => {
                let path = Self::canonical(path)?;
                if self.mounts.contains_key(&path) {
                    return Err(VaultError::WriterBusy);
                }
                let store = Store::open(&path, &password)?;
                let mount = Mount::start(store, letter)?;
                self.mounts.insert(path, mount);
                Ok("unlocked_notice")
            }
            Command::Lock(path) => {
                let mount = self.mounts.get_mut(&path).ok_or(VaultError::Locked)?;
                mount.lock()?;
                self.mounts.remove(&path);
                Ok("locked_notice")
            }
            Command::LockAll | Command::Quit => {
                self.lock_all()?;
                Ok("locked_notice")
            }
            Command::Save(mut p) => {
                p.vaults = self.preferences.vaults.clone();
                self.preferences = p;
                self.save()?;
                Ok("saved")
            }
            Command::Forget(path) => {
                if self.mounts.contains_key(&path) {
                    return Err(VaultError::OpenHandles);
                }
                self.preferences.vaults.retain(|v| v.path != path);
                self.save()?;
                Ok("forgotten")
            }
        }
    }
}

impl Backend {
    pub fn start(
        preferences: Preferences,
        settings: PathBuf,
        wake: impl Fn() + Send + Sync + 'static,
    ) -> Self {
        let (commands, receiver) = mpsc::sync_channel(16);
        let (sender, events) = mpsc::channel();
        let emitter = Emitter {
            sender,
            wake: Arc::new(wake),
        };
        let worker = emitter.clone();
        std::thread::Builder::new()
            .name("vault-filesystem".into())
            .spawn(move || {
                let mut controller = Controller {
                    preferences,
                    settings,
                    mounts: BTreeMap::new(),
                };
                let mut idle_warned = BTreeSet::new();
                loop {
                    let command = if controller.preferences.idle_minutes == 0
                        || controller.mounts.is_empty()
                    {
                        match receiver.recv() {
                            Ok(c) => Some(c),
                            Err(_) => break,
                        }
                    } else {
                        match receiver.recv_timeout(Duration::from_secs(30)) {
                            Ok(c) => Some(c),
                            Err(mpsc::RecvTimeoutError::Timeout) => None,
                            Err(_) => break,
                        }
                    };
                    if let Some(command) = command {
                        let quit = matches!(command, Command::Quit);
                        let result = controller.execute(command);
                        let success = result.is_ok();
                        let (message, error) =
                            result.map_or_else(|e| (error_key(&e), true), |m| (m, false));
                        worker.send(Event::Finished {
                            snapshot: controller.snapshot(),
                            message,
                            error,
                        });
                        if quit && success {
                            worker.send(Event::QuitAllowed);
                            break;
                        }
                    } else {
                        let threshold =
                            Duration::from_secs(controller.preferences.idle_minutes as u64 * 60);
                        let candidates: Vec<_> = controller
                            .mounts
                            .iter()
                            .filter_map(|(path, mount)| {
                                if mount.idle_for().is_ok_and(|d| d >= threshold) {
                                    if !idle_warned.contains(path) {
                                        Some(path.clone())
                                    } else {
                                        None
                                    }
                                } else {
                                    idle_warned.remove(path);
                                    None
                                }
                            })
                            .collect();
                        for path in candidates {
                            let result = controller.execute(Command::Lock(path.clone()));
                            if result.is_err() {
                                idle_warned.insert(path);
                            }
                            let (message, error) =
                                result.map_or_else(|e| (error_key(&e), true), |m| (m, false));
                            worker.send(Event::Finished {
                                snapshot: controller.snapshot(),
                                message,
                                error,
                            });
                        }
                    }
                }
            })
            .expect("start filesystem worker");
        Self {
            commands,
            events,
            emitter,
        }
    }
    pub fn check_updates(&self, silent: bool) {
        let emitter = self.emitter.clone();
        std::thread::Builder::new()
            .name("vault-release-check".into())
            .spawn(move || emitter.send(Event::UpdateChecked(updates::check(), silent)))
            .expect("start update worker");
    }
    pub fn download(&self, available: updates::Available, target: PathBuf) {
        let emitter = self.emitter.clone();
        std::thread::Builder::new()
            .name("vault-download".into())
            .spawn(move || {
                let result = updates::download(&available, &target, |p| {
                    emitter.send(Event::DownloadProgress(p))
                });
                emitter.send(Event::Downloaded(result));
            })
            .expect("start download worker");
    }
}
