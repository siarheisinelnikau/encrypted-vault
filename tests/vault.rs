use encrypted_vault::{
    crypto::{CHUNK_SIZE, MAX_FILE_SIZE, MAX_IO},
    error::VaultError,
    filesystem::{DELETE, Disposition, FileSystem, OpenRequest, Phase, READ, SHARE_ALL, WRITE},
    store::{ROOT, Store},
};

const PASSWORD: &str = "A synthetic test password 2026!";

fn request(path: &str, disposition: Disposition, directory: bool) -> OpenRequest<'_> {
    OpenRequest {
        path,
        disposition,
        directory: Some(directory),
        access: READ | WRITE | DELETE,
        share: SHARE_ALL,
        attributes: 0,
        delete_on_close: false,
    }
}

#[test]
fn encrypted_random_access_reopen_and_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault");
    let mut store = Store::create(&path, PASSWORD).unwrap();
    let dir = store.create_entry("Private", true, 0).unwrap();
    let file = store
        .create_entry("Private\\Sensitive résumé.txt", false, 0)
        .unwrap();
    let payload: Vec<_> = (0..(CHUNK_SIZE * 2 + 113))
        .map(|i| (i % 251) as u8)
        .collect();
    store.write(&file, 317, &payload).unwrap();
    let expected = [vec![0; 317], payload].concat();
    assert_eq!(&*store.read(&file, 0, MAX_IO).unwrap(), &expected);
    store
        .write(&file, CHUNK_SIZE as u64 - 7, b"cross-chunk secret")
        .unwrap();
    assert_eq!(
        &*store.read(&file, CHUNK_SIZE as u64 - 7, 18).unwrap(),
        b"cross-chunk secret"
    );
    store.rename(&dir, "Renamed", false).unwrap();
    assert_eq!(
        store.resolve("RENAMED\\sensitive RÉSUMÉ.TXT").unwrap(),
        file
    );
    store.truncate(&file, 19).unwrap();
    store.truncate(&file, CHUNK_SIZE as u64 + 1).unwrap();
    assert!(
        store
            .read(&file, 19, CHUNK_SIZE)
            .unwrap()
            .iter()
            .all(|b| *b == 0)
    );
    store
        .set_metadata(&file, Some(2), Some(1234), Some(5678), Some(9999))
        .unwrap();
    let generation = store.generation();
    store.flush().unwrap();
    drop(store);
    let store = Store::open(&path, PASSWORD).unwrap();
    assert_eq!(store.generation(), generation);
    assert_eq!(store.entry(&file).unwrap().created, 1234);
    assert_eq!(store.entry(&file).unwrap().size, CHUNK_SIZE as u64 + 1);
    assert_eq!(store.list(ROOT).unwrap().len(), 1);
    drop(store);
    for entry in std::fs::read_dir(&path)
        .unwrap()
        .chain(std::fs::read_dir(path.join("objects")).unwrap())
    {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            let bytes = std::fs::read(entry.path()).unwrap();
            assert!(!bytes.windows(b"Sensitive".len()).any(|w| w == b"Sensitive"));
            assert!(
                !bytes
                    .windows(b"cross-chunk secret".len())
                    .any(|w| w == b"cross-chunk secret")
            );
        }
    }
}

#[test]
fn wrong_password_tamper_truncation_and_bounds() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault");
    let mut store = Store::create(&path, PASSWORD).unwrap();
    let file = store.create_entry("test.txt", false, 0).unwrap();
    store.write(&file, 0, b"secret").unwrap();
    assert!(matches!(
        store.write(&file, MAX_FILE_SIZE, &[1]),
        Err(VaultError::TooLarge)
    ));
    assert!(matches!(
        store.read(&file, 0, MAX_IO + 1),
        Err(VaultError::TooLarge)
    ));
    assert!(matches!(
        Store::open(&path, PASSWORD),
        Err(VaultError::WriterBusy)
    ));
    let object = store.entry(&file).unwrap().chunks.get(&0).unwrap().clone();
    let object_path = path.join("objects").join(object);
    let good = std::fs::read(&object_path).unwrap();
    let mut damaged = good.clone();
    damaged[100] ^= 1;
    std::fs::write(&object_path, &damaged).unwrap();
    assert!(matches!(
        store.read(&file, 0, 6),
        Err(VaultError::Authentication)
    ));
    std::fs::write(&object_path, &good[..100]).unwrap();
    assert!(matches!(
        store.read(&file, 0, 6),
        Err(VaultError::Authentication)
    ));
    drop(store);
    assert!(matches!(
        Store::open(&path, "incorrect password"),
        Err(VaultError::Authentication)
    ));
    let catalog_path = path.join("catalog.ev");
    let mut bytes = std::fs::read(&catalog_path).unwrap();
    bytes[50] ^= 1;
    std::fs::write(&catalog_path, bytes).unwrap();
    assert!(matches!(
        Store::open(&path, PASSWORD),
        Err(VaultError::Authentication)
    ));
}

#[test]
fn provider_handles_sharing_paging_rename_delete_and_lock() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault");
    let mut fs = FileSystem::new(Store::create(&path, PASSWORD).unwrap());
    let (h, _, _) = fs
        .open(request("draft.txt", Disposition::Create, false))
        .unwrap();
    fs.write(h, Some(0), b"draft", false).unwrap();
    fs.rename(h, "final.txt", false).unwrap();
    let (h2, _, _) = fs
        .open(request("FINAL.txt", Disposition::Open, false))
        .unwrap();
    assert_eq!(&*fs.read(h2, 0, 100).unwrap(), b"draft");
    assert!(matches!(fs.begin_lock(), Err(VaultError::OpenHandles)));
    assert_eq!(fs.phase(), Phase::Active);
    fs.cleanup(h, false).unwrap();
    assert_eq!(fs.write(h, Some(4), b"tXXXX", true).unwrap(), 1);
    fs.close(h).unwrap();
    let mut exclusive = request("final.txt", Disposition::Open, false);
    exclusive.share = 0;
    assert!(matches!(fs.open(exclusive), Err(VaultError::Sharing)));
    fs.can_delete(h2, false).unwrap();
    fs.cleanup(h2, true).unwrap();
    assert!(matches!(
        fs.open(request("final.txt", Disposition::Open, false)),
        Err(VaultError::DeletePending)
    ));
    assert!(matches!(fs.begin_lock(), Err(VaultError::OpenHandles)));
    fs.close(h2).unwrap();
    assert!(fs.list(0, "\\").unwrap().is_empty());
    fs.begin_lock().unwrap();
    assert!(matches!(
        fs.open(request("new", Disposition::Create, false)),
        Err(VaultError::Locked)
    ));
    fs.cancel_lock();
    fs.begin_lock().unwrap();
    fs.finish_lock().unwrap();
    assert_eq!(fs.phase(), Phase::Closed);
    assert!(
        Store::open(&path, PASSWORD)
            .unwrap()
            .list(ROOT)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn windows_paths_and_directory_safety() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::create(&temp.path().join("vault"), PASSWORD).unwrap();
    for path in [
        "..",
        "a\\..\\b",
        "a:b",
        "CON",
        "nul.txt",
        "a.",
        "a ",
        "a/b",
        "\\\\server\\x",
        "a\\\\b",
    ] {
        assert!(
            matches!(
                store.create_entry(path, false, 0),
                Err(VaultError::InvalidPath)
            ),
            "{path}"
        );
    }
    let dir = store.create_entry("a", true, 0).unwrap();
    store.create_entry("a\\b", true, 0).unwrap();
    assert!(matches!(
        store.rename(&dir, "a\\b\\c", false),
        Err(VaultError::InvalidPath)
    ));
    assert!(matches!(store.remove(&dir), Err(VaultError::NotEmpty)));
    assert!(matches!(
        store.create_entry("A", false, 0),
        Err(VaultError::Exists)
    ));
}

#[test]
fn deterministic_random_writes_truncations_and_concurrent_appends() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault");
    let mut store = Store::create(&path, PASSWORD).unwrap();
    let id = store.create_entry("random.bin", false, 0).unwrap();
    let mut expected = Vec::new();
    let mut seed = 20261115u64;
    let mut next = || {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        seed
    };
    for step in 0..100 {
        let offset = (next() % (CHUNK_SIZE as u64 * 3)) as usize;
        if step % 7 == 0 {
            store.truncate(&id, offset as u64).unwrap();
            expected.resize(offset, 0);
        } else {
            let len = (next() % 5000 + 1) as usize;
            let bytes = vec![(next() % 251) as u8; len];
            store.write(&id, offset as u64, &bytes).unwrap();
            if expected.len() < offset + len {
                expected.resize(offset + len, 0);
            }
            expected[offset..offset + len].copy_from_slice(&bytes);
        }
        if step % 10 == 0 {
            assert_eq!(&*store.read(&id, 0, MAX_IO).unwrap(), &expected);
        }
    }
    drop(store);
    let store = Store::open(&path, PASSWORD).unwrap();
    assert_eq!(&*store.read(&id, 0, MAX_IO).unwrap(), &expected);
    let mut fs = FileSystem::new(store);
    let (h1, _, _) = fs
        .open(request("append.txt", Disposition::Create, false))
        .unwrap();
    let (h2, _, _) = fs
        .open(request("append.txt", Disposition::Open, false))
        .unwrap();
    let shared = std::sync::Arc::new(std::sync::Mutex::new(fs));
    let threads: Vec<_> = [(h1, 11u8), (h2, 22u8)]
        .into_iter()
        .map(|(h, byte)| {
            let shared = shared.clone();
            std::thread::spawn(move || {
                for _ in 0..16 {
                    shared
                        .lock()
                        .unwrap()
                        .write(h, None, &[byte; 8], false)
                        .unwrap();
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    let mut fs = shared.lock().unwrap();
    let data = fs.read(h1, 0, MAX_IO).unwrap();
    assert_eq!(data.len(), 256);
    assert_eq!(data.chunks_exact(8).filter(|c| *c == [11; 8]).count(), 16);
    assert_eq!(data.chunks_exact(8).filter(|c| *c == [22; 8]).count(), 16);
    for h in [h1, h2] {
        fs.cleanup(h, false).unwrap();
        fs.close(h).unwrap();
    }
    fs.begin_lock().unwrap();
    fs.finish_lock().unwrap();
}

#[test]
fn directory_delete_reservation_can_be_cancelled() {
    let temp = tempfile::tempdir().unwrap();
    let mut fs = FileSystem::new(Store::create(&temp.path().join("vault"), PASSWORD).unwrap());
    let (dir, _, _) = fs
        .open(request("folder", Disposition::Create, true))
        .unwrap();
    fs.set_delete_disposition(dir, true, true).unwrap();
    assert!(matches!(
        fs.open(request("folder\\child", Disposition::Create, false)),
        Err(VaultError::DeletePending)
    ));
    fs.set_delete_disposition(dir, true, false).unwrap();
    let (child, _, _) = fs
        .open(request("folder\\child", Disposition::Create, false))
        .unwrap();
    assert!(matches!(
        fs.set_delete_disposition(dir, true, true),
        Err(VaultError::NotEmpty)
    ));
    fs.set_delete_disposition(child, false, true).unwrap();
    fs.cleanup(child, true).unwrap();
    fs.close(child).unwrap();
    fs.set_delete_disposition(dir, true, true).unwrap();
    fs.cleanup(dir, true).unwrap();
    fs.close(dir).unwrap();
    assert!(fs.list(0, "\\").unwrap().is_empty());
    fs.begin_lock().unwrap();
    fs.finish_lock().unwrap();
}
