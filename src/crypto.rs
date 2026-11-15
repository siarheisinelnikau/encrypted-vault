use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use ring::hkdf;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Result, VaultError};

pub const FORMAT_VERSION: u32 = 1;
pub const CHUNK_SIZE: usize = 65_536;
pub const MAX_CATALOG: usize = 16 * 1024 * 1024;
pub const MAX_FILE_SIZE: u64 = 1 << 40;
pub const MAX_IO: usize = 16 * 1024 * 1024;
pub type Id = String;

pub fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes)
        .map_err(|_| VaultError::Io(std::io::Error::other("Secure randomness unavailable")))?;
    Ok(bytes)
}

pub fn new_id() -> Result<Id> {
    Ok(hex::encode(random::<16>()?))
}
pub fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicHeader {
    pub magic: String,
    pub version: u32,
    pub vault_id: Id,
    pub salt: [u8; 16],
    pub memory_kib: u32,
    pub passes: u32,
    pub lanes: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub public: PublicHeader,
    pub wrapped_key: Vec<u8>,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Keys {
    pub catalog: [u8; 32],
    pub chunks: [u8; 32],
}

impl Header {
    pub fn create(password: &str) -> Result<(Self, Keys)> {
        if password.chars().count() < 12 || password.len() > 1024 {
            return Err(VaultError::Access);
        }
        let public = PublicHeader {
            magic: "EncryptedVault".into(),
            version: FORMAT_VERSION,
            vault_id: new_id()?,
            salt: random()?,
            memory_kib: 65_536,
            passes: 3,
            lanes: 1,
        };
        let key = public.password_key(password)?;
        let master = Zeroizing::new(random::<32>()?);
        let aad = serde_json::to_vec(&public).map_err(|_| VaultError::Format)?;
        let wrapped_key = seal(&key, &aad, &master[..])?;
        let keys = expand(&master, &public.vault_id)?;
        Ok((
            Self {
                public,
                wrapped_key,
            },
            keys,
        ))
    }

    pub fn unlock(&self, password: &str) -> Result<Keys> {
        let key = self.public.password_key(password)?;
        let aad = serde_json::to_vec(&self.public).map_err(|_| VaultError::Format)?;
        let master = open(&key, &aad, &self.wrapped_key)?;
        let master: &[u8; 32] = master
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::Format)?;
        expand(master, &self.public.vault_id)
    }
}

impl PublicHeader {
    fn password_key(&self, password: &str) -> Result<Zeroizing<[u8; 32]>> {
        if self.magic != "EncryptedVault"
            || self.version != FORMAT_VERSION
            || !valid_id(&self.vault_id)
            || self.memory_kib != 65_536
            || self.passes != 3
            || self.lanes != 1
            || password.len() > 1024
        {
            return Err(VaultError::Format);
        }
        let params = Params::new(self.memory_kib, self.passes, self.lanes, Some(32))
            .map_err(|_| VaultError::Format)?;
        let mut key = Zeroizing::new([0; 32]);
        let mut memory = Zeroizing::new(vec![Block::default(); params.block_count()]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into_with_memory(
                password.as_bytes(),
                &self.salt,
                &mut *key,
                &mut *memory,
            )
            .map_err(|_| VaultError::Format)?;
        Ok(key)
    }
}

fn expand(master: &[u8; 32], vault_id: &str) -> Result<Keys> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, vault_id.as_bytes()).extract(master);
    let mut keys = Keys {
        catalog: [0; 32],
        chunks: [0; 32],
    };
    prk.expand(&[b"EncryptedVault/1/catalog"], hkdf::HKDF_SHA256)
        .map_err(|_| VaultError::Format)?
        .fill(&mut keys.catalog)
        .map_err(|_| VaultError::Format)?;
    prk.expand(&[b"EncryptedVault/1/chunks"], hkdf::HKDF_SHA256)
        .map_err(|_| VaultError::Format)?
        .fill(&mut keys.chunks)
        .map_err(|_| VaultError::Format)?;
    Ok(keys)
}

pub fn seal(key: &[u8; 32], aad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let nonce = random::<24>()?;
    let mut result = nonce.to_vec();
    result.extend(
        XChaCha20Poly1305::new(key.into())
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: data, aad })
            .map_err(|_| VaultError::Authentication)?,
    );
    Ok(result)
}

pub fn open(key: &[u8; 32], aad: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if data.len() < 40 {
        return Err(VaultError::Authentication);
    }
    XChaCha20Poly1305::new(key.into())
        .decrypt(
            XNonce::from_slice(&data[..24]),
            Payload {
                msg: &data[24..],
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| VaultError::Authentication)
}

pub fn aad(vault_id: &str, domain: &str, file_id: &str, index: u64, object_id: &str) -> Vec<u8> {
    format!("EncryptedVault/1/{vault_id}/{domain}/{file_id}/{index}/{object_id}").into_bytes()
}
