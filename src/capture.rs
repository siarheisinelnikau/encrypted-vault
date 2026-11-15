//! A small PNG encoder for bounded capture of the application's real GDI client area.
use crate::{
    crypto,
    error::{Result, VaultError},
    store::{atomic_replace, write_new},
};
use std::path::Path;

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= *byte as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0xedb88320 } else { 0 };
        }
    }
    !crc
}
fn chunk(output: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    output.extend_from_slice(&(data.len() as u32).to_be_bytes());
    let start = output.len();
    output.extend_from_slice(kind);
    output.extend_from_slice(data);
    output.extend_from_slice(&crc32(&output[start..]).to_be_bytes());
}
pub fn encode_rgba(width: u32, height: u32, rgba: &[u8]) -> Result<Vec<u8>> {
    if width == 0
        || height == 0
        || width > 4096
        || height > 4096
        || rgba.len() != width as usize * height as usize * 4
    {
        return Err(VaultError::TooLarge);
    }
    let mut scanlines = Vec::with_capacity(rgba.len() + height as usize);
    for row in rgba.chunks_exact(width as usize * 4) {
        scanlines.push(0);
        scanlines.extend_from_slice(row);
    }
    // RFC 1950/1951 zlib stream with bounded uncompressed DEFLATE blocks.
    let mut zlib = vec![0x78, 0x01];
    let blocks = scanlines.chunks(65535);
    let count = blocks.len();
    for (index, block) in blocks.enumerate() {
        zlib.push(if index + 1 == count { 1 } else { 0 });
        let n = block.len() as u16;
        zlib.extend_from_slice(&n.to_le_bytes());
        zlib.extend_from_slice(&(!n).to_le_bytes());
        zlib.extend_from_slice(block);
    }
    let (mut a, mut b) = (1u32, 0u32);
    for byte in &scanlines {
        a = (a + *byte as u32) % 65521;
        b = (b + a) % 65521;
    }
    zlib.extend_from_slice(&((b << 16) | a).to_be_bytes());
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);
    chunk(&mut png, b"IHDR", &ihdr);
    chunk(&mut png, b"IDAT", &zlib);
    chunk(&mut png, b"IEND", &[]);
    Ok(png)
}
pub fn save_png(path: &Path, width: u32, height: u32, rgba: &[u8]) -> Result<()> {
    if !path.is_absolute() || path.exists() {
        return Err(VaultError::InvalidPath);
    }
    let parent = path.parent().ok_or(VaultError::InvalidPath)?;
    let pending = parent.join(format!("capture-{}.pending", crypto::new_id()?));
    write_new(&pending, &encode_rgba(width, height, rgba)?)?;
    atomic_replace(&pending, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn png_has_valid_chunks_and_bounds() {
        let png = encode_rgba(2, 1, &[255, 0, 0, 255, 0, 255, 0, 255]).unwrap();
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
        let mut at = 8;
        while at < png.len() {
            let n = u32::from_be_bytes(png[at..at + 4].try_into().unwrap()) as usize;
            assert_eq!(
                crc32(&png[at + 4..at + 8 + n]),
                u32::from_be_bytes(png[at + 8 + n..at + 12 + n].try_into().unwrap())
            );
            at += 12 + n;
        }
        assert_eq!(at, png.len());
        assert!(encode_rgba(4097, 1, &[]).is_err());
    }
}
