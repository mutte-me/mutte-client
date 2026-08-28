//! Streaming, resumable client-side attachment encryption and local downloads.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use directories::ProjectDirs;
use mutte_protocol::{
    ATTACHMENT_CHUNK_BYTES, ATTACHMENT_CHUNK_OVERHEAD, ATTACHMENT_VERSION, AttachmentMetadata,
    MAX_ATTACHMENT_BYTES, MAX_ATTACHMENT_CHUNKS,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

const ATTACHMENT_AAD_DOMAIN: &[u8] = b"mutte attachment chunk v1\0";
const MAX_FILENAME_BYTES: usize = 255;

pub struct PreparedAttachment {
    pub source_path: PathBuf,
    pub metadata: AttachmentMetadata,
}

pub fn prepare(path: &Path) -> Result<PreparedAttachment> {
    let source_path = fs::canonicalize(path).context("resolve attachment path")?;
    let file_metadata = fs::metadata(&source_path).context("inspect attachment")?;
    if !file_metadata.is_file() {
        bail!("attachment must be a regular file")
    }
    if file_metadata.len() > MAX_ATTACHMENT_BYTES {
        bail!("attachment exceeds the 32 MiB alpha limit")
    }
    let filename = source_path
        .file_name()
        .and_then(|name| name.to_str())
        .context("attachment filename must be valid UTF-8")?
        .to_owned();
    validate_filename(&filename)?;
    let plaintext_size = file_metadata.len();
    let chunk_count = chunk_count(plaintext_size)?;
    let plaintext_hash = hash_file(&source_path)?;
    let file_key = Zeroizing::new(rand::random::<[u8; 32]>());
    Ok(PreparedAttachment {
        source_path,
        metadata: AttachmentMetadata {
            version: ATTACHMENT_VERSION,
            attachment_id: Uuid::new_v4(),
            filename,
            plaintext_size,
            chunk_count,
            file_key: URL_SAFE_NO_PAD.encode(*file_key),
            plaintext_hash,
        },
    })
}

pub fn validate_source(path: &Path, metadata: &AttachmentMetadata) -> Result<()> {
    validate_metadata(metadata)?;
    let file_metadata = fs::metadata(path).context("attachment source is unavailable")?;
    if !file_metadata.is_file() || file_metadata.len() != metadata.plaintext_size {
        bail!("attachment source changed since it was queued")
    }
    if hash_file(path)? != metadata.plaintext_hash {
        bail!("attachment source changed since it was queued")
    }
    Ok(())
}

pub fn ciphertext_size(metadata: &AttachmentMetadata) -> Result<u64> {
    validate_metadata(metadata)?;
    metadata
        .plaintext_size
        .checked_add(u64::from(metadata.chunk_count) * ATTACHMENT_CHUNK_OVERHEAD)
        .context("attachment ciphertext size overflow")
}

pub fn encrypt_chunk(
    source_path: &Path,
    metadata: &AttachmentMetadata,
    chunk_index: u32,
) -> Result<String> {
    validate_metadata(metadata)?;
    let expected = expected_chunk_size(metadata, chunk_index)?;
    let offset = u64::from(chunk_index)
        .checked_mul(ATTACHMENT_CHUNK_BYTES as u64)
        .context("attachment chunk offset overflow")?;
    let mut source = File::open(source_path).context("open attachment source")?;
    source.seek(SeekFrom::Start(offset))?;
    let mut plaintext = Zeroizing::new(vec![0u8; expected]);
    source
        .read_exact(&mut plaintext)
        .context("attachment source changed while uploading")?;
    let key = decode_key(metadata)?;
    let nonce = rand::random::<[u8; 24]>();
    let ciphertext = XChaCha20Poly1305::new((&*key).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &chunk_aad(metadata, chunk_index),
            },
        )
        .map_err(|_| anyhow::anyhow!("encrypt attachment chunk"))?;
    let mut encoded = Vec::with_capacity(nonce.len() + ciphertext.len());
    encoded.extend_from_slice(&nonce);
    encoded.extend_from_slice(&ciphertext);
    Ok(URL_SAFE_NO_PAD.encode(encoded))
}

pub fn validate_metadata(metadata: &AttachmentMetadata) -> Result<()> {
    if metadata.version != ATTACHMENT_VERSION {
        bail!("unsupported encrypted attachment version")
    }
    validate_filename(&metadata.filename)?;
    if metadata.plaintext_size > MAX_ATTACHMENT_BYTES {
        bail!("attachment exceeds the size limit")
    }
    if metadata.chunk_count != chunk_count(metadata.plaintext_size)? {
        bail!("attachment chunk count does not match its size")
    }
    decode_key(metadata)?;
    let hash = URL_SAFE_NO_PAD
        .decode(&metadata.plaintext_hash)
        .context("invalid attachment plaintext hash")?;
    if hash.len() != 32 {
        bail!("invalid attachment plaintext hash length")
    }
    Ok(())
}

pub fn existing_download(metadata: &AttachmentMetadata) -> Result<Option<PathBuf>> {
    existing_download_at(&downloads_dir()?, metadata)
}

pub fn cancel_partial_download(metadata: &AttachmentMetadata) -> Result<()> {
    cancel_partial_download_at(&downloads_dir()?, metadata)
}

pub fn cancel_partial_download_at(directory: &Path, metadata: &AttachmentMetadata) -> Result<()> {
    validate_metadata(metadata)?;
    let temporary_path = directory.join(format!(".{}.part", metadata.attachment_id));
    match fs::remove_file(&temporary_path) {
        Ok(()) => sync_parent(directory),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub fn existing_download_at(
    directory: &Path,
    metadata: &AttachmentMetadata,
) -> Result<Option<PathBuf>> {
    validate_metadata(metadata)?;
    let path = final_download_path(directory, metadata);
    if !path.exists() {
        return Ok(None);
    }
    if fs::metadata(&path)?.len() != metadata.plaintext_size
        || hash_file(&path)? != metadata.plaintext_hash
    {
        bail!("existing attachment download failed its integrity check")
    }
    Ok(Some(path))
}

pub struct AttachmentDownload {
    metadata: AttachmentMetadata,
    temporary_path: PathBuf,
    final_path: PathBuf,
    file: File,
    hash: Sha256,
    written: u64,
    next_chunk: u32,
}

impl AttachmentDownload {
    pub fn resume(metadata: &AttachmentMetadata) -> Result<Self> {
        Self::resume_at(&downloads_dir()?, metadata)
    }

    pub fn resume_at(directory: &Path, metadata: &AttachmentMetadata) -> Result<Self> {
        validate_metadata(metadata)?;
        fs::create_dir_all(directory)?;
        set_private_dir(directory)?;
        let temporary_path = directory.join(format!(".{}.part", metadata.attachment_id));
        let final_path = final_download_path(directory, metadata);
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary_path)?;
        let current_length = file.metadata()?.len().min(metadata.plaintext_size);
        let resumable_length = if current_length == metadata.plaintext_size {
            current_length
        } else {
            current_length / ATTACHMENT_CHUNK_BYTES as u64 * ATTACHMENT_CHUNK_BYTES as u64
        };
        file.set_len(resumable_length)?;
        file.seek(SeekFrom::Start(0))?;
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        let mut remaining = resumable_length;
        while remaining > 0 {
            let capacity = buffer.len();
            let read = file.read(&mut buffer[..remaining.min(capacity as u64) as usize])?;
            if read == 0 {
                bail!("attachment partial download is truncated")
            }
            hash.update(&buffer[..read]);
            remaining -= read as u64;
        }
        file.seek(SeekFrom::Start(resumable_length))?;
        let next_chunk = if resumable_length == metadata.plaintext_size {
            metadata.chunk_count
        } else {
            u32::try_from(resumable_length / ATTACHMENT_CHUNK_BYTES as u64)
                .context("attachment resume chunk index")?
        };
        Ok(Self {
            metadata: metadata.clone(),
            temporary_path,
            final_path,
            file,
            hash,
            written: resumable_length,
            next_chunk,
        })
    }

    pub fn next_chunk(&self) -> u32 {
        self.next_chunk
    }

    pub fn write_chunk(&mut self, chunk_index: u32, encoded: &str) -> Result<()> {
        if chunk_index != self.next_chunk {
            bail!("attachment chunk arrived out of order")
        }
        let expected = expected_chunk_size(&self.metadata, chunk_index)?;
        let encoded = URL_SAFE_NO_PAD
            .decode(encoded)
            .context("attachment chunk is not valid base64url")?;
        if encoded.len() != expected + ATTACHMENT_CHUNK_OVERHEAD as usize {
            bail!("attachment chunk has an invalid encrypted size")
        }
        let (nonce, ciphertext) = encoded.split_at(24);
        let key = decode_key(&self.metadata)?;
        let plaintext = Zeroizing::new(
            XChaCha20Poly1305::new((&*key).into())
                .decrypt(
                    XNonce::from_slice(nonce),
                    Payload {
                        msg: ciphertext,
                        aad: &chunk_aad(&self.metadata, chunk_index),
                    },
                )
                .map_err(|_| anyhow::anyhow!("attachment chunk authentication failed"))?,
        );
        if plaintext.len() != expected {
            bail!("attachment chunk plaintext has an invalid size")
        }
        self.file.write_all(&plaintext)?;
        self.file.sync_data()?;
        self.hash.update(&*plaintext);
        self.written += plaintext.len() as u64;
        self.next_chunk += 1;
        Ok(())
    }

    pub fn finish(self) -> Result<PathBuf> {
        if self.next_chunk != self.metadata.chunk_count
            || self.written != self.metadata.plaintext_size
        {
            bail!("attachment download is incomplete")
        }
        let actual = URL_SAFE_NO_PAD.encode(self.hash.finalize());
        if actual != self.metadata.plaintext_hash {
            bail!("attachment plaintext integrity check failed")
        }
        self.file.sync_all()?;
        drop(self.file);
        fs::rename(&self.temporary_path, &self.final_path)?;
        sync_parent(
            self.final_path
                .parent()
                .context("invalid attachment download path")?,
        )?;
        Ok(self.final_path)
    }
}

fn chunk_count(size: u64) -> Result<u32> {
    let chunks = if size == 0 {
        0
    } else {
        size.div_ceil(ATTACHMENT_CHUNK_BYTES as u64)
    };
    let chunks = u32::try_from(chunks).context("attachment chunk count")?;
    if chunks > MAX_ATTACHMENT_CHUNKS {
        bail!("attachment exceeds the chunk limit")
    }
    Ok(chunks)
}

fn expected_chunk_size(metadata: &AttachmentMetadata, chunk_index: u32) -> Result<usize> {
    if chunk_index >= metadata.chunk_count {
        bail!("attachment chunk index is outside the manifest")
    }
    let offset = u64::from(chunk_index) * ATTACHMENT_CHUNK_BYTES as u64;
    usize::try_from((metadata.plaintext_size - offset).min(ATTACHMENT_CHUNK_BYTES as u64))
        .context("attachment chunk size")
}

fn chunk_aad(metadata: &AttachmentMetadata, chunk_index: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ATTACHMENT_AAD_DOMAIN.len() + 16 + 4 + 4 + 8);
    aad.extend_from_slice(ATTACHMENT_AAD_DOMAIN);
    aad.extend_from_slice(metadata.attachment_id.as_bytes());
    aad.extend_from_slice(&chunk_index.to_be_bytes());
    aad.extend_from_slice(&metadata.chunk_count.to_be_bytes());
    aad.extend_from_slice(&metadata.plaintext_size.to_be_bytes());
    aad
}

fn decode_key(metadata: &AttachmentMetadata) -> Result<Zeroizing<[u8; 32]>> {
    let key = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(&metadata.file_key)
            .context("invalid attachment file key")?,
    );
    let key: [u8; 32] = key
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid attachment file key length"))?;
    Ok(Zeroizing::new(key))
}

fn validate_filename(filename: &str) -> Result<()> {
    if filename.is_empty()
        || filename.len() > MAX_FILENAME_BYTES
        || filename == "."
        || filename == ".."
        || filename
            .chars()
            .any(|character| character.is_control() || matches!(character, '/' | '\\'))
    {
        bail!("invalid attachment filename")
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(URL_SAFE_NO_PAD.encode(hash.finalize()))
}

fn downloads_dir() -> Result<PathBuf> {
    let project =
        ProjectDirs::from("chat", "mutte", "mutte").context("locate Mutte data directory")?;
    Ok(project.data_local_dir().join("downloads"))
}

fn final_download_path(directory: &Path, metadata: &AttachmentMetadata) -> PathBuf {
    let prefix = &metadata.attachment_id.simple().to_string()[..8];
    directory.join(format!("{prefix}-{}", metadata.filename))
}

#[cfg(unix)]
fn set_private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_dir(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_chunks_resume_and_reject_tampering() {
        let root = std::env::temp_dir().join(format!("mutte-attachment-{}", Uuid::new_v4()));
        let source = root.join("source.bin");
        let downloads = root.join("downloads");
        fs::create_dir_all(&root).unwrap();
        let mut plaintext = vec![0x5au8; ATTACHMENT_CHUNK_BYTES + 37];
        plaintext[ATTACHMENT_CHUNK_BYTES - 1] = 0x11;
        fs::write(&source, &plaintext).unwrap();
        let prepared = prepare(&source).unwrap();
        assert_eq!(prepared.metadata.chunk_count, 2);
        validate_source(&prepared.source_path, &prepared.metadata).unwrap();
        let first = encrypt_chunk(&prepared.source_path, &prepared.metadata, 0).unwrap();
        let second = encrypt_chunk(&prepared.source_path, &prepared.metadata, 1).unwrap();

        let mut writer = AttachmentDownload::resume_at(&downloads, &prepared.metadata).unwrap();
        writer.write_chunk(0, &first).unwrap();
        drop(writer);
        cancel_partial_download_at(&downloads, &prepared.metadata).unwrap();
        assert!(
            !downloads
                .join(format!(".{}.part", prepared.metadata.attachment_id))
                .exists()
        );
        let mut writer = AttachmentDownload::resume_at(&downloads, &prepared.metadata).unwrap();
        writer.write_chunk(0, &first).unwrap();
        drop(writer);
        let mut writer = AttachmentDownload::resume_at(&downloads, &prepared.metadata).unwrap();
        assert_eq!(writer.next_chunk(), 1);
        let mut tampered = URL_SAFE_NO_PAD.decode(&second).unwrap();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(
            writer
                .write_chunk(1, &URL_SAFE_NO_PAD.encode(tampered))
                .is_err()
        );
        assert_eq!(writer.next_chunk(), 1);
        writer.write_chunk(1, &second).unwrap();
        let output = writer.finish().unwrap();
        assert_eq!(fs::read(&output).unwrap(), plaintext);
        assert_eq!(
            existing_download_at(&downloads, &prepared.metadata).unwrap(),
            Some(output)
        );

        fs::write(&source, b"changed").unwrap();
        assert!(validate_source(&prepared.source_path, &prepared.metadata).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unsafe_filenames_and_oversized_metadata_are_rejected() {
        let key = URL_SAFE_NO_PAD.encode([7u8; 32]);
        let hash = URL_SAFE_NO_PAD.encode(Sha256::digest([]));
        let mut metadata = AttachmentMetadata {
            version: ATTACHMENT_VERSION,
            attachment_id: Uuid::new_v4(),
            filename: "../secret".into(),
            plaintext_size: 0,
            chunk_count: 0,
            file_key: key,
            plaintext_hash: hash,
        };
        assert!(validate_metadata(&metadata).is_err());
        metadata.filename = "safe.txt".into();
        metadata.plaintext_size = MAX_ATTACHMENT_BYTES + 1;
        assert!(validate_metadata(&metadata).is_err());
    }
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> Result<()> {
    Ok(())
}
