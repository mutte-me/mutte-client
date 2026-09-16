use std::{fs, io::Write, path::PathBuf};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use mutte_protocol::{ATTACHMENT_CHUNK_BYTES, AttachmentMetadata};
use mutte_store::attachment::{
    AttachmentDownload, cancel_partial_download_at, encrypt_chunk, existing_download_at, prepare,
};
use uuid::Uuid;

struct Fixture {
    root: PathBuf,
    downloads: PathBuf,
    source: PathBuf,
    metadata: AttachmentMetadata,
    plaintext: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("mutte-attachment-safety-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let source = root.join("sample.bin");
        let plaintext = (0..ATTACHMENT_CHUNK_BYTES * 2 + 37)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        fs::write(&source, &plaintext).unwrap();
        let metadata = prepare(&source).unwrap().metadata;
        Self {
            downloads: root.join("downloads"),
            root,
            source,
            metadata,
            plaintext,
        }
    }

    fn chunk(&self, index: u32) -> String {
        encrypt_chunk(&self.source, &self.metadata, index).unwrap()
    }

    fn resume(&self) -> AttachmentDownload {
        AttachmentDownload::resume_at(&self.downloads, &self.metadata).unwrap()
    }

    fn partial(&self) -> PathBuf {
        self.downloads
            .join(format!(".{}.part", self.metadata.attachment_id))
    }

    fn complete(&self) -> PathBuf {
        let mut writer = self.resume();
        for index in writer.next_chunk()..self.metadata.chunk_count {
            writer.write_chunk(index, &self.chunk(index)).unwrap();
        }
        writer.finish().unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn rejected_chunks_preserve_progress_and_allow_correct_retry() {
    let f = Fixture::new();
    let first = f.chunk(0);
    let second = f.chunk(1);
    let mut writer = f.resume();
    assert!(writer.write_chunk(1, &second).is_err());
    // Both chunks have equal size: relabelling must fail authentication, not just size checks.
    assert!(writer.write_chunk(0, &second).is_err());
    assert_eq!(writer.next_chunk(), 0);
    assert_eq!(fs::metadata(f.partial()).unwrap().len(), 0);
    writer.write_chunk(0, &first).unwrap();
    let saved = fs::read(f.partial()).unwrap();
    let bytes = URL_SAFE_NO_PAD.decode(&second).unwrap();
    let mut tampered = bytes.clone();
    *tampered.last_mut().unwrap() ^= 1;
    for invalid in [
        "!invalid!".to_owned(),
        URL_SAFE_NO_PAD.encode(&bytes[..bytes.len() - 1]),
        URL_SAFE_NO_PAD.encode(tampered),
    ] {
        assert!(writer.write_chunk(1, &invalid).is_err());
        assert_eq!(writer.next_chunk(), 1);
        assert_eq!(fs::read(f.partial()).unwrap(), saved);
    }
    assert!(writer.write_chunk(0, &first).is_err());
    assert_eq!(writer.next_chunk(), 1);
    drop(writer);
    assert_eq!(fs::read(f.complete()).unwrap(), f.plaintext);
}

#[test]
fn ciphertext_from_another_attachment_is_rejected_even_with_the_same_key() {
    let f = Fixture::new();
    let mut foreign = f.metadata.clone();
    foreign.attachment_id = Uuid::new_v4();
    let substituted = encrypt_chunk(&f.source, &foreign, 0).unwrap();
    let mut writer = f.resume();
    assert!(writer.write_chunk(0, &substituted).is_err());
    assert_eq!(writer.next_chunk(), 0);
    assert_eq!(fs::metadata(f.partial()).unwrap().len(), 0);
    drop(writer);
    assert_eq!(fs::read(f.complete()).unwrap(), f.plaintext);
}

#[test]
fn incomplete_finish_does_not_publish_and_partial_tail_is_discarded_on_resume() {
    let f = Fixture::new();
    let mut writer = f.resume();
    writer.write_chunk(0, &f.chunk(0)).unwrap();
    assert!(writer.finish().is_err());
    assert_eq!(
        existing_download_at(&f.downloads, &f.metadata).unwrap(),
        None
    );
    {
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(f.partial())
            .unwrap();
        file.write_all(&[0x77; 19]).unwrap();
        file.sync_all().unwrap();
    }
    let writer = f.resume();
    assert_eq!(writer.next_chunk(), 1);
    assert_eq!(
        fs::read(f.partial()).unwrap(),
        f.plaintext[..ATTACHMENT_CHUNK_BYTES]
    );
    drop(writer);
    assert_eq!(fs::read(f.complete()).unwrap(), f.plaintext);
}

#[test]
fn corrupted_resumed_plaintext_cannot_publish_and_cancel_allows_clean_retry() {
    let f = Fixture::new();
    let mut writer = f.resume();
    writer.write_chunk(0, &f.chunk(0)).unwrap();
    drop(writer);
    let mut bytes = fs::read(f.partial()).unwrap();
    bytes[0] ^= 1;
    fs::write(f.partial(), bytes).unwrap();
    let mut writer = f.resume();
    for index in writer.next_chunk()..f.metadata.chunk_count {
        writer.write_chunk(index, &f.chunk(index)).unwrap();
    }
    assert!(writer.finish().is_err());
    assert_eq!(
        existing_download_at(&f.downloads, &f.metadata).unwrap(),
        None
    );
    cancel_partial_download_at(&f.downloads, &f.metadata).unwrap();
    cancel_partial_download_at(&f.downloads, &f.metadata).unwrap();
    assert_eq!(fs::read(f.complete()).unwrap(), f.plaintext);
}

#[test]
fn modified_completed_file_is_not_returned_as_verified_cache() {
    let f = Fixture::new();
    let path = f.complete();
    let mut modified = f.plaintext.clone();
    modified[0] ^= 1;
    fs::write(&path, modified).unwrap();
    assert!(existing_download_at(&f.downloads, &f.metadata).is_err());
}

#[test]
fn different_full_ids_with_the_same_short_prefix_never_overwrite_downloads() {
    let mut first = Fixture::new();
    first.metadata.attachment_id = Uuid::parse_str("12345678-1111-4111-8111-111111111111").unwrap();
    let first_path = first.complete();
    let mut second = Fixture::new();
    second.downloads = first.downloads.clone();
    second.plaintext[0] ^= 1;
    fs::write(&second.source, &second.plaintext).unwrap();
    second.metadata = prepare(&second.source).unwrap().metadata;
    second.metadata.attachment_id =
        Uuid::parse_str("12345678-2222-4222-8222-222222222222").unwrap();
    let second_path = second.complete();
    assert_ne!(first_path, second_path);
    assert_eq!(fs::read(&first_path).unwrap(), first.plaintext);
    assert_eq!(fs::read(&second_path).unwrap(), second.plaintext);
    assert_eq!(
        existing_download_at(&first.downloads, &first.metadata).unwrap(),
        Some(first_path)
    );
    assert_eq!(
        existing_download_at(&second.downloads, &second.metadata).unwrap(),
        Some(second_path)
    );
}

#[test]
fn maximum_length_filename_can_be_downloaded_without_losing_its_name() {
    let mut f = Fixture::new();
    f.metadata.filename = "a".repeat(255);
    let path = f.complete();
    assert_eq!(
        path.file_name().unwrap().to_str().unwrap(),
        f.metadata.filename
    );
    assert_eq!(fs::read(path).unwrap(), f.plaintext);
}

#[test]
fn verified_legacy_cache_remains_readable_without_moving_or_rewriting_it() {
    let f = Fixture::new();
    fs::create_dir_all(&f.downloads).unwrap();
    let prefix = &f.metadata.attachment_id.simple().to_string()[..8];
    let legacy = f
        .downloads
        .join(format!("{prefix}-{}", f.metadata.filename));
    fs::write(&legacy, &f.plaintext).unwrap();
    assert_eq!(
        existing_download_at(&f.downloads, &f.metadata).unwrap(),
        Some(legacy.clone())
    );
    assert_eq!(fs::read(&legacy).unwrap(), f.plaintext);
    assert_eq!(fs::read_dir(&f.downloads).unwrap().count(), 1);
}

#[test]
fn conflicting_legacy_cache_allows_new_download_without_overwriting_old_file() {
    let f = Fixture::new();
    fs::create_dir_all(&f.downloads).unwrap();
    let prefix = &f.metadata.attachment_id.simple().to_string()[..8];
    let legacy = f
        .downloads
        .join(format!("{prefix}-{}", f.metadata.filename));
    let mut other = f.plaintext.clone();
    other[0] ^= 1;
    fs::write(&legacy, &other).unwrap();
    assert_eq!(
        existing_download_at(&f.downloads, &f.metadata).unwrap(),
        None
    );
    let downloaded = f.complete();
    assert_ne!(legacy, downloaded);
    assert_eq!(fs::read(&downloaded).unwrap(), f.plaintext);
    assert_eq!(fs::read(&legacy).unwrap(), other);
    assert_eq!(
        existing_download_at(&f.downloads, &f.metadata).unwrap(),
        Some(downloaded)
    );
}

#[cfg(unix)]
#[test]
fn completed_download_and_containing_directories_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    let downloaded = f.complete();
    assert_eq!(
        fs::metadata(&downloaded).unwrap().permissions().mode() & 0o777,
        0o600
    );
    for directory in [f.downloads.as_path(), downloaded.parent().unwrap()] {
        assert_eq!(
            fs::metadata(directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
}

#[test]
fn legacy_filename_matching_a_full_id_does_not_block_new_download() {
    let mut f = Fixture::new();
    f.metadata.attachment_id = Uuid::parse_str("12345678-1111-4111-8111-111111111111").unwrap();
    fs::create_dir_all(&f.downloads).unwrap();
    // A legacy attachment with prefix 12345678 and this valid filename
    // occupies the exact UUID name that a directory-only upgrade would use.
    let legacy = f.downloads.join("12345678-1111-4111-8111-111111111111");
    fs::write(&legacy, b"retained legacy download").unwrap();
    let downloaded = f.complete();
    assert_eq!(fs::read(downloaded).unwrap(), f.plaintext);
    assert_eq!(fs::read(legacy).unwrap(), b"retained legacy download");
}
