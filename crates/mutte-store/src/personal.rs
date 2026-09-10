//! A separate encrypted sidecar prevents older clients from dropping personal data.
use super::*;

const FORMAT: &str = "mutte-personal/v1";
impl Vault {
    fn personal_path(&self) -> PathBuf {
        self.path.with_extension("personal.json")
    }
    fn personal_context(&self) -> Result<Vec<u8>> {
        // Authenticated sessions bind to relay/account/device. Isolated pre-auth
        // test vaults bind to their path and cannot be substituted for a session.
        Ok(if let Some(session) = &self.data.session {
            serde_json::to_vec(&(
                FORMAT,
                RelayOrigin::from_url(&session.server)?.as_str(),
                session.profile.id,
                session.device_id,
            ))?
        } else {
            serde_json::to_vec(&(FORMAT, &self.path))?
        })
    }
    fn personal_key(&self) -> Result<Zeroizing<[u8; 32]>> {
        let mut key = Zeroizing::new([0; 32]);
        Hkdf::<Sha256>::new(Some(FORMAT.as_bytes()), self.key.expose_secret())
            .expand(b"local personal document", &mut *key)
            .map_err(|_| anyhow::anyhow!("derive personal key"))?;
        Ok(key)
    }
    pub fn load_personal_document(&self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let bytes = match fs::read(self.personal_path()) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let envelope: EncryptedVault = serde_json::from_slice(&bytes)?;
        if envelope.format != FORMAT {
            bail!("unsupported personal document version");
        }
        let nonce = URL_SAFE_NO_PAD.decode(envelope.nonce)?;
        if nonce.len() != 24 {
            bail!("invalid personal nonce");
        }
        let key = self.personal_key()?;
        let plaintext = XChaCha20Poly1305::new((&*key).into())
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &URL_SAFE_NO_PAD.decode(envelope.ciphertext)?,
                    aad: &self.personal_context()?,
                },
            )
            .map_err(|_| {
                anyhow::anyhow!("personal document authentication failed; original file preserved")
            })?;
        Ok(Some(Zeroizing::new(plaintext)))
    }
    pub fn save_personal_document(&self, plaintext: &[u8]) -> Result<()> {
        if plaintext.len() > 128 * 1024 * 1024 {
            bail!("personal storage limit reached");
        }
        let parent = self.path.parent().context("invalid vault path")?;
        fs::create_dir_all(parent)?;
        set_private_dir(parent)?;
        let nonce = rand::random::<[u8; 24]>();
        let key = self.personal_key()?;
        let ciphertext = XChaCha20Poly1305::new((&*key).into())
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &self.personal_context()?,
                },
            )
            .map_err(|_| anyhow::anyhow!("encrypt personal document"))?;
        let envelope = EncryptedVault {
            format: FORMAT.into(),
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        };
        write_private(&self.personal_path(), &serde_json::to_vec(&envelope)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authenticated_personal_state_is_bound_to_relay_account_and_device() {
        let root = std::env::temp_dir().join(format!("mutte-personal-scope-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let server = Url::parse("https://api.example.test").unwrap();
        let profile = mutte_protocol::Profile {
            id: Uuid::new_v4(),
            handle: "mira".into(),
            display_name: "Mira".into(),
            bio: String::new(),
            status: String::new(),
        };
        let session = StoredSession {
            access_token: SecretString::from("test-only"),
            device_id: Uuid::new_v4(),
            profile,
        };
        let mut vault = Vault::open_at(root.join("a.json"), &[8; 32]).unwrap();
        vault.save_session(&server, &session).unwrap();
        vault.save_personal_document(b"private").unwrap();
        for kind in ["same", "relay", "account", "device"] {
            let mut other = Vault::open_at(root.join(format!("{kind}.json")), &[8; 32]).unwrap();
            let mut binding = session.clone();
            if kind == "account" {
                binding.profile.id = Uuid::new_v4();
            }
            if kind == "device" {
                binding.device_id = Uuid::new_v4();
            }
            let origin = if kind == "relay" {
                Url::parse("https://staging.example.test").unwrap()
            } else {
                server.clone()
            };
            other.save_session(&origin, &binding).unwrap();
            fs::copy(vault.personal_path(), other.personal_path()).unwrap();
            assert_eq!(other.load_personal_document().is_ok(), kind == "same");
        }
        vault.clear_session_for(&server, Uuid::new_v4()).unwrap();
        assert!(vault.load_session(&server).is_some());
        vault
            .clear_session_for(
                &Url::parse("https://unrelated.example.test").unwrap(),
                session.device_id,
            )
            .unwrap();
        assert!(vault.load_session(&server).is_some());
        vault.clear_session_for(&server, session.device_id).unwrap();
        assert!(vault.load_session(&server).is_none());
        assert!(vault.load_personal_document().is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn personal_document_is_private_bound_and_corruption_is_preserved() {
        let directory = std::env::temp_dir().join(format!("mutte-personal-{}", Uuid::new_v4()));
        fs::create_dir_all(&directory).unwrap();
        let vault = Vault::open_at(directory.join("messages.json"), &[7; 32]).unwrap();
        assert!(vault.load_personal_document().unwrap().is_none());
        vault
            .save_personal_document(b"private note and draft")
            .unwrap();
        assert_eq!(
            &*vault.load_personal_document().unwrap().unwrap(),
            b"private note and draft"
        );
        let path = vault.personal_path();
        let bytes = fs::read(&path).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("private note"));
        let other = Vault::open_at(directory.join("other.json"), &[7; 32]).unwrap();
        fs::copy(&path, other.personal_path()).unwrap();
        assert!(other.load_personal_document().is_err());
        fs::write(&path, b"corrupt").unwrap();
        assert!(vault.load_personal_document().is_err());
        assert_eq!(fs::read(&path).unwrap(), b"corrupt");
        fs::remove_dir_all(directory).unwrap();
    }
}
