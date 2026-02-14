use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{VerifyingKey, PUBLIC_KEY_LENGTH};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::convert::TryInto;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Metadata for a trusted signer.
#[derive(Debug, Clone)]
pub struct TrustedSigner {
    verifying_key: VerifyingKey,
    fingerprint: String,
    source: PathBuf,
}

impl TrustedSigner {
    /// Return the Ed25519 verifying key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Hex-encoded SHA-256 fingerprint of the public key.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Source file path for diagnostics.
    pub fn source(&self) -> &Path {
        &self.source
    }
}

/// Registry of trusted signer public keys loaded from disk.
#[derive(Debug, Clone, Default)]
pub struct TrustedSigners {
    signers: HashMap<String, TrustedSigner>,
}

impl TrustedSigners {
    /// Load trusted signer public keys from a directory.
    pub fn load_from_dir(dir: &Path) -> Result<Self> {
        if !dir.exists() {
            anyhow::bail!("Trusted signer directory does not exist: {}", dir.display());
        }

        let mut signers = HashMap::new();

        for entry in fs::read_dir(dir).with_context(|| {
            format!("Failed to read trusted signer directory: {}", dir.display())
        })? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }

            let path = entry.path();
            let raw = fs::read_to_string(&path).with_context(|| {
                format!("Failed to read trusted signer file: {}", path.display())
            })?;

            let normalized = normalize_key_material(&raw);
            if normalized.is_empty() {
                warn!(path = %path.display(), "Trusted signer file empty or only comments");
                continue;
            }

            let key_bytes = match BASE64.decode(&normalized) {
                Ok(bytes) => bytes,
                Err(err) => {
                    warn!(
                        path = %path.display(),
                        error = %err,
                        "Failed to decode trusted signer key from base64"
                    );
                    continue;
                }
            };

            let key_array: [u8; PUBLIC_KEY_LENGTH] = match key_bytes.try_into() {
                Ok(array) => array,
                Err(_) => {
                    warn!(
                        path = %path.display(),
                        "Trusted signer key has invalid length (expected {} bytes)",
                        PUBLIC_KEY_LENGTH
                    );
                    continue;
                }
            };

            let verifying_key = match VerifyingKey::from_bytes(&key_array) {
                Ok(key) => key,
                Err(err) => {
                    warn!(
                        path = %path.display(),
                        error = %err,
                        "Trusted signer key is not a valid Ed25519 public key"
                    );
                    continue;
                }
            };

            let fingerprint = compute_fingerprint(&verifying_key);
            let entry = TrustedSigner {
                verifying_key,
                fingerprint,
                source: path.clone(),
            };

            match signers.insert(normalized.clone(), entry) {
                Some(previous) => {
                    warn!(
                        path = %path.display(),
                        previous = %previous.source.display(),
                        "Duplicate trusted signer entry detected"
                    );
                }
                None => {
                    debug!(
                        path = %path.display(),
                        "Loaded trusted signer key"
                    );
                }
            }
        }

        info!(count = signers.len(), directory = %dir.display(), "Trusted signer keys loaded");
        Ok(Self { signers })
    }

    /// Returns the trusted signer entry for the provided base64 key, if present.
    pub fn get(&self, signer_b64: &str) -> Option<&TrustedSigner> {
        let normalized = normalize_key_material(signer_b64);
        self.signers.get(&normalized)
    }

    /// Returns true if the provided base64 key is trusted.
    pub fn contains(&self, signer_b64: &str) -> bool {
        self.get(signer_b64).is_some()
    }

    /// Count of trusted signers currently loaded.
    pub fn len(&self) -> usize {
        self.signers.len()
    }

    /// Whether no trusted signers are configured.
    pub fn is_empty(&self) -> bool {
        self.signers.is_empty()
    }
}

fn normalize_key_material(source: &str) -> String {
    source
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && !line.starts_with('#')
                && !line.starts_with("//")
                && !line.starts_with("-----BEGIN")
                && !line.starts_with("-----END")
        })
        .collect::<String>()
}

fn compute_fingerprint(key: &VerifyingKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.to_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::SigningKey;
    use tempfile::tempdir;

    #[test]
    fn loads_valid_signer() {
        let temp = tempdir().unwrap();
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let public_key_b64 = BASE64.encode(key.verifying_key().to_bytes());
        let key_path = temp.path().join("signer.pub");
        fs::write(&key_path, &public_key_b64).unwrap();

        let signers = TrustedSigners::load_from_dir(temp.path()).unwrap();
        assert!(signers.contains(&public_key_b64));
    }

    #[test]
    fn ignores_invalid_files() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("not_a_key.txt"), "bad key").unwrap();

        let signers = TrustedSigners::load_from_dir(temp.path()).unwrap();
        assert!(signers.is_empty());
    }
}
