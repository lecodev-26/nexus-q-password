//! Bounded, atomic persistence for encrypted NQPW vault envelopes.
//!
//! This layer never serializes or writes plaintext. Callers must pass the complete
//! ciphertext envelope returned by `seal_payload`.

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

use atomic_write_file::AtomicWriteFile;

use crate::{HEADER_LEN, MAX_VAULT_BYTES, TAG_LEN};

/// Errors produced while reading or writing an encrypted vault file.
#[derive(Debug)]
pub enum VaultStorageError {
    Io(io::Error),
    TooLarge,
    InvalidFileType,
    InvalidEnvelope,
}

impl std::fmt::Display for VaultStorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(_) => f.write_str("Vault file could not be accessed."),
            Self::TooLarge => f.write_str("Vault file exceeds the supported size limit."),
            Self::InvalidFileType => f.write_str("Vault path must refer to a regular file."),
            Self::InvalidEnvelope => f.write_str("Vault envelope is malformed."),
        }
    }
}

impl std::error::Error for VaultStorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for VaultStorageError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Atomically replace `path` with a complete encrypted NQPW envelope.
///
/// The temporary file is created by `atomic-write-file` in the destination directory,
/// synced before replacement, and the parent directory is synced by that crate after
/// the rename. On Unix the temporary file is explicitly restricted to mode `0600`.
pub fn save_envelope(path: impl AsRef<Path>, envelope: &[u8]) -> Result<(), VaultStorageError> {
    validate_envelope_shape(envelope)?;
    let path = path.as_ref();

    if let Ok(metadata) = fs::symlink_metadata(path)
        && (metadata.file_type().is_symlink() || !metadata.is_file())
    {
        return Err(VaultStorageError::InvalidFileType);
    }

    let mut atomic = AtomicWriteFile::open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        atomic.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    atomic.write_all(envelope)?;
    atomic.commit()?;
    Ok(())
}

/// Read an encrypted envelope without following a symbolic link and with a hard size bound.
pub fn load_envelope(path: impl AsRef<Path>) -> Result<Vec<u8>, VaultStorageError> {
    let path = path.as_ref();
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT: inspect the reparse point itself, not its target.
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }

    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(VaultStorageError::InvalidFileType);
    }
    if metadata.len() > MAX_VAULT_BYTES as u64 {
        return Err(VaultStorageError::TooLarge);
    }

    let mut envelope = Vec::with_capacity(metadata.len() as usize);
    file.take((MAX_VAULT_BYTES + 1) as u64)
        .read_to_end(&mut envelope)?;
    if envelope.len() > MAX_VAULT_BYTES {
        return Err(VaultStorageError::TooLarge);
    }
    validate_envelope_shape(&envelope)?;
    Ok(envelope)
}

fn validate_envelope_shape(envelope: &[u8]) -> Result<(), VaultStorageError> {
    if envelope.len() > MAX_VAULT_BYTES {
        return Err(VaultStorageError::TooLarge);
    }
    if envelope.len() < HEADER_LEN + TAG_LEN || &envelope[..4] != b"NQPW" {
        return Err(VaultStorageError::InvalidEnvelope);
    }
    let declared = u64::from_be_bytes(
        envelope[58..66]
            .try_into()
            .map_err(|_| VaultStorageError::InvalidEnvelope)?,
    );
    let declared = usize::try_from(declared).map_err(|_| VaultStorageError::InvalidEnvelope)?;
    if declared < TAG_LEN || declared != envelope.len() - HEADER_LEN {
        return Err(VaultStorageError::InvalidEnvelope);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal_payload;
    use std::fs::File;

    fn encrypted_fixture() -> Vec<u8> {
        seal_payload(b"test master password", b"encrypted vault fixture").expect("seal fixture")
    }

    #[test]
    fn saves_and_reopens_complete_envelope() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.nqpw");
        let envelope = encrypted_fixture();
        save_envelope(&path, &envelope).expect("save");
        assert_eq!(load_envelope(&path).expect("load"), envelope);
        assert_eq!(fs::read_dir(dir.path()).expect("list dir").count(), 1);
    }

    #[test]
    fn failed_validation_preserves_existing_vault() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.nqpw");
        let original = encrypted_fixture();
        save_envelope(&path, &original).expect("initial save");
        assert!(matches!(
            save_envelope(&path, b"not an envelope"),
            Err(VaultStorageError::InvalidEnvelope)
        ));
        assert_eq!(load_envelope(&path).expect("old vault remains"), original);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_destinations_and_sources() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target.nqpw");
        let link = dir.path().join("link.nqpw");
        fs::write(&target, b"do not touch").expect("target");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        assert!(matches!(
            save_envelope(&link, &encrypted_fixture()),
            Err(VaultStorageError::InvalidFileType)
        ));
        assert!(load_envelope(&link).is_err());
        assert_eq!(
            fs::read(&target).expect("target unchanged"),
            b"do not touch"
        );
    }

    #[cfg(unix)]
    #[test]
    fn saved_vault_permissions_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.nqpw");
        save_envelope(&path, &encrypted_fixture()).expect("save");
        assert_eq!(
            fs::metadata(path).expect("metadata").permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn filesystem_failure_keeps_previous_vault_and_cleans_temp_file() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.nqpw");
        let original = encrypted_fixture();
        save_envelope(&path, &original).expect("initial save");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).expect("lock dir");
        let result = save_envelope(&path, &encrypted_fixture());
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("unlock dir");
        assert!(result.is_err());
        assert_eq!(load_envelope(&path).expect("old vault remains"), original);
        assert_eq!(fs::read_dir(dir.path()).expect("list dir").count(), 1);
    }

    #[test]
    fn rejects_truncated_and_oversized_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.nqpw");
        fs::write(&path, b"NQPW").expect("write truncated");
        assert!(matches!(
            load_envelope(&path),
            Err(VaultStorageError::InvalidEnvelope)
        ));
        let file = File::create(&path).expect("create");
        file.set_len((MAX_VAULT_BYTES + 1) as u64).expect("extend");
        assert!(matches!(
            load_envelope(&path),
            Err(VaultStorageError::TooLarge)
        ));
    }
}
