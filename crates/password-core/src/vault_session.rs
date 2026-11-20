//! In-memory master-key lifecycle for an unlocked local vault.
//!
//! Master passwords are accepted only as call arguments and are never retained.
//! Derived keys live only in `Zeroizing` memory and are discarded on lock/drop.

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use zeroize::Zeroizing;

use crate::{
    CIPHER_XCHACHA20_POLY1305, DEFAULT_ITERATIONS, DEFAULT_MEMORY_KIB, DEFAULT_PARALLELISM,
    FORMAT_VERSION, HEADER_LEN, KDF_ARGON2ID, KEY_LEN, MAGIC, MAX_VAULT_BYTES, NONCE_LEN, SALT_LEN,
    TAG_LEN, VaultCryptoError, decrypt_with_key, open_payload_with_key, seal_payload_with_key,
};

struct KeyMaterial {
    key: Zeroizing<[u8; KEY_LEN]>,
    salt: [u8; SALT_LEN],
    memory_kib: u32,
    iterations: u32,
    parallelism: u8,
}

/// An unlocked vault session. It deliberately has no serialization support.
pub struct VaultSession {
    material: Option<KeyMaterial>,
    generation: u64,
}

/// A password-change result that must be persisted before it is committed to the session.
pub struct PasswordChange {
    generation: u64,
    expected_salt: [u8; SALT_LEN],
    material: Option<KeyMaterial>,
    envelope: Vec<u8>,
}

impl PasswordChange {
    /// The new encrypted envelope. Persist this atomically before committing the change.
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }
}

impl VaultSession {
    /// Create a new vault session and its initial encrypted envelope.
    pub fn create(
        master_password: &[u8],
        initial_payload: &[u8],
    ) -> Result<(Self, Vec<u8>), VaultCryptoError> {
        let (envelope, key, salt) = seal_payload_with_key(master_password, initial_payload)?;
        Ok((
            Self {
                material: Some(KeyMaterial {
                    key,
                    salt,
                    memory_kib: DEFAULT_MEMORY_KIB,
                    iterations: DEFAULT_ITERATIONS,
                    parallelism: DEFAULT_PARALLELISM,
                }),
                generation: 0,
            },
            envelope,
        ))
    }

    /// Unlock an existing envelope. No session is returned unless authentication succeeds.
    pub fn unlock(
        master_password: &[u8],
        envelope: &[u8],
    ) -> Result<(Self, Zeroizing<Vec<u8>>), VaultCryptoError> {
        let (key, salt, memory_kib, iterations, parallelism, plaintext) =
            open_payload_with_key(master_password, envelope)?;
        Ok((
            Self {
                material: Some(KeyMaterial {
                    key,
                    salt,
                    memory_kib,
                    iterations,
                    parallelism,
                }),
                generation: 0,
            },
            plaintext,
        ))
    }

    pub fn is_unlocked(&self) -> bool {
        self.material.is_some()
    }

    /// Immediately invalidate this session and zeroize its derived key.
    pub fn lock(&mut self) {
        self.material = None;
        self.generation = self.generation.wrapping_add(1);
    }

    /// Encrypt a complete serialized vault snapshot with the active in-memory key.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, VaultCryptoError> {
        let material = self
            .material
            .as_ref()
            .ok_or(VaultCryptoError::SessionLocked)?;
        if plaintext.len() > MAX_VAULT_BYTES - HEADER_LEN - TAG_LEN {
            return Err(VaultCryptoError::TooLarge);
        }
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| VaultCryptoError::RandomnessUnavailable)?;
        let ciphertext_len = plaintext.len() + TAG_LEN;
        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(MAGIC);
        header.push(FORMAT_VERSION);
        header.push(KDF_ARGON2ID);
        header.push(CIPHER_XCHACHA20_POLY1305);
        header.push(0);
        header.extend_from_slice(&material.memory_kib.to_be_bytes());
        header.extend_from_slice(&material.iterations.to_be_bytes());
        header.push(material.parallelism);
        header.push(KEY_LEN as u8);
        header.extend_from_slice(&material.salt);
        header.extend_from_slice(&nonce);
        header.extend_from_slice(&(ciphertext_len as u64).to_be_bytes());
        let cipher = XChaCha20Poly1305::new_from_slice(&material.key[..])
            .map_err(|_| VaultCryptoError::EncryptionFailed)?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &header,
                },
            )
            .map_err(|_| VaultCryptoError::EncryptionFailed)?;
        header.extend_from_slice(&ciphertext);
        Ok(header)
    }

    /// Decrypt only envelopes belonging to this session's KDF salt and parameters.
    pub fn open(&self, envelope: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultCryptoError> {
        let material = self
            .material
            .as_ref()
            .ok_or(VaultCryptoError::SessionLocked)?;
        if envelope.len() < HEADER_LEN + TAG_LEN {
            return Err(VaultCryptoError::InvalidFormat);
        }
        let header = &envelope[..HEADER_LEN];
        if header[18..34] != material.salt
            || u32::from_be_bytes(
                header[8..12]
                    .try_into()
                    .map_err(|_| VaultCryptoError::InvalidFormat)?,
            ) != material.memory_kib
            || u32::from_be_bytes(
                header[12..16]
                    .try_into()
                    .map_err(|_| VaultCryptoError::InvalidFormat)?,
            ) != material.iterations
            || header[16] != material.parallelism
        {
            return Err(VaultCryptoError::AuthenticationFailed);
        }
        decrypt_with_key(&material.key, envelope)
    }

    /// Prepare a master-password change without changing the active session.
    /// The caller must persist `change.envelope()` atomically before committing it.
    pub fn prepare_master_password_change(
        &self,
        current_envelope: &[u8],
        new_master_password: &[u8],
    ) -> Result<PasswordChange, VaultCryptoError> {
        let _ = self
            .material
            .as_ref()
            .ok_or(VaultCryptoError::SessionLocked)?;
        let plaintext = self.open(current_envelope)?;
        let (envelope, key, salt) = seal_payload_with_key(new_master_password, &plaintext)?;
        let current_salt = self
            .material
            .as_ref()
            .ok_or(VaultCryptoError::SessionLocked)?
            .salt;
        Ok(PasswordChange {
            generation: self.generation,
            expected_salt: current_salt,
            material: Some(KeyMaterial {
                key,
                salt,
                memory_kib: DEFAULT_MEMORY_KIB,
                iterations: DEFAULT_ITERATIONS,
                parallelism: DEFAULT_PARALLELISM,
            }),
            envelope,
        })
    }

    /// Activate new key material only after the caller has successfully persisted its envelope.
    pub fn commit_master_password_change(
        &mut self,
        mut change: PasswordChange,
    ) -> Result<(), VaultCryptoError> {
        let Some(current) = self.material.as_ref() else {
            return Err(VaultCryptoError::StaleSession);
        };
        if self.generation != change.generation || current.salt != change.expected_salt {
            return Err(VaultCryptoError::StaleSession);
        }
        self.material = change.material.take();
        Ok(())
    }
}

impl Drop for VaultSession {
    fn drop(&mut self) {
        self.lock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_unlock_and_reopen_without_retaining_password() {
        let (session, envelope) =
            VaultSession::create(b"master password", b"empty vault").expect("create");
        assert!(session.is_unlocked());
        assert_eq!(&session.open(&envelope).expect("open")[..], b"empty vault");
        let (unlocked, plaintext) =
            VaultSession::unlock(b"master password", &envelope).expect("unlock");
        assert_eq!(&plaintext[..], b"empty vault");
        assert_eq!(
            &unlocked.open(&envelope).expect("session open")[..],
            b"empty vault"
        );
    }

    #[test]
    fn wrong_password_does_not_create_a_session() {
        let (_, envelope) = VaultSession::create(b"correct password", b"payload").expect("create");
        assert!(matches!(
            VaultSession::unlock(b"wrong password", &envelope),
            Err(VaultCryptoError::AuthenticationFailed)
        ));
    }

    #[test]
    fn lock_invalidates_all_sensitive_operations() {
        let (mut session, envelope) =
            VaultSession::create(b"master password", b"payload").expect("create");
        session.lock();
        assert!(!session.is_unlocked());
        assert_eq!(
            session.open(&envelope).unwrap_err(),
            VaultCryptoError::SessionLocked
        );
        assert_eq!(
            session.seal(b"new payload").unwrap_err(),
            VaultCryptoError::SessionLocked
        );
        assert!(matches!(
            session.prepare_master_password_change(&envelope, b"new password"),
            Err(VaultCryptoError::SessionLocked)
        ));
    }

    #[test]
    fn password_change_requires_persistence_before_session_rotation() {
        let (mut session, old_envelope) =
            VaultSession::create(b"old password", b"payload").expect("create");
        let change = session
            .prepare_master_password_change(&old_envelope, b"new password")
            .expect("prepare");
        assert_eq!(
            &session.open(&old_envelope).expect("old session remains")[..],
            b"payload"
        );
        let new_envelope = change.envelope().to_vec();
        session
            .commit_master_password_change(change)
            .expect("commit after persistence");
        assert_eq!(
            &session.open(&new_envelope).expect("new session")[..],
            b"payload"
        );
        assert_eq!(
            session.open(&old_envelope).unwrap_err(),
            VaultCryptoError::AuthenticationFailed
        );
        assert_eq!(
            VaultSession::unlock(b"new password", &new_envelope)
                .unwrap()
                .1
                .as_slice(),
            b"payload"
        );
    }

    #[test]
    fn pending_password_change_cannot_reactivate_a_locked_session() {
        let (mut session, envelope) =
            VaultSession::create(b"old password", b"payload").expect("create");
        let pending = session
            .prepare_master_password_change(&envelope, b"new password")
            .expect("prepare");
        session.lock();
        assert_eq!(
            session.commit_master_password_change(pending).unwrap_err(),
            VaultCryptoError::StaleSession
        );
        assert!(!session.is_unlocked());
    }

    #[test]
    fn password_change_token_cannot_be_committed_to_another_vault_session() {
        let (mut first, first_envelope) =
            VaultSession::create(b"same password", b"first").expect("first");
        let (mut second, _) = VaultSession::create(b"same password", b"second").expect("second");
        let pending = first
            .prepare_master_password_change(&first_envelope, b"new password")
            .expect("prepare");
        assert_eq!(
            second.commit_master_password_change(pending).unwrap_err(),
            VaultCryptoError::StaleSession
        );
        assert_eq!(
            &second.seal(b"still second").expect("second remains active")[..4],
            b"NQPW"
        );
        first.lock();
    }

    #[test]
    fn session_rejects_envelopes_with_a_different_salt() {
        let (session, envelope) =
            VaultSession::create(b"master password", b"payload").expect("create");
        let (_, mut other) =
            VaultSession::create(b"master password", b"payload").expect("create another");
        other[18] ^= 1;
        assert_eq!(
            session.open(&other).unwrap_err(),
            VaultCryptoError::AuthenticationFailed
        );
        assert_eq!(&session.open(&envelope).expect("original")[..], b"payload");
    }
}
