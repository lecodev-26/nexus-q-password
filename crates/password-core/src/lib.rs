//! Versioned authenticated-encryption envelope for the local password vault.
//!
//! This module is an initial implementation baseline. The format remains subject
//! to review before real user credentials are stored in a release build.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"NQPW";
const FORMAT_VERSION: u8 = 1;
const KDF_ARGON2ID: u8 = 1;
const CIPHER_XCHACHA20_POLY1305: u8 = 1;
const HEADER_LEN: usize = 66;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const DEFAULT_MEMORY_KIB: u32 = 64 * 1024;
const DEFAULT_ITERATIONS: u32 = 3;
const DEFAULT_PARALLELISM: u8 = 1;
const MIN_MEMORY_KIB: u32 = 32 * 1024;
const MAX_MEMORY_KIB: u32 = 256 * 1024;
const MIN_ITERATIONS: u32 = 2;
const MAX_ITERATIONS: u32 = 6;
const MAX_PARALLELISM: u8 = 4;
const MAX_VAULT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum VaultCryptoError {
    InvalidPassword,
    InvalidFormat,
    UnsupportedVersion,
    UnsupportedAlgorithm,
    UnsafeParameters,
    TooLarge,
    RandomnessUnavailable,
    EncryptionFailed,
    AuthenticationFailed,
}

impl std::fmt::Display for VaultCryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidPassword => "Master password is invalid.",
            Self::InvalidFormat => "Vault file is malformed.",
            Self::UnsupportedVersion => "Vault format version is not supported.",
            Self::UnsupportedAlgorithm => "Vault cryptographic algorithm is not supported.",
            Self::UnsafeParameters => "Vault key-derivation parameters are outside safe limits.",
            Self::TooLarge => "Vault file exceeds the supported size limit.",
            Self::RandomnessUnavailable => "Secure random number generation is unavailable.",
            Self::EncryptionFailed => "Vault encryption failed.",
            Self::AuthenticationFailed => {
                "Vault could not be authenticated. Check the master password or file integrity."
            }
        })
    }
}

impl std::error::Error for VaultCryptoError {}

/// Encrypt a complete serialized vault payload into a v1 NQPW envelope.
pub fn seal_payload(password: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, VaultCryptoError> {
    if password.is_empty() || password.len() > 1024 {
        return Err(VaultCryptoError::InvalidPassword);
    }
    if plaintext.len() > MAX_VAULT_BYTES - HEADER_LEN - TAG_LEN {
        return Err(VaultCryptoError::TooLarge);
    }

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut salt).map_err(|_| VaultCryptoError::RandomnessUnavailable)?;
    getrandom::fill(&mut nonce).map_err(|_| VaultCryptoError::RandomnessUnavailable)?;

    let ciphertext_len = plaintext.len() + TAG_LEN;
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.push(FORMAT_VERSION);
    header.push(KDF_ARGON2ID);
    header.push(CIPHER_XCHACHA20_POLY1305);
    header.push(0); // Reserved; must be zero in v1.
    header.extend_from_slice(&DEFAULT_MEMORY_KIB.to_be_bytes());
    header.extend_from_slice(&DEFAULT_ITERATIONS.to_be_bytes());
    header.push(DEFAULT_PARALLELISM);
    header.push(KEY_LEN as u8);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);
    header.extend_from_slice(&(ciphertext_len as u64).to_be_bytes());
    debug_assert_eq!(header.len(), HEADER_LEN);

    let key = derive_key(
        password,
        &salt,
        DEFAULT_MEMORY_KIB,
        DEFAULT_ITERATIONS,
        DEFAULT_PARALLELISM,
    )?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|_| VaultCryptoError::EncryptionFailed)?;
    let encrypted = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .map_err(|_| VaultCryptoError::EncryptionFailed)?;

    let mut envelope = header;
    envelope.extend_from_slice(&encrypted);
    Ok(envelope)
}

/// Authenticate and decrypt a complete v1 NQPW envelope.
pub fn open_payload(
    password: &[u8],
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, VaultCryptoError> {
    if password.is_empty() || password.len() > 1024 {
        return Err(VaultCryptoError::InvalidPassword);
    }
    if envelope.len() > MAX_VAULT_BYTES {
        return Err(VaultCryptoError::TooLarge);
    }
    if envelope.len() < HEADER_LEN + TAG_LEN {
        return Err(VaultCryptoError::InvalidFormat);
    }

    let header = &envelope[..HEADER_LEN];
    if &header[..4] != MAGIC {
        return Err(VaultCryptoError::InvalidFormat);
    }
    if header[4] != FORMAT_VERSION {
        return Err(VaultCryptoError::UnsupportedVersion);
    }
    if header[5] != KDF_ARGON2ID || header[6] != CIPHER_XCHACHA20_POLY1305 {
        return Err(VaultCryptoError::UnsupportedAlgorithm);
    }
    if header[7] != 0 || header[17] != KEY_LEN as u8 {
        return Err(VaultCryptoError::InvalidFormat);
    }

    let memory_kib = u32::from_be_bytes(
        header[8..12]
            .try_into()
            .map_err(|_| VaultCryptoError::InvalidFormat)?,
    );
    let iterations = u32::from_be_bytes(
        header[12..16]
            .try_into()
            .map_err(|_| VaultCryptoError::InvalidFormat)?,
    );
    let parallelism = header[16];
    validate_parameters(memory_kib, iterations, parallelism)?;

    let salt: [u8; SALT_LEN] = header[18..34]
        .try_into()
        .map_err(|_| VaultCryptoError::InvalidFormat)?;
    let nonce: [u8; NONCE_LEN] = header[34..58]
        .try_into()
        .map_err(|_| VaultCryptoError::InvalidFormat)?;
    let ciphertext_len = u64::from_be_bytes(
        header[58..66]
            .try_into()
            .map_err(|_| VaultCryptoError::InvalidFormat)?,
    );
    let ciphertext_len = usize::try_from(ciphertext_len).map_err(|_| VaultCryptoError::TooLarge)?;
    if !(TAG_LEN..=MAX_VAULT_BYTES - HEADER_LEN).contains(&ciphertext_len) {
        return Err(VaultCryptoError::TooLarge);
    }
    if envelope.len() != HEADER_LEN + ciphertext_len {
        return Err(VaultCryptoError::InvalidFormat);
    }

    let key = derive_key(password, &salt, memory_kib, iterations, parallelism)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|_| VaultCryptoError::AuthenticationFailed)?;
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &envelope[HEADER_LEN..],
                aad: header,
            },
        )
        .map_err(|_| VaultCryptoError::AuthenticationFailed)?;
    Ok(Zeroizing::new(plaintext))
}

fn validate_parameters(
    memory_kib: u32,
    iterations: u32,
    parallelism: u8,
) -> Result<(), VaultCryptoError> {
    if !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&memory_kib)
        || !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations)
        || !(1..=MAX_PARALLELISM).contains(&parallelism)
        || memory_kib < 8 * u32::from(parallelism)
    {
        return Err(VaultCryptoError::UnsafeParameters);
    }
    Ok(())
}

fn derive_key(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    memory_kib: u32,
    iterations: u32,
    parallelism: u8,
) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultCryptoError> {
    validate_parameters(memory_kib, iterations, parallelism)?;
    let params = Params::new(
        memory_kib,
        iterations,
        u32::from(parallelism),
        Some(KEY_LEN),
    )
    .map_err(|_| VaultCryptoError::UnsafeParameters)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|_| VaultCryptoError::EncryptionFailed)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_authenticates_payload() {
        let password = b"correct horse battery staple";
        let plaintext = b"serialized credential vault payload";
        let sealed = seal_payload(password, plaintext).expect("seal");
        let opened = open_payload(password, &sealed).expect("open");
        assert_eq!(&opened[..], plaintext);
    }

    #[test]
    fn wrong_password_fails_authentication() {
        let sealed = seal_payload(b"right password", b"secret data").expect("seal");
        assert_eq!(
            open_payload(b"wrong password", &sealed).unwrap_err(),
            VaultCryptoError::AuthenticationFailed
        );
    }

    #[test]
    fn modified_ciphertext_fails_authentication() {
        let mut sealed = seal_payload(b"master password", b"secret data").expect("seal");
        let last = sealed.len() - 1;
        sealed[last] ^= 0x80;
        assert_eq!(
            open_payload(b"master password", &sealed).unwrap_err(),
            VaultCryptoError::AuthenticationFailed
        );
    }

    #[test]
    fn modified_header_fails_authentication() {
        let mut sealed = seal_payload(b"master password", b"secret data").expect("seal");
        sealed[11] ^= 0x01;
        assert_eq!(
            open_payload(b"master password", &sealed).unwrap_err(),
            VaultCryptoError::AuthenticationFailed
        );
    }

    #[test]
    fn rejects_unbounded_kdf_parameters_before_derivation() {
        let mut sealed = seal_payload(b"master password", b"secret data").expect("seal");
        sealed[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            open_payload(b"master password", &sealed).unwrap_err(),
            VaultCryptoError::UnsafeParameters
        );
    }

    #[test]
    fn every_save_uses_a_fresh_salt_and_nonce() {
        let first = seal_payload(b"master password", b"same payload").expect("seal");
        let second = seal_payload(b"master password", b"same payload").expect("seal");
        assert_ne!(&first[18..58], &second[18..58]);
    }
}

pub mod password_generator;
pub use password_generator::{PasswordGeneratorError, PasswordPolicy, generate_password};

#[cfg(test)]
mod envelope_parser_tests {
    use super::*;

    fn minimal_envelope() -> Vec<u8> {
        let mut bytes = vec![0u8; HEADER_LEN + TAG_LEN];
        bytes[..4].copy_from_slice(MAGIC);
        bytes[4] = FORMAT_VERSION;
        bytes[5] = KDF_ARGON2ID;
        bytes[6] = CIPHER_XCHACHA20_POLY1305;
        bytes[8..12].copy_from_slice(&DEFAULT_MEMORY_KIB.to_be_bytes());
        bytes[12..16].copy_from_slice(&DEFAULT_ITERATIONS.to_be_bytes());
        bytes[16] = DEFAULT_PARALLELISM;
        bytes[17] = KEY_LEN as u8;
        bytes[58..66].copy_from_slice(&(TAG_LEN as u64).to_be_bytes());
        bytes
    }

    #[test]
    fn rejects_unknown_format_versions() {
        let mut envelope = minimal_envelope();
        envelope[4] = 2;
        assert_eq!(
            open_payload(b"master password", &envelope).unwrap_err(),
            VaultCryptoError::UnsupportedVersion
        );
    }

    #[test]
    fn rejects_invalid_key_length_and_reserved_header_fields() {
        let mut envelope = minimal_envelope();
        envelope[17] = 16;
        assert_eq!(
            open_payload(b"master password", &envelope).unwrap_err(),
            VaultCryptoError::InvalidFormat
        );

        let mut envelope = minimal_envelope();
        envelope[7] = 1;
        assert_eq!(
            open_payload(b"master password", &envelope).unwrap_err(),
            VaultCryptoError::InvalidFormat
        );
    }

    #[test]
    fn rejects_unknown_algorithm_identifiers() {
        let mut envelope = minimal_envelope();
        envelope[5] = 9;
        assert_eq!(
            open_payload(b"master password", &envelope).unwrap_err(),
            VaultCryptoError::UnsupportedAlgorithm
        );

        let mut envelope = minimal_envelope();
        envelope[6] = 9;
        assert_eq!(
            open_payload(b"master password", &envelope).unwrap_err(),
            VaultCryptoError::UnsupportedAlgorithm
        );
    }

    #[test]
    fn rejects_kdf_parameters_outside_each_bound() {
        for (offset, value) in [
            (8, (MIN_MEMORY_KIB - 1).to_be_bytes()),
            (8, (MAX_MEMORY_KIB + 1).to_be_bytes()),
            (12, (MIN_ITERATIONS - 1).to_be_bytes()),
            (12, (MAX_ITERATIONS + 1).to_be_bytes()),
        ] {
            let mut envelope = minimal_envelope();
            envelope[offset..offset + 4].copy_from_slice(&value);
            assert_eq!(
                open_payload(b"master password", &envelope).unwrap_err(),
                VaultCryptoError::UnsafeParameters
            );
        }

        let mut envelope = minimal_envelope();
        envelope[16] = MAX_PARALLELISM + 1;
        assert_eq!(
            open_payload(b"master password", &envelope).unwrap_err(),
            VaultCryptoError::UnsafeParameters
        );
    }

    #[test]
    fn rejects_passwords_outside_input_bounds() {
        assert_eq!(
            open_payload(b"", &minimal_envelope()).unwrap_err(),
            VaultCryptoError::InvalidPassword
        );
        let oversized = vec![b'x'; 1025];
        assert_eq!(
            open_payload(&oversized, &minimal_envelope()).unwrap_err(),
            VaultCryptoError::InvalidPassword
        );
    }

    #[test]
    fn rejects_oversized_container_before_parsing() {
        let oversized = vec![0u8; MAX_VAULT_BYTES + 1];
        assert_eq!(
            open_payload(b"master password", &oversized).unwrap_err(),
            VaultCryptoError::TooLarge
        );
    }

    #[test]
    fn rejects_trailing_bytes_even_when_declared_length_is_valid() {
        let mut envelope = minimal_envelope();
        envelope.push(0);
        assert_eq!(
            open_payload(b"master password", &envelope).unwrap_err(),
            VaultCryptoError::InvalidFormat
        );
    }

    #[test]
    fn rejects_truncated_and_inconsistent_envelopes() {
        let mut envelope = minimal_envelope();
        envelope.pop();
        assert_eq!(
            open_payload(b"master password", &envelope).unwrap_err(),
            VaultCryptoError::InvalidFormat
        );

        let mut envelope = minimal_envelope();
        envelope[65] = 17;
        assert_eq!(
            open_payload(b"master password", &envelope).unwrap_err(),
            VaultCryptoError::InvalidFormat
        );
    }
}
