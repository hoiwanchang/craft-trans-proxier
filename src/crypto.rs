//! Profile master-password encryption — the original's encrypted-profile feature
//! (fnd_13: "profile master password").
//!
//! This is REAL cryptography, not a homegrown stand-in: the profile bytes are
//! sealed with XChaCha-free **ChaCha20-Poly1305** (AEAD) under a key stretched
//! from the master password with **Argon2id**, using a per-profile random salt
//! and a random nonce. Authenticated encryption means a wrong password OR any
//! tampering with the ciphertext/header fails to open (it cannot silently
//! return corrupt data). The plaintext profile is never written to disk in the
//! sealed format.
//!
//! On-disk layout:
//!   `MAGIC(4) || salt(16) || nonce(12) || ciphertext||tag`
//! where the header bytes (MAGIC..nonce) are fed in as **AAD** so they cannot be
//! swapped to detach a ciphertext from its salt/nonce.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{AeadInPlace, OsRng, rand_core::RngCore};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit};
use chacha20poly1305::aead::generic_array::GenericArray;

/// File fingerprint of a sealed profile. A plaintext `.ini` starts with a
/// comment (`#`), so this never collides with an unencrypted profile.
pub const MAGIC: [u8; 4] = *b"TPE1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

// Argon2id cost parameters (memory 19 MiB / 2 passes / 1 lane) — the crate's
// recommended baseline: strong enough to make offline password guessing
// expensive while opening a profile stays sub-second on a desktop.
const ARGON2_M_KIB: u32 = 19 * 1024;
const ARGON2_T: u32 = 2;
const ARGON2_P: u32 = 1;

/// Does this byte blob look like a sealed profile (vs a plaintext `.ini`)?
pub fn is_encrypted(bytes: &[u8]) -> bool {
    bytes.len() > MAGIC.len() + SALT_LEN + NONCE_LEN && bytes[..MAGIC.len()] == MAGIC
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN], String> {
    let params = Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, Some(KEY_LEN))
        .map_err(|e| format!("kdf params: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("key derivation failed: {e}"))?;
    Ok(key)
}

/// Seal the (plaintext) profile bytes under `password` into the on-disk format.
pub fn seal(plaintext: &[u8], password: &str) -> Result<Vec<u8>, String> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let key = derive_key(password, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

    let mut header = Vec::with_capacity(MAGIC.len() + SALT_LEN + NONCE_LEN);
    header.extend_from_slice(&MAGIC);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);

    let nonce = GenericArray::from_slice(&nonce);
    let mut buf = plaintext.to_vec();
    // AAD = the header; binds salt+nonce to this ciphertext.
    cipher
        .encrypt_in_place(nonce, &header, &mut buf)
        .map_err(|_| "seal failed".to_string())?;

    header.extend_from_slice(&buf); // ciphertext || tag
    Ok(header)
}

/// Open a sealed profile blob with `password`. Errors on a wrong password, a
/// tampered ciphertext/header, or a non-sealed blob.
pub fn open(sealed: &[u8], password: &str) -> Result<Vec<u8>, String> {
    if !is_encrypted(sealed) {
        return Err("not an encrypted profile".into());
    }
    let body = &sealed[MAGIC.len()..];
    if body.len() < SALT_LEN + NONCE_LEN {
        return Err("encrypted profile truncated".into());
    }
    let (salt, rest) = body.split_at(SALT_LEN);
    let (nonce, ct) = rest.split_at(NONCE_LEN);

    let key = derive_key(password, salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

    let aad = &sealed[..MAGIC.len() + SALT_LEN + NONCE_LEN];
    let mut buf = ct.to_vec();
    cipher
        .decrypt_in_place(GenericArray::from_slice(nonce), aad, &mut buf)
        .map_err(|_| "密码错误或文件已损坏（认证失败）".to_string())?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let plaintext = b"[settings]\nname = \"Secret Work\"\n".to_vec();
        let sealed = seal(&plaintext, "hunter2").unwrap();
        assert!(is_encrypted(&sealed));
        assert!(!sealed.windows(plaintext.len()).any(|w| w == &plaintext[..]), "plaintext must not leak");
        let back = open(&sealed, "hunter2").unwrap();
        assert_eq!(back, plaintext);
    }

    #[test]
    fn wrong_password_fails() {
        let sealed = seal(b"top-secret-profile", "right").unwrap();
        assert!(open(&sealed, "wrong").is_err(), "wrong password must not open");
    }

    #[test]
    fn tamper_detection() {
        let mut sealed = seal(b"payload-bytes-here", "pw").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01; // flip one ciphertext byte
        assert!(open(&sealed, "pw").is_err(), "tampered ciphertext must fail AEAD");

        // Flip a header (salt) byte too.
        let mut sealed2 = seal(b"payload-bytes-here", "pw").unwrap();
        sealed2[MAGIC.len()] ^= 0x80;
        assert!(open(&sealed2, "pw").is_err(), "tampered salt must fail");
    }

    #[test]
    fn distinct_salts_produce_distinct_ciphertexts() {
        // Same plaintext + same password, sealed twice, must differ (random salt/nonce).
        let a = seal(b"same", "same").unwrap();
        let b = seal(b"same", "same").unwrap();
        assert_ne!(a, b);
        assert_eq!(open(&a, "same").unwrap(), b"same");
        assert_eq!(open(&b, "same").unwrap(), b"same");
    }

    #[test]
    fn rejects_plaintext_and_short_input() {
        assert!(!is_encrypted(b"# Settings.ini ..."));
        assert!(open(b"# not sealed", "pw").is_err());
        assert!(open(&MAGIC, "pw").is_err());
    }
}
