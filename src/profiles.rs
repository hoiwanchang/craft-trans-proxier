//! Profile management, mirroring the original's "Profiles" (fnd_13): a set of named
//! configuration profiles stored as `.ini` files in a profiles folder, with
//! new / save / load / delete / rename and import / export to an arbitrary path.
//!
//! Profiles can additionally be protected with a "master password" (an encrypted
//! profile), matching the original's encrypted-profile feature. This uses REAL
//! authenticated encryption via [`crate::crypto`] (ChaCha20-Poly1305 under an
//! Argon2id key) — not a homegrown cipher — so a wrong password or a tampered
//! file cannot open. See [`ProfileStore::save_password`] / [`ProfileStore::load_with`].

use crate::config::Config;
use crate::crypto;
use std::fs;
use std::path::{Path, PathBuf};

pub struct ProfileStore {
    dir: PathBuf,
}

fn sanitize(name: &str) -> String {
    name.trim()
        .chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c => c,
        })
        .collect::<String>()
}

impl ProfileStore {
    /// Open (or create) the profiles folder. Usually a `profiles/` sibling of
    /// the active Settings.ini, matching the original's "folder with multiple
    /// profiles" concept.
    pub fn new(dir: impl AsRef<Path>) -> std::io::Result<ProfileStore> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        Ok(ProfileStore { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{}.ini", sanitize(name)))
    }

    /// Profile names (file stems), sorted.
    pub fn list(&self) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(&self.dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter_map(|e| {
                        let p = e.path();
                        if p.extension().and_then(|x| x.to_str()) == Some("ini") {
                            p.file_stem().and_then(|s| s.to_str()).map(|s| s.to_string())
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    }

    pub fn save(&self, name: &str, config: &Config) -> Result<(), String> {
        config.write(&self.path(name))
    }

    /// Save a profile encrypted under a master password (the original's protected
    /// profile). The plaintext never touches disk; the file is written atomically
    /// enough for our purposes (single write of the sealed blob).
    pub fn save_password(&self, name: &str, config: &Config, password: &str) -> Result<(), String> {
        let sealed = crypto::seal(config.serialize().as_bytes(), password)?;
        fs::write(self.path(name), sealed).map_err(|e| format!("write encrypted profile: {e}"))
    }

    pub fn load(&self, name: &str) -> Result<Config, String> {
        self.load_with(name, None)
    }

    /// Load a profile. A plaintext `.ini` loads regardless of `password`. An
    /// encrypted profile requires the correct `password`; without it (or with a
    /// wrong one) this returns a clear error rather than failing to parse.
    pub fn load_with(&self, name: &str, password: Option<&str>) -> Result<Config, String> {
        let bytes = fs::read(self.path(name)).map_err(|e| format!("read profile: {e}"))?;
        self.parse_bytes(&bytes, password)
    }

    /// Decode profile bytes (sealed or plaintext) into a Config.
    fn parse_bytes(&self, bytes: &[u8], password: Option<&str>) -> Result<Config, String> {
        if crypto::is_encrypted(bytes) {
            let pw = password.ok_or_else(|| "此配置文件已加密，需要主密码".to_string())?;
            let plain = crypto::open(bytes, pw)?;
            let text = String::from_utf8(plain).map_err(|e| format!("profile not utf-8: {e}"))?;
            Config::parse(&text)
        } else {
            let text = String::from_utf8(bytes.to_vec()).map_err(|e| format!("profile not utf-8: {e}"))?;
            Config::parse(&text)
        }
    }

    /// Is this stored profile encrypted (so the UI can prompt for a password)?
    pub fn is_encrypted(&self, name: &str) -> bool {
        fs::read(self.path(name)).map(|b| crypto::is_encrypted(&b)).unwrap_or(false)
    }

    pub fn delete(&self, name: &str) -> Result<(), String> {
        match fs::remove_file(self.path(name)) {
            Ok(()) => Ok(()),
            Err(e) => Err(format!("delete {name}: {e}")),
        }
    }

    pub fn exists(&self, name: &str) -> bool {
        self.path(name).exists()
    }

    pub fn rename(&self, from: &str, to: &str) -> Result<(), String> {
        if self.exists(to) {
            return Err(format!("profile '{to}' already exists"));
        }
        fs::rename(self.path(from), self.path(to)).map_err(|e| format!("rename: {e}"))
    }

    /// Export = copy the profile file to an arbitrary destination path.
    pub fn export(&self, name: &str, dest: &Path) -> Result<(), String> {
        fs::copy(self.path(name), dest).map_err(|e| format!("export: {e}"))?;
        Ok(())
    }

    /// Import = copy an external profile into the store under `name`. The file's
    /// sealed/plaintext form is preserved (an encrypted profile stays encrypted);
    /// we only validate it parses (decrypting with `password` if sealed).
    pub fn import(&self, src: &Path, name: &str) -> Result<(), String> {
        self.import_with(src, name, None)
    }

    pub fn import_with(&self, src: &Path, name: &str, password: Option<&str>) -> Result<(), String> {
        let bytes = fs::read(src).map_err(|e| format!("import (read): {e}"))?;
        // Validate before committing.
        self.parse_bytes(&bytes, password)
            .map_err(|e| format!("import (invalid profile): {e}"))?;
        fs::write(self.path(name), bytes).map_err(|e| format!("import (write): {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("tpprof-{}-{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn save_load_list_delete_roundtrip() {
        let dir = tmpdir("rwd");
        let store = ProfileStore::new(&dir).unwrap();
        let mut cfg = Config::default();
        cfg.settings.name = "Work".into();
        store.save("work", &cfg).unwrap();
        cfg.settings.name = "Home".into();
        store.save("home", &cfg).unwrap();

        assert_eq!(store.list(), vec!["home".to_string(), "work".to_string()]);
        let back = store.load("work").unwrap();
        assert_eq!(back.settings.name, "Work");

        store.delete("home").unwrap();
        assert_eq!(store.list(), vec!["work".to_string()]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rename_and_duplicate_guard() {
        let dir = tmpdir("rename");
        let store = ProfileStore::new(&dir).unwrap();
        store.save("a", &Config::default()).unwrap();
        assert!(store.rename("a", "b").is_ok());
        assert!(!store.exists("a") && store.exists("b"));
        // renaming onto an existing name must fail
        store.save("c", &Config::default()).unwrap();
        assert!(store.rename("b", "c").is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn import_rejects_invalid_and_export_copies() {
        let dir = tmpdir("imex");
        let store = ProfileStore::new(&dir).unwrap();
        // bogus import fails validation
        let bad = dir.join("bad.ini");
        fs::write(&bad, "[bogussection]\nx = 1\n").unwrap();
        assert!(store.import(&bad, "nope").is_err());
        assert!(!store.exists("nope"));
        // good profile → export → re-import
        store.save("keep", &Config::default()).unwrap();
        let out = dir.join("out.ini");
        store.export("keep", &out).unwrap();
        assert!(out.exists());
        assert!(store.import(&out, "again").is_ok());
        assert!(store.exists("again"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn name_sanitized_against_path_traversal() {
        let dir = tmpdir("san");
        let store = ProfileStore::new(&dir).unwrap();
        store.save("../../etc/passwd", &Config::default()).unwrap();
        // The real invariant: no stored path escapes the store directory.
        let listed = store.list();
        let canon_dir = dir.canonicalize().unwrap();
        for n in &listed {
            assert!(!n.contains('/') && !n.contains('\\'), "separator in name {n:?}");
            let p = store.path(n).canonicalize().unwrap();
            assert!(p.starts_with(&canon_dir), "path escaped store: {p:?}");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn encrypted_profile_roundtrip_and_password() {
        let dir = tmpdir("enc");
        let store = ProfileStore::new(&dir).unwrap();
        let mut cfg = Config::default();
        cfg.settings.name = "Vaulted".into();
        store.save_password("vault", &cfg, "s3cret").unwrap();

        // On disk it is NOT plaintext.
        let raw = fs::read(store.path("vault")).unwrap();
        assert!(crypto::is_encrypted(&raw));
        assert!(!String::from_utf8_lossy(&raw).contains("Vaulted"));
        assert!(store.is_encrypted("vault"));

        // Right password loads; missing/wrong password errors.
        assert_eq!(store.load_with("vault", Some("s3cret")).unwrap().settings.name, "Vaulted");
        assert!(store.load_with("vault", Some("nope")).is_err());
        assert!(store.load("vault").is_err(), "plaintext load must fail on an encrypted profile");

        // An encrypted profile exports + imports still encrypted (form preserved).
        let out = dir.join("copy.ini");
        store.export("vault", &out).unwrap();
        store.import_with(&out, "vault2", Some("s3cret")).unwrap();
        assert!(store.is_encrypted("vault2"));
        assert_eq!(store.load_with("vault2", Some("s3cret")).unwrap().settings.name, "Vaulted");

        // A plaintext profile loads with or without a password argument.
        store.save("plain", &cfg).unwrap();
        assert!(!store.is_encrypted("plain"));
        assert_eq!(store.load_with("plain", Some("ignored")).unwrap().settings.name, "Vaulted");
        assert_eq!(store.load("plain").unwrap().settings.name, "Vaulted");

        let _ = fs::remove_dir_all(&dir);
    }
}
