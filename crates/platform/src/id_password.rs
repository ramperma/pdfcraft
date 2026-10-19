//! A PKCS #12 password the user asked PdfCraft to remember.
//!
//! It is kept in the operating system's credential store, keyed by the certificate's SHA-256
//! fingerprint: the Secret Service (the desktop keyring) on Linux and FreeBSD, Credential
//! Manager on Windows, and the Keychain on macOS. Settings, recovery files and logs never
//! receive the password. The web build has no store.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Service name the operating system shows for these entries.
const SERVICE: &str = "ai.storyteller.pdfcraft";

/// Where a remembered password lives. [`Store::system`] is the user's keyring.
/// [`Store::memory`] keeps it in this process, for tests.
#[derive(Clone)]
pub struct Store {
    memory: Option<Arc<Mutex<HashMap<String, String>>>>,
}

impl Default for Store {
    fn default() -> Self {
        Self::system()
    }
}

/// A lookup that does not say why the store was unreachable, and never includes the password.
#[derive(PartialEq, Eq)]
pub enum Load {
    Found(String),
    Missing,
    Unavailable,
}

impl std::fmt::Debug for Load {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Found(_) => f.write_str("Found(_)"),
            Self::Missing => f.write_str("Missing"),
            Self::Unavailable => f.write_str("Unavailable"),
        }
    }
}

/// The desktop credential store can remember a password on this build.
pub const fn available() -> bool {
    cfg!(any(target_os = "linux", target_os = "freebsd", target_os = "windows", target_os = "macos"))
}

impl Store {
    /// The operating system's credential store. On a build with no store, every call reports
    /// [`Load::Unavailable`] or [`StoreError::Unavailable`].
    pub fn system() -> Self {
        Self { memory: None }
    }

    /// An in-memory store. Forgotten when this value and its clones are dropped.
    pub fn memory() -> Self {
        Self { memory: Some(Arc::new(Mutex::new(HashMap::new()))) }
    }

    pub fn load(&self, fingerprint: &str) -> Load {
        let Some(account) = account(fingerprint) else {
            return Load::Missing;
        };
        if let Some(memory) = &self.memory {
            return match memory.lock() {
                Ok(guard) => guard.get(&account).cloned().map(Load::Found).unwrap_or(Load::Missing),
                Err(poisoned) => poisoned.into_inner().get(&account).cloned().map(Load::Found).unwrap_or(Load::Missing),
            };
        }
        os_load(&account)
    }

    pub fn save(&self, fingerprint: &str, password: &str) -> Result<(), StoreError> {
        if password.is_empty() || password.len() > 1024 {
            return Err(StoreError::Rejected);
        }
        let Some(account) = account(fingerprint) else {
            return Err(StoreError::Rejected);
        };
        if let Some(memory) = &self.memory {
            let mut guard = match memory.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard.insert(account, password.to_owned());
            return Ok(());
        }
        os_save(&account, password)
    }

    /// Removes a saved password. Missing entries are success.
    pub fn forget(&self, fingerprint: &str) -> Result<(), StoreError> {
        let Some(account) = account(fingerprint) else {
            return Ok(());
        };
        if let Some(memory) = &self.memory {
            let mut guard = match memory.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard.remove(&account);
            return Ok(());
        }
        os_forget(&account)
    }
}

/// Why a save or a deletion did not happen. The text is for logs; the interface uses its own
/// sentences, so this does not name the password.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    /// The fingerprint is not a SHA-256, or the password is empty or too long.
    Rejected,
    /// The operating system has no credential store, or it refused the call.
    Unavailable,
}

/// `pkcs12:` plus the 64 hex digits of a SHA-256 fingerprint. Spaces and case in the
/// certificate's displayed fingerprint are ignored. Anything else is not an account.
pub fn account(fingerprint: &str) -> Option<String> {
    let mut hex = String::new();
    for c in fingerprint.chars() {
        if c.is_ascii_whitespace() {
            continue;
        }
        if !c.is_ascii_hexdigit() {
            return None;
        }
        hex.push(c.to_ascii_lowercase());
        if hex.len() > 64 {
            return None;
        }
    }
    if hex.len() != 64 {
        return None;
    }
    Some(format!("pkcs12:{hex}"))
}

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "windows", target_os = "macos"))]
fn entry(account: &str) -> Result<keyring::Entry, StoreError> {
    keyring::Entry::new(SERVICE, account).map_err(|_| StoreError::Unavailable)
}

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "windows", target_os = "macos"))]
fn os_load(account: &str) -> Load {
    let entry = match entry(account) {
        Ok(entry) => entry,
        Err(_) => return Load::Unavailable,
    };
    match entry.get_password() {
        Ok(password) => Load::Found(password),
        Err(keyring::Error::NoEntry) => Load::Missing,
        Err(_) => Load::Unavailable,
    }
}

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "windows", target_os = "macos"))]
fn os_save(account: &str, password: &str) -> Result<(), StoreError> {
    entry(account)?.set_password(password).map_err(|_| StoreError::Unavailable)
}

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "windows", target_os = "macos"))]
fn os_forget(account: &str) -> Result<(), StoreError> {
    match entry(account)?.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(_) => Err(StoreError::Unavailable),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "windows", target_os = "macos")))]
fn os_load(_account: &str) -> Load {
    Load::Unavailable
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "windows", target_os = "macos")))]
fn os_save(_account: &str, _password: &str) -> Result<(), StoreError> {
    Err(StoreError::Unavailable)
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "windows", target_os = "macos")))]
fn os_forget(_account: &str) -> Result<(), StoreError> {
    Err(StoreError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 32 bytes of `ab`, shown as upper-case pairs with spaces, the way a certificate fingerprint is.
    fn fingerprint() -> String {
        let mut out = String::new();
        for i in 0..32 {
            if i > 0 {
                out.push(' ');
            }
            out.push_str("AB");
        }
        out
    }

    #[test]
    fn a_fingerprint_is_an_account_of_sixty_four_hex_digits() {
        let name = super::account(&fingerprint()).unwrap();
        assert!(name.starts_with("pkcs12:"));
        assert_eq!(name.len(), "pkcs12:".len() + 64);
        assert!(name["pkcs12:".len()..].chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_eq!(super::account(&name[7..]), Some(name));
        assert!(super::account("not a fingerprint").is_none());
        assert!(super::account(&"ab".repeat(40)).is_none());
    }

    #[test]
    fn the_memory_store_remembers_forgets_and_hides_the_password_in_debug() {
        let store = Store::memory();
        let fp = fingerprint();
        assert_eq!(store.load(&fp), Load::Missing);
        assert_eq!(store.save(&fp, ""), Err(StoreError::Rejected));
        store.save(&fp, "secret12").unwrap();
        match store.load(&fp) {
            Load::Found(password) => assert_eq!(password, "secret12"),
            other => panic!("expected the password, got {other:?}"),
        }
        let shown = format!("{:?}", store.load(&fp));
        assert!(!shown.contains("secret12"), "{shown}");
        store.forget(&fp).unwrap();
        assert_eq!(store.load(&fp), Load::Missing);
        assert!(store.save("nope", "secret12").is_err());
    }
}
