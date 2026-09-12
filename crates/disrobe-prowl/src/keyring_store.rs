use keyring::{Entry, Error as KeyringError};

use crate::keys::{KeyError, KeyringBackend};

#[derive(Debug, Default)]
pub struct OsKeyring;

impl OsKeyring {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    fn entry(service: &str, account: &str) -> Result<Entry, KeyError> {
        Entry::new(service, account).map_err(|e: KeyringError| KeyError::Keyring(e.to_string()))
    }
}

impl KeyringBackend for OsKeyring {
    fn get(&self, service: &str, account: &str) -> Result<Option<String>, KeyError> {
        match Self::entry(service, account)?.get_password() {
            Ok(secret) => Ok(Some(secret)),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(e) => Err(KeyError::Keyring(e.to_string())),
        }
    }

    fn set(&self, service: &str, account: &str, secret: &str) -> Result<(), KeyError> {
        Self::entry(service, account)?
            .set_password(secret)
            .map_err(|e: KeyringError| KeyError::Keyring(e.to_string()))
    }

    fn delete(&self, service: &str, account: &str) -> Result<(), KeyError> {
        match Self::entry(service, account)?.delete_credential() {
            Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
            Err(e) => Err(KeyError::Keyring(e.to_string())),
        }
    }
}
