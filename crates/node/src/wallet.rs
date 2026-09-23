//! The small account wallet used by the `thrylos` testnet CLI.
//!
//! This is intentionally separate from validator consensus keys. It stores one
//! Ed25519 account key in an owner-only file, refuses to overwrite it, and
//! never exposes the secret through a public method.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use chain_types::{Address, PublicKey};
use ed25519_dalek::SigningKey;

const KEY_BYTES: usize = 32;

#[derive(Debug)]
pub enum WalletError {
    NoHome,
    Exists(PathBuf),
    Io { path: PathBuf, problem: String },
    OpenPermissions(PathBuf),
    Invalid(PathBuf),
    Randomness,
}

impl core::fmt::Display for WalletError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoHome => f.write_str(
                "cannot find your home directory; set THRYLOS_WALLET to the wallet file to use",
            ),
            Self::Exists(path) => write!(
                f,
                "a wallet already exists at {}; it was left unchanged",
                path.display()
            ),
            Self::Io { path, problem } => write!(f, "{}: {problem}", path.display()),
            Self::OpenPermissions(path) => write!(
                f,
                "{} can be read by another user; protect it with `chmod 600 {}`",
                path.display(),
                path.display()
            ),
            Self::Invalid(path) => write!(
                f,
                "{} is not a valid Thrylos wallet key; restore it from a safe backup or choose another wallet",
                path.display()
            ),
            Self::Randomness => {
                f.write_str("the operating system could not provide secure randomness")
            }
        }
    }
}

impl std::error::Error for WalletError {}

fn io(path: &Path, error: impl core::fmt::Display) -> WalletError {
    WalletError::Io {
        path: path.to_owned(),
        problem: error.to_string(),
    }
}

/// The wallet selected by `THRYLOS_WALLET`, or `~/.thrylos/wallet.key`.
pub fn default_path() -> Result<PathBuf, WalletError> {
    if let Some(path) = std::env::var_os("THRYLOS_WALLET") {
        return Ok(PathBuf::from(path));
    }
    let home = std::env::var_os("HOME").ok_or(WalletError::NoHome)?;
    Ok(PathBuf::from(home).join(".thrylos").join("wallet.key"))
}

/// One account signing key. Its bytes are deliberately not exposed.
pub struct Wallet {
    key: SigningKey,
    address: Address,
    public_key: PublicKey,
}

impl Wallet {
    /// Create a new wallet without ever replacing an existing one.
    pub fn create(path: &Path) -> Result<Self, WalletError> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).map_err(|error| io(parent, error))?;
        }

        let mut bytes = [0u8; KEY_BYTES];
        let (key, public_key, address) = loop {
            getrandom::fill(&mut bytes).map_err(|_| WalletError::Randomness)?;
            let candidate = SigningKey::from_bytes(&bytes);
            if let Ok(public) = PublicKey::from_ed25519_bytes(candidate.verifying_key().to_bytes())
            {
                break (candidate, public, Address::from_public_key(&public));
            }
        };

        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    WalletError::Exists(path.to_owned())
                } else {
                    io(path, error)
                }
            })?;
        file.write_all(&bytes).map_err(|error| io(path, error))?;
        file.sync_all().map_err(|error| io(path, error))?;
        Ok(Self {
            key,
            address,
            public_key,
        })
    }

    /// Load a wallet only when its key file is private to its owner.
    pub fn load(path: &Path) -> Result<Self, WalletError> {
        let metadata = fs::metadata(path).map_err(|error| io(path, error))?;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(WalletError::OpenPermissions(path.to_owned()));
        }
        let bytes = fs::read(path).map_err(|error| io(path, error))?;
        let bytes: [u8; KEY_BYTES] = bytes
            .try_into()
            .map_err(|_| WalletError::Invalid(path.to_owned()))?;
        let key = SigningKey::from_bytes(&bytes);
        let public_key = PublicKey::from_ed25519_bytes(key.verifying_key().to_bytes())
            .map_err(|_| WalletError::Invalid(path.to_owned()))?;
        let address = Address::from_public_key(&public_key);
        Ok(Self {
            key,
            address,
            public_key,
        })
    }

    pub fn address(&self) -> Address {
        self.address
    }

    /// The public key `address()` was derived from — what a genesis
    /// allocation or validator entry names an account or operator by
    /// (`docs/core-network-alpha.md`, "Create the alpha genesis and release
    /// configuration"). An address cannot be turned back into this; it is
    /// only ever available from the wallet that made it.
    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.key
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn a_wallet_is_private_round_trips_and_is_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.key");
        let made = Wallet::create(&path).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(Wallet::load(&path).unwrap().address(), made.address());
        assert!(matches!(
            Wallet::create(&path),
            Err(WalletError::Exists(at)) if at == path
        ));
        assert_eq!(Wallet::load(&path).unwrap().address(), made.address());
    }

    #[test]
    fn public_key_is_what_the_address_was_derived_from_and_survives_a_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.key");
        let made = Wallet::create(&path).unwrap();
        assert_eq!(Address::from_public_key(&made.public_key()), made.address());
        assert_eq!(Wallet::load(&path).unwrap().public_key(), made.public_key());
    }

    #[test]
    fn a_key_other_users_can_read_is_refused_with_a_fix() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.key");
        Wallet::create(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let error = Wallet::load(&path).err().unwrap();
        assert!(matches!(error, WalletError::OpenPermissions(ref at) if *at == path));
        assert!(error.to_string().contains("chmod 600"));
    }
}
