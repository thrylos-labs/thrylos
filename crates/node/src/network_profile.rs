//! Named RPC endpoints saved for the `thrylos` CLI, so a public testnet's
//! gateway URL does not need to be typed on every command
//! (`docs/core-network-alpha.md`, "a saved testnet network profile").
//!
//! This file holds no secret: just names and RPC addresses, the same things
//! `--rpc` already accepts on the command line.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::atomic::write_atomic;
use crate::remote_rpc::Endpoint;

#[derive(Debug)]
pub enum ProfileError {
    NoHome,
    Io { path: PathBuf, problem: String },
    Invalid(PathBuf),
    UnknownRpc(String),
    NotFound(String),
}

impl core::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoHome => f.write_str(
                "cannot find your home directory; set THRYLOS_NETWORKS to the file to use",
            ),
            Self::Io { path, problem } => write!(f, "{}: {problem}", path.display()),
            Self::Invalid(path) => {
                write!(f, "{} is not a valid saved-networks file", path.display())
            }
            Self::UnknownRpc(reason) => f.write_str(reason),
            Self::NotFound(name) => write!(
                f,
                "no saved network named {name:?}; add one with `thrylos network add {name} <rpc>`"
            ),
        }
    }
}

impl std::error::Error for ProfileError {}

fn io(path: &Path, error: impl core::fmt::Display) -> ProfileError {
    ProfileError::Io {
        path: path.to_owned(),
        problem: error.to_string(),
    }
}

/// The file selected by `THRYLOS_NETWORKS`, or `~/.thrylos/networks.json`.
pub fn default_path() -> Result<PathBuf, ProfileError> {
    if let Some(path) = std::env::var_os("THRYLOS_NETWORKS") {
        return Ok(PathBuf::from(path));
    }
    let home = std::env::var_os("HOME").ok_or(ProfileError::NoHome)?;
    Ok(PathBuf::from(home).join(".thrylos").join("networks.json"))
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Store {
    current: Option<String>,
    #[serde(default)]
    networks: BTreeMap<String, String>,
}

fn load(path: &Path) -> Result<Store, ProfileError> {
    match fs::read(path) {
        Ok(bytes) => {
            serde_json::from_slice(&bytes).map_err(|_| ProfileError::Invalid(path.to_owned()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Store::default()),
        Err(error) => Err(io(path, error)),
    }
}

fn save(path: &Path, store: &Store) -> Result<(), ProfileError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|error| io(parent, error))?;
    }
    let bytes = serde_json::to_vec_pretty(store).map_err(|error| io(path, error))?;
    write_atomic(path, &bytes).map_err(|error| io(path, error))
}

/// Saves `name` pointing at `rpc`, replacing any earlier network of the same
/// name. `rpc` must already parse the way `--rpc` would take it.
pub fn add(path: &Path, name: &str, rpc: &str) -> Result<(), ProfileError> {
    Endpoint::parse(rpc).map_err(ProfileError::UnknownRpc)?;
    let mut store = load(path)?;
    store.networks.insert(name.to_owned(), rpc.to_owned());
    save(path, &store)
}

/// Removes a saved network. Clears it as the active one if it was.
pub fn remove(path: &Path, name: &str) -> Result<(), ProfileError> {
    let mut store = load(path)?;
    if store.networks.remove(name).is_none() {
        return Err(ProfileError::NotFound(name.to_owned()));
    }
    if store.current.as_deref() == Some(name) {
        store.current = None;
    }
    save(path, &store)
}

/// Makes `name` the active network for future commands that do not pass
/// `--rpc` or set `THRYLOS_RPC`.
pub fn use_network(path: &Path, name: &str) -> Result<(), ProfileError> {
    let mut store = load(path)?;
    if !store.networks.contains_key(name) {
        return Err(ProfileError::NotFound(name.to_owned()));
    }
    store.current = Some(name.to_owned());
    save(path, &store)
}

/// Every saved network and which one, if any, is active.
pub fn list(path: &Path) -> Result<(Option<String>, BTreeMap<String, String>), ProfileError> {
    let store = load(path)?;
    Ok((store.current, store.networks))
}

/// The RPC address of the active network, if one is set.
pub fn active_rpc(path: &Path) -> Result<Option<String>, ProfileError> {
    let store = load(path)?;
    Ok(store
        .current
        .as_ref()
        .and_then(|name| store.networks.get(name).cloned()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn path() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("networks.json");
        (dir, path)
    }

    #[test]
    fn adding_and_using_a_network_makes_it_active() {
        let (_dir, path) = path();
        add(&path, "alpha", "https://rpc.alpha.example").unwrap();
        assert_eq!(active_rpc(&path).unwrap(), None);

        use_network(&path, "alpha").unwrap();
        assert_eq!(
            active_rpc(&path).unwrap().as_deref(),
            Some("https://rpc.alpha.example")
        );

        let (current, networks) = list(&path).unwrap();
        assert_eq!(current.as_deref(), Some("alpha"));
        assert_eq!(
            networks.get("alpha").map(String::as_str),
            Some("https://rpc.alpha.example")
        );
    }

    #[test]
    fn an_invalid_rpc_is_refused_before_it_is_saved() {
        let (_dir, path) = path();
        let error = add(&path, "alpha", "not a url").unwrap_err().to_string();
        assert!(error.contains("needs a port"), "{error}");
        assert_eq!(list(&path).unwrap().1.len(), 0);
    }

    #[test]
    fn using_or_removing_an_unknown_network_says_how_to_add_it() {
        let (_dir, path) = path();
        let error = use_network(&path, "alpha").unwrap_err().to_string();
        assert!(error.contains("thrylos network add alpha"), "{error}");
        let error = remove(&path, "alpha").unwrap_err().to_string();
        assert!(error.contains("thrylos network add alpha"), "{error}");
    }

    #[test]
    fn removing_the_active_network_clears_it() {
        let (_dir, path) = path();
        add(&path, "alpha", "https://rpc.alpha.example").unwrap();
        use_network(&path, "alpha").unwrap();
        remove(&path, "alpha").unwrap();
        assert_eq!(active_rpc(&path).unwrap(), None);
        assert_eq!(list(&path).unwrap().1.len(), 0);
    }
}
