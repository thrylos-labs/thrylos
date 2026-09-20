//! Minimal signer process. The secret key and high-water mark are read only
//! here; the node connects through the authenticated Unix-socket protocol.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use blst::min_pk::SecretKey;
use chain_node::{FileMarkStore, SignerCredential, SignerServer};
use chain_signer::Signer;

const USAGE: &str = "usage: chain-signer <socket> <key-file> <credential-file> <mark-file>";

fn required_path(
    args: &mut impl Iterator<Item = std::ffi::OsString>,
    name: &str,
) -> Result<PathBuf, io::Error> {
    args.next().map(PathBuf::from).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("missing {name}; {USAGE}"),
        )
    })
}

fn private_file(path: &Path) -> Result<Vec<u8>, io::Error> {
    let metadata = fs::metadata(path)?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} must not be accessible by group or other users; run: chmod 600 {}",
                path.display(),
                path.display()
            ),
        ));
    }
    fs::read(path)
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1).peekable();
    match args.peek().and_then(|arg| arg.to_str()) {
        Some("-h" | "--help") => {
            println!("{USAGE}");
            return Ok(());
        }
        Some("-V" | "--version") => {
            println!("chain-signer {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        _ => {}
    }
    let socket = required_path(&mut args, "socket")?;
    let key_path = required_path(&mut args, "key file")?;
    let credential_path = required_path(&mut args, "credential file")?;
    let mark_path = required_path(&mut args, "mark file")?;
    if args.next().is_some() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "too many arguments").into());
    }

    let key_bytes = private_file(&key_path)?;
    let secret = SecretKey::from_bytes(&key_bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "consensus key file is not one 32-byte BLS secret key",
        )
    })?;
    let credential_bytes = private_file(&credential_path)?;
    let credential_array: [u8; 32] = credential_bytes.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "signer credential file must contain exactly 32 bytes",
        )
    })?;
    let credential = SignerCredential::from_bytes(credential_array);
    let signer = Signer::load(secret, FileMarkStore::open(&mark_path))?;
    let mut server = SignerServer::bind(&socket, credential, signer, Duration::from_secs(5))?;
    server.serve()?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("chain-signer: {error}");
        std::process::exit(1);
    }
}
