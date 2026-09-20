//! Test fixture representing a node process. It obtains one remote signature,
//! reports success, and waits to be killed while the signer keeps running.

use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;

use chain_node::{RemoteSigner, SignerCredential};
use chain_signer::{ConsensusSigner, HighWaterMark, Step};
use chain_types::{BlockHeight, Round};

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let socket = args
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing socket"))?;
    let credential_path = args
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing credential"))?;
    let credential = SignerCredential::read(&credential_path)?;
    let mut signer = RemoteSigner::connect(&socket, credential, Duration::from_secs(2))?;
    signer
        .sign(
            HighWaterMark::new(BlockHeight(1), Round(0), Step::Propose),
            b"node crash request",
        )
        .map_err(|_| io::Error::other("remote signer refused the request"))?;
    println!("SIGNED");
    io::stdout().flush()?;
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("signer node crash helper: {error}");
        std::process::exit(1);
    }
}
