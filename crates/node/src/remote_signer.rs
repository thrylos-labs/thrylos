//! Authenticated local protocol between the node and its signer process.
//!
//! One request is carried by each Unix-domain connection. The fixed header is
//! read and bounded before allocation. A keyed BLAKE3 MAC is checked before a
//! request is decoded, and the response MAC is bound to that exact request.
//! The protocol exposes only vote/proposal signing, beacon reveals and a mark
//! query; the node cannot choose a BLS domain or ask for key material.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use chain_signer::{ConsensusSigner, HighWaterMark, HighWaterMarkStore, Signer, SignerError, Step};
use chain_types::bls::{BlsSignature, BLS_SIGNATURE_LEN, DST_VOTE};
use chain_types::{BlockHeight, Hash, Round};

const MAGIC: &[u8; 8] = b"THRYSIG1";
const REQUEST_DOMAIN: &[u8] = b"THRYLOS-SIGNER-REQUEST-V1";
const RESPONSE_DOMAIN: &[u8] = b"THRYLOS-SIGNER-RESPONSE-V1";
const HEADER_BYTES: usize = 12;
const MAC_BYTES: usize = 32;
const MARK_BYTES: usize = 17;
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_BYTES: usize = 1 + BLS_SIGNATURE_LEN;

const SIGN: u8 = 0;
const BEACON: u8 = 1;
const MARK: u8 = 2;

const SIGNATURE: u8 = 0;
const CURRENT_MARK: u8 = 1;
const REGRESSION: u8 = 2;
const PERSISTENCE_FAILED: u8 = 3;
const MALFORMED_SIGNATURE: u8 = 4;
const UNAVAILABLE: u8 = 5;

#[derive(Debug)]
pub enum RemoteSignerError {
    Io(std::io::Error),
    InvalidCredential,
    FrameTooLarge,
    AuthenticationFailed,
    Malformed,
}

impl core::fmt::Display for RemoteSignerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "signer protocol I/O: {error}"),
            Self::InvalidCredential => f.write_str("signer credential must be exactly 32 bytes"),
            Self::FrameTooLarge => f.write_str("signer protocol frame exceeds its hard limit"),
            Self::AuthenticationFailed => f.write_str("signer protocol authentication failed"),
            Self::Malformed => f.write_str("malformed signer protocol frame"),
        }
    }
}

impl std::error::Error for RemoteSignerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for RemoteSignerError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone)]
pub struct SignerCredential([u8; MAC_BYTES]);

impl SignerCredential {
    pub const fn from_bytes(bytes: [u8; MAC_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn read(path: &Path) -> Result<Self, RemoteSignerError> {
        let bytes = fs::read(path)?;
        let bytes: [u8; MAC_BYTES] = bytes
            .try_into()
            .map_err(|_| RemoteSignerError::InvalidCredential)?;
        Ok(Self(bytes))
    }
}

/// Node-side handle. It contains the protocol credential and signer socket
/// path, never the consensus secret key.
pub struct RemoteSigner {
    socket: PathBuf,
    credential: SignerCredential,
    timeout: Duration,
    mark: Option<HighWaterMark>,
}

impl RemoteSigner {
    pub fn connect(
        socket: &Path,
        credential: SignerCredential,
        timeout: Duration,
    ) -> Result<Self, RemoteSignerError> {
        if timeout.is_zero() {
            return Err(RemoteSignerError::Malformed);
        }
        let mut client = Self {
            socket: socket.to_path_buf(),
            credential,
            timeout,
            mark: None,
        };
        client.mark = client.query_mark()?;
        Ok(client)
    }

    fn exchange(&self, payload: &[u8]) -> Result<Vec<u8>, RemoteSignerError> {
        let mut stream = UnixStream::connect(&self.socket)?;
        configure(&stream, self.timeout)?;
        let request_mac = write_request(&mut stream, payload, &self.credential)?;
        read_response(&mut stream, &self.credential, &request_mac)
    }

    fn query_mark(&self) -> Result<Option<HighWaterMark>, RemoteSignerError> {
        decode_mark_response(&self.exchange(&[MARK])?)
    }
}

impl ConsensusSigner for RemoteSigner {
    fn high_water_mark(&self) -> Option<HighWaterMark> {
        self.mark
    }

    fn sign(
        &mut self,
        requested: HighWaterMark,
        message: &[u8],
    ) -> Result<BlsSignature, SignerError> {
        let payload =
            encode_sign_request(requested, message).map_err(|_| SignerError::Unavailable)?;
        let response = self
            .exchange(&payload)
            .map_err(|_| SignerError::Unavailable)?;
        let signature = decode_sign_response(&response, requested)?;
        self.mark = Some(requested);
        Ok(signature)
    }

    fn sign_beacon(&self, height: BlockHeight, seed: &Hash) -> Result<BlsSignature, SignerError> {
        let response = self
            .exchange(&encode_beacon_request(height, seed))
            .map_err(|_| SignerError::Unavailable)?;
        decode_sign_response(
            &response,
            HighWaterMark::new(height, Round(0), Step::Propose),
        )
    }
}

/// Signer-process endpoint. The secret key and durable mark remain behind
/// this boundary.
pub struct SignerServer<S: HighWaterMarkStore> {
    listener: UnixListener,
    socket: PathBuf,
    credential: SignerCredential,
    signer: Signer<S>,
    timeout: Duration,
}

impl<S: HighWaterMarkStore> SignerServer<S> {
    pub fn bind(
        socket: &Path,
        credential: SignerCredential,
        signer: Signer<S>,
        timeout: Duration,
    ) -> Result<Self, RemoteSignerError> {
        if timeout.is_zero() {
            return Err(RemoteSignerError::Malformed);
        }
        remove_stale_socket(socket)?;
        let listener = UnixListener::bind(socket)?;
        fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
        Ok(Self {
            listener,
            socket: socket.to_path_buf(),
            credential,
            signer,
            timeout,
        })
    }

    pub fn serve(&mut self) -> Result<(), RemoteSignerError> {
        loop {
            let (stream, _) = self.listener.accept()?;
            let _ = self.handle_stream(stream);
        }
    }

    fn handle_stream(&mut self, mut stream: UnixStream) -> Result<(), RemoteSignerError> {
        configure(&stream, self.timeout)?;
        let (payload, request_mac) = read_request(&mut stream, &self.credential)?;
        let response = process_request(&mut self.signer, &payload)?;
        write_response(&mut stream, &response, &self.credential, &request_mac)
    }
}

impl<S: HighWaterMarkStore> Drop for SignerServer<S> {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket);
    }
}

fn configure(stream: &UnixStream, timeout: Duration) -> Result<(), RemoteSignerError> {
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    Ok(())
}

fn remove_stale_socket(path: &Path) -> Result<(), RemoteSignerError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            fs::remove_file(path).map_err(Into::into)
        }
        Ok(_) => Err(RemoteSignerError::Malformed),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn header(length: usize) -> Result<[u8; HEADER_BYTES], RemoteSignerError> {
    let length = u32::try_from(length).map_err(|_| RemoteSignerError::FrameTooLarge)?;
    let mut header = [0u8; HEADER_BYTES];
    header
        .get_mut(..8)
        .ok_or(RemoteSignerError::Malformed)?
        .copy_from_slice(MAGIC);
    header
        .get_mut(8..)
        .ok_or(RemoteSignerError::Malformed)?
        .copy_from_slice(&length.to_be_bytes());
    Ok(header)
}

fn parse_header(bytes: &[u8; HEADER_BYTES], maximum: usize) -> Result<usize, RemoteSignerError> {
    if bytes.get(..8) != Some(MAGIC.as_slice()) {
        return Err(RemoteSignerError::Malformed);
    }
    let length: [u8; 4] = bytes
        .get(8..)
        .ok_or(RemoteSignerError::Malformed)?
        .try_into()
        .map_err(|_| RemoteSignerError::Malformed)?;
    let length = usize::try_from(u32::from_be_bytes(length))
        .map_err(|_| RemoteSignerError::FrameTooLarge)?;
    if length > maximum {
        return Err(RemoteSignerError::FrameTooLarge);
    }
    Ok(length)
}

fn mac(
    credential: &SignerCredential,
    domain: &[u8],
    binding: &[u8],
    header: &[u8; HEADER_BYTES],
    payload: &[u8],
) -> [u8; MAC_BYTES] {
    let mut hasher = blake3::Hasher::new_keyed(&credential.0);
    hasher.update(domain);
    hasher.update(binding);
    hasher.update(header);
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

fn authentic(expected: &[u8; MAC_BYTES], received: &[u8; MAC_BYTES]) -> bool {
    expected
        .iter()
        .zip(received)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

fn write_request(
    stream: &mut UnixStream,
    payload: &[u8],
    credential: &SignerCredential,
) -> Result<[u8; MAC_BYTES], RemoteSignerError> {
    if payload.len() > MAX_REQUEST_BYTES {
        return Err(RemoteSignerError::FrameTooLarge);
    }
    let header = header(payload.len())?;
    let request_mac = mac(credential, REQUEST_DOMAIN, &[], &header, payload);
    stream.write_all(&header)?;
    stream.write_all(payload)?;
    stream.write_all(&request_mac)?;
    stream.flush()?;
    Ok(request_mac)
}

fn read_request(
    stream: &mut UnixStream,
    credential: &SignerCredential,
) -> Result<(Vec<u8>, [u8; MAC_BYTES]), RemoteSignerError> {
    let mut header = [0u8; HEADER_BYTES];
    stream.read_exact(&mut header)?;
    let length = parse_header(&header, MAX_REQUEST_BYTES)?;
    let mut payload = vec![0u8; length];
    stream.read_exact(&mut payload)?;
    let mut received = [0u8; MAC_BYTES];
    stream.read_exact(&mut received)?;
    let expected = mac(credential, REQUEST_DOMAIN, &[], &header, &payload);
    if !authentic(&expected, &received) {
        return Err(RemoteSignerError::AuthenticationFailed);
    }
    Ok((payload, expected))
}

fn write_response(
    stream: &mut UnixStream,
    payload: &[u8],
    credential: &SignerCredential,
    request_mac: &[u8; MAC_BYTES],
) -> Result<(), RemoteSignerError> {
    if payload.len() > MAX_RESPONSE_BYTES {
        return Err(RemoteSignerError::FrameTooLarge);
    }
    let header = header(payload.len())?;
    let response_mac = mac(credential, RESPONSE_DOMAIN, request_mac, &header, payload);
    stream.write_all(&header)?;
    stream.write_all(payload)?;
    stream.write_all(&response_mac)?;
    stream.flush()?;
    Ok(())
}

fn read_response(
    stream: &mut UnixStream,
    credential: &SignerCredential,
    request_mac: &[u8; MAC_BYTES],
) -> Result<Vec<u8>, RemoteSignerError> {
    let mut header = [0u8; HEADER_BYTES];
    stream.read_exact(&mut header)?;
    let length = parse_header(&header, MAX_RESPONSE_BYTES)?;
    let mut payload = vec![0u8; length];
    stream.read_exact(&mut payload)?;
    let mut received = [0u8; MAC_BYTES];
    stream.read_exact(&mut received)?;
    let expected = mac(credential, RESPONSE_DOMAIN, request_mac, &header, &payload);
    if !authentic(&expected, &received) {
        return Err(RemoteSignerError::AuthenticationFailed);
    }
    Ok(payload)
}

fn encode_mark(mark: HighWaterMark, out: &mut Vec<u8>) {
    out.extend_from_slice(&mark.height.0.to_be_bytes());
    out.extend_from_slice(&mark.round.0.to_be_bytes());
    out.push(mark.step as u8);
}

fn decode_mark(bytes: &[u8]) -> Result<HighWaterMark, RemoteSignerError> {
    if bytes.len() != MARK_BYTES {
        return Err(RemoteSignerError::Malformed);
    }
    let height = u64::from_be_bytes(
        bytes
            .get(..8)
            .ok_or(RemoteSignerError::Malformed)?
            .try_into()
            .map_err(|_| RemoteSignerError::Malformed)?,
    );
    let round = u64::from_be_bytes(
        bytes
            .get(8..16)
            .ok_or(RemoteSignerError::Malformed)?
            .try_into()
            .map_err(|_| RemoteSignerError::Malformed)?,
    );
    let step = match bytes.get(16).copied() {
        Some(0) => Step::Propose,
        Some(1) => Step::Prevote,
        Some(2) => Step::Precommit,
        _ => return Err(RemoteSignerError::Malformed),
    };
    Ok(HighWaterMark::new(BlockHeight(height), Round(round), step))
}

fn encode_sign_request(mark: HighWaterMark, message: &[u8]) -> Result<Vec<u8>, RemoteSignerError> {
    let capacity = 1usize
        .checked_add(MARK_BYTES)
        .and_then(|value| value.checked_add(message.len()))
        .ok_or(RemoteSignerError::FrameTooLarge)?;
    if capacity > MAX_REQUEST_BYTES {
        return Err(RemoteSignerError::FrameTooLarge);
    }
    let mut out = Vec::with_capacity(capacity);
    out.push(SIGN);
    encode_mark(mark, &mut out);
    out.extend_from_slice(message);
    Ok(out)
}

fn encode_beacon_request(height: BlockHeight, seed: &Hash) -> Vec<u8> {
    let mut out = Vec::with_capacity(41);
    out.push(BEACON);
    out.extend_from_slice(&height.0.to_be_bytes());
    out.extend_from_slice(seed.as_bytes());
    out
}

fn process_request<S: HighWaterMarkStore>(
    signer: &mut Signer<S>,
    payload: &[u8],
) -> Result<Vec<u8>, RemoteSignerError> {
    match payload.first().copied() {
        Some(SIGN) => {
            let mark = decode_mark(payload.get(1..18).ok_or(RemoteSignerError::Malformed)?)?;
            let message = payload.get(18..).ok_or(RemoteSignerError::Malformed)?;
            Ok(encode_signer_result(signer.sign(mark, message, DST_VOTE)))
        }
        Some(BEACON) if payload.len() == 41 => {
            let height = u64::from_be_bytes(
                payload
                    .get(1..9)
                    .ok_or(RemoteSignerError::Malformed)?
                    .try_into()
                    .map_err(|_| RemoteSignerError::Malformed)?,
            );
            let seed: [u8; 32] = payload
                .get(9..41)
                .ok_or(RemoteSignerError::Malformed)?
                .try_into()
                .map_err(|_| RemoteSignerError::Malformed)?;
            Ok(encode_signer_result(
                signer.sign_beacon(BlockHeight(height), &Hash::from_bytes(seed)),
            ))
        }
        Some(MARK) if payload.len() == 1 => {
            let mut out = Vec::with_capacity(2usize.saturating_add(MARK_BYTES));
            out.push(CURRENT_MARK);
            match signer.high_water_mark() {
                Some(mark) => {
                    out.push(1);
                    encode_mark(mark, &mut out);
                }
                None => out.push(0),
            }
            Ok(out)
        }
        _ => Err(RemoteSignerError::Malformed),
    }
}

fn encode_signer_result(result: Result<BlsSignature, SignerError>) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + BLS_SIGNATURE_LEN);
    match result {
        Ok(signature) => {
            out.push(SIGNATURE);
            out.extend_from_slice(&signature.to_bytes());
        }
        Err(SignerError::Regression { mark, .. }) => {
            out.push(REGRESSION);
            encode_mark(mark, &mut out);
        }
        Err(SignerError::PersistenceFailed) => out.push(PERSISTENCE_FAILED),
        Err(SignerError::MalformedSignature) => out.push(MALFORMED_SIGNATURE),
        Err(SignerError::Unavailable) => out.push(UNAVAILABLE),
    }
    out
}

fn decode_sign_response(
    payload: &[u8],
    requested: HighWaterMark,
) -> Result<BlsSignature, SignerError> {
    match payload.first().copied() {
        Some(SIGNATURE) if payload.len() == 1usize.saturating_add(BLS_SIGNATURE_LEN) => {
            let bytes: [u8; BLS_SIGNATURE_LEN] = payload
                .get(1..)
                .ok_or(SignerError::Unavailable)?
                .try_into()
                .map_err(|_| SignerError::Unavailable)?;
            BlsSignature::from_bytes(bytes).map_err(|_| SignerError::MalformedSignature)
        }
        Some(REGRESSION) => {
            let mark = decode_mark(payload.get(1..).ok_or(SignerError::Unavailable)?)
                .map_err(|_| SignerError::Unavailable)?;
            Err(SignerError::Regression { requested, mark })
        }
        Some(PERSISTENCE_FAILED) if payload.len() == 1 => Err(SignerError::PersistenceFailed),
        Some(MALFORMED_SIGNATURE) if payload.len() == 1 => Err(SignerError::MalformedSignature),
        Some(UNAVAILABLE) if payload.len() == 1 => Err(SignerError::Unavailable),
        _ => Err(SignerError::Unavailable),
    }
}

fn decode_mark_response(payload: &[u8]) -> Result<Option<HighWaterMark>, RemoteSignerError> {
    if payload.first().copied() != Some(CURRENT_MARK) {
        return Err(RemoteSignerError::Malformed);
    }
    match payload.get(1).copied() {
        Some(0) if payload.len() == 2 => Ok(None),
        Some(1) if payload.len() == 2usize.saturating_add(MARK_BYTES) => payload
            .get(2..)
            .ok_or(RemoteSignerError::Malformed)
            .and_then(decode_mark)
            .map(Some),
        _ => Err(RemoteSignerError::Malformed),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn an_oversized_declared_request_is_rejected_from_its_header() {
        let bytes = header(MAX_REQUEST_BYTES.saturating_add(1)).unwrap();
        assert!(matches!(
            parse_header(&bytes, MAX_REQUEST_BYTES),
            Err(RemoteSignerError::FrameTooLarge)
        ));
    }
}
