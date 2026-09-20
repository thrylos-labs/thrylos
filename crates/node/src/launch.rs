//! Running a generated network: one process per signer and one per node.
//!
//! [`launch`] starts each node's `chain-signer`, waits until it accepts
//! connections (a node refuses to start without its signer), starts each
//! `chain-node`, and then watches them. Each process's output goes to a log
//! beside its files (`signer.log`, `node.log`), appended to, so a restart keeps
//! what came before.
//!
//! It returns when every node has exited, or, if it was given a height, when
//! every node still running has committed it (it reads that from the node's
//! log) and stops them. It does not give the nodes the height to stop at
//! themselves: a node that joins late has to be waited for, and one that had
//! stopped could not be helped to catch up. Without a height a healthy network
//! never returns; interrupt it.
//!
//! Nodes are stopped through the pipe each is given as its standard input:
//! closing it makes a node stop between one thing it does and the next, never
//! in the middle of signing (see `chain-node run --stop-when-stdin-closes`), so
//! what it leaves on disk can be started from again. The same happens if this
//! process is killed outright, since its pipes close with it. Ctrl-C is
//! different: it reaches every process at once and stops each wherever it is,
//! which can leave a node unable to restart (see that flag's documentation).
//! Signers, which are idle once their nodes have stopped, are killed. A failure
//! or a panic here kills whatever was started.

// Waiting for a signer and for nodes is real time, which nothing here feeds
// into consensus.
#![allow(clippy::disallowed_methods)]

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::config::{ConfigError, NodeConfig};
use crate::devnet::{nodes_in, DevnetError, NodeDir};
use crate::event_loop::committed_height;

/// How long a signer has to start accepting connections.
const SIGNER_PATIENCE: Duration = Duration::from_secs(10);
/// How long a node has to stop once told to.
const STOP_PATIENCE: Duration = Duration::from_secs(15);
const POLL: Duration = Duration::from_millis(50);

/// Why a network could not be run, or how it ended.
#[derive(Debug)]
pub enum LaunchError {
    Network(DevnetError),
    Config {
        node: usize,
        error: ConfigError,
    },
    /// A process could not be started.
    Spawn {
        what: String,
        error: String,
    },
    /// A log file could not be opened.
    Log {
        path: PathBuf,
        error: String,
    },
    /// A signer did not come up.
    Signer {
        node: usize,
        problem: String,
    },
    /// Some nodes ended other than by reaching their height.
    NodesFailed(Vec<(usize, String)>),
}

impl core::fmt::Display for LaunchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Network(error) => write!(f, "{error}"),
            Self::Config { node, error } => write!(f, "node {node}: {error}"),
            Self::Spawn { what, error } => write!(f, "could not start {what}: {error}"),
            Self::Log { path, error } => write!(f, "{}: {error}", path.display()),
            Self::Signer { node, problem } => write!(f, "the signer of node {node}: {problem}"),
            Self::NodesFailed(nodes) => {
                let list: Vec<String> = nodes
                    .iter()
                    .map(|(node, how)| format!("node {node} {how}"))
                    .collect();
                write!(f, "{}", list.join("; "))
            }
        }
    }
}

impl std::error::Error for LaunchError {}

impl From<DevnetError> for LaunchError {
    fn from(error: DevnetError) -> Self {
        Self::Network(error)
    }
}

/// What to run, and until when.
#[derive(Debug, Clone, Copy)]
pub struct LaunchOptions<'a> {
    pub node_exe: &'a Path,
    pub signer_exe: &'a Path,
    /// Stop the network once every node still running has committed this
    /// height.
    pub until_height: Option<u64>,
}

/// Processes to kill when it goes out of scope, however that happens.
#[derive(Default)]
struct Children(Vec<Child>);

impl Drop for Children {
    fn drop(&mut self) {
        for child in &mut self.0 {
            // Already gone is fine: there is nothing left to kill.
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn append_log(path: &Path) -> Result<File, LaunchError> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| LaunchError::Log {
            path: path.to_path_buf(),
            error: error.to_string(),
        })
}

fn spawn(
    what: String,
    command: &mut Command,
    stdin: Stdio,
    log: &Path,
) -> Result<Child, LaunchError> {
    let file = append_log(log)?;
    let second = file.try_clone().map_err(|error| LaunchError::Log {
        path: log.to_path_buf(),
        error: error.to_string(),
    })?;
    command
        .stdin(stdin)
        .stdout(file)
        .stderr(second)
        .spawn()
        .map_err(|error| LaunchError::Spawn {
            what,
            error: error.to_string(),
        })
}

/// Waits until something accepts connections at `socket`. A leftover socket
/// file from an earlier run refuses them, so its existence proves nothing.
fn wait_for_signer(socket: &Path, signer: &mut Child, node: usize) -> Result<(), LaunchError> {
    let started = Instant::now();
    loop {
        if UnixStream::connect(socket).is_ok() {
            return Ok(());
        }
        if let Ok(Some(status)) = signer.try_wait() {
            return Err(LaunchError::Signer {
                node,
                problem: format!("exited with {status} before it was ready; see its signer.log"),
            });
        }
        if started.elapsed() >= SIGNER_PATIENCE {
            return Err(LaunchError::Signer {
                node,
                problem: format!(
                    "did not accept connections within {} seconds",
                    SIGNER_PATIENCE.as_secs()
                ),
            });
        }
        thread::sleep(POLL);
    }
}

fn describe(status: ExitStatus) -> String {
    if status.success() {
        "finished".to_owned()
    } else {
        format!("exited with {status}")
    }
}

/// Runs the network in `dir` until every node has exited. `say` is told, as it
/// happens, what was started and what has ended.
pub fn launch(
    dir: &Path,
    options: LaunchOptions<'_>,
    say: &mut dyn FnMut(String),
) -> Result<(), LaunchError> {
    let mut nodes: Vec<(NodeDir, NodeConfig)> = Vec::new();
    for node in nodes_in(dir)? {
        let config = NodeConfig::load(&node.config()).map_err(|error| LaunchError::Config {
            node: node.number,
            error,
        })?;
        nodes.push((node, config));
    }

    let mut signers = Children::default();
    for (node, config) in &nodes {
        let mut command = Command::new(options.signer_exe);
        command
            .arg(&config.signer_socket)
            .arg(node.signer_key())
            .arg(&config.signer_credential)
            .arg(node.signer_mark());
        let child = spawn(
            format!("the signer of node {}", node.number),
            &mut command,
            Stdio::null(),
            &node.signer_log(),
        )?;
        signers.0.push(child);
    }
    for ((node, config), signer) in nodes.iter().zip(signers.0.iter_mut()) {
        wait_for_signer(&config.signer_socket, signer, node.number)?;
    }

    let mut processes = Children::default();
    // The write ends of the nodes' standard input; closing one stops its node.
    let mut stoppers: Vec<Option<ChildStdin>> = Vec::with_capacity(nodes.len());
    let mut logs_from = Vec::with_capacity(nodes.len());
    for ((node, config), signer) in nodes.iter().zip(signers.0.iter()) {
        // The log is appended to across runs: only what this run writes counts.
        logs_from.push(fs::metadata(node.node_log()).map_or(0, |meta| meta.len()));
        let mut command = Command::new(options.node_exe);
        command
            .arg("run")
            .arg(node.config())
            .arg("--stop-when-stdin-closes");
        let mut child = spawn(
            format!("node {}", node.number),
            &mut command,
            Stdio::piped(),
            &node.node_log(),
        )?;
        stoppers.push(child.stdin.take());
        say(format!(
            "node {}  {}  listening on {}  pid {} (signer pid {})  log {}",
            node.number,
            chain_text::format_address(&config.validator),
            config.listen,
            child.id(),
            signer.id(),
            node.node_log().display()
        ));
        processes.0.push(child);
    }

    let mut ended: Vec<Option<ExitStatus>> = vec![None; nodes.len()];
    let mut reached = vec![false; nodes.len()];
    let mut signer_gone = vec![false; nodes.len()];
    // Done when no node is both still running and short of the height: with no
    // height to reach, when every node has ended.
    while ended
        .iter()
        .zip(&reached)
        .any(|(ended, reached)| ended.is_none() && !reached)
    {
        for (((node, _), child), outcome) in
            nodes.iter().zip(processes.0.iter_mut()).zip(&mut ended)
        {
            if outcome.is_none() {
                if let Ok(Some(status)) = child.try_wait() {
                    say(format!("node {} {}", node.number, describe(status)));
                    *outcome = Some(status);
                }
            }
        }
        if let Some(target) = options.until_height {
            for ((((node, _), from), outcome), done) in
                nodes.iter().zip(&logs_from).zip(&ended).zip(&mut reached)
            {
                if !*done && outcome.is_none() && committed_since(&node.node_log(), *from) >= target
                {
                    say(format!("node {} reached height {target}", node.number));
                    *done = true;
                }
            }
        }
        for (((node, _), signer), gone) in
            nodes.iter().zip(signers.0.iter_mut()).zip(&mut signer_gone)
        {
            if !*gone {
                if let Ok(Some(status)) = signer.try_wait() {
                    say(format!(
                        "the signer of node {} exited with {status}; that node cannot vote on",
                        node.number
                    ));
                    *gone = true;
                }
            }
        }
        thread::sleep(POLL);
    }

    // Tell the nodes still running to stop, and wait for them to.
    if ended.iter().any(Option::is_none) {
        say("stopping the nodes".to_owned());
        stoppers.clear();
        let asked = Instant::now();
        while ended.iter().any(Option::is_none) && asked.elapsed() < STOP_PATIENCE {
            for (((node, _), child), outcome) in
                nodes.iter().zip(processes.0.iter_mut()).zip(&mut ended)
            {
                if outcome.is_none() {
                    if let Ok(Some(status)) = child.try_wait() {
                        say(format!("node {} stopped: {status}", node.number));
                        *outcome = Some(status);
                    }
                }
            }
            thread::sleep(POLL);
        }
    }
    // Any that did not stop are killed as `processes` goes out of scope.
    let failed: Vec<(usize, String)> = nodes
        .iter()
        .zip(&ended)
        .filter_map(|((node, _), status)| match status {
            Some(status) if !status.success() => Some((node.number, describe(*status))),
            _ => None,
        })
        .collect();
    if failed.is_empty() {
        Ok(())
    } else {
        Err(LaunchError::NodesFailed(failed))
    }
}

/// The highest block the log at `path` says was committed, counting only what
/// was written after its first `from` bytes.
fn committed_since(path: &Path, from: u64) -> u64 {
    let mut text = String::new();
    let read = File::open(path).and_then(|mut file| {
        file.seek(SeekFrom::Start(from))?;
        file.read_to_string(&mut text)
    });
    if read.is_err() {
        return 0;
    }
    text.lines().filter_map(committed_height).max().unwrap_or(0)
}
