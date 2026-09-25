//! Running a generated network: one process per signer and one per node.
//!
//! [`launch`] starts each node's `chain-signer`, waits until it accepts
//! connections (a node refuses to start without its signer), starts each
//! `chain-node`, and then watches them. Each process's output goes to a log
//! beside its files (`signer.log`, `node.log`), appended to, so a restart keeps
//! what came before.
//!
//! **A node or signer that dies is started again** when the network is run as a
//! service (no height given): after a wait that doubles from a few seconds up to
//! a minute, and only if it did not run for a while before it died the last
//! several times, so a node that fails at once does not spin. A validator that
//! stops itself because it could not reach its signer (which is what it does
//! rather than risk signing twice) used to stay down for good while the others
//! carried on without it, and with two of four down the network stopped for
//! nine hours. Starting it again is the recovery that halt is designed for: the
//! node restores its chain and replays what it had signed.
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
//! process is killed outright, since its pipes close with it. Ctrl-C reaches
//! every process at once and stops each wherever it is, which a node and its
//! signer also survive. Signers, which are idle once their nodes have stopped,
//! are killed. A failure
//! or a panic here kills whatever was started.

// Waiting for a signer and for nodes is real time, which nothing here feeds
// into consensus.
#![allow(clippy::disallowed_methods)]

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::net::SocketAddr;
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
    /// Start a node or signer that dies again, as a service should. `None`
    /// leaves it dead, as a run to a set height wants.
    pub restart: Option<RestartPolicy>,
}

/// How a dead node or signer is started again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartPolicy {
    /// The wait before the first restart; it doubles for each one after.
    pub initial_wait: Duration,
    /// The longest the wait grows to.
    pub max_wait: Duration,
    /// A run at least this long counts as having worked, and forgets the
    /// failures before it.
    pub stable_after: Duration,
    /// Give up on a node after this many failures in a row, none of which ran
    /// for `stable_after`. It stays down, and says so.
    pub give_up_after: u32,
}

impl RestartPolicy {
    /// What a network run as a service uses.
    pub const fn service() -> Self {
        Self {
            initial_wait: Duration::from_secs(5),
            max_wait: Duration::from_secs(60),
            stable_after: Duration::from_secs(120),
            give_up_after: 8,
        }
    }

    /// The wait before the restart that follows the `failures`th failure in a row.
    pub fn wait_after(&self, failures: u32) -> Duration {
        let doublings = failures.saturating_sub(1).min(16);
        self.initial_wait
            .saturating_mul(1u32 << doublings)
            .min(self.max_wait)
    }
}

/// Where a node or signer is in being kept running.
struct Upkeep {
    started: Instant,
    /// Failures in a row that did not run for the policy's `stable_after`.
    failures: u32,
    /// When to start it again, if it is waiting to be.
    retry_at: Option<Instant>,
}

impl Upkeep {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            failures: 0,
            retry_at: None,
        }
    }
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

fn spawn_node(node: &NodeDir, node_exe: &Path) -> Result<Child, LaunchError> {
    let mut command = Command::new(node_exe);
    command
        .arg("run")
        .arg(node.config())
        .arg("--stop-when-stdin-closes");
    spawn(
        format!("node {}", node.number),
        &mut command,
        Stdio::piped(),
        &node.node_log(),
    )
}

fn spawn_signer(
    node: &NodeDir,
    config: &NodeConfig,
    signer_exe: &Path,
) -> Result<Child, LaunchError> {
    let mut command = Command::new(signer_exe);
    command
        .arg(&config.signer_socket)
        .arg(node.signer_key())
        .arg(&config.signer_credential)
        .arg(node.signer_mark());
    spawn(
        format!("the signer of node {}", node.number),
        &mut command,
        Stdio::null(),
        &node.signer_log(),
    )
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
        signers
            .0
            .push(spawn_signer(node, config, options.signer_exe)?);
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
        let mut child = spawn_node(node, options.node_exe)?;
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

    let rpcs: Vec<(usize, SocketAddr)> = nodes
        .iter()
        .filter_map(|(node, config)| config.rpc_listen.map(|address| (node.number, address)))
        .collect();
    let first_log = nodes.first().map(|(node, _)| node.node_log());
    for line in next_steps(
        options.node_exe,
        dir,
        first_log.as_deref(),
        &rpcs,
        options.until_height,
    ) {
        say(line);
    }

    let mut ended: Vec<Option<ExitStatus>> = vec![None; nodes.len()];
    let mut reached = vec![false; nodes.len()];
    let mut signer_gone = vec![false; nodes.len()];
    let mut node_upkeep: Vec<Upkeep> = nodes.iter().map(|_| Upkeep::new()).collect();
    let mut signer_upkeep: Vec<Upkeep> = nodes.iter().map(|_| Upkeep::new()).collect();
    // Done when no node is both still running and short of the height: with no
    // height to reach, when every node has ended.
    while ended
        .iter()
        .zip(&reached)
        .any(|(ended, reached)| ended.is_none() && !reached)
    {
        for index in 0..nodes.len() {
            let Some((node, _)) = nodes.get(index) else {
                continue;
            };
            if ended.get(index).is_some_and(Option::is_some) {
                continue;
            }
            let (Some(child), Some(upkeep), Some(outcome)) = (
                processes.0.get_mut(index),
                node_upkeep.get_mut(index),
                ended.get_mut(index),
            ) else {
                continue;
            };
            // Waiting to be started again.
            if let Some(at) = upkeep.retry_at {
                if Instant::now() < at {
                    continue;
                }
                match spawn_node(node, options.node_exe) {
                    Ok(mut fresh) => {
                        if let Some(slot) = stoppers.get_mut(index) {
                            *slot = fresh.stdin.take();
                        }
                        say(format!(
                            "node {} started again (pid {}, failure {} in a row)",
                            node.number,
                            fresh.id(),
                            upkeep.failures
                        ));
                        *child = fresh;
                        upkeep.started = Instant::now();
                        upkeep.retry_at = None;
                    }
                    Err(error) => {
                        say(format!(
                            "node {} could not be started again: {error}",
                            node.number
                        ));
                        upkeep.failures = upkeep.failures.saturating_add(1);
                        let Some(policy) = options.restart else {
                            continue;
                        };
                        if upkeep.failures >= policy.give_up_after {
                            say(format!("giving up on node {}", node.number));
                            *outcome = child.try_wait().ok().flatten().or(*outcome);
                        } else {
                            upkeep.retry_at =
                                Instant::now().checked_add(policy.wait_after(upkeep.failures));
                        }
                    }
                }
                continue;
            }
            let Ok(Some(status)) = child.try_wait() else {
                continue;
            };
            say(format!("node {} {}", node.number, describe(status)));
            match options.restart {
                // A service keeps its nodes running; only a clean finish is left alone.
                Some(policy) if !status.success() => {
                    if upkeep.started.elapsed() >= policy.stable_after {
                        upkeep.failures = 0;
                    }
                    upkeep.failures = upkeep.failures.saturating_add(1);
                    if upkeep.failures >= policy.give_up_after {
                        say(format!(
                            "node {} keeps failing straight after it starts ({} times in a row); leaving it stopped, and its log will say why",
                            node.number, upkeep.failures
                        ));
                        *outcome = Some(status);
                    } else {
                        let wait = policy.wait_after(upkeep.failures);
                        say(format!(
                            "node {} will be started again in {}s",
                            node.number,
                            wait.as_secs()
                        ));
                        upkeep.retry_at = Instant::now().checked_add(wait);
                    }
                }
                _ => *outcome = Some(status),
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
        for index in 0..nodes.len() {
            let Some((node, config)) = nodes.get(index) else {
                continue;
            };
            let (Some(signer), Some(gone), Some(upkeep)) = (
                signers.0.get_mut(index),
                signer_gone.get_mut(index),
                signer_upkeep.get_mut(index),
            ) else {
                continue;
            };
            if *gone {
                continue;
            }
            let Ok(Some(status)) = signer.try_wait() else {
                continue;
            };
            let Some(policy) = options.restart else {
                say(format!(
                    "the signer of node {} exited with {status}; that node cannot vote on",
                    node.number
                ));
                *gone = true;
                continue;
            };
            // A signer that died is started again at once, and waited for, since its node
            // cannot sign without it. It goes through the same limit as a node does.
            if upkeep.started.elapsed() >= policy.stable_after {
                upkeep.failures = 0;
            }
            upkeep.failures = upkeep.failures.saturating_add(1);
            say(format!(
                "the signer of node {} exited with {status}",
                node.number
            ));
            if upkeep.failures >= policy.give_up_after {
                say(format!(
                    "the signer of node {} keeps failing; leaving it stopped, so that node cannot vote on",
                    node.number
                ));
                *gone = true;
                continue;
            }
            thread::sleep(policy.wait_after(upkeep.failures));
            match spawn_signer(node, config, options.signer_exe) {
                Ok(mut fresh) => {
                    match wait_for_signer(&config.signer_socket, &mut fresh, node.number) {
                        Ok(()) => {
                            say(format!("the signer of node {} started again", node.number));
                            *signer = fresh;
                            upkeep.started = Instant::now();
                        }
                        Err(error) => {
                            say(format!(
                                "the signer of node {} did not come back: {error}",
                                node.number
                            ));
                            *signer = fresh;
                        }
                    }
                }
                Err(error) => {
                    say(format!(
                        "the signer of node {} could not be started again: {error}",
                        node.number
                    ));
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

/// What to tell someone who has just started a network: how it stops, where its
/// RPCs are, and what to try next, with commands they can paste as they are.
fn next_steps(
    exe: &Path,
    dir: &Path,
    first_log: Option<&Path>,
    rpcs: &[(usize, SocketAddr)],
    until_height: Option<u64>,
) -> Vec<String> {
    let mut lines = vec![String::new()];
    lines.push(match until_height {
        None => "the network is running: Ctrl-C stops every node.".to_owned(),
        Some(height) => format!(
            "the network is running until every node has block {height}: Ctrl-C stops it sooner."
        ),
    });
    if !rpcs.is_empty() {
        lines.push("RPC (JSON-RPC over HTTP, from this machine only):".to_owned());
        for (number, address) in rpcs {
            lines.push(format!("  node {number}  http://{address}"));
        }
    }
    lines.push("to try, in another terminal:".to_owned());
    // The descriptions are shell comments, so a whole line can be pasted as it is.
    lines.push(format!(
        "  {} devnet bump {}    # send a transaction and watch it get included",
        exe.display(),
        dir.display()
    ));
    lines.push(format!(
        "  {} devnet check {}   # is it committing, and do the nodes agree?",
        exe.display(),
        dir.display()
    ));
    let explorer = exe.with_file_name(format!("chain-explorer{}", std::env::consts::EXE_SUFFIX));
    lines.push(format!(
        "  {} {}    # browse blocks, transactions, accounts and network health",
        explorer.display(),
        dir.display()
    ));
    if let Some(log) = first_log {
        lines.push(format!(
            "  tail -f {}    # watch blocks being made",
            log.display()
        ));
    }
    lines.push(String::new());
    lines
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    fn rpcs() -> Vec<(usize, SocketAddr)> {
        vec![
            (1, "127.0.0.1:26660".parse().unwrap()),
            (2, "127.0.0.1:26661".parse().unwrap()),
        ]
    }

    fn said(until: Option<u64>, rpcs: &[(usize, SocketAddr)]) -> String {
        next_steps(
            Path::new("/opt/chain-node"),
            Path::new("/tmp/thrylos-devnet"),
            Some(Path::new("/tmp/thrylos-devnet/node1/node.log")),
            rpcs,
            until,
        )
        .join("\n")
    }

    #[test]
    fn a_network_that_runs_until_stopped_says_how_to_stop_it_where_its_rpcs_are_and_what_to_try() {
        let text = said(None, &rpcs());
        assert!(text.contains("Ctrl-C stops every node"), "{text}");
        assert!(text.contains("node 1  http://127.0.0.1:26660"), "{text}");
        assert!(text.contains("node 2  http://127.0.0.1:26661"), "{text}");
        // Commands that can be pasted as they are: the program and the directory.
        assert!(
            text.contains("/opt/chain-node devnet bump /tmp/thrylos-devnet"),
            "{text}"
        );
        assert!(
            text.contains("/opt/chain-node devnet check /tmp/thrylos-devnet"),
            "{text}"
        );
        assert!(
            text.contains("/opt/chain-explorer /tmp/thrylos-devnet"),
            "{text}"
        );
        assert!(
            text.contains("tail -f /tmp/thrylos-devnet/node1/node.log"),
            "{text}"
        );
    }

    #[test]
    fn every_command_in_the_note_can_be_pasted_whole_because_its_description_is_a_comment() {
        let text = said(None, &rpcs());
        let commands: Vec<&str> = text
            .lines()
            .filter(|line| {
                line.contains("devnet bump")
                    || line.contains("devnet check")
                    || line.contains("chain-explorer")
                    || line.contains("tail -f")
            })
            .collect();
        assert_eq!(commands.len(), 4, "{text}");
        for line in commands {
            // Everything after the `#` is a comment to the shell; nothing else
            // may follow the command's last argument.
            let (command, comment) = line
                .split_once('#')
                .unwrap_or_else(|| panic!("no comment: {line}"));
            assert!(!comment.trim().is_empty(), "{line}");
            assert!(
                !command.contains("send a") && !command.contains("watch blocks"),
                "{line}"
            );
        }
    }

    #[test]
    fn a_network_told_to_stop_at_a_height_says_so_and_that_ctrl_c_still_works() {
        let text = said(Some(30), &rpcs());
        assert!(text.contains("until every node has block 30"), "{text}");
        assert!(text.contains("Ctrl-C stops it sooner"), "{text}");
        assert!(!text.contains("Ctrl-C stops every node"), "{text}");
    }

    #[test]
    fn nodes_with_no_rpc_have_no_rpc_section_and_the_rest_still_stands() {
        let text = said(None, &[]);
        assert!(!text.contains("RPC"), "{text}");
        assert!(text.contains("devnet bump"), "{text}");
    }

    #[test]
    fn the_note_never_uses_the_words_the_launcher_reports_progress_in() {
        // A caller counts "reached height" lines to know every node is done.
        let text = said(Some(5), &rpcs());
        assert!(!text.contains("reached height"), "{text}");
        assert!(!text.contains("committed block"), "{text}");
    }
}
