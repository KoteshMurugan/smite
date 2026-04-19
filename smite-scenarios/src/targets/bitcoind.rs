//! Shared bitcoind management for all targets.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::process::CommandExt as _;

use smite::process::ManagedProcess;

use super::TargetError;

/// Number of blocks to generate at startup for coinbase maturity.
pub const INITIAL_BLOCKS: u64 = 101;

/// Bitcoind configuration.
pub struct BitcoindConfig {
    /// Bitcoin RPC port (default: 18443 for regtest).
    pub rpc_port: u16,
    /// Bitcoin P2P port (default: 18444 for regtest).
    pub p2p_port: u16,
    /// Optional ZMQ raw block notification port (`zmqpubrawblock`).
    pub zmq_block_port: Option<u16>,
    /// Optional ZMQ hash block notification port (`zmqpubhashblock`).
    pub zmq_hashblock_port: Option<u16>,
    /// Optional ZMQ transaction notification port (`zmqpubrawtx`).
    pub zmq_tx_port: Option<u16>,
    /// Additional bitcoind arguments (e.g. `-addresstype=bech32`).
    pub extra_args: Vec<String>,
}

impl Default for BitcoindConfig {
    fn default() -> Self {
        Self {
            rpc_port: 18443,
            p2p_port: 18444,
            zmq_block_port: None,
            zmq_hashblock_port: None,
            zmq_tx_port: None,
            extra_args: Vec::new(),
        }
    }
}

/// Resolves the data directory: uses `SMITE_DATA_DIR` if set, otherwise creates a temp dir.
///
/// Returns `(path, temp_dir)` where `temp_dir` is `Some` if a temp directory was created
/// (it will be cleaned up when dropped).
pub fn resolve_data_dir() -> Result<(PathBuf, Option<tempfile::TempDir>), TargetError> {
    if let Ok(dir) = std::env::var("SMITE_DATA_DIR") {
        let path = PathBuf::from(dir);
        fs::create_dir_all(&path)?;
        log::info!("Preserving data directory: {}", path.display());
        Ok((path, None))
    } else {
        let temp = tempfile::tempdir()?;
        let path = temp.path().to_path_buf();
        Ok((path, Some(temp)))
    }
}

/// Starts bitcoind and waits for it to be ready.
pub fn start(config: &BitcoindConfig, data_dir: &Path) -> Result<ManagedProcess, TargetError> {
    log::info!("Starting bitcoind...");

    let bitcoind_dir = data_dir.join("bitcoind");
    fs::create_dir_all(&bitcoind_dir)?;

    let mut cmd = Command::new("bitcoind");
    cmd.arg("-regtest")
        .arg(format!("-datadir={}", bitcoind_dir.display()))
        .arg(format!("-port={}", config.p2p_port))
        .arg(format!("-rpcport={}", config.rpc_port))
        .arg("-rpcuser=rpcuser")
        .arg("-rpcpassword=rpcpass")
        .arg("-fallbackfee=0.00001")
        .arg("-txindex=1")
        .arg("-server=1")
        .arg("-rest=1")
        .arg("-printtoconsole=0")
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    // Add ZMQ args if configured
    if let Some(port) = config.zmq_block_port {
        cmd.arg(format!("-zmqpubrawblock=tcp://127.0.0.1:{port}"));
    }
    if let Some(port) = config.zmq_hashblock_port {
        cmd.arg(format!("-zmqpubhashblock=tcp://127.0.0.1:{port}"));
    }
    if let Some(port) = config.zmq_tx_port {
        cmd.arg(format!("-zmqpubrawtx=tcp://127.0.0.1:{port}"));
    }

    // Add any extra args
    for arg in &config.extra_args {
        cmd.arg(arg);
    }

    // macOS sets RLIMIT_NOFILE soft limit to RLIM_INFINITY (2^63-1). When
    // Bitcoin Core casts this to `int` it overflows to -1, causing the fd
    // availability check to fail with "Not enough file descriptors available.
    // -1 available, 160 required." Set a concrete limit in the child process
    // before exec so Bitcoin Core's arithmetic works correctly.
    #[cfg(unix)]
    unsafe {
        cmd.pre_exec(|| {
            let lim = libc::rlimit {
                rlim_cur: 10240,
                rlim_max: 10240,
            };
            libc::setrlimit(libc::RLIMIT_NOFILE, &lim);
            Ok(())
        });
    }

    let bitcoind = ManagedProcess::spawn(&mut cmd, "bitcoind")?;

    // Wait for bitcoind to be ready
    log::info!("Waiting for bitcoind to be ready...");
    for _ in 0..30 {
        let status = Command::new("bitcoin-cli")
            .arg("-regtest")
            .arg(format!("-datadir={}", bitcoind_dir.display()))
            .arg(format!("-rpcport={}", config.rpc_port))
            .arg("-rpcuser=rpcuser")
            .arg("-rpcpassword=rpcpass")
            .arg("getblockchaininfo")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        if status.is_ok_and(|s| s.success()) {
            log::info!("bitcoind is ready");
            return setup_wallet(config, &bitcoind_dir, bitcoind);
        }

        std::thread::sleep(Duration::from_secs(1));
    }

    Err(TargetError::StartFailed(
        "bitcoind failed to become ready".into(),
    ))
}

/// Creates wallet and generates initial blocks.
fn setup_wallet(
    config: &BitcoindConfig,
    bitcoind_dir: &Path,
    bitcoind: ManagedProcess,
) -> Result<ManagedProcess, TargetError> {
    let rpc_args = || {
        vec![
            "-regtest".to_string(),
            format!("-datadir={}", bitcoind_dir.display()),
            format!("-rpcport={}", config.rpc_port),
            "-rpcuser=rpcuser".to_string(),
            "-rpcpassword=rpcpass".to_string(),
        ]
    };

    // Try createwallet; if it fails (wallet already exists on disk), try loadwallet.
    // Bitcoin Core v22+ does not auto-load wallets from disk on startup.
    let created = Command::new("bitcoin-cli")
        .args(rpc_args())
        .arg("createwallet")
        .arg("default")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());

    if !created {
        // Wallet may already exist from a previous run — attempt to load it.
        let _ = Command::new("bitcoin-cli")
            .args(rpc_args())
            .arg("loadwallet")
            .arg("default")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    // Get a fresh address from the wallet, then generate blocks to it.
    // This is compatible with Bitcoin Core v21–v27 (unlike `bitcoin-cli -generate`
    // which silently fails when no wallet is loaded in newer Core versions).
    let addr_output = Command::new("bitcoin-cli")
        .args(rpc_args())
        .arg("-rpcwallet=default")
        .arg("getnewaddress")
        .output()?;

    if !addr_output.status.success() {
        return Err(TargetError::StartFailed(
            "failed to get new address from wallet".into(),
        ));
    }

    let addr = String::from_utf8_lossy(&addr_output.stdout).trim().to_string();

    let status = Command::new("bitcoin-cli")
        .args(rpc_args())
        .arg("-rpcwallet=default")
        .arg("generatetoaddress")
        .arg(INITIAL_BLOCKS.to_string())
        .arg(&addr)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;

    if !status.success() {
        return Err(TargetError::StartFailed(
            "failed to generate initial blocks".into(),
        ));
    }

    Ok(bitcoind)
}
