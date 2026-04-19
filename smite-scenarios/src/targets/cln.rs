//! CLN (Core Lightning) target implementation.
//!
//! CLN is written in C, so AFL instrumentation (via `afl-clang-fast`) writes
//! directly to shared memory. No coverage pipes are needed.
//!
//! CLN uses a subdaemon architecture: `lightningd` spawns separate binaries
//! (`lightning_connectd`, `lightning_gossipd`, etc.). Global subdaemons have
//! `must_not_exit = true`, so if any of them crash, lightningd itself exits.
//! This means checking lightningd's liveness is sufficient for crash detection.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::Deserialize;
use smite::process::ManagedProcess;
use smite_ir::context::FundingUtxo;

use super::bitcoind;
use super::{Target, TargetError, check_crash_log};

/// Configuration for the CLN target.
pub struct ClnConfig {
    /// Bitcoin RPC port (default: 18443 for regtest).
    pub bitcoind_rpc_port: u16,
    /// Bitcoin P2P port (default: 18444 for regtest).
    pub bitcoind_p2p_port: u16,
    /// CLN P2P listen port (default: 9735).
    pub cln_p2p_port: u16,
}

impl Default for ClnConfig {
    fn default() -> Self {
        Self {
            bitcoind_rpc_port: 18443,
            bitcoind_p2p_port: 18444,
            cln_p2p_port: 9735,
        }
    }
}

impl ClnConfig {
    fn bitcoind_config(&self) -> bitcoind::BitcoindConfig {
        bitcoind::BitcoindConfig {
            rpc_port: self.bitcoind_rpc_port,
            p2p_port: self.bitcoind_p2p_port,
            ..bitcoind::BitcoindConfig::default()
        }
    }
}

/// CLN (Core Lightning) node target.
///
/// Field order matters: `cln` is declared before `bitcoind` so it drops first,
/// which allows CLN to exit cleanly before bitcoind shuts down.
pub struct ClnTarget {
    cln: ManagedProcess,
    #[allow(dead_code)] // bitcoind shuts down on drop
    bitcoind: ManagedProcess,
    pubkey: secp256k1::PublicKey,
    addr: SocketAddr,
    cln_dir: PathBuf,
    #[allow(dead_code)] // TempDir auto-cleans on drop
    temp_dir: Option<tempfile::TempDir>,
    /// Fuzzer-controlled UTXOs for real dual-funding contributions.
    fuzzer_utxos: Vec<FundingUtxo>,
}

impl ClnTarget {
    /// Starts lightningd and waits for it to be ready.
    /// Returns the process, CLN's identity pubkey, and the lightning-dir path.
    fn start_cln(
        config: &ClnConfig,
        data_dir: &Path,
    ) -> Result<(ManagedProcess, secp256k1::PublicKey, PathBuf), TargetError> {
        log::info!("Starting lightningd...");

        let cln_dir = data_dir.join("cln");
        fs::create_dir_all(&cln_dir)?;

        // Run lightningd in foreground mode (no --daemon) so ManagedProcess
        // can track the PID for liveness checks and signal delivery.
        let mut cmd = Command::new("lightningd");

        // LD_PRELOAD the crash handler into lightningd and its subdaemons.
        // Set only on lightningd (not lightning-cli/bitcoin-cli) to avoid
        // interfering with helper processes.
        if let Ok(handler) = std::env::var("SMITE_CRASH_HANDLER") {
            cmd.env("LD_PRELOAD", handler);
        }

        cmd.arg(format!("--lightning-dir={}", cln_dir.display()))
            .arg("--network=regtest")
            .arg(format!(
                "--bitcoin-rpcconnect=127.0.0.1:{}",
                config.bitcoind_rpc_port
            ))
            .arg("--bitcoin-rpcuser=rpcuser")
            .arg("--bitcoin-rpcpassword=rpcpass")
            .arg(format!("--addr=0.0.0.0:{}", config.cln_p2p_port))
            .arg("--log-level=debug")
            .arg(format!("--log-file={}/cln.log", cln_dir.display()))
            // Enable dual-funding (option_dual_fund, bit 28).
            .arg("--experimental-dual-fund")
            // Funder policy: contribute all available wallet balance to
            // incoming dual-funding requests, even if the opener contributes
            // nothing (funding_satoshis=0).  This lets us exercise the full
            // tx_signatures exchange path (handle_tx_sigs in dualopend.c)
            // even when the fuzzer acts as a zero-contribution opener.
            //
            // We keep the match-policy off here because making CLN add its
            // own input changes the funding-tx layout, invalidating our
            // pre-computed commitment_signed (CLN replies with TX_ABORT).
            .arg("--funder-policy=available")
            .arg("--funder-min-their-funding=0")
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let cln = ManagedProcess::spawn(&mut cmd, "lightningd")?;

        // Wait for CLN to be ready and fully synced. We poll getinfo until
        // blockheight matches the initial blocks we generated.
        log::info!("Waiting for lightningd to be ready and synced...");
        for _ in 0..120 {
            if let Ok((pubkey, blockheight)) = Self::query_info(&cln_dir) {
                if blockheight >= bitcoind::INITIAL_BLOCKS {
                    log::info!("lightningd synced (blockheight={blockheight})");
                    return Ok((cln, pubkey, cln_dir));
                }
                log::debug!("lightningd not yet synced (blockheight={blockheight})");
            }
            std::thread::sleep(Duration::from_secs(1));
        }

        Err(TargetError::StartFailed(
            "lightningd failed to sync chain".into(),
        ))
    }

    /// Funds CLN's internal wallet from the bitcoind default wallet.
    ///
    /// This is called after CLN starts and syncs.  Giving CLN on-chain funds
    /// lets it act as a dual-funding contributor (with `--funder-policy=available`),
    /// which enables the full `tx_signatures` exchange path in dualopend.c
    /// (`handle_tx_sigs`) to be reached by the fuzzer.
    fn fund_cln_wallet(
        config: &ClnConfig,
        data_dir: &Path,
        cln_dir: &Path,
    ) -> Result<(), TargetError> {
        let bitcoind_dir = data_dir.join("bitcoind");
        let rpc_args = || {
            vec![
                "-regtest".to_string(),
                format!("-datadir={}", bitcoind_dir.display()),
                format!("-rpcport={}", config.bitcoind_rpc_port),
                "-rpcuser=rpcuser".to_string(),
                "-rpcpassword=rpcpass".to_string(),
            ]
        };

        // Ask CLN for a deposit address.
        let newaddr_out = Command::new("lightning-cli")
            .arg(format!("--lightning-dir={}", cln_dir.display()))
            .arg("--network=regtest")
            .arg("newaddr")
            .output()?;

        if !newaddr_out.status.success() {
            log::warn!("CLN newaddr failed — skipping wallet funding (CLN may not have funder plugin)");
            return Ok(());
        }

        let newaddr_json: serde_json::Value =
            serde_json::from_slice(&newaddr_out.stdout).map_err(|e| {
                TargetError::StartFailed(format!("parse CLN newaddr response: {e}"))
            })?;

        let cln_addr = newaddr_json
            .get("bech32")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                TargetError::StartFailed("no bech32 field in CLN newaddr response".into())
            })?
            .to_string();

        log::info!("CLN deposit address: {cln_addr}");

        // Send 1 BTC from the bitcoind default wallet to CLN.
        let _ = Command::new("bitcoin-cli")
            .args(rpc_args())
            .arg("-rpcwallet=default")
            .arg("sendtoaddress")
            .arg(&cln_addr)
            .arg("1.0") // 1 BTC — plenty for dual-funding contributions
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        // Mine 6 blocks so CLN's UTXO has 6 confirmations (safe depth).
        let mine_addr_out = Command::new("bitcoin-cli")
            .args(rpc_args())
            .arg("-rpcwallet=default")
            .arg("getnewaddress")
            .output()?;

        if mine_addr_out.status.success() {
            let mine_addr = String::from_utf8_lossy(&mine_addr_out.stdout)
                .trim()
                .to_string();
            let _ = Command::new("bitcoin-cli")
                .args(rpc_args())
                .arg("-rpcwallet=default")
                .arg("generatetoaddress")
                .arg("6")
                .arg(&mine_addr)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }

        // Give CLN time to detect the new blocks and import the UTXO.
        std::thread::sleep(Duration::from_secs(3));
        log::info!("CLN wallet funded with 1 BTC — dual-funding contributions enabled");
        Ok(())
    }

    /// Creates a fuzzer-controlled wallet in bitcoind, funds it with a small
    /// amount of Bitcoin, and returns the UTXO details for use in real
    /// dual-funding contributions.
    ///
    /// The fuzzer generates a deterministic private key, derives the P2WPKH
    /// address, sends funds to it, mines confirmations, then queries the UTXO
    /// via `listunspent`.  Since the fuzzer holds the private key (not bitcoind),
    /// no `dumpprivkey` call is needed.
    fn setup_fuzzer_wallet(
        config: &ClnConfig,
        data_dir: &Path,
    ) -> Result<Vec<FundingUtxo>, TargetError> {
        use secp256k1::{PublicKey, Secp256k1, SecretKey};

        let bitcoind_dir = data_dir.join("bitcoind");
        let rpc_args = || {
            vec![
                "-regtest".to_string(),
                format!("-datadir={}", bitcoind_dir.display()),
                format!("-rpcport={}", config.bitcoind_rpc_port),
                "-rpcuser=rpcuser".to_string(),
                "-rpcpassword=rpcpass".to_string(),
            ]
        };

        // ── Step 1: Generate a deterministic fuzzer private key ─────────────
        //
        // We use a fixed test key so UTXOs are reproducible across runs.
        // In Nyx mode, the snapshot captures this key's UTXO state — it never
        // needs to be regenerated.
        let privkey_bytes: [u8; 32] = {
            use secp256k1::hashes::{sha256, Hash};
            // Derive from a stable seed string — not cryptographically random,
            // but that's fine for a regtest fuzzer wallet.
            *sha256::Hash::hash(b"smite-fuzzer-dual-fund-key-v1").as_byte_array()
        };

        let secp = Secp256k1::new();
        let sk = SecretKey::from_byte_array(privkey_bytes).map_err(|e| {
            TargetError::StartFailed(format!("fuzzer privkey invalid: {e}"))
        })?;
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let pubkey_bytes: [u8; 33] = pk.serialize();

        // ── Step 2: Derive the P2WPKH bech32 regtest address ────────────────
        //
        // Use bitcoin-cli to derive the address from the pubkey descriptor.
        // `bitcoin-cli deriveaddresses "wpkh(<compressed_hex>)"` returns the
        // P2WPKH bech32 address on the current network.
        let pubkey_hex = hex::encode(pubkey_bytes);
        let descriptor_bare = format!("wpkh({pubkey_hex})");

        // Bitcoin Core 0.21+ requires a checksum in descriptor strings passed
        // to `deriveaddresses` and `scantxoutset`.  Use `getdescriptorinfo` to
        // obtain the canonical form with checksum (e.g. "wpkh(...)#xxxxxxxx").
        // Falls back to the bare descriptor on older nodes that don't need it.
        let descriptor = {
            let info_out = Command::new("bitcoin-cli")
                .args(rpc_args())
                .arg("getdescriptorinfo")
                .arg(&descriptor_bare)
                .output()?;
            if info_out.status.success() {
                let info: serde_json::Value =
                    serde_json::from_slice(&info_out.stdout).unwrap_or_default();
                info["descriptor"]
                    .as_str()
                    .unwrap_or(&descriptor_bare)
                    .to_string()
            } else {
                descriptor_bare.clone()
            }
        };

        let derive_out = Command::new("bitcoin-cli")
            .args(rpc_args())
            .arg("deriveaddresses")
            .arg(&descriptor)
            .output()?;

        if !derive_out.status.success() {
            return Err(TargetError::StartFailed(format!(
                "bitcoin-cli deriveaddresses failed: {}",
                String::from_utf8_lossy(&derive_out.stderr)
            )));
        }

        let addresses: Vec<String> = serde_json::from_slice(&derive_out.stdout).map_err(|e| {
            TargetError::StartFailed(format!("parse deriveaddresses output: {e}"))
        })?;

        let fuzzer_addr = addresses.into_iter().next().ok_or_else(|| {
            TargetError::StartFailed("deriveaddresses returned empty list".into())
        })?;

        log::info!("Fuzzer P2WPKH address: {fuzzer_addr}");

        // ── Step 3: Send 1M sats (0.01 BTC) to the fuzzer address ──────────
        let send_out = Command::new("bitcoin-cli")
            .args(rpc_args())
            .arg("-rpcwallet=default")
            .arg("sendtoaddress")
            .arg(&fuzzer_addr)
            .arg("0.01") // 1_000_000 sats — plenty for a single tx_add_input
            .output()?;

        if !send_out.status.success() {
            return Err(TargetError::StartFailed(format!(
                "sendtoaddress to fuzzer wallet failed: {}",
                String::from_utf8_lossy(&send_out.stderr)
            )));
        }

        let funding_txid = String::from_utf8_lossy(&send_out.stdout).trim().to_string();
        log::info!("Fuzzer wallet funded — txid: {funding_txid}");

        // ── Step 4: Mine 6 blocks to confirm ────────────────────────────────
        let mine_addr_out = Command::new("bitcoin-cli")
            .args(rpc_args())
            .arg("-rpcwallet=default")
            .arg("getnewaddress")
            .output()?;

        if mine_addr_out.status.success() {
            let mine_addr = String::from_utf8_lossy(&mine_addr_out.stdout).trim().to_string();
            let _ = Command::new("bitcoin-cli")
                .args(rpc_args())
                .arg("-rpcwallet=default")
                .arg("generatetoaddress")
                .arg("6")
                .arg(&mine_addr)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }

        // ── Step 5: Find our UTXO via scantxoutset ──────────────────────────
        //
        // We don't import the address into a wallet — instead we scan UTXOs
        // directly.  This avoids wallet management complexity.
        let scan_out = Command::new("bitcoin-cli")
            .args(rpc_args())
            .arg("scantxoutset")
            .arg("start")
            .arg(format!("[\"{descriptor}\"]"))
            .output()?;

        if !scan_out.status.success() {
            return Err(TargetError::StartFailed(format!(
                "scantxoutset failed: {}",
                String::from_utf8_lossy(&scan_out.stderr)
            )));
        }

        #[derive(Deserialize)]
        struct ScanResult {
            unspents: Vec<Unspent>,
        }
        #[derive(Deserialize)]
        struct Unspent {
            txid: String,
            vout: u32,
            amount: f64,
        }

        let scan: ScanResult = serde_json::from_slice(&scan_out.stdout).map_err(|e| {
            TargetError::StartFailed(format!("parse scantxoutset output: {e}"))
        })?;

        let unspent = scan.unspents.into_iter().next().ok_or_else(|| {
            TargetError::StartFailed(
                "no UTXO found for fuzzer address after funding".into(),
            )
        })?;

        // ── Step 6: Get the raw transaction bytes ────────────────────────────
        let rawtx_out = Command::new("bitcoin-cli")
            .args(rpc_args())
            .arg("getrawtransaction")
            .arg(&unspent.txid)
            .output()?;

        if !rawtx_out.status.success() {
            return Err(TargetError::StartFailed(format!(
                "getrawtransaction failed: {}",
                String::from_utf8_lossy(&rawtx_out.stderr)
            )));
        }

        let raw_hex = String::from_utf8_lossy(&rawtx_out.stdout).trim().to_string();
        let raw_tx = hex::decode(&raw_hex).map_err(|e| {
            TargetError::StartFailed(format!("decode raw tx hex: {e}"))
        })?;

        // ── Step 7: Decode txid to internal byte order ───────────────────────
        //
        // Bitcoin txids are displayed in reversed byte order (big-endian display,
        // little-endian storage).  The BOLT 2 tx_add_input prevtx field contains
        // the full raw tx, and the txid for our records is internal byte order.
        let txid_display_bytes =
            hex::decode(&unspent.txid).map_err(|e| {
                TargetError::StartFailed(format!("decode txid hex: {e}"))
            })?;
        let mut txid = [0u8; 32];
        if txid_display_bytes.len() == 32 {
            // Reverse: display order → internal byte order
            for (i, b) in txid_display_bytes.iter().enumerate() {
                txid[31 - i] = *b;
            }
        }

        let amount_sats = (unspent.amount * 100_000_000.0).round() as u64;

        let utxo = FundingUtxo {
            txid,
            vout: unspent.vout,
            raw_tx,
            amount_sats,
            pubkey: pubkey_bytes,
            privkey: privkey_bytes,
        };

        log::info!(
            "Fuzzer UTXO ready: txid={} vout={} amount={}sats",
            unspent.txid, unspent.vout, amount_sats
        );

        Ok(vec![utxo])
    }

    /// Queries CLN's identity public key and blockheight via lightning-cli.
    fn query_info(cln_dir: &Path) -> Result<(secp256k1::PublicKey, u64), TargetError> {
        #[derive(Deserialize)]
        struct GetInfoResponse {
            id: String,
            blockheight: u64,
        }

        let output = Command::new("lightning-cli")
            .arg(format!("--lightning-dir={}", cln_dir.display()))
            .arg("--network=regtest")
            .arg("getinfo")
            .output()?;

        if !output.status.success() {
            return Err(TargetError::StartFailed(format!(
                "lightning-cli getinfo failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        let info: GetInfoResponse = serde_json::from_slice(&output.stdout).map_err(|e| {
            TargetError::StartFailed(format!("failed to parse lightning-cli output: {e}"))
        })?;

        log::info!(
            "CLN identity pubkey: {}, blockheight: {}",
            info.id,
            info.blockheight
        );

        let pubkey_bytes = hex::decode(&info.id)
            .map_err(|e| TargetError::StartFailed(format!("failed to decode pubkey hex: {e}")))?;

        let pubkey = secp256k1::PublicKey::from_slice(&pubkey_bytes)
            .map_err(|e| TargetError::StartFailed(format!("failed to parse pubkey: {e}")))?;

        Ok((pubkey, info.blockheight))
    }
}

impl Drop for ClnTarget {
    fn drop(&mut self) {
        // Use `lightning-cli stop` for graceful shutdown instead of SIGTERM.
        // lightningd's SIGTERM handler calls _exit(), which skips atexit handlers
        // and prevents LLVM coverage profraw data from being written. The `stop`
        // RPC triggers a clean exit through the event loop, running atexit handlers.
        log::debug!("lightningd: requesting graceful shutdown via lightning-cli stop");

        // Spawn `lightning-cli stop` and bound it with a deadline. If a
        // subdaemon (e.g. dualopend stuck in a transient failure state) blocks
        // the JSON-RPC reply, the call would otherwise hang forever — which
        // also blocks the per-input docker container in the coverage script.
        let cli_deadline = std::time::Instant::now() + Duration::from_secs(8);
        let mut cli_status = None;
        if let Ok(mut cli) = Command::new("lightning-cli")
            .arg(format!("--lightning-dir={}", self.cln_dir.display()))
            .arg("--network=regtest")
            .arg("stop")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            while std::time::Instant::now() < cli_deadline {
                match cli.try_wait() {
                    Ok(Some(s)) => {
                        cli_status = Some(s);
                        break;
                    }
                    Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                    Err(_) => break,
                }
            }
            if cli_status.is_none() {
                log::debug!("lightningd: lightning-cli stop timed out, killing CLI");
                let _ = cli.kill();
                let _ = cli.wait();
            }
        } else {
            log::debug!("lightningd: failed to spawn lightning-cli stop");
        }

        if cli_status.is_some_and(|s| s.success()) {
            // Wait for lightningd to fully exit with a timeout. The RPC response
            // is sent just before `return` from main(), so there's a small window
            // where the CLI has returned but lightningd hasn't exited yet.
            log::debug!("lightningd: waiting for process to exit");
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while self.cln.is_running() && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
        } else {
            log::debug!("lightningd: lightning-cli stop failed/timed out, falling back to SIGTERM");
        }
        // ManagedProcess::drop handles cleanup. If lightningd already exited,
        // is_running() returns false and no signal is sent. If the timeout
        // expired, ManagedProcess sends SIGTERM as a fallback.
    }
}

impl Target for ClnTarget {
    type Config = ClnConfig;

    fn start(config: Self::Config) -> Result<Self, TargetError> {
        let (data_path, temp_dir) = bitcoind::resolve_data_dir()?;

        let bitcoind = bitcoind::start(&config.bitcoind_config(), &data_path)?;
        let (cln, pubkey, cln_dir) = Self::start_cln(&config, &data_path)?;

        // Fund CLN's internal wallet so it can act as a dual-funding
        // contributor.  A non-zero CLN balance is required for the
        // tx_signatures exchange to succeed and cover handle_tx_sigs.
        if let Err(e) = Self::fund_cln_wallet(&config, &data_path, &cln_dir) {
            log::warn!("CLN wallet funding failed: {e:?} — continuing without wallet funds");
        }

        // Create the fuzzer-controlled wallet with a real UTXO.
        // The fuzzer uses this UTXO in tx_add_input to act as a genuine
        // dual-funding contributor (both sides contribute real Bitcoin).
        let fuzzer_utxos = match Self::setup_fuzzer_wallet(&config, &data_path) {
            Ok(utxos) => {
                log::info!("Fuzzer wallet ready: {} UTXO(s) for dual-funding", utxos.len());
                utxos
            }
            Err(e) => {
                log::warn!("Fuzzer wallet setup failed: {e:?} — real dual-funding disabled");
                vec![]
            }
        };

        let addr = SocketAddr::from(([127, 0, 0, 1], config.cln_p2p_port));

        log::info!("Both daemons are running, ready to fuzz");

        Ok(Self {
            cln,
            bitcoind,
            pubkey,
            addr,
            cln_dir,
            temp_dir,
            fuzzer_utxos,
        })
    }

    fn pubkey(&self) -> &secp256k1::PublicKey {
        &self.pubkey
    }

    fn addr(&self) -> SocketAddr {
        self.addr
    }

    fn check_alive(&mut self) -> Result<(), TargetError> {
        check_crash_log()?;
        if !self.cln.is_running() {
            return Err(TargetError::Crashed);
        }
        Ok(())
    }

    fn funding_utxos(&self) -> Vec<FundingUtxo> {
        self.fuzzer_utxos.clone()
    }
}
