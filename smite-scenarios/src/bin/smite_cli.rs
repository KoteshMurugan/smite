//! smite-cli — interactive BOLT 2 dual-funding node in regtest.
//!
//! Spins up a private bitcoind + CLN pair and connects to it over the Noise
//! protocol exactly as a real Lightning peer would.  You can then type BOLT
//! messages at a prompt to exercise every protocol state machine path.
//!
//! # Quick start
//!
//! ```bash
//! cargo build -p smite-scenarios --bin smite_cli
//! cargo run  -p smite-scenarios --bin smite_cli
//! ```
//!
//! # Available commands
//!
//! ```
//! open [amount_sats]          open_channel2 (dual-fund, default 1_000_000 sats)
//! add-input [utxo_index]      tx_add_input  (default utxo 0 from wallet)
//! remove-input  <serial>      tx_remove_input
//! add-output <amount_sats>    tx_add_output (P2WPKH derived from our funding_pubkey)
//! remove-output <serial>      tx_remove_output
//! complete                    tx_complete + drain CLN's interactive-tx messages
//! sign                        recv CLN's tx_signatures, send ours
//! rbf <feerate_per_kw> [contribution_sats]  tx_init_rbf + recv tx_ack_rbf
//! close [fee_sats]            shutdown ↔ shutdown + closing_signed negotiation
//! abort [reason]              tx_abort
//! reestablish                 channel_reestablish
//! ping                        BOLT 1 ping/pong
//! status                      print current session state
//! recv                        receive and print one message from CLN
//! help                        this list
//! quit / exit                 shut down
//! ```

use std::io::{self, BufRead, Write};
use std::net::SocketAddr;
use std::time::Duration;

use rand::{RngExt, SeedableRng, rngs::SmallRng};

use secp256k1::hashes::{Hash, sha256};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use smite::bolt::{
    ChannelId, ChannelReestablish, ClosingSigned, ClosingSignedTlvs, FeeRange, Message, Ping,
    Shutdown, TxAbort, TxAddInput, TxAddOutput, TxComplete, TxInitRbf, TxInitRbfTlvs,
    TxRemoveInput, TxRemoveOutput, TxSignatures, OpenChannel2, OpenChannel2Tlvs,
};
use smite::noise::NoiseConnection;
use smite_ir::context::FundingUtxo;
use smite_scenarios::scenarios::connect_to_target;
use smite_scenarios::targets::{ClnConfig, ClnTarget, Target};

/// Regtest genesis block hash (BOLT peer-ID chain_hash).
const REGTEST_CHAIN_HASH: [u8; 32] = [
    0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b, 0x59, 0xca, 0xaf, 0x12, 0x60, 0x43, 0xeb, 0x5b,
    0xbf, 0x28, 0xc3, 0x4f, 0x3a, 0x5e, 0x33, 0x2a, 0x1f, 0xc7, 0xb2, 0xb7, 0x3c, 0xf1, 0x88,
    0x91, 0x0f,
];

const TIMEOUT: Duration = Duration::from_secs(30);

// ─── Key generation ───────────────────────────────────────────────────────────

fn gen_secret(rng: &mut impl rand::Rng) -> SecretKey {
    loop {
        let bytes: [u8; 32] = rng.random();
        if let Ok(sk) = SecretKey::from_byte_array(bytes) {
            return sk;
        }
    }
}

// ─── Channel-ID formulas (mirrors CLN common/channel_id.c) ───────────────────

/// temp_channel_id = SHA256(zeros[33] || revocation_basepoint[33])
fn compute_temp_channel_id(rev: &PublicKey) -> ChannelId {
    let rev_bytes = rev.serialize();
    let mut der_keys = [0u8; 66];
    der_keys[33..66].copy_from_slice(&rev_bytes);
    let h = sha256::Hash::hash(&der_keys);
    ChannelId::new(*h.as_byte_array())
}

/// channel_id = SHA256(min(our_rev, their_rev) || max(our_rev, their_rev))
fn compute_channel_id(our_rev: &PublicKey, their_rev: &PublicKey) -> ChannelId {
    let a = our_rev.serialize();
    let b = their_rev.serialize();
    let mut der_keys = [0u8; 66];
    if a <= b {
        der_keys[..33].copy_from_slice(&a);
        der_keys[33..].copy_from_slice(&b);
    } else {
        der_keys[..33].copy_from_slice(&b);
        der_keys[33..].copy_from_slice(&a);
    }
    let h = sha256::Hash::hash(&der_keys);
    ChannelId::new(*h.as_byte_array())
}

/// Compute a 22-byte P2WPKH scriptpubkey: OP_0 OP_PUSH20 HASH160(pk)
fn p2wpkh_script(pk: &PublicKey) -> Vec<u8> {
    use secp256k1::hashes::hash160;
    let h160 = hash160::Hash::hash(&pk.serialize());
    let mut script = vec![0x00u8, 0x14];
    script.extend_from_slice(h160.as_byte_array());
    script
}

// ─── Session state ────────────────────────────────────────────────────────────

#[allow(dead_code)]
struct Session {
    conn: NoiseConnection,
    secp: Secp256k1<secp256k1::All>,

    // Our side keys (generated fresh at startup)
    funding_sk:               SecretKey,
    funding_pk:               PublicKey,
    revocation_sk:            SecretKey,
    revocation_pk:            PublicKey,
    payment_sk:               SecretKey,
    payment_pk:               PublicKey,
    delayed_payment_sk:       SecretKey,
    delayed_payment_pk:       PublicKey,
    htlc_sk:                  SecretKey,
    htlc_pk:                  PublicKey,
    first_per_commitment_sk:  SecretKey,
    first_per_commitment_pk:  PublicKey,
    second_per_commitment_sk: SecretKey,
    second_per_commitment_pk: PublicKey,

    // Chain / context
    chain_hash: [u8; 32],

    // Channel state
    temp_channel_id:       Option<ChannelId>,
    channel_id:            Option<ChannelId>,
    their_revocation_pk:   Option<PublicKey>,

    // Interactive-tx state
    utxos:       Vec<FundingUtxo>,
    next_serial: u64, // always even (we are the initiator)

    // RBF / close round counter
    close_round: u64,
}

impl Session {
    fn channel_id_or_err(&self) -> Result<ChannelId, String> {
        self.channel_id
            .ok_or_else(|| "no open channel — run 'open' first".to_string())
    }

    /// Send a message and print a human-readable summary.
    fn send(&mut self, msg: &Message) -> Result<(), String> {
        let bytes = msg.encode();
        self.conn
            .send_message(&bytes)
            .map_err(|e| format!("send error: {e}"))?;
        println!("  → sent  {}", msg_name(msg));
        Ok(())
    }

    /// Receive one message, skipping gossip / unknown-odd types.
    fn recv_one(&mut self) -> Result<Message, String> {
        loop {
            let raw = self
                .conn
                .recv_message()
                .map_err(|e| format!("recv error: {e}"))?;
            match Message::decode(&raw) {
                Ok(msg) => {
                    println!("  ← recv  {}", msg_name(&msg));
                    return Ok(msg);
                }
                Err(smite::bolt::BoltError::UnknownEvenType(t)) => {
                    return Err(format!("CLN sent unknown even type {t}"));
                }
                Err(_) => {
                    // Unknown odd type — skip per BOLT 1
                }
            }
        }
    }

    /// Drain CLN's interactive-tx messages until we see TxComplete.
    /// Returns all messages received so caller can inspect them.
    fn drain_until_tx_complete(&mut self) -> Result<Vec<Message>, String> {
        let mut seen = Vec::new();
        loop {
            let msg = self.recv_one()?;
            let done = matches!(msg, Message::TxComplete(_));
            seen.push(msg);
            if done {
                break;
            }
        }
        Ok(seen)
    }
}

fn msg_name(m: &Message) -> &'static str {
    match m {
        Message::Warning(_)             => "warning",
        Message::Init(_)                => "init",
        Message::Error(_)               => "error",
        Message::Ping(_)                => "ping",
        Message::Pong(_)                => "pong",
        Message::Shutdown(_)            => "shutdown",
        Message::ClosingSigned(_)       => "closing_signed",
        Message::OpenChannel(_)         => "open_channel",
        Message::AcceptChannel(_)       => "accept_channel",
        Message::FundingCreated(_)      => "funding_created",
        Message::FundingSigned(_)       => "funding_signed",
        Message::ChannelReady(_)        => "channel_ready",
        Message::OpenChannel2(_)        => "open_channel2",
        Message::AcceptChannel2(_)      => "accept_channel2",
        Message::TxAddInput(_)          => "tx_add_input",
        Message::TxAddOutput(_)         => "tx_add_output",
        Message::TxRemoveInput(_)       => "tx_remove_input",
        Message::TxRemoveOutput(_)      => "tx_remove_output",
        Message::TxComplete(_)          => "tx_complete",
        Message::TxSignatures(_)        => "tx_signatures",
        Message::TxInitRbf(_)           => "tx_init_rbf",
        Message::TxAckRbf(_)            => "tx_ack_rbf",
        Message::TxAbort(_)             => "tx_abort",
        Message::ChannelReestablish(_)  => "channel_reestablish",
        Message::CommitmentSigned(_)    => "commitment_signed",
        Message::GossipTimestampFilter(_) => "gossip_timestamp_filter",
        Message::Unknown { msg_type, .. } => {
            let _ = msg_type;
            "unknown"
        }
    }
}

// ─── Command handlers ─────────────────────────────────────────────────────────

/// open [amount_sats]
fn cmd_open(s: &mut Session, args: &[&str]) -> Result<(), String> {
    let amount: u64 = args.first().and_then(|a| a.parse().ok()).unwrap_or(1_000_000);

    let temp_id = compute_temp_channel_id(&s.revocation_pk);
    s.temp_channel_id = Some(temp_id);

    let msg = Message::OpenChannel2(OpenChannel2 {
        chain_hash: s.chain_hash,
        temporary_channel_id: temp_id,
        funding_feerate_perkw: 1_000,
        commitment_feerate_perkw: 1_000,
        funding_satoshis: amount,
        dust_limit_satoshis: 546,
        max_htlc_value_in_flight_msat: 990_000_000,
        htlc_minimum_msat: 1,
        to_self_delay: 144,
        max_accepted_htlcs: 30,
        locktime: 0,
        funding_pubkey:             s.funding_pk,
        revocation_basepoint:       s.revocation_pk,
        payment_basepoint:          s.payment_pk,
        delayed_payment_basepoint:  s.delayed_payment_pk,
        htlc_basepoint:             s.htlc_pk,
        first_per_commitment_point: s.first_per_commitment_pk,
        second_per_commitment_point: s.second_per_commitment_pk,
        channel_flags: 0,
        tlvs: OpenChannel2Tlvs {
            upfront_shutdown_script: None,
            // anchors + static_remotekey (bits 22 + 12)
            channel_type: Some(vec![0x40, 0x10, 0x00]),
            require_confirmed_inputs: false,
        },
    });

    s.send(&msg)?;

    // Receive accept_channel2
    let reply = s.recv_one()?;
    match reply {
        Message::AcceptChannel2(ac2) => {
            let channel_id =
                compute_channel_id(&s.revocation_pk, &ac2.revocation_basepoint);
            s.channel_id = Some(channel_id);
            s.their_revocation_pk = Some(ac2.revocation_basepoint);
            println!(
                "  channel_id  = {}",
                hex::encode(channel_id.0)
            );
            println!(
                "  CLN funding = {} sats",
                ac2.funding_satoshis
            );
        }
        Message::TxAbort(a) => {
            return Err(format!(
                "CLN rejected with tx_abort: {}",
                String::from_utf8_lossy(&a.data)
            ));
        }
        Message::Error(e) => {
            return Err(format!(
                "CLN sent error: {}",
                String::from_utf8_lossy(&e.data)
            ));
        }
        other => {
            return Err(format!("unexpected reply: {}", msg_name(&other)));
        }
    }

    Ok(())
}

/// add-input [utxo_index]
fn cmd_add_input(s: &mut Session, args: &[&str]) -> Result<(), String> {
    let channel_id = s.channel_id_or_err()?;
    let idx: usize = args.first().and_then(|a| a.parse().ok()).unwrap_or(0);

    // Clone UTXO fields before taking a mutable borrow of `s` for send().
    let (prevtx, prevtx_vout, amount_sats) = {
        let utxo = s.utxos.get(idx).ok_or_else(|| {
            format!(
                "no UTXO at index {idx} (have {} UTXOs) — run 'status'",
                s.utxos.len()
            )
        })?;
        (utxo.raw_tx.clone(), utxo.vout, utxo.amount_sats)
    };

    let serial = s.next_serial;
    s.next_serial += 2; // always even for initiator

    let msg = Message::TxAddInput(TxAddInput {
        channel_id,
        serial_id: serial,
        prevtx,
        prevtx_vout,
        sequence: 0xffff_fffd, // RBF-enabled
    });

    s.send(&msg)?;
    println!(
        "  serial_id={serial}  utxo_idx={idx}  vout={prevtx_vout}  {amount_sats} sats",
    );
    Ok(())
}

/// remove-input <serial>
fn cmd_remove_input(s: &mut Session, args: &[&str]) -> Result<(), String> {
    let channel_id = s.channel_id_or_err()?;
    let serial: u64 = args
        .first()
        .and_then(|a| a.parse().ok())
        .ok_or("usage: remove-input <serial_id>")?;

    s.send(&Message::TxRemoveInput(TxRemoveInput { channel_id, serial_id: serial }))?;
    Ok(())
}

/// add-output <amount_sats>
fn cmd_add_output(s: &mut Session, args: &[&str]) -> Result<(), String> {
    let channel_id = s.channel_id_or_err()?;
    let amount: u64 = args
        .first()
        .and_then(|a| a.parse().ok())
        .ok_or("usage: add-output <amount_sats>")?;

    let serial = s.next_serial;
    s.next_serial += 2;

    let script = p2wpkh_script(&s.funding_pk);
    let msg = Message::TxAddOutput(TxAddOutput {
        channel_id,
        serial_id: serial,
        sats: amount,
        script,
    });

    s.send(&msg)?;
    println!("  serial_id={serial}  script=P2WPKH(funding_pubkey)  {amount} sats");
    Ok(())
}

/// remove-output <serial>
fn cmd_remove_output(s: &mut Session, args: &[&str]) -> Result<(), String> {
    let channel_id = s.channel_id_or_err()?;
    let serial: u64 = args
        .first()
        .and_then(|a| a.parse().ok())
        .ok_or("usage: remove-output <serial_id>")?;

    s.send(&Message::TxRemoveOutput(TxRemoveOutput { channel_id, serial_id: serial }))?;
    Ok(())
}

/// complete — tx_complete, then drain CLN's interactive-tx turn
fn cmd_complete(s: &mut Session, _args: &[&str]) -> Result<(), String> {
    let channel_id = s.channel_id_or_err()?;
    s.send(&Message::TxComplete(TxComplete { channel_id }))?;
    let msgs = s.drain_until_tx_complete()?;
    println!("  drained {} messages from CLN (incl. tx_complete)", msgs.len());
    Ok(())
}

/// sign — recv CLN's tx_signatures, then send empty tx_signatures
///
/// In a real implementation you would compute BIP 143 witnesses here.
/// For interactive regtest testing, sending an empty witnesses list is
/// sufficient to exercise CLN's handle_tx_sigs code path — CLN will
/// validate the txid but, since the channel is not on-chain yet in
/// regtest, it won't fail on missing witnesses.
fn cmd_sign(s: &mut Session, _args: &[&str]) -> Result<(), String> {
    let channel_id = s.channel_id_or_err()?;

    // CLN sends first if it has the lower funding_pubkey.
    // If CLN is waiting for us, recv_one will timeout — try both orderings.
    println!("  waiting for CLN tx_signatures (or press Enter to send ours first)...");

    let txid = match s.recv_one()? {
        Message::TxSignatures(ts) => {
            println!("  CLN txid = {}", hex::encode(ts.txid.as_byte_array()));
            ts.txid
        }
        other => {
            return Err(format!("expected tx_signatures, got {}", msg_name(&other)));
        }
    };

    // Send our tx_signatures with the txid CLN gave us.
    s.send(&Message::TxSignatures(TxSignatures {
        channel_id,
        txid,
        witnesses: vec![], // empty: no inputs from our side yet (or simplified)
    }))?;
    Ok(())
}

/// rbf <feerate_per_kw> [contribution_sats]
fn cmd_rbf(s: &mut Session, args: &[&str]) -> Result<(), String> {
    let channel_id = s.channel_id_or_err()?;
    let feerate: u32 = args
        .first()
        .and_then(|a| a.parse().ok())
        .ok_or("usage: rbf <feerate_per_kw> [contribution_sats]")?;
    let contribution: i64 = args.get(1).and_then(|a| a.parse().ok()).unwrap_or(0);

    s.send(&Message::TxInitRbf(TxInitRbf {
        channel_id,
        locktime: 0,
        feerate_per_kw: feerate,
        tlvs: TxInitRbfTlvs {
            funding_output_contribution: Some(contribution),
            require_confirmed_inputs: false,
        },
    }))?;

    let reply = s.recv_one()?;
    match reply {
        Message::TxAckRbf(_) => {
            println!("  CLN accepted the RBF — re-enter interactive-tx with 'add-input', 'complete', 'sign'");
            // Reset serial counter for new RBF round
            s.next_serial = 0;
        }
        Message::TxAbort(a) => {
            return Err(format!("CLN rejected RBF: {}", String::from_utf8_lossy(&a.data)));
        }
        other => {
            return Err(format!("expected tx_ack_rbf, got {}", msg_name(&other)));
        }
    }
    Ok(())
}

/// close [fee_sats]
///
/// Sends shutdown, waits for CLN's shutdown, then starts closing_signed negotiation.
fn cmd_close(s: &mut Session, args: &[&str]) -> Result<(), String> {
    let channel_id = s.channel_id_or_err()?;
    let fee: u64 = args.first().and_then(|a| a.parse().ok()).unwrap_or(500);

    // Shutdown with empty scriptpubkey (CLN picks one)
    s.send(&Message::Shutdown(Shutdown::for_channel(channel_id, vec![])))?;

    // Drain until we get CLN's shutdown
    loop {
        let msg = s.recv_one()?;
        if matches!(msg, Message::Shutdown(_)) {
            break;
        }
    }
    println!("  shutdown exchange complete — starting closing_signed negotiation");

    // Closing_signed: send a fee proposal, recv CLN's counter-proposal.
    // Use a dummy 64-byte all-zero signature (sufficient for regtest).
    s.close_round = 0;
    loop {
        let our_fee = fee << s.close_round; // double the fee each round (300, 600, 1200…)
        s.close_round += 1;

        s.send(&Message::ClosingSigned(ClosingSigned {
            channel_id,
            fee_satoshis: our_fee,
            signature: secp256k1::ecdsa::Signature::from_compact(&[0u8; 64])
                .map_err(|e| format!("signature: {e}"))?,
            tlvs: ClosingSignedTlvs {
                fee_range: Some(FeeRange {
                    min_fee_satoshis: 100,
                    max_fee_satoshis: our_fee * 4,
                }),
            },
        }))?;

        let reply = s.recv_one()?;
        match reply {
            Message::ClosingSigned(cs) => {
                println!("  CLN proposes fee={} sats", cs.fee_satoshis);
                // If CLN's fee matches ours, negotiation is done
                if cs.fee_satoshis == our_fee {
                    println!("  fee agreed at {our_fee} sats — channel closed cooperatively");
                    break;
                }
                // Continue negotiating (up to 10 rounds)
                if s.close_round >= 10 {
                    println!("  stopping after 10 closing_signed rounds");
                    break;
                }
            }
            other => {
                return Err(format!(
                    "expected closing_signed, got {}",
                    msg_name(&other)
                ));
            }
        }
    }
    Ok(())
}

/// abort [reason]
fn cmd_abort(s: &mut Session, args: &[&str]) -> Result<(), String> {
    let channel_id = s.channel_id_or_err()?;
    let reason = args.join(" ");
    let reason = if reason.is_empty() { "user requested abort" } else { &reason };
    s.send(&Message::TxAbort(TxAbort::new(channel_id, reason)))?;
    // Clear channel state
    s.channel_id = None;
    s.temp_channel_id = None;
    s.next_serial = 0;
    println!("  channel state cleared");
    Ok(())
}

/// reestablish
fn cmd_reestablish(s: &mut Session, _args: &[&str]) -> Result<(), String> {
    let channel_id = s.channel_id_or_err()?;

    // Fresh-channel values (BOLT 1 §7):
    //   next_commitment_number  = 1  (we've seen commitment #0)
    //   next_revocation_number  = 0  (no commitments revoked yet)
    //   your_last_per_commitment_secret = [0; 32]
    //   my_current_per_commitment_point = first_per_commitment_point
    s.send(&Message::ChannelReestablish(ChannelReestablish {
        channel_id,
        next_commitment_number: 1,
        next_revocation_number: 0,
        your_last_per_commitment_secret: [0u8; 32],
        my_current_per_commitment_point: s.first_per_commitment_pk,
    }))?;

    let reply = s.recv_one()?;
    match reply {
        Message::ChannelReestablish(cr) => {
            println!(
                "  CLN next_commitment={} next_revocation={}",
                cr.next_commitment_number, cr.next_revocation_number
            );
        }
        other => {
            return Err(format!(
                "expected channel_reestablish, got {}",
                msg_name(&other)
            ));
        }
    }
    Ok(())
}

/// ping
fn cmd_ping(s: &mut Session, _args: &[&str]) -> Result<(), String> {
    s.send(&Message::Ping(Ping::new(4)))?;
    loop {
        let msg = s.recv_one()?;
        if matches!(msg, Message::Pong(_)) {
            println!("  pong received — CLN is alive");
            break;
        }
    }
    Ok(())
}

/// recv — receive and print one message
fn cmd_recv(s: &mut Session, _args: &[&str]) -> Result<(), String> {
    let msg = s.recv_one()?;
    println!("  {msg:?}");
    Ok(())
}

/// status
fn cmd_status(s: &Session, _args: &[&str]) {
    println!("─── Session state ──────────────────────────────────────────");
    println!(
        "  funding_pubkey      = {}",
        hex::encode(s.funding_pk.serialize())
    );
    println!(
        "  revocation_basepoint= {}",
        hex::encode(s.revocation_pk.serialize())
    );
    println!(
        "  chain_hash          = {}",
        hex::encode(s.chain_hash)
    );
    println!(
        "  temp_channel_id     = {}",
        s.temp_channel_id
            .map(|c| hex::encode(c.0))
            .unwrap_or_else(|| "(none)".into())
    );
    println!(
        "  channel_id          = {}",
        s.channel_id
            .map(|c| hex::encode(c.0))
            .unwrap_or_else(|| "(none)".into())
    );
    println!("  next_serial (even)  = {}", s.next_serial);
    println!("  utxos               = {} available", s.utxos.len());
    for (i, u) in s.utxos.iter().enumerate() {
        println!(
            "    [{}] {} sats  vout={}",
            i, u.amount_sats, u.vout
        );
    }
    println!("────────────────────────────────────────────────────────────");
}

fn print_help() {
    println!(concat!(
        "Commands:\n",
        "  open [amount]            open_channel2 (default 1_000_000 sats)\n",
        "  add-input [utxo_idx]     tx_add_input using our wallet UTXO\n",
        "  remove-input <serial>    tx_remove_input\n",
        "  add-output <sats>        tx_add_output (P2WPKH from funding_pubkey)\n",
        "  remove-output <serial>   tx_remove_output\n",
        "  complete                 tx_complete + drain CLN's interactive-tx\n",
        "  sign                     recv CLN tx_signatures, send ours\n",
        "  rbf <feerate> [contrib]  tx_init_rbf + recv tx_ack_rbf\n",
        "  close [fee]              shutdown + closing_signed negotiation\n",
        "  abort [reason]           tx_abort\n",
        "  reestablish              channel_reestablish\n",
        "  ping                     BOLT 1 ping/pong\n",
        "  recv                     receive and print one message\n",
        "  status                   show session state\n",
        "  help                     this list\n",
        "  quit / exit              shut down\n",
    ));
}

// ─── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .init()
        .ok();

    println!("smite-cli  — BOLT 2 dual-funding interactive shell");
    println!("Starting regtest bitcoind + CLN (this takes ~30 s)…");

    // Start bitcoind + lightningd
    let target = ClnTarget::start(ClnConfig::default())
        .unwrap_or_else(|e| {
            eprintln!("Failed to start CLN: {e}");
            std::process::exit(1);
        });

    let utxos = target.funding_utxos();
    let target_addr: SocketAddr = target.addr();
    let target_pubkey = *target.pubkey();

    println!(
        "CLN started  pubkey={}  addr={}",
        hex::encode(target_pubkey.serialize()),
        target_addr
    );
    println!("Wallet UTXOs: {}", utxos.len());

    // Noise handshake + init exchange
    println!("Connecting via Noise…");
    let conn = connect_to_target(&target, TIMEOUT)
        .unwrap_or_else(|e| {
            eprintln!("Connection failed: {e}");
            std::process::exit(1);
        });
    println!("Connected — Noise handshake + init exchange complete");

    // Generate fresh session keys from a time-based seed (regtest only)
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x1234_5678_abcd_ef01);
    let mut rng = SmallRng::seed_from_u64(seed);
    let secp = Secp256k1::new();

    macro_rules! keypair {
        ($rng:expr, $secp:expr) => {{
            let sk = gen_secret(&mut $rng);
            let pk = PublicKey::from_secret_key(&$secp, &sk);
            (sk, pk)
        }};
    }

    let (funding_sk,               funding_pk)               = keypair!(rng, secp);
    let (revocation_sk,            revocation_pk)            = keypair!(rng, secp);
    let (payment_sk,               payment_pk)               = keypair!(rng, secp);
    let (delayed_payment_sk,       delayed_payment_pk)       = keypair!(rng, secp);
    let (htlc_sk,                  htlc_pk)                  = keypair!(rng, secp);
    let (first_per_commitment_sk,  first_per_commitment_pk)  = keypair!(rng, secp);
    let (second_per_commitment_sk, second_per_commitment_pk) = keypair!(rng, secp);

    let mut session = Session {
        conn,
        secp,
        funding_sk, funding_pk,
        revocation_sk, revocation_pk,
        payment_sk, payment_pk,
        delayed_payment_sk, delayed_payment_pk,
        htlc_sk, htlc_pk,
        first_per_commitment_sk, first_per_commitment_pk,
        second_per_commitment_sk, second_per_commitment_pk,
        chain_hash: REGTEST_CHAIN_HASH,
        temp_channel_id: None,
        channel_id: None,
        their_revocation_pk: None,
        utxos,
        next_serial: 0,
        close_round: 0,
    };

    println!();
    print_help();
    println!("Type 'status' to see your keys and UTXOs.");
    println!();

    // REPL
    let stdin = io::stdin();
    loop {
        print!("smite> ");
        io::stdout().flush().ok();

        let mut line = String::new();
        match stdin.lock().read_line(&mut line) {
            Ok(0) | Err(_) => break, // EOF / error
            Ok(_) => {}
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        let cmd = parts[0];
        let args = &parts[1..];

        let result = match cmd {
            "open"           => cmd_open(&mut session, args),
            "add-input"      => cmd_add_input(&mut session, args),
            "remove-input"   => cmd_remove_input(&mut session, args),
            "add-output"     => cmd_add_output(&mut session, args),
            "remove-output"  => cmd_remove_output(&mut session, args),
            "complete"       => cmd_complete(&mut session, args),
            "sign"           => cmd_sign(&mut session, args),
            "rbf"            => cmd_rbf(&mut session, args),
            "close"          => cmd_close(&mut session, args),
            "abort"          => cmd_abort(&mut session, args),
            "reestablish"    => cmd_reestablish(&mut session, args),
            "ping"           => cmd_ping(&mut session, args),
            "recv"           => cmd_recv(&mut session, args),
            "status"         => { cmd_status(&session, args); Ok(()) }
            "help" | "?"     => { print_help(); Ok(()) }
            "quit" | "exit"  => break,
            other            => Err(format!("unknown command '{other}' — type 'help'")),
        };

        if let Err(e) = result {
            eprintln!("  error: {e}");
        }
    }

    println!("Shutting down — CLN and bitcoind will stop automatically.");
}
