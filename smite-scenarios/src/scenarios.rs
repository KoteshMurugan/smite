//! Scenario implementations and helpers.

mod dual_funding;
mod encrypted_bytes;
mod init;
mod noise;

pub use dual_funding::DualFundingScenario;
pub use encrypted_bytes::EncryptedBytesScenario;
pub use init::InitScenario;
pub use noise::NoiseScenario;
use smite::scenarios::ScenarioError;

use std::time::Duration;

use secp256k1::SecretKey;
use smite::bolt::{Init, Message, Ping};
use smite::noise::NoiseConnection;

use crate::targets::Target;

/// Static keys for Noise handshake. Using fixed keys ensures reproducibility
/// of fuzz failures across runs.
const STATIC_KEY: [u8; 32] = [
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
];
const EPHEMERAL_KEY: [u8; 32] = [
    0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
    0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
];

/// `option_dual_fund` feature bits (BOLT 9).
///
/// Bit 28 = required version, bit 29 = optional version.
/// CLN v25.x with `--experimental-dual-fund` advertises bit 29 (optional).
/// Feature is negotiated if EITHER bit is set on both sides.
const OPT_DUAL_FUND_BIT_REQUIRED: usize = 28;
const OPT_DUAL_FUND_BIT_OPTIONAL: usize = 29;

/// Check whether a feature bit is set in a big-endian feature byte vector.
fn has_feature_bit(features: &[u8], bit: usize) -> bool {
    let byte_from_end = bit / 8;
    let bit_mask = 1u8 << (bit % 8);
    if features.len() <= byte_from_end {
        return false;
    }
    let idx = features.len() - 1 - byte_from_end;
    features[idx] & bit_mask != 0
}

/// Connect to a target and perform the init handshake.
///
/// # Errors
///
/// Returns an error if connection, handshake, or init exchange fails.
#[allow(clippy::missing_panics_doc)] // Static keys are known-valid constants
pub fn connect_to_target<T: Target>(
    target: &T,
    timeout: Duration,
) -> Result<NoiseConnection, ScenarioError> {
    let local_static = SecretKey::from_byte_array(STATIC_KEY).expect("valid static key");
    let local_ephemeral = SecretKey::from_byte_array(EPHEMERAL_KEY).expect("valid ephemeral key");

    let mut conn = NoiseConnection::connect(
        target.addr(),
        *target.pubkey(),
        local_static,
        local_ephemeral,
        timeout,
    )?;

    // Receive and validate target's init message
    let init_bytes = conn.recv_message()?;
    let Message::Init(init) = Message::decode(&init_bytes)? else {
        return Err(ScenarioError::Protocol("expected init message".into()));
    };

    log::debug!(
        "Target init: globalfeatures={} features={}",
        hex::encode(&init.globalfeatures),
        hex::encode(&init.features),
    );

    // Echo features back, removing TLVs
    let our_init = Init::echo(&init);

    log::debug!(
        "Our  init: globalfeatures={} features={}",
        hex::encode(&our_init.globalfeatures),
        hex::encode(&our_init.features),
    );

    // Warn if CLN did not advertise option_dual_fund (neither bit 28 nor 29).
    // Bit 29 (optional) is what CLN v25 uses with --experimental-dual-fund.
    // Bit 28 (required) is what strict BOLT-compliant nodes use.
    if !has_feature_bit(&our_init.features, OPT_DUAL_FUND_BIT_REQUIRED)
        && !has_feature_bit(&our_init.features, OPT_DUAL_FUND_BIT_OPTIONAL)
    {
        log::warn!(
            "CLN did not advertise option_dual_fund (bits 28/29)! \
             open_channel2 will be rejected. \
             Ensure lightningd is started with --experimental-dual-fund."
        );
    }

    let encoded = Message::Init(our_init).encode();
    conn.send_message(&encoded)?;

    log::debug!("Connected to target, init exchange complete");

    Ok(conn)
}

/// Send ping and wait for pong (for synchronization).
///
/// This ensures the target has done initial processing of any previously sent
/// message before we check if it's still alive.
///
/// # Errors
///
/// Returns an error if the connection is closed or times out.
pub fn ping_pong(conn: &mut NoiseConnection) -> Result<(), ScenarioError> {
    conn.send_message(&Message::Ping(Ping::new(0)).encode())?;

    // Read messages until we get a pong
    loop {
        let msg_bytes = conn.recv_message()?;
        if matches!(Message::decode(&msg_bytes)?, Message::Pong(_)) {
            return Ok(());
        }
        // Ignore other messages (warnings, errors, etc.)
    }
}
