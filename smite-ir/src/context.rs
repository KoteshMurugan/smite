//! Program execution context from snapshot setup.

use serde::{Deserialize, Serialize};

/// A funded UTXO controlled by the fuzzer, used as a real tx_add_input contribution.
///
/// Created during target setup (before the Nyx snapshot).  Because Nyx resets
/// to the snapshot on every fuzz iteration, these UTXOs are always unspent at
/// the start of each iteration — Bitcoin state is part of the snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FundingUtxo {
    /// UTXO outpoint txid (Bitcoin internal byte order, 32 bytes).
    /// This is the txid of the *previous* transaction we are spending.
    pub txid: [u8; 32],
    /// UTXO output index in the previous transaction.
    pub vout: u32,
    /// Full raw serialized previous transaction (Bitcoin wire format).
    /// Used verbatim as the `prevtx` field in `tx_add_input`.
    pub raw_tx: Vec<u8>,
    /// UTXO value in satoshis.
    pub amount_sats: u64,
    /// Compressed secp256k1 public key for this P2WPKH UTXO (33 bytes).
    #[serde(with = "serde_array_33")]
    pub pubkey: [u8; 33],
    /// secp256k1 private key (32 bytes) for signing this input via BIP 143.
    pub privkey: [u8; 32],
}

/// State captured during snapshot setup, available to IR programs at execution
/// time via `LoadContext*` operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProgramContext {
    /// Target node's compressed public key.
    #[serde(with = "serde_array_33")]
    pub target_pubkey: [u8; 33],
    /// Chain hash (genesis block hash).
    pub chain_hash: [u8; 32],
    /// Current block height at snapshot time.
    pub block_height: u32,
    /// Target's advertised feature bits from init message.
    pub target_features: Vec<u8>,
    /// Fuzzer-controlled UTXOs for real dual-funding contributions.
    ///
    /// These are funded regtest UTXOs where the fuzzer holds the private key.
    /// Programs reference them via `LoadFundingUtxo*` operations.  The executor
    /// uses these to provide real `tx_add_input` data and compute BIP 143
    /// P2WPKH witness signatures in `ComputeFundingWitness`.
    #[serde(default)]
    pub funding_utxos: Vec<FundingUtxo>,
}

/// Custom serde for `[u8; 33]` -- serde's derive only supports arrays up to 32.
mod serde_array_33 {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 33], s: S) -> Result<S::Ok, S::Error> {
        bytes.as_slice().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 33], D::Error> {
        let v = <Vec<u8>>::deserialize(d)?;
        v.try_into()
            .map_err(|v: Vec<u8>| D::Error::invalid_length(v.len(), &"33"))
    }
}
