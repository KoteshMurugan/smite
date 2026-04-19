//! BOLT 3 commitment transaction construction and BIP 143 sighash signing.
//!
//! Implements the per-commitment key derivation, anchor-channel script
//! construction, output ordering (BIP 69), and segwit-v0 sighash needed to
//! produce a `commitment_signed` message that CLN will accept as
//! cryptographically valid.

use secp256k1::ecdsa::Signature;
use secp256k1::hashes::{Hash, sha256};
use secp256k1::{All, Message, PublicKey, Scalar, Secp256k1, SecretKey};

/// Per-commitment pubkey derivation per BOLT 3:
/// `pubkey = basepoint + SHA256(per_commitment_point || basepoint) * G`
pub fn derive_pubkey(
    secp: &Secp256k1<All>,
    basepoint: &PublicKey,
    per_commitment_point: &PublicKey,
) -> PublicKey {
    use secp256k1::hashes::HashEngine;
    let mut h = sha256::Hash::engine();
    h.input(&per_commitment_point.serialize());
    h.input(&basepoint.serialize());
    let tweak_bytes = sha256::Hash::from_engine(h).to_byte_array();
    let scalar = Scalar::from_be_bytes(tweak_bytes).expect("hash within curve order");
    basepoint
        .add_exp_tweak(secp, &scalar)
        .expect("derived key not at infinity")
}

/// Per-commitment private key derivation matching `derive_pubkey`:
/// `privkey = basepoint_secret + SHA256(per_commitment_point || basepoint)`
pub fn derive_privkey(
    basepoint_secret: &SecretKey,
    basepoint: &PublicKey,
    per_commitment_point: &PublicKey,
) -> SecretKey {
    use secp256k1::hashes::HashEngine;
    let mut h = sha256::Hash::engine();
    h.input(&per_commitment_point.serialize());
    h.input(&basepoint.serialize());
    let tweak_bytes = sha256::Hash::from_engine(h).to_byte_array();
    let scalar = Scalar::from_be_bytes(tweak_bytes).expect("hash within curve order");
    basepoint_secret.add_tweak(&scalar).expect("non-zero result")
}

/// Revocation pubkey per BOLT 3:
/// `revocation_pubkey =
///     revocation_basepoint * SHA256(revocation_basepoint || per_commitment_point)
///   + per_commitment_point * SHA256(per_commitment_point || revocation_basepoint)`
pub fn derive_revocation_pubkey(
    secp: &Secp256k1<All>,
    revocation_basepoint: &PublicKey,
    per_commitment_point: &PublicKey,
) -> PublicKey {
    use secp256k1::hashes::HashEngine;
    let mut h1 = sha256::Hash::engine();
    h1.input(&revocation_basepoint.serialize());
    h1.input(&per_commitment_point.serialize());
    let t1 = sha256::Hash::from_engine(h1).to_byte_array();
    let s1 = Scalar::from_be_bytes(t1).expect("within order");

    let mut h2 = sha256::Hash::engine();
    h2.input(&per_commitment_point.serialize());
    h2.input(&revocation_basepoint.serialize());
    let t2 = sha256::Hash::from_engine(h2).to_byte_array();
    let s2 = Scalar::from_be_bytes(t2).expect("within order");

    let term_a = revocation_basepoint
        .mul_tweak(secp, &s1)
        .expect("non-zero tweak");
    let term_b = per_commitment_point
        .mul_tweak(secp, &s2)
        .expect("non-zero tweak");
    term_a.combine(&term_b).expect("sum not at infinity")
}

/// Obscured commitment number per BOLT 3.
///
/// Computed as `commitment_number XOR (lower-48-bits of
/// SHA256(open_payment_basepoint || accept_payment_basepoint))`.
///
/// The `opener_payment_basepoint` is the *funding-opener*'s payment
/// basepoint and `accepter_payment_basepoint` is the *accepter*'s.
#[must_use]
pub fn obscured_commitment_number(
    opener_payment_basepoint: &PublicKey,
    accepter_payment_basepoint: &PublicKey,
    commit_num: u64,
) -> u64 {
    use secp256k1::hashes::HashEngine;
    let mut h = sha256::Hash::engine();
    h.input(&opener_payment_basepoint.serialize());
    h.input(&accepter_payment_basepoint.serialize());
    let digest = sha256::Hash::from_engine(h).to_byte_array();
    // Lower 48 bits, big-endian, taken from the last 6 bytes.
    let mut mask: u64 = 0;
    for &b in &digest[26..32] {
        mask = (mask << 8) | u64::from(b);
    }
    commit_num ^ mask
}

/// Append a minimal-push of `data` to `out` (Bitcoin Script PUSH op).
fn push_data(out: &mut Vec<u8>, data: &[u8]) {
    let n = data.len();
    if n < 0x4c {
        out.push(n as u8);
    } else if n <= 0xff {
        out.push(0x4c);
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0x4d);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else {
        out.push(0x4e);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    }
    out.extend_from_slice(data);
}

/// Push a small integer (0-16) using OP_0 / OP_1..OP_16, or fall back to
/// `push_data` for larger values. Uses minimal CScriptNum encoding for
/// values > 16.
fn push_scriptnum(out: &mut Vec<u8>, n: i64) {
    if n == 0 {
        out.push(0x00);
        return;
    }
    if (1..=16).contains(&n) {
        out.push(0x50 + n as u8); // OP_1 .. OP_16
        return;
    }
    // CScriptNum LE with sign bit (BOLT 3 always uses positive small ints).
    let mut v = n.unsigned_abs();
    let mut buf = Vec::with_capacity(8);
    while v != 0 {
        buf.push((v & 0xff) as u8);
        v >>= 8;
    }
    if buf.last().copied().unwrap_or(0) & 0x80 != 0 {
        buf.push(if n < 0 { 0x80 } else { 0x00 });
    } else if n < 0 {
        *buf.last_mut().unwrap() |= 0x80;
    }
    push_data(out, &buf);
}

/// `to_local` witness script per BOLT 3 (used by both commitment formats).
///
/// ```text
/// OP_IF
///     <revocation_pubkey>
/// OP_ELSE
///     `to_self_delay`
///     OP_CHECKSEQUENCEVERIFY
///     OP_DROP
///     <local_delayedpubkey>
/// OP_ENDIF
/// OP_CHECKSIG
/// ```
#[must_use]
pub fn to_local_script(
    revocation_pubkey: &PublicKey,
    to_self_delay: u16,
    local_delayed_payment_pubkey: &PublicKey,
) -> Vec<u8> {
    let mut s = Vec::with_capacity(80);
    s.push(0x63); // OP_IF
    push_data(&mut s, &revocation_pubkey.serialize());
    s.push(0x67); // OP_ELSE
    push_scriptnum(&mut s, i64::from(to_self_delay));
    s.push(0xb2); // OP_CHECKSEQUENCEVERIFY
    s.push(0x75); // OP_DROP
    push_data(&mut s, &local_delayed_payment_pubkey.serialize());
    s.push(0x68); // OP_ENDIF
    s.push(0xac); // OP_CHECKSIG
    s
}

/// `to_remote` witness script for anchor commitments (BOLT 3 §
/// "to_remote Output"):
///
/// ```text
/// <remote_pubkey> OP_CHECKSIGVERIFY 1 OP_CHECKSEQUENCEVERIFY
/// ```
#[must_use]
pub fn anchor_to_remote_script(remote_payment_pubkey: &PublicKey) -> Vec<u8> {
    let mut s = Vec::with_capacity(40);
    push_data(&mut s, &remote_payment_pubkey.serialize());
    s.push(0xad); // OP_CHECKSIGVERIFY
    s.push(0x51); // OP_1
    s.push(0xb2); // OP_CHECKSEQUENCEVERIFY
    s
}

/// Anchor witness script per BOLT 3:
///
/// ```text
/// <funding_pubkey> OP_CHECKSIG OP_IFDUP OP_NOTIF OP_16 OP_CHECKSEQUENCEVERIFY OP_ENDIF
/// ```
#[must_use]
pub fn anchor_script(funding_pubkey: &PublicKey) -> Vec<u8> {
    let mut s = Vec::with_capacity(40);
    push_data(&mut s, &funding_pubkey.serialize());
    s.push(0xac); // OP_CHECKSIG
    s.push(0x73); // OP_IFDUP
    s.push(0x64); // OP_NOTIF
    s.push(0x60); // OP_16
    s.push(0xb2); // OP_CHECKSEQUENCEVERIFY
    s.push(0x68); // OP_ENDIF
    s
}

/// Wrap a witness script in `OP_0 OP_PUSH32 <SHA256(script)>` (P2WSH).
#[must_use]
pub fn p2wsh(witness_script: &[u8]) -> Vec<u8> {
    let h = sha256::Hash::hash(witness_script);
    let mut s = Vec::with_capacity(34);
    s.push(0x00);
    s.push(0x20);
    s.extend_from_slice(h.as_byte_array());
    s
}

/// 2-of-2 funding redeem script: `OP_2 <a> <b> OP_2 OP_CHECKMULTISIG`,
/// pubkeys sorted lexicographically.
#[must_use]
pub fn funding_redeem_script(pk_a: &PublicKey, pk_b: &PublicKey) -> Vec<u8> {
    let a = pk_a.serialize();
    let b = pk_b.serialize();
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut s = Vec::with_capacity(71);
    s.push(0x52); // OP_2
    push_data(&mut s, &lo);
    push_data(&mut s, &hi);
    s.push(0x52); // OP_2
    s.push(0xae); // OP_CHECKMULTISIG
    s
}

/// One transaction output (value + scriptpubkey).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOut {
    pub value_sat: u64,
    pub script_pubkey: Vec<u8>,
}

/// One transaction input (outpoint + sequence).  `script_sig` is empty for
/// segwit inputs.  `witness` is set when serializing-with-witness.
#[derive(Debug, Clone)]
pub struct TxIn {
    pub prev_txid: [u8; 32],
    pub prev_vout: u32,
    pub sequence: u32,
}

/// BIP 69 sort: by value ascending, then scriptpubkey lexicographic.
pub fn sort_outputs_bip69(outputs: &mut [TxOut]) {
    outputs.sort_by(|a, b| {
        a.value_sat
            .cmp(&b.value_sat)
            .then_with(|| a.script_pubkey.cmp(&b.script_pubkey))
    });
}

/// Serialize a varint per Bitcoin Core conventions.
fn write_varint(out: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

/// BIP 143 sighash for a segwit-v0 input. `sighash_type` is typically
/// `0x01` (`SIGHASH_ALL`).
///
/// Reference: <https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki>
#[must_use]
pub fn sighash_segwit_v0(
    inputs: &[TxIn],
    outputs: &[TxOut],
    version: i32,
    locktime: u32,
    input_index: usize,
    script_code: &[u8],
    value_sat: u64,
    sighash_type: u32,
) -> [u8; 32] {
    use secp256k1::hashes::HashEngine;
    use secp256k1::hashes::sha256d;

    // hashPrevouts = dSHA256(serialize(all-prev-outpoints))
    let hash_prevouts = {
        let mut e = sha256d::Hash::engine();
        for inp in inputs {
            e.input(&inp.prev_txid);
            e.input(&inp.prev_vout.to_le_bytes());
        }
        sha256d::Hash::from_engine(e).to_byte_array()
    };
    // hashSequence = dSHA256(serialize(all-input-sequences))
    let hash_sequence = {
        let mut e = sha256d::Hash::engine();
        for inp in inputs {
            e.input(&inp.sequence.to_le_bytes());
        }
        sha256d::Hash::from_engine(e).to_byte_array()
    };
    // hashOutputs = dSHA256(serialize(all-outputs))
    let hash_outputs = {
        let mut e = sha256d::Hash::engine();
        let mut buf = Vec::new();
        for o in outputs {
            buf.clear();
            buf.extend_from_slice(&o.value_sat.to_le_bytes());
            write_varint(&mut buf, o.script_pubkey.len() as u64);
            buf.extend_from_slice(&o.script_pubkey);
            e.input(&buf);
        }
        sha256d::Hash::from_engine(e).to_byte_array()
    };

    let inp = &inputs[input_index];
    let mut preimage = Vec::with_capacity(156 + script_code.len());
    preimage.extend_from_slice(&version.to_le_bytes());
    preimage.extend_from_slice(&hash_prevouts);
    preimage.extend_from_slice(&hash_sequence);
    preimage.extend_from_slice(&inp.prev_txid);
    preimage.extend_from_slice(&inp.prev_vout.to_le_bytes());
    write_varint(&mut preimage, script_code.len() as u64);
    preimage.extend_from_slice(script_code);
    preimage.extend_from_slice(&value_sat.to_le_bytes());
    preimage.extend_from_slice(&inp.sequence.to_le_bytes());
    preimage.extend_from_slice(&hash_outputs);
    preimage.extend_from_slice(&locktime.to_le_bytes());
    preimage.extend_from_slice(&sighash_type.to_le_bytes());

    sha256d::Hash::hash(&preimage).to_byte_array()
}

/// Compute txid (double-SHA256, displayed in reverse byte order on the
/// wire — but the BIP 143 sighash uses little-endian internal form).
#[must_use]
pub fn compute_txid(
    inputs: &[TxIn],
    outputs: &[TxOut],
    version: i32,
    locktime: u32,
) -> [u8; 32] {
    use secp256k1::hashes::HashEngine;
    use secp256k1::hashes::sha256d;

    let mut e = sha256d::Hash::engine();
    e.input(&version.to_le_bytes());
    write_varint_engine(&mut e, inputs.len() as u64);
    for inp in inputs {
        e.input(&inp.prev_txid);
        e.input(&inp.prev_vout.to_le_bytes());
        // Empty script_sig
        e.input(&[0u8]);
        e.input(&inp.sequence.to_le_bytes());
    }
    write_varint_engine(&mut e, outputs.len() as u64);
    for o in outputs {
        e.input(&o.value_sat.to_le_bytes());
        let mut tmp = Vec::new();
        write_varint(&mut tmp, o.script_pubkey.len() as u64);
        e.input(&tmp);
        e.input(&o.script_pubkey);
    }
    e.input(&locktime.to_le_bytes());
    sha256d::Hash::from_engine(e).to_byte_array()
}

fn write_varint_engine(e: &mut sha256::HashEngine, n: u64) {
    let mut buf = Vec::with_capacity(9);
    write_varint(&mut buf, n);
    use secp256k1::hashes::HashEngine;
    e.input(&buf);
}

/// Sign a sighash with the given private key, returning a low-S compact
/// 64-byte ECDSA signature suitable for the BOLT `signature` field.
pub fn sign_sighash(secret: &SecretKey, sighash: &[u8; 32]) -> Signature {
    let secp = Secp256k1::new();
    let msg = Message::from_digest(*sighash);
    secp.sign_ecdsa(msg, secret)
}

/// Convert a `secp256k1::ecdsa::Signature` to its 64-byte compact form
/// expected by Lightning wire messages.
#[must_use]
pub fn signature_to_compact(sig: &Signature) -> [u8; 64] {
    sig.serialize_compact()
}

// ─── Commitment-transaction assembly (anchor channels, no HTLCs) ─────────────

/// CLN's dust limit for anchor channels.
pub const ANCHOR_DUST_LIMIT_SAT: u64 = 354;

/// 330-sat anchor output value.
pub const ANCHOR_VALUE_SAT: u64 = 330;

/// Static commitment-tx base weight for anchor channels with no HTLCs and
/// both to_local and to_remote present.  Per BOLT 3 (anchor outputs section).
pub const ANCHOR_COMMIT_WEIGHT_NO_HTLCS: u64 = 1124;

/// Compute the commitment fee in satoshis for the no-HTLC anchor case.
#[must_use]
pub fn anchor_commit_fee_sat(feerate_per_kw: u32) -> u64 {
    (ANCHOR_COMMIT_WEIGHT_NO_HTLCS * u64::from(feerate_per_kw)) / 1000
}

/// All channel-level parameters needed to construct a commitment tx.
#[derive(Debug, Clone)]
pub struct CommitTxParams {
    /// Funding outpoint (txid in internal/little-endian byte order, vout).
    pub funding_txid: [u8; 32],
    pub funding_vout: u32,
    /// Total funding output value.
    pub funding_value_sat: u64,

    /// Our funding pubkey (derived from local funding privkey).
    pub local_funding_pubkey: PublicKey,
    /// Their funding pubkey.
    pub remote_funding_pubkey: PublicKey,

    /// Our basepoints (sent in open_channel2).
    pub local_revocation_basepoint: PublicKey,
    pub local_payment_basepoint: PublicKey,
    pub local_delayed_payment_basepoint: PublicKey,
    /// Their basepoints (received in accept_channel2).
    pub remote_revocation_basepoint: PublicKey,
    pub remote_payment_basepoint: PublicKey,
    pub remote_delayed_payment_basepoint: PublicKey,

    /// Their per-commitment point for this commit number (sent in
    /// accept_channel2 as `first_per_commitment_point`).
    pub remote_per_commitment_point: PublicKey,

    /// `to_self_delay` *we* require for funds we send to *their* commit's
    /// to_local — this is the value WE put in `open_channel2.to_self_delay`,
    /// which CLN uses as `their_to_self_delay` when constructing the
    /// remote commitment tx (the one we sign).
    pub local_to_self_delay: u16,

    /// Commitment-tx feerate (per kilo-weight-unit).
    pub feerate_per_kw: u32,
    /// Per-side dust limit (use ANCHOR_DUST_LIMIT_SAT for anchor channels).
    pub dust_limit_sat: u64,

    /// True if we are the channel funder (we pay the commit fee + anchor
    /// reserve).  In dual-funding both sides may contribute, but the
    /// "opener" (sender of `open_channel2`) is treated as the funder for
    /// fee purposes per BOLT 2.
    pub local_is_opener: bool,

    /// Total satoshis WE contributed to the channel.
    pub local_contribution_sat: u64,
    /// Total satoshis THEY contributed to the channel.
    pub remote_contribution_sat: u64,

    /// Commitment number (0 for initial commit).
    pub commitment_number: u64,
}

/// Build the *remote* commitment transaction (the tx that CLN broadcasts
/// in a unilateral close, paid out from THEIR perspective).
///
/// Returns `(inputs, outputs, version, locktime, sequence)` with outputs
/// already BIP-69 sorted.  The single input is the funding outpoint.
#[must_use]
pub fn build_remote_commit_tx(
    secp: &Secp256k1<All>,
    params: &CommitTxParams,
) -> (Vec<TxIn>, Vec<TxOut>, i32, u32) {
    // ── Per-commitment derived keys (from THEIR per-commit point) ───────────
    let revocation_pubkey = derive_revocation_pubkey(
        secp,
        &params.local_revocation_basepoint,
        &params.remote_per_commitment_point,
    );
    let remote_delayed_pubkey = derive_pubkey(
        secp,
        &params.remote_delayed_payment_basepoint,
        &params.remote_per_commitment_point,
    );
    // option_static_remotekey: to_remote uses our payment_basepoint
    // directly (no per-commitment derivation).
    let local_static_pubkey = params.local_payment_basepoint;

    // ── Compute balances ────────────────────────────────────────────────────
    // In their commit tx:
    //   to_local  = THEIR balance (CLN can claim after delay)
    //   to_remote = OUR balance (we can claim immediately)
    let mut their_balance_sat = params.remote_contribution_sat;
    let mut our_balance_sat = params.local_contribution_sat;

    let commit_fee = anchor_commit_fee_sat(params.feerate_per_kw);

    // Funder pays the commit fee + 660-sat anchor reserve.
    if params.local_is_opener {
        our_balance_sat = our_balance_sat
            .saturating_sub(commit_fee)
            .saturating_sub(2 * ANCHOR_VALUE_SAT);
    } else {
        their_balance_sat = their_balance_sat
            .saturating_sub(commit_fee)
            .saturating_sub(2 * ANCHOR_VALUE_SAT);
    }

    // ── Construct outputs ───────────────────────────────────────────────────
    let mut outputs = Vec::with_capacity(4);

    let to_local_present = their_balance_sat >= params.dust_limit_sat;
    let to_remote_present = our_balance_sat >= params.dust_limit_sat;

    if to_local_present {
        let witscript = to_local_script(
            &revocation_pubkey,
            params.local_to_self_delay,
            &remote_delayed_pubkey,
        );
        outputs.push(TxOut {
            value_sat: their_balance_sat,
            script_pubkey: p2wsh(&witscript),
        });
    }
    if to_remote_present {
        let witscript = anchor_to_remote_script(&local_static_pubkey);
        outputs.push(TxOut {
            value_sat: our_balance_sat,
            script_pubkey: p2wsh(&witscript),
        });
    }
    // Anchor outputs: present only if corresponding to_X is present
    // (BOLT 3 anchor section, no-HTLC case).
    if to_local_present {
        let witscript = anchor_script(&params.remote_funding_pubkey);
        outputs.push(TxOut {
            value_sat: ANCHOR_VALUE_SAT,
            script_pubkey: p2wsh(&witscript),
        });
    }
    if to_remote_present {
        let witscript = anchor_script(&params.local_funding_pubkey);
        outputs.push(TxOut {
            value_sat: ANCHOR_VALUE_SAT,
            script_pubkey: p2wsh(&witscript),
        });
    }

    sort_outputs_bip69(&mut outputs);

    // ── Compute obscured commitment number → locktime + sequence ────────────
    // The "opener" used in the obscure-mask is the FUNDING opener.
    let obscured = obscured_commitment_number(
        if params.local_is_opener {
            &params.local_payment_basepoint
        } else {
            &params.remote_payment_basepoint
        },
        if params.local_is_opener {
            &params.remote_payment_basepoint
        } else {
            &params.local_payment_basepoint
        },
        params.commitment_number,
    );
    // Locktime: upper 8 bits = 0x20, lower 24 = lower 24 of obscured.
    let locktime: u32 = 0x2000_0000u32 | ((obscured & 0x00ff_ffff) as u32);
    // Sequence: upper 8 bits = 0x80, lower 24 = upper 24 of obscured.
    let sequence: u32 = 0x8000_0000u32 | (((obscured >> 24) & 0x00ff_ffff) as u32);

    let inputs = vec![TxIn {
        prev_txid: params.funding_txid,
        prev_vout: params.funding_vout,
        sequence,
    }];

    (inputs, outputs, 2, locktime)
}

/// Sign the remote commitment tx with our funding privkey, producing the
/// 64-byte compact signature to put in `commitment_signed.signature`.
#[must_use]
pub fn sign_remote_commit_tx(
    secp: &Secp256k1<All>,
    params: &CommitTxParams,
    local_funding_secret: &SecretKey,
) -> [u8; 64] {
    let (inputs, outputs, version, locktime) = build_remote_commit_tx(secp, params);

    let funding_redeem = funding_redeem_script(
        &params.local_funding_pubkey,
        &params.remote_funding_pubkey,
    );

    let sighash = sighash_segwit_v0(
        &inputs,
        &outputs,
        version,
        locktime,
        0,
        &funding_redeem,
        params.funding_value_sat,
        1, // SIGHASH_ALL
    );

    let sig = sign_sighash(local_funding_secret, &sighash);
    signature_to_compact(&sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::Secp256k1;

    /// BOLT 3 test vector for `derive_pubkey`:
    ///
    /// base_secret = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
    /// per_commitment_secret = 0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100
    /// localpubkey = 0x0235f2dbfaa89b57ec7b055afe29849ef7ddfeb1cefdb9ebdc43f5494984db29e5
    #[test]
    fn derive_pubkey_bolt3_vector() {
        let secp = Secp256k1::new();
        let base_secret = SecretKey::from_byte_array([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ])
        .unwrap();
        let per_secret = SecretKey::from_byte_array([
            0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18,
            0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10,
            0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
            0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        ])
        .unwrap();
        let basepoint = PublicKey::from_secret_key(&secp, &base_secret);
        let per_point = PublicKey::from_secret_key(&secp, &per_secret);
        let derived = derive_pubkey(&secp, &basepoint, &per_point);
        let expected = hex_to_bytes("0235f2dbfaa89b57ec7b055afe29849ef7ddfeb1cefdb9ebdc43f5494984db29e5");
        assert_eq!(&derived.serialize()[..], &expected[..]);
    }

    /// BOLT 3 test vector for `derive_revocation_pubkey`:
    /// revocationpubkey = 0x02916e326636d19c33f13e8c0c3a03dd157f332f3e99c317c141dd865eb01f8ff0
    #[test]
    fn derive_revocation_pubkey_bolt3_vector() {
        let secp = Secp256k1::new();
        let base_secret = SecretKey::from_byte_array([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ])
        .unwrap();
        let per_secret = SecretKey::from_byte_array([
            0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18,
            0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10,
            0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
            0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        ])
        .unwrap();
        let basepoint = PublicKey::from_secret_key(&secp, &base_secret);
        let per_point = PublicKey::from_secret_key(&secp, &per_secret);
        let derived = derive_revocation_pubkey(&secp, &basepoint, &per_point);
        let expected = hex_to_bytes("02916e326636d19c33f13e8c0c3a03dd157f332f3e99c317c141dd865eb01f8ff0");
        assert_eq!(&derived.serialize()[..], &expected[..]);
    }

    /// BOLT 3 test vector for the obscured commitment number:
    /// `local_payment_basepoint = 034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa`
    /// `remote_payment_basepoint = 032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991`
    /// `obscured_commitment_number = 0x2bb038521914 ^ 42`
    #[test]
    fn obscured_commitment_number_vector() {
        let lp = PublicKey::from_slice(&hex_to_bytes(
            "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
        ))
        .unwrap();
        let rp = PublicKey::from_slice(&hex_to_bytes(
            "032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991",
        ))
        .unwrap();
        let got = obscured_commitment_number(&lp, &rp, 42);
        let expected = 0x2bb0_3852_1914u64 ^ 42u64;
        assert_eq!(got, expected);
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
