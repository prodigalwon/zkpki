//! PoP-asserted action primitives.
//!
//! A [`PopAssertion`] is a hardware-bound identity assertion
//! attached to a pallet extrinsic. It proves the caller controls a
//! specific hardware-anchored cert keypair AND that the attesting
//! hardware is still intact since genesis — completely independent
//! of the Substrate keypair that pays fees and sequences the
//! transaction.
//!
//! The two-key separation is load-bearing:
//! - The Substrate keypair proves fee payment + replay protection
//!   at the transaction layer.
//! - The PopAssertion proves hardware-anchored identity at the
//!   extrinsic layer.
//!
//! If the two keypairs were collapsed, a compromised wallet key
//! would imply a compromised identity. Keeping them separate means
//! a stolen seed phrase can drain funds but cannot impersonate the
//! holder's cert-backed identity — the attacker needs physical
//! control of the hardware-bound keypair.

use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::{pallet_prelude::ConstU32, BoundedVec};
use scale_info::TypeInfo;

use crate::hip::CanonicalHipProof;

/// Hardware-bound identity assertion attached to a pallet extrinsic.
/// See module docs.
#[derive(Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, TypeInfo, MaxEncodedLen, Debug)]
pub struct PopAssertion {
    /// Thumbprint of the cert being asserted.
    pub cert_thumbprint: [u8; 32],
    /// ECDSA P-256 signature (DER or raw r||s) over
    /// `blake2_256(call_data || nonce)` produced by the
    /// hardware-bound `cert_ec_pubkey` stored on the cert's cold
    /// record. Proves the caller controls the private half of the
    /// cert keypair.
    pub cert_ec_signature: BoundedVec<u8, ConstU32<72>>,
    /// Hardware integrity proof — proves the attesting hardware is
    /// still in the same boot state it was at genesis. Required
    /// for standard-path PoP assertions so a compromised device
    /// cannot replay yesterday's cert_ec signature.
    pub hip_proof: CanonicalHipProof,
}

/// Derive the PopAssertion nonce.
///
/// `parent_hash` is the hash of the parent (most-recently-finalised)
/// block — available to both the client before submission and the
/// pallet during execution via `frame_system::Pallet::<T>::parent_hash()`.
/// That plus the cert thumbprint plus the call's own argument bytes
/// gives a nonce that is:
/// - **Knowable** to the client before signing (parent hash is
///   already sealed by the time the client crafts the transaction).
/// - **Unique** per cert per call per block (the cert thumbprint
///   prevents collision between different certs executing the same
///   call in the same block).
/// - **Not-pre-predictable** by an attacker ahead of time (can't
///   forge a valid signature before the parent block exists).
/// - **Verifiable** by the pallet by calling `parent_hash()` at
///   verification time — the same value the client committed to.
///
/// Client-side derivation and pallet-side derivation MUST agree
/// byte-for-byte, including SCALE-encoding of the tuple.
pub fn derive_pop_nonce(
    parent_hash: &[u8; 32],
    cert_thumbprint: &[u8; 32],
    call_data: &[u8],
) -> [u8; 32] {
    sp_io::hashing::blake2_256(
        &(parent_hash, cert_thumbprint, call_data).encode(),
    )
}

/// Marker trait for extrinsic call structs (or the extrinsics
/// themselves) that require a `PopAssertion`. Implementors must
/// call the pallet's `verify_pop_assertion` helper before any
/// state changes. The assertion is independent of the Substrate
/// keypair — it proves hardware-bound identity, not fee payment.
///
/// No concrete implementations yet — this is the framework marker
/// for the future relying-party extrinsics that follow the
/// `self_discard_cert` standard path pattern.
pub trait PopGated {
    /// Return the `PopAssertion` carried on this call.
    fn pop_assertion(&self) -> &PopAssertion;
}
