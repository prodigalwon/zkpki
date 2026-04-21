//! Hardware Integrity Proof verifier.
//!
//! Verifies [`CanonicalHipProof`] (from `zk-pki-primitives::hip`)
//! structs produced by platform-specific probes. The probe handles
//! wire-format parsing (TPMS_ATTEST, StrongBox attestation bytes,
//! etc.) in userspace where `std` is available; this crate operates
//! purely on the canonical struct and runs in `no_std`.
//!
//! Current support:
//!
//! - `HipPlatform::Tpm2Windows` — full verification path (AIK↔EK
//!   binding via TPM2_Certify, quote signature over
//!   PCR-digest||nonce by AIK).
//! - `HipPlatform::Tpm2Linux` — stub, returns
//!   [`HipError::PlatformNotImplemented`].
//! - `HipPlatform::StrongBox` — stub, returns
//!   [`HipError::PlatformNotImplemented`].
//!
//! The verifier exposes two entry points:
//!
//! - [`verify_hip_proof_internal`] — internal consistency only. Used
//!   at `mint_cert` to record the genesis fingerprint. No prior
//!   fingerprint to compare against, so only the cryptographic
//!   structure is checked.
//! - [`verify_hip_proof_against_genesis`] — ongoing verification.
//!   Runs the internal checks and additionally compares the proof's
//!   AIK and PCR7 to the stored [`GenesisHardwareFingerprint`]. Used
//!   by future HIP-gated extrinsics (not yet wired).

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod tpm2;
pub mod android;

use zk_pki_primitives::hip::{
    CanonicalHipProof, GenesisHardwareFingerprint, HipPlatform, PcrValue,
};

/// Error cases for HIP verification. Each failure mode is a distinct
/// variant so callers (and tests) can assert the exact reason a
/// proof was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HipError {
    /// Platform variant on the proof doesn't have a verifier wired
    /// yet (Android StrongBox, Linux tpm2). Not a security failure —
    /// scope boundary.
    PlatformNotImplemented,
    /// `blake2_256(ek_public) != ek_hash` — the proof claims a cert
    /// hash that doesn't match the supplied EK pubkey.
    EkHashMismatch,
    /// AIK-certify signature verification failed. Either the AIK
    /// wasn't created under this EK's hierarchy or the bytes were
    /// tampered.
    AikCertifyInvalid,
    /// Quote signature over `SHA-256(quote_attest)` by the AIK
    /// failed — the attest bytes or signature were tampered.
    QuoteSignatureInvalid,
    /// `quote_attest` did not parse as a well-formed TPMS_ATTEST
    /// quote structure (bad magic, wrong type, truncated fields,
    /// etc).
    QuoteAttestMalformed,
    /// Inner `pcrDigest` parsed from `quote_attest` does not match
    /// the redundant `proof.pcr_digest` field. Tamper or probe bug.
    PcrDigestMismatch,
    /// Inner `extraData` parsed from `quote_attest` does not match
    /// the redundant `proof.nonce` field. The caller's nonce
    /// wasn't what the TPM quoted against.
    NonceAttestMismatch,
    /// Caller-supplied `expected_nonce` does not match
    /// `proof.nonce`. Catches stale-proof replay where the proof
    /// was valid for a previous request but doesn't bind to this
    /// one. Used by PopAssertion verification.
    NonceExpectedMismatch,
    /// The AIK in this proof doesn't match the one recorded at
    /// genesis. Device identity diverged.
    AikGenesisMismatch,
    /// PCR 7 (Secure Boot state) in this proof differs from the
    /// value recorded at genesis. Most common reason for this is the
    /// user disabled Secure Boot or reinstalled a non-signed OS —
    /// device no longer attestable against its genesis baseline.
    Pcr7GenesisMismatch,
    /// Genesis fingerprint is missing PCR 7. Either the probe at
    /// genesis didn't include PCR 7 (bug) or the fingerprint was
    /// constructed incorrectly.
    GenesisPcr7Missing,
    /// The current proof doesn't include PCR 7. Probe output was
    /// incomplete.
    CurrentPcr7Missing,
    /// AIK or EK public key bytes were malformed or not a valid
    /// curve point.
    BadPublicKey,
    /// Signature bytes not valid DER / SEC1.
    BadSignature,
}

/// Successful-verification report. Surfaces the structured facts
/// that gated extrinsics / relying parties act on.
#[derive(Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct HipVerificationReport {
    pub platform: HipPlatform,
    pub device_identity_confirmed: bool,
    pub secure_boot_intact: bool,
}

/// Internal-only consistency check. Used at genesis (`mint_cert`)
/// where there's no prior fingerprint to compare against — the point
/// is just to confirm the proof structure is cryptographically
/// sound. The AIK↔EK binding, AIK-over-PCR signature, and PCR digest
/// consistency are all checked.
pub fn verify_hip_proof_internal(
    proof: &CanonicalHipProof,
) -> Result<HipVerificationReport, HipError> {
    match proof.platform {
        HipPlatform::Tpm2Windows => tpm2::verify_internal(proof),
        HipPlatform::Tpm2Linux | HipPlatform::StrongBox => {
            Err(HipError::PlatformNotImplemented)
        }
    }
}

/// Ongoing verification — runs the internal checks AND compares
/// against the stored genesis fingerprint (AIK identity, PCR 7
/// match). Also binds the proof to a caller-supplied
/// `expected_nonce` — closes the stale-proof replay gap flagged
/// during the HIP pass. Used by PopAssertion verification.
///
/// For self-as-genesis / internal-consistency tests, pass
/// `&proof.nonce` as `expected_nonce` (the check reduces to a
/// tautology and doesn't exclude any valid proof).
pub fn verify_hip_proof_against_genesis(
    proof: &CanonicalHipProof,
    genesis: &GenesisHardwareFingerprint,
    expected_nonce: &[u8; 32],
) -> Result<HipVerificationReport, HipError> {
    let report = verify_hip_proof_internal(proof)?;

    // Bind to caller's expected nonce. The internal check already
    // pinned attest.extraData == proof.nonce; this closes the
    // remaining replay path where a previously-valid proof is
    // replayed with a different intended context.
    if &proof.nonce != expected_nonce {
        return Err(HipError::NonceExpectedMismatch);
    }

    // AIK identity — must match genesis.
    let aik_hash = sp_io::hashing::blake2_256(proof.aik_public.as_slice());
    if aik_hash != genesis.aik_public_hash {
        return Err(HipError::AikGenesisMismatch);
    }

    // PCR 7 (Secure Boot state) must match genesis. Other PCRs may
    // progress forward across legitimate OS updates — full policy
    // is a future-pass concern.
    let genesis_pcr7 = find_pcr(&genesis.pcr_values, 7)
        .ok_or(HipError::GenesisPcr7Missing)?;
    let current_pcr7 = find_pcr(&proof.pcr_values, 7)
        .ok_or(HipError::CurrentPcr7Missing)?;
    if current_pcr7 != genesis_pcr7 {
        return Err(HipError::Pcr7GenesisMismatch);
    }

    Ok(report)
}

/// Look up a PCR value by index in a `BoundedVec<PcrValue, _>`.
pub(crate) fn find_pcr<B>(pcrs: &frame_support::BoundedVec<PcrValue, B>, index: u8) -> Option<[u8; 32]>
where
    B: frame_support::traits::Get<u32>,
{
    pcrs.iter().find(|p| p.index == index).map(|p| p.value)
}
