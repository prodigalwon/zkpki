//! Android StrongBox HIP proof verification — stubbed for a later
//! pass.
//!
//! StrongBox does not expose a `TPM2_Quote` equivalent. The planned
//! Android HIP proof will use a fresh attestation chain with
//! `hardwareEnforced` RootOfTrust values (`deviceLocked`,
//! `verifiedBootState`, `verifiedBootKey`, `verifiedBootHash`)
//! compared against genesis snapshots. That work references the
//! existing `AttestationPayloadV3` verification path in
//! `zk-pki-tpm` and is out of scope for the Windows TPM 2.0 pass.

use zk_pki_primitives::hip::CanonicalHipProof;

use crate::{HipError, HipVerificationReport};

/// Placeholder — always returns `PlatformNotImplemented`. Kept as a
/// module so the dispatch in `crate::verify_hip_proof_internal`
/// reads naturally and so follow-on code has an obvious landing
/// spot.
#[allow(dead_code)]
pub(crate) fn verify_internal(
    _proof: &CanonicalHipProof,
) -> Result<HipVerificationReport, HipError> {
    Err(HipError::PlatformNotImplemented)
}
