//! Hardware Integrity Proof (HIP) primitives.
//!
//! A `CanonicalHipProof` is the pallet's pre-canonicalized, platform-
//! agnostic representation of a hardware integrity assertion. Platform-
//! specific wire formats (TPM2 `TPMS_ATTEST`, Android StrongBox
//! attestation, etc.) are parsed off-chain by the probe/ceremony and
//! reduced to this struct before being sent on-chain. The pallet
//! verifier in `zk-pki-hip` operates purely on this struct — no TPM2
//! wire-format parsing lives in `no_std`.
//!
//! Two types of HIP usage:
//!
//! 1. **Genesis recording** — at `mint_cert`, PoP cert holders submit
//!    a HIP proof that becomes the `GenesisHardwareFingerprint`
//!    pinned to the cold record. Verification at genesis is internal
//!    consistency only (signatures, nonce); there is no prior
//!    fingerprint to compare against.
//!
//! 2. **Ongoing attestation** — future pass. Relying parties / gated
//!    extrinsics submit a HIP proof compared against the stored
//!    genesis fingerprint. Out of scope for the current pass.

use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::{pallet_prelude::ConstU32, BoundedVec};
use scale_info::TypeInfo;

/// Platform enum for the HIP proof's origin. Determines which verifier
/// path the pallet/`zk-pki-hip` dispatches to. Only `Tpm2Windows` is
/// implemented in the current pass.
#[derive(Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, TypeInfo, MaxEncodedLen, Debug)]
pub enum HipPlatform {
    /// Windows TPM 2.0 via TBS — `TPM2_Quote` over selected PCRs,
    /// signed by an AIK certified under the EK hierarchy.
    Tpm2Windows,
    /// Linux TPM 2.0 via tcti-device. TODO: separate pass.
    Tpm2Linux,
    /// Android StrongBox attestation. TODO: separate pass — StrongBox
    /// does not expose a TPM2_Quote equivalent; HIP proof will use a
    /// fresh attestation chain with hardwareEnforced RootOfTrust
    /// values.
    StrongBox,
}

/// A single PCR (Platform Configuration Register) value. The `index`
/// is the PCR slot number; `value` is the SHA-256 digest of what's
/// extended into that slot.
///
/// PCRs of interest for HIP:
/// - PCR 0 — firmware / BIOS
/// - PCR 1 — host platform configuration
/// - PCR 4 — boot manager / MBR / GPT
/// - PCR 7 — Secure Boot state (the critical one)
/// - PCR 11 — BitLocker volume encryption
#[derive(Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, TypeInfo, MaxEncodedLen, Debug)]
pub struct PcrValue {
    pub index: u8,
    pub value: [u8; 32],
}

/// Pre-canonicalized HIP proof. The probe / ceremony parses the
/// platform's native wire format (TPMS_ATTEST, StrongBox attestation
/// bytes, etc.) into this struct and submits it SCALE-encoded. The
/// pallet/verifier never touches raw TPM2 structures.
///
/// Verification steps (`zk-pki-hip`):
/// 1. `blake2_256(ek_public) == ek_hash` — consistency check.
/// 2. `aik_certify_signature` verifies over `aik_certify_info` under
///    `ek_public` — proves AIK was certified by the EK (TPM2_Certify).
/// 3. `quote_signature` verifies over `blake2_256(pcr_digest || nonce)`
///    under `aik_public` — proves PCR digest came from this AIK.
/// 4. (Against genesis, future pass) PCR 7 matches stored genesis
///    value; `blake2_256(aik_public)` matches `aik_public_hash` on the
///    genesis fingerprint.
#[derive(Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, TypeInfo, MaxEncodedLen, Debug)]
pub struct CanonicalHipProof {
    pub platform: HipPlatform,
    /// `blake2_256(leaf_spki_der)` — hash of the leaf EK cert's
    /// SubjectPublicKeyInfo. Device-unique (fresh per secure-hardware
    /// keypair) and bound to the signed TBS of the leaf, so a verified
    /// chain cannot have a mutated SPKI. This is the device identity
    /// anchor used by the root-scoped EK deduplication registry.
    pub ek_hash: [u8; 32],
    /// EK public key bytes (SEC1 uncompressed for ECC). Needed to
    /// verify the AIK-certify signature; redundant-by-design with
    /// `ek_hash` (verifier checks the two agree).
    pub ek_public: BoundedVec<u8, ConstU32<128>>,
    /// AIK public key bytes (SEC1 uncompressed for ECC).
    pub aik_public: BoundedVec<u8, ConstU32<128>>,
    /// TPMS_ATTEST-derived bytes describing the certified AIK.
    /// Produced by `TPM2_Certify` on the EK hierarchy.
    pub aik_certify_info: BoundedVec<u8, ConstU32<512>>,
    /// Signature over `aik_certify_info` by the EK. Proves the AIK
    /// was created under the EK hierarchy.
    pub aik_certify_signature: BoundedVec<u8, ConstU32<256>>,
    /// PCR values included in the quote. Probe lists only those the
    /// pallet cares about; genesis pins them for subsequent compares.
    pub pcr_values: BoundedVec<PcrValue, ConstU32<16>>,
    /// SHA-256 digest of the selected PCRs, as produced by the TPM
    /// internally for the quote. Redundant-by-design with the
    /// `pcrDigest` field inside `quote_attest`; verifier pins them.
    pub pcr_digest: [u8; 32],
    /// Raw `TPMS_ATTEST` blob returned by `TPM2_Quote`. This is what
    /// the TPM actually signed — a restricted AIK cannot sign
    /// arbitrary data, only TPM-internal structures. The verifier
    /// checks `quote_signature` against `SHA-256(quote_attest)` and
    /// then pins the inner `pcrDigest` / `extraData` fields against
    /// the redundant-by-design `pcr_digest` / `nonce` fields on
    /// this struct.
    pub quote_attest: BoundedVec<u8, ConstU32<512>>,
    /// ECDSA-SHA256 signature by the AIK over `quote_attest` (the
    /// TPM's actual signing domain — TPM2_Quote signs
    /// `SHA-256(TPMS_ATTEST)`, not a caller-synthesized commitment).
    pub quote_signature: BoundedVec<u8, ConstU32<256>>,
    /// Nonce injected by the caller to bind the quote to a specific
    /// request. Echoed back from the TPM in `TPMS_ATTEST.extraData`.
    /// Redundant-by-design with the `extraData` field inside
    /// `quote_attest`; verifier pins them.
    pub nonce: [u8; 32],
}

/// Genesis hardware fingerprint — ground truth snapshot of the PoP
/// cert holder's device state at mint. Stored on `CertRecordCold`
/// when a PoP cert is minted. Subsequent (future-pass) HIP proofs
/// are compared against this.
///
/// Only PCR 7 (Secure Boot state) is an exact-match invariant. Other
/// PCRs may legitimately progress forward across OS updates; the
/// full comparison policy is a future-pass concern.
#[derive(Encode, Decode, Clone, PartialEq, Eq, TypeInfo, MaxEncodedLen, Debug)]
pub struct GenesisHardwareFingerprint {
    pub platform: HipPlatform,
    /// `blake2_256(leaf_spki_der)` — device identity. Hash of the
    /// leaf EK cert's SubjectPublicKeyInfo, bound to the signed TBS.
    pub ek_hash: [u8; 32],
    /// `blake2_256(aik_public)` — AIK identity. Ongoing proofs must
    /// use the same AIK (via TPM2_Certify at genesis establishing
    /// AIK's EK-hierarchy membership).
    pub aik_public_hash: [u8; 32],
    /// PCR values at genesis — ground truth for boot-state compares.
    pub pcr_values: BoundedVec<PcrValue, ConstU32<16>>,
    /// Schema version at genesis — for future migrations.
    pub schema_version: crate::cert::SchemaVersion,
}
