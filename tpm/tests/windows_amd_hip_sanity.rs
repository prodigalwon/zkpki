//! Sanity tests for the captured Windows AMD fTPM HIP proof.
//!
//! Confirms the real-hardware bytes decode as a `CanonicalHipProof`,
//! the critical fields round-trip correctly through SCALE, and the
//! `zk-pki-hip` verifier accepts the bytes when `self` is used as
//! the genesis fingerprint (end-to-end crypto check against real
//! AMD fTPM hardware — the signing-domain-mismatch catch that
//! motivated adding `quote_attest` to the canonical struct).

#[path = "fixtures/windows_amd_hip_proof.rs"]
mod fixture;

use codec::Decode;
use zk_pki_primitives::cert::CURRENT_SCHEMA_VERSION;
use zk_pki_primitives::hip::{
    CanonicalHipProof, GenesisHardwareFingerprint, HipPlatform,
};

#[test]
fn hip_proof_bytes_not_empty() {
    let bytes = fixture::canonical_hip_proof_bytes();
    assert!(!bytes.is_empty());
}

#[test]
fn hip_proof_decodes_from_scale() {
    let bytes = fixture::canonical_hip_proof_bytes();
    let proof = CanonicalHipProof::decode(&mut &bytes[..])
        .expect("CanonicalHipProof should decode from real hardware bytes");
    // Platform should be Tpm2Windows
    assert!(matches!(
        proof.platform,
        zk_pki_primitives::hip::HipPlatform::Tpm2Windows,
    ));
}

#[test]
fn hip_proof_nonce_matches_capture() {
    let bytes = fixture::canonical_hip_proof_bytes();
    let proof = CanonicalHipProof::decode(&mut &bytes[..]).unwrap();
    assert_eq!(proof.nonce, fixture::genesis_nonce());
}

#[test]
fn hip_proof_pcr_values_present() {
    let bytes = fixture::canonical_hip_proof_bytes();
    let proof = CanonicalHipProof::decode(&mut &bytes[..]).unwrap();
    assert!(!proof.pcr_values.is_empty());
}

#[test]
fn hip_proof_aik_public_present() {
    let bytes = fixture::canonical_hip_proof_bytes();
    let proof = CanonicalHipProof::decode(&mut &bytes[..]).unwrap();
    assert!(!proof.aik_public.is_empty());
}

#[test]
fn hip_proof_verifies_against_self_as_genesis() {
    // Build a genesis fingerprint from this proof's own values and
    // run it through the full verifier. This proves the crypto path
    // (EK-hash consistency, AIK-certify signature under EK, quote
    // signature under AIK) executes correctly on real AMD fTPM
    // hardware bytes — not just that the SCALE struct decodes.
    //
    // Self-as-genesis is the right pattern for a single capture; it
    // does NOT exercise cross-proof comparison (the PCR7 / AIK
    // identity gates between a fresh proof and a stored genesis),
    // which requires two separate captures.
    //
    // Wrapped in a TestExternalities block because
    // `sp_io::hashing::blake2_256` (called inside the verifier) is a
    // runtime-interface function that requires an externalities
    // context.
    sp_io::TestExternalities::default().execute_with(|| {
        let bytes = fixture::canonical_hip_proof_bytes();
        let proof = CanonicalHipProof::decode(&mut &bytes[..]).unwrap();

        let genesis = GenesisHardwareFingerprint {
            platform: HipPlatform::Tpm2Windows,
            ek_hash: proof.ek_hash,
            aik_public_hash: sp_io::hashing::blake2_256(proof.aik_public.as_slice()),
            pcr_values: proof.pcr_values.clone(),
            schema_version: CURRENT_SCHEMA_VERSION,
        };

        // Self-as-genesis — pass the proof's own nonce as the
        // caller-expected nonce. The check is a tautology here and
        // doesn't exclude any valid proof; it's what PopAssertion
        // paths supply the caller's request-specific nonce for.
        let expected_nonce = proof.nonce;
        let result =
            zk_pki_hip::verify_hip_proof_against_genesis(&proof, &genesis, &expected_nonce);
        assert!(
            result.is_ok(),
            "real-hardware HIP proof should verify against its own genesis: {:?}",
            result.err(),
        );
    });
}
