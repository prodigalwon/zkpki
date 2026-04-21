//! Verifier unit tests using synthesized `CanonicalHipProof` structs.
//!
//! These tests do not touch real TPM hardware — they construct
//! proofs with RustCrypto `p256` keypairs, sign the three synthetic
//! elements (EK-over-aik_certify_info, AIK-over-commitment), and
//! confirm `zk_pki_hip::verify_hip_proof_internal` accepts or
//! rejects them as designed.

use frame_support::{traits::ConstU32, BoundedVec};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use zk_pki_hip::{verify_hip_proof_internal, HipError};
use zk_pki_primitives::hip::{CanonicalHipProof, HipPlatform, PcrValue};

fn sign_p256(sk: &SigningKey, msg: &[u8]) -> Vec<u8> {
    let sig: Signature = sk.sign(msg);
    sig.to_der().as_bytes().to_vec()
}

fn pub_bytes(sk: &SigningKey) -> Vec<u8> {
    sk.verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}

/// Build a minimal TPMS_ATTEST (type = TPM_ST_ATTEST_QUOTE) blob.
/// `extraData` = nonce, `pcrDigest` = pcr_digest, everything else
/// zeroed — the verifier's attest parser ignores the metadata
/// fields (qualifiedSigner, clockInfo, firmwareVersion, pcrSelect)
/// and only pins extraData + pcrDigest against the canonical proof.
fn synth_tpms_attest_quote(nonce: &[u8; 32], pcr_digest: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xFF54_4347u32.to_be_bytes()); // magic
    out.extend_from_slice(&0x8018u16.to_be_bytes()); // TPM_ST_ATTEST_QUOTE
    out.extend_from_slice(&0u16.to_be_bytes()); // qualifiedSigner: empty name
    out.extend_from_slice(&32u16.to_be_bytes()); // extraData size
    out.extend_from_slice(nonce);
    out.extend_from_slice(&[0u8; 17]); // clockInfo: zeros
    out.extend_from_slice(&0u64.to_be_bytes()); // firmwareVersion
    out.extend_from_slice(&0u32.to_be_bytes()); // pcrSelect count = 0
    out.extend_from_slice(&32u16.to_be_bytes()); // pcrDigest size
    out.extend_from_slice(pcr_digest);
    out
}

/// Build a fresh synthesized valid proof. Fixed scalars → deterministic.
fn valid_proof() -> CanonicalHipProof {
    let ek = SigningKey::from_slice(&[0x11u8; 32]).unwrap();
    let aik = SigningKey::from_slice(&[0x22u8; 32]).unwrap();
    let ek_pub = pub_bytes(&ek);
    let aik_pub = pub_bytes(&aik);

    let aik_certify_info = b"aik-certify-info".to_vec();
    let aik_certify_sig = sign_p256(&ek, &aik_certify_info);

    let pcr_digest = [0xAAu8; 32];
    let nonce = [0x01u8; 32];

    // TPM's actual signing domain: SHA-256(TPMS_ATTEST) under AIK.
    // `Signer::sign` hashes with SHA-256 internally, matching the
    // verifier's `Sha256::digest(quote_attest)` + verify_prehash.
    let quote_attest = synth_tpms_attest_quote(&nonce, &pcr_digest);
    let quote_sig = sign_p256(&aik, &quote_attest);

    let pcr_values: BoundedVec<PcrValue, ConstU32<16>> = BoundedVec::try_from(vec![
        PcrValue { index: 0, value: [0u8; 32] },
        PcrValue { index: 7, value: [0x77u8; 32] },
    ])
    .unwrap();

    let ek_hash = sp_io::hashing::blake2_256(&ek_pub);

    CanonicalHipProof {
        platform: HipPlatform::Tpm2Windows,
        ek_hash,
        ek_public: BoundedVec::try_from(ek_pub).unwrap(),
        aik_public: BoundedVec::try_from(aik_pub).unwrap(),
        aik_certify_info: BoundedVec::try_from(aik_certify_info).unwrap(),
        aik_certify_signature: BoundedVec::try_from(aik_certify_sig).unwrap(),
        pcr_values,
        pcr_digest,
        quote_attest: BoundedVec::try_from(quote_attest).unwrap(),
        quote_signature: BoundedVec::try_from(quote_sig).unwrap(),
        nonce,
    }
}

#[test]
fn synth_valid_proof_verifies() {
    sp_io::TestExternalities::default().execute_with(|| {
        let proof = valid_proof();
        let report = verify_hip_proof_internal(&proof).expect("synth proof verifies");
        assert!(matches!(report.platform, HipPlatform::Tpm2Windows));
        assert!(report.device_identity_confirmed);
    });
}

#[test]
fn ek_hash_mismatch_rejected() {
    sp_io::TestExternalities::default().execute_with(|| {
        let mut proof = valid_proof();
        proof.ek_hash = [0x99u8; 32]; // bogus
        assert_eq!(
            verify_hip_proof_internal(&proof).unwrap_err(),
            HipError::EkHashMismatch,
        );
    });
}

#[test]
fn tampered_aik_certify_signature_rejected() {
    sp_io::TestExternalities::default().execute_with(|| {
        let mut proof = valid_proof();
        // Flip a byte in the signature — DER parse will still work but
        // the curve check fails. If DER parse fails we land on
        // BadSignature. Either path is acceptable for a tamper test.
        let mut sig_bytes = proof.aik_certify_signature.to_vec();
        sig_bytes[5] ^= 0x01;
        proof.aik_certify_signature = BoundedVec::try_from(sig_bytes).unwrap();
        let err = verify_hip_proof_internal(&proof).unwrap_err();
        assert!(
            matches!(err, HipError::AikCertifyInvalid | HipError::BadSignature),
            "unexpected error variant: {:?}",
            err,
        );
    });
}

#[test]
fn tampered_quote_signature_rejected() {
    sp_io::TestExternalities::default().execute_with(|| {
        let mut proof = valid_proof();
        let mut sig_bytes = proof.quote_signature.to_vec();
        sig_bytes[5] ^= 0x01;
        proof.quote_signature = BoundedVec::try_from(sig_bytes).unwrap();
        let err = verify_hip_proof_internal(&proof).unwrap_err();
        assert!(
            matches!(err, HipError::QuoteSignatureInvalid | HipError::BadSignature),
            "unexpected error variant: {:?}",
            err,
        );
    });
}

#[test]
fn tampered_pcr_digest_rejected() {
    sp_io::TestExternalities::default().execute_with(|| {
        let mut proof = valid_proof();
        // Tamper the outer fast-access field. The inner attest's
        // pcrDigest is untouched, so the pin check catches the
        // divergence.
        proof.pcr_digest[0] ^= 0x01;
        assert_eq!(
            verify_hip_proof_internal(&proof).unwrap_err(),
            HipError::PcrDigestMismatch,
        );
    });
}

#[test]
fn tampered_nonce_rejected() {
    sp_io::TestExternalities::default().execute_with(|| {
        let mut proof = valid_proof();
        // Tampering the outer nonce field without updating the
        // attest's extraData triggers the nonce-pin error. The
        // quote signature still verifies (it's over the
        // unchanged attest) — the pin is what catches this.
        proof.nonce[0] ^= 0x01;
        assert_eq!(
            verify_hip_proof_internal(&proof).unwrap_err(),
            HipError::NonceAttestMismatch,
        );
    });
}

#[test]
fn android_platform_not_implemented() {
    sp_io::TestExternalities::default().execute_with(|| {
        let mut proof = valid_proof();
        proof.platform = HipPlatform::StrongBox;
        assert_eq!(
            verify_hip_proof_internal(&proof).unwrap_err(),
            HipError::PlatformNotImplemented,
        );
    });
}

#[test]
fn linux_platform_not_implemented() {
    sp_io::TestExternalities::default().execute_with(|| {
        let mut proof = valid_proof();
        proof.platform = HipPlatform::Tpm2Linux;
        assert_eq!(
            verify_hip_proof_internal(&proof).unwrap_err(),
            HipError::PlatformNotImplemented,
        );
    });
}

#[test]
fn genesis_path_aik_hash_mismatch_rejected() {
    use zk_pki_primitives::hip::GenesisHardwareFingerprint;

    sp_io::TestExternalities::default().execute_with(|| {
        let proof = valid_proof();
        let wrong_aik_hash = [0xBBu8; 32];
        let genesis = GenesisHardwareFingerprint {
            platform: HipPlatform::Tpm2Windows,
            ek_hash: proof.ek_hash,
            aik_public_hash: wrong_aik_hash,
            pcr_values: proof.pcr_values.clone(),
            schema_version: zk_pki_primitives::cert::CURRENT_SCHEMA_VERSION,
        };
        assert_eq!(
            zk_pki_hip::verify_hip_proof_against_genesis(&proof, &genesis, &proof.nonce).unwrap_err(),
            HipError::AikGenesisMismatch,
        );
    });
}

#[test]
fn genesis_path_pcr7_mismatch_rejected() {
    use zk_pki_primitives::hip::GenesisHardwareFingerprint;

    sp_io::TestExternalities::default().execute_with(|| {
        let proof = valid_proof();
        let aik_hash = sp_io::hashing::blake2_256(proof.aik_public.as_slice());
        // Genesis has PCR 7 = [0x00; 32] which differs from proof's [0x77; 32].
        let genesis_pcrs: BoundedVec<PcrValue, ConstU32<16>> = BoundedVec::try_from(vec![
            PcrValue { index: 7, value: [0x00u8; 32] },
        ])
        .unwrap();
        let genesis = GenesisHardwareFingerprint {
            platform: HipPlatform::Tpm2Windows,
            ek_hash: proof.ek_hash,
            aik_public_hash: aik_hash,
            pcr_values: genesis_pcrs,
            schema_version: zk_pki_primitives::cert::CURRENT_SCHEMA_VERSION,
        };
        assert_eq!(
            zk_pki_hip::verify_hip_proof_against_genesis(&proof, &genesis, &proof.nonce).unwrap_err(),
            HipError::Pcr7GenesisMismatch,
        );
    });
}

#[test]
fn genesis_path_valid_against_matching_fingerprint() {
    use zk_pki_primitives::hip::GenesisHardwareFingerprint;

    sp_io::TestExternalities::default().execute_with(|| {
        let proof = valid_proof();
        let aik_hash = sp_io::hashing::blake2_256(proof.aik_public.as_slice());
        let genesis = GenesisHardwareFingerprint {
            platform: HipPlatform::Tpm2Windows,
            ek_hash: proof.ek_hash,
            aik_public_hash: aik_hash,
            pcr_values: proof.pcr_values.clone(),
            schema_version: zk_pki_primitives::cert::CURRENT_SCHEMA_VERSION,
        };
        let expected_nonce = proof.nonce;
        let report =
            zk_pki_hip::verify_hip_proof_against_genesis(&proof, &genesis, &expected_nonce)
                .expect("matching genesis verifies");
        assert!(report.device_identity_confirmed);
    });
}
