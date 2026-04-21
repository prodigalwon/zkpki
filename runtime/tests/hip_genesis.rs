//! Genesis fingerprint recording tests.
//!
//! Exercises the `mint_cert` → `CertRecordCold.genesis_fingerprint`
//! wiring added for the HIP pass. Four paths covered:
//!
//! 1. Non-PoP mint with no HIP proof → cert is created, fingerprint is None.
//! 2. Non-PoP mint with a (silently-ignored) HIP proof → same result.
//! 3. PoP mint without HIP proof → rejected with `HipProofRequired`.
//! 4. PoP mint with valid synth HIP proof → fingerprint recorded,
//!    fields (platform, ek_hash, aik_public_hash, pcr_values,
//!    schema_version) match the proof's inputs.
//!
//! Synthesized HIP proofs are built in-process using RustCrypto
//! `p256` keypairs. Real Windows TPM bytes would be captured via
//! the `tpm2-hip-probe` binary and plumbed into a separate fixture
//! file — out of scope for this test.

use codec::Encode;
use frame_support::{assert_noop, assert_ok, traits::ConstU32, BoundedVec};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use sp_core::crypto::AccountId32;
use sp_runtime::BuildStorage;
use zk_pki_primitives::crypto::DevicePublicKey;
use zk_pki_primitives::eku::Eku;
use zk_pki_primitives::hip::{CanonicalHipProof, HipPlatform, PcrValue};
use zk_pki_primitives::template::PopRequirement;
use zk_pki_runtime::{Runtime, RuntimeOrigin, ZkPki};
use zk_pki_tpm::test_mock_verifier::MockVerdict;
use zk_pki_tpm::AttestationPayloadV3;

// ──────────────────────────────────────────────────────────────────────
// Shared harness
// ──────────────────────────────────────────────────────────────────────

const ROOT_ACCOUNT: [u8; 32] = [0xA1; 32];
const ISSUER_ACCOUNT: [u8; 32] = [0xB2; 32];
const USER_ACCOUNT: [u8; 32] = [0xC3; 32];
const ROOT_PROXY: [u8; 32] = [0xD4; 32];
const ISSUER_PROXY: [u8; 32] = [0xE5; 32];

const INITIAL_BALANCE: u128 = 100_000_000_000_000;

fn account(seed: [u8; 32]) -> AccountId32 {
    AccountId32::from(seed)
}

fn test_cert_ec_pubkey() -> Vec<u8> {
    use p256::ecdsa::VerifyingKey;
    let sk = SigningKey::from_slice(&[7u8; 32]).expect("valid P-256 scalar");
    let vk: VerifyingKey = *sk.verifying_key();
    vk.to_encoded_point(false).as_bytes().to_vec()
}

fn template_name() -> BoundedVec<u8, ConstU32<64>> {
    BoundedVec::try_from(b"hip-template".to_vec()).unwrap()
}

fn new_test_ext() -> sp_io::TestExternalities {
    let mut t = frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .unwrap();
    pallet_balances::GenesisConfig::<Runtime> {
        balances: vec![
            (account(ROOT_ACCOUNT), INITIAL_BALANCE),
            (account(ISSUER_ACCOUNT), INITIAL_BALANCE),
            (account(USER_ACCOUNT), INITIAL_BALANCE),
            (account(ROOT_PROXY), INITIAL_BALANCE),
            (account(ISSUER_PROXY), INITIAL_BALANCE),
        ],
        dev_accounts: None,
    }
    .assimilate_storage(&mut t)
    .unwrap();
    t.into()
}

fn run<R>(f: impl FnOnce() -> R) -> R {
    new_test_ext().execute_with(|| {
        frame_system::Pallet::<Runtime>::set_block_number(1);
        f()
    })
}

/// Register root + issuer + one template. `pop_required` toggles
/// whether the template carries `ProofOfPersonhood` EKU.
fn setup(pop_required: bool) -> ([u8; 32], u64) {
    let root_pubkey =
        DevicePublicKey::new_p256(&test_cert_ec_pubkey()).expect("valid P-256 pubkey");
    let empty_att: BoundedVec<_, _> = BoundedVec::try_from(vec![]).unwrap();
    let empty_cap_ekus: BoundedVec<Eku, ConstU32<8>> =
        BoundedVec::try_from(vec![]).unwrap();
    let pop_cap_ekus: BoundedVec<Eku, ConstU32<8>> =
        BoundedVec::try_from(vec![Eku::ProofOfPersonhood]).unwrap();
    let empty_template_ekus: BoundedVec<Eku, ConstU32<16>> =
        BoundedVec::try_from(vec![]).unwrap();

    assert_ok!(ZkPki::register_root(
        RuntimeOrigin::signed(account(ROOT_ACCOUNT)),
        account(ROOT_PROXY),
        root_pubkey.clone(),
        empty_att.clone(),
        1_000_000u64,
        if pop_required { pop_cap_ekus.clone() } else { empty_cap_ekus.clone() },
    ));
    assert_ok!(ZkPki::issue_issuer_cert(
        RuntimeOrigin::signed(account(ROOT_ACCOUNT)),
        account(ISSUER_ACCOUNT),
        account(ISSUER_PROXY),
        root_pubkey,
        empty_att,
        500_000u64,
        if pop_required { pop_cap_ekus } else { empty_cap_ekus },
    ));
    assert_ok!(ZkPki::create_cert_template(
        RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
        template_name(),
        if pop_required {
            PopRequirement::Required
        } else {
            PopRequirement::NotRequired
        },
        400_000u64,
        1_000u64,
        None,
        None,
        empty_template_ekus,
    ));
    let empty_meta: BoundedVec<_, _> = BoundedVec::try_from(vec![]).unwrap();
    assert_ok!(ZkPki::offer_contract(
        RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
        account(USER_ACCOUNT),
        10_000u64,
        template_name(),
        empty_meta,
    ));
    let ui_key = zk_pki_primitives::keys::IssuerUserKey::new(
        account(ISSUER_ACCOUNT),
        account(USER_ACCOUNT),
    );
    let nonce = zk_pki_pallet::OfferIndex::<Runtime>::get(&ui_key).unwrap();
    let offer = zk_pki_pallet::ContractOffers::<Runtime>::get(nonce).unwrap();
    (nonce, offer.created_at)
}

fn payload_with_verdict(verdict: MockVerdict) -> AttestationPayloadV3 {
    AttestationPayloadV3 {
        cert_ec_chain: vec![vec![]],
        attest_ec_chain: vec![vec![]],
        hmac_binding_output: [0u8; 32],
        binding_signature: vec![],
        integrity_blob: verdict.encode(),
        integrity_signature: vec![],
    }
}

/// Build a minimal TPMS_ATTEST quote blob.
fn synth_tpms_attest_quote(nonce: &[u8; 32], pcr_digest: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xFF54_4347u32.to_be_bytes());
    out.extend_from_slice(&0x8018u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&32u16.to_be_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&[0u8; 17]);
    out.extend_from_slice(&0u64.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&32u16.to_be_bytes());
    out.extend_from_slice(pcr_digest);
    out
}

/// Build a synthesized valid CanonicalHipProof. Mirrors the helper
/// in `cert_template.rs` but duplicated here to keep tests
/// decoupled. PCR 7 = [0x77; 32] is the ground-truth value pinned.
fn synth_hip_proof() -> CanonicalHipProof {
    let ek = SigningKey::from_slice(&[0x11u8; 32]).unwrap();
    let aik = SigningKey::from_slice(&[0x22u8; 32]).unwrap();
    let ek_pub = ek
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let aik_pub = aik
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();

    let aik_certify_info = b"aik-certify-info".to_vec();
    let aik_certify_sig: Signature = ek.sign(&aik_certify_info);

    let pcr_digest = [0xAAu8; 32];
    let nonce = [0x01u8; 32];

    // TPM2_Quote signs SHA-256(TPMS_ATTEST) under the AIK.
    let quote_attest = synth_tpms_attest_quote(&nonce, &pcr_digest);
    let quote_sig: Signature = aik.sign(&quote_attest);

    let pcr_values: BoundedVec<PcrValue, ConstU32<16>> = BoundedVec::try_from(vec![
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
        aik_certify_signature: BoundedVec::try_from(aik_certify_sig.to_der().as_bytes().to_vec()).unwrap(),
        pcr_values,
        pcr_digest,
        quote_attest: BoundedVec::try_from(quote_attest).unwrap(),
        quote_signature: BoundedVec::try_from(quote_sig.to_der().as_bytes().to_vec()).unwrap(),
        nonce,
    }
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

#[test]
fn non_pop_mint_without_hip_proof_records_no_fingerprint() {
    run(|| {
        let (nonce, created_at) = setup(false);
        assert_ok!(ZkPki::mint_cert(
            RuntimeOrigin::signed(account(USER_ACCOUNT)),
            nonce,
            payload_with_verdict(MockVerdict::Packed {
                pubkey_bytes: test_cert_ec_pubkey(),
            }),
            created_at,
            None,
        ));
        let ui_key = zk_pki_primitives::keys::UserIssuerKey::new(
            account(USER_ACCOUNT),
            account(ISSUER_ACCOUNT),
        );
        let thumbprint =
            zk_pki_pallet::UserIssuerIndex::<Runtime>::get(&ui_key).unwrap();
        let cold = zk_pki_pallet::CertLookupCold::<Runtime>::get(thumbprint).unwrap();
        assert!(
            cold.genesis_fingerprint.is_none(),
            "non-PoP cert must not carry a fingerprint",
        );
    });
}

#[test]
fn non_pop_mint_with_hip_proof_silently_ignores_it() {
    run(|| {
        let (nonce, created_at) = setup(false);
        assert_ok!(ZkPki::mint_cert(
            RuntimeOrigin::signed(account(USER_ACCOUNT)),
            nonce,
            payload_with_verdict(MockVerdict::Packed {
                pubkey_bytes: test_cert_ec_pubkey(),
            }),
            created_at,
            Some(synth_hip_proof()),
        ));
        let ui_key = zk_pki_primitives::keys::UserIssuerKey::new(
            account(USER_ACCOUNT),
            account(ISSUER_ACCOUNT),
        );
        let thumbprint =
            zk_pki_pallet::UserIssuerIndex::<Runtime>::get(&ui_key).unwrap();
        let cold = zk_pki_pallet::CertLookupCold::<Runtime>::get(thumbprint).unwrap();
        // Non-PoP templates don't record a fingerprint even when a
        // proof is supplied — documented behaviour.
        assert!(cold.genesis_fingerprint.is_none());
    });
}

#[test]
fn pop_mint_without_hip_proof_rejected() {
    run(|| {
        let (nonce, created_at) = setup(true);
        assert_noop!(
            ZkPki::mint_cert(
                RuntimeOrigin::signed(account(USER_ACCOUNT)),
                nonce,
                payload_with_verdict(MockVerdict::Tpm {
                    ek_hash: [0x42u8; 32],
                    pubkey_bytes: test_cert_ec_pubkey(),
                }),
                created_at,
                None,
            ),
            zk_pki_pallet::Error::<Runtime>::HipProofRequired,
        );
    });
}

#[test]
fn pop_mint_with_valid_hip_proof_records_fingerprint() {
    run(|| {
        let (nonce, created_at) = setup(true);
        let proof = synth_hip_proof();
        let expected_ek_hash = proof.ek_hash;
        let expected_aik_hash = sp_io::hashing::blake2_256(proof.aik_public.as_slice());
        let expected_pcr_values = proof.pcr_values.clone();

        assert_ok!(ZkPki::mint_cert(
            RuntimeOrigin::signed(account(USER_ACCOUNT)),
            nonce,
            payload_with_verdict(MockVerdict::Tpm {
                ek_hash: [0x42u8; 32],
                pubkey_bytes: test_cert_ec_pubkey(),
            }),
            created_at,
            Some(proof),
        ));

        let ui_key = zk_pki_primitives::keys::UserIssuerKey::new(
            account(USER_ACCOUNT),
            account(ISSUER_ACCOUNT),
        );
        let thumbprint =
            zk_pki_pallet::UserIssuerIndex::<Runtime>::get(&ui_key).unwrap();
        let cold = zk_pki_pallet::CertLookupCold::<Runtime>::get(thumbprint).unwrap();
        let fp = cold
            .genesis_fingerprint
            .expect("PoP mint must record a fingerprint");

        assert!(matches!(fp.platform, HipPlatform::Tpm2Windows));
        assert_eq!(fp.ek_hash, expected_ek_hash);
        assert_eq!(fp.aik_public_hash, expected_aik_hash);
        assert_eq!(fp.pcr_values, expected_pcr_values);
        assert_eq!(
            fp.schema_version,
            zk_pki_primitives::cert::CURRENT_SCHEMA_VERSION,
        );
    });
}

#[test]
fn pop_mint_with_invalid_hip_proof_rejected() {
    run(|| {
        let (nonce, created_at) = setup(true);
        let mut bad_proof = synth_hip_proof();
        bad_proof.ek_hash = [0x99u8; 32]; // EK hash mismatch.

        assert_noop!(
            ZkPki::mint_cert(
                RuntimeOrigin::signed(account(USER_ACCOUNT)),
                nonce,
                payload_with_verdict(MockVerdict::Tpm {
                    ek_hash: [0x42u8; 32],
                    pubkey_bytes: test_cert_ec_pubkey(),
                }),
                created_at,
                Some(bad_proof),
            ),
            zk_pki_pallet::Error::<Runtime>::HipProofInvalid,
        );
    });
}

#[test]
fn pop_mint_with_unimplemented_platform_rejected() {
    run(|| {
        let (nonce, created_at) = setup(true);
        let mut proof = synth_hip_proof();
        proof.platform = HipPlatform::StrongBox;

        assert_noop!(
            ZkPki::mint_cert(
                RuntimeOrigin::signed(account(USER_ACCOUNT)),
                nonce,
                payload_with_verdict(MockVerdict::Tpm {
                    ek_hash: [0x42u8; 32],
                    pubkey_bytes: test_cert_ec_pubkey(),
                }),
                created_at,
                Some(proof),
            ),
            zk_pki_pallet::Error::<Runtime>::HipProofPlatformNotImplemented,
        );
    });
}
