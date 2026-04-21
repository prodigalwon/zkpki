# ZK-PKI Security Notes

## TpmTestAttestationVerifier / NoopBindingProofVerifier

The `TpmTestAttestationVerifier` (in `zk-pki-primitives::traits`) and the
`NoopBindingProofVerifier` (in `zk-pki-tpm::test_mock_verifier`) accept
caller-controlled EK hashes and bypass all hardware attestation chain
verification. They exist solely for testing purposes.

**These verifiers MUST NEVER be enabled in any runtime handling real
value.**

They are currently wired in `zk-pki-runtime` (test runtime) and in
`paseo-node/runtime` (testnet) via the `test-attestation` Cargo feature,
with explicit TODO comments marking them for replacement with the real
`ProductionBindingProofVerifier` and `TpmAttestationVerifier` before
Kusama deployment.

Enabling `test-attestation` in production is equivalent to removing all
Sybil resistance from the protocol. An attacker could mint unlimited PoP
certificates by providing arbitrary EK hashes.

## Feature Flag Guard

`paseo-node/runtime/Cargo.toml` defines two mutually-exclusive features:

- `test-attestation` — forwards `zk-pki-tpm/test-utils`, enabling the
  bypass-crypto verifiers. Included in `default` so testnet builds work
  without extra flags.
- `production` — marker feature for production builds. No functional
  forward today; the downstream wiring swap is a separate pre-Kusama
  task.

`paseo-node/runtime/src/lib.rs` contains a `compile_error!` that refuses
to compile when both are enabled. A production build must pass
`--no-default-features --features std,production`.

## Pre-Kusama Checklist

- [ ] Remove `test-attestation` from default features in
      `paseo-node/runtime/Cargo.toml`.
- [ ] Swap `T::Attestation` from `TpmTestAttestationVerifier` to the real
      `zk_pki_tpm::TpmAttestationVerifier` in
      `paseo-node/runtime/src/configs/mod.rs`.
- [ ] Swap `T::BindingProofVerifier` from
      `zk_pki_tpm::test_mock_verifier::NoopBindingProofVerifier` to
      `zk_pki_tpm::ProductionBindingProofVerifier`.
- [ ] Run the benchmark CLI against the production runtime and replace
      the placeholder `zk_pki_pallet::weights::SubstrateWeight<Runtime>`
      stub with real weight values.
- [ ] Replace all `YOUR_PEN` placeholders with the IANA Private
      Enterprise Number once PHH7-C3F-3EC is assigned.
- [ ] Replace the `DOTWAVE_SIGNING_CERT_HASH` placeholder in
      `zk-pki-integrity` with the real production APK signing cert hash.
- [ ] Replace the `PkiProtocolFeeRecipient: AccountId = [0u8; 32]`
      placeholder in `paseo-node/runtime/src/configs/mod.rs` with the
      production treasury SS58 account.
- [ ] Build with `--no-default-features --features std,production` and
      confirm the `compile_error!` guard in `src/lib.rs` does not fire.

## Post-Paseo Fix List

Issues surfaced by the 2026-04-19 red-team remediation pass that are
out of scope for Paseo launch but must land before Kusama.

- **`deregister_root` deposit mismatch.** `issue_issuer_cert` places
  the issuer-cert hold on `root_addr`; `deregister_root` tries to
  release from `issuer_addr`. The release path fails (or no-ops on a
  zero held balance). See `BUG:` comments at
  `pallet/src/lib.rs` around the `hold_cert_deposit` site in
  `issue_issuer_cert` and the `release_cert_deposit` site in the
  `deregister_root` cascade loop. Fix direction: release from
  `root_addr` (the holder) and optionally transfer to `issuer_addr`
  if the policy calls for it.
- **`PurgeIndex` 256-slot griefing.** An attacker paying 256 mint
  fees can fill a single block's slot; the 257th mint aborts with
  `PurgeIndexFull`. Economically bounded but worth fixing. See
  `KNOWN LIMITATION` doc on the `PurgeIndex` storage item. Fix
  direction: spill-to-next-block or hash-striped slots.
