# ZK-PKI Pallet — Project Context for Claude Code

## What This Project Is

A blockchain-native, FIDO2-compliant Public Key Infrastructure implemented as a **FRAME pallet** for the Polkadot network. It provides proof of personhood (PoP), digital signature, and non-repudiation through a hierarchical certificate system where trust is contextual, composable, and reputation-scored.

This is **infrastructure for anyone to become their own certificate authority** on-chain. The pallet doesn't care what the cert means — it provides identity binding, authority hierarchy, validity state, non-repudiation, and reputation signal. Application logic (KYC policy, access gating, ticket validation, etc.) lives in consuming contracts and dApps.

The protocol is amoral infrastructure. It records facts and provides signal. The application layer (dotwave, a bank's dApp, a venue scanner) is where judgment happens. The pallet says "this issuer is compromised." The app decides what to do with that fact.

## Workspace Layout

```
../pns-node/        ← Polkadot SDK / Substrate node (neighboring project)
./                  ← This pallet workspace (zk-pki)
```

The Polkadot SDK is at `../pns-node/`. Use it for dependency paths and for running integration tests via the reference runtime.

## Crate Structure

| Crate | Role |
|---|---|
| `zk-pki-primitives` | Shared types, traits, SCALE helpers, P-521 crypto. `no_std` compatible, no internal deps. |
| `zk-pki-tpm` | TPM attestation parsing, EK extraction, trust chain verification. Depends only on primitives. |
| `zk-pki-pallet` | All FRAME extrinsics, storage, lookup table, EK registry, TTL validation, purge, atomic ops. |
| `zk-pki-rpc` | JSON-RPC node extension, off-chain query layer. Depends on primitives + pallet via runtime-api. |
| `zk-pki-runtime` | Reference runtime wiring the pallet in, for integration testing only. |
| `zk-pki-client` | Mobile app Rust layer: TPM extrinsic construction, TOTP handoff, contract signing. |

**Dependency direction is strictly one-way.** Nothing depends on `rpc` or `runtime`. `primitives` depends on nothing internal.

## Trust Hierarchy

```
Root (self-signed, TPM keypair, proxy account)
 └─ Issuer (cert from root, TPM keypair, proxy account)
     └─ End User (contract offer → TPM genesis → NFT cert minted)
```

Three tiers, strict hierarchy, no shortcuts.

- **Root**: issues issuer certs only. Cannot certify end users directly. Can invalidate issuers. Reputation-scored. Self-signed — trust is earned, not assumed. An address cannot be both root and issuer simultaneously (hard reject at registration).
- **Issuer**: issues to end users only. Cannot issue to other issuers. Can invalidate/suspend user certs. Can unilaterally reissue (the issuer owns the credential — same as a government owns a passport). Cannot burn user NFTs. One cert per user address per issuer maximum. Max issuers per root is a configurable runtime constant (`MaxIssuersPerRoot`) with a hard pallet ceiling of 100.
- **End User**: receives contract offer from issuer. Responds with proof of physical device possession. Holds the cert NFT (receipt of credential) — issuer can only invalidate lookup presence, not burn the token. Can self-discard.

## State Machine — Root & Issuer

Five states: **active**, **retired**, **challenge**, **compromised**, and implicit **deregistered**.

Precedence order: `compromised → challenge → retired → active`.

### Active
Normal operating state. Can issue, renew, operate.

### Retired
Legacy state during renewal. When a root or issuer renews, the old cert enters `retired` state. No new issuance allowed from the retired cert. Existing end-user certs anchored to the retired cert remain valid until their own NotAfter. The active (current) cert handles all new issuance. Point-of-use checks walk the chain: look up active first, then retired if needed for cert validation.

### Challenge
45-day contest window. Only the flagged entity can initiate. Reputation unchanged during challenge — innocent until proven guilty. Falls back to `compromised` automatically if unresolved. No new issuance during challenge.

### Compromised
Permanent. Entire issuance history suspect. No surgical cert rescue. Overrides all other states — a compromised entity in retired or active state is radioactive immediately, no grace period, no continuity window.

### Deregistered
Voluntary exit. Root-initiated via `deregister_root`. All issuer records under the root invalidated and deposits returned. End-user certs not touched — they belong to users who reclaim deposits via self-discard. Root's own deposit reclaimed.

### Compromise Handling

**Issuer compromise**: only the root or the advisory contract can mark an issuer compromised. Total invalidation — entire issuance history suspect. Root bears operational responsibility to act. Advisory contract provides public, append-only, irrevocable compromise signal.

**Root compromise**: only the advisory contract (via OpenGov referendum) can mark a root compromised. No self-flag extrinsic — voluntary self-disclosure routes through the advisory contract quorum out of band. Prevents attacker with root's seed phrase from using self-flagging as denial of service.

**Axis of evil**: the pallet does not hard-block compromised entities from calling extrinsics. In a decentralized system, you cannot unilaterally prevent an actor from submitting transactions. Instead, the pallet surfaces compromise context via events alongside every action taken by a compromised entity. The RPC layer exposes this. Application layers (dotwave, etc.) present this to users ("this issuer is compromised — are you sure?"). The protocol provides signal, not judgment.

**Re-anchoring prohibition**: a compromised issuer cannot re-anchor certs under a new identity. Re-anchoring requires the original issuer, in good standing, never compromised. Compromise is a permanent disqualifier.

**Challenge state effects**: makes cert chain radioactive to regulated relying parties by their own policy. Decentralized communities can continue trusting if they choose.

## Certificate / NFT Structure

The NFT is a receipt of the credential. The issuer owns the credential — they verified you, they control its validity. Same as a passport: you hold the physical document, but the issuing nation can revoke it at will.

### Canonical Serialization (thumbprint input order)
All fields **SCALE-encoded individually** before concatenation. Raw byte concatenation is **prohibited** — ambiguous field boundaries create preimage collision vectors.

1. `schema_version` (u16) — always first, enables migration detection
2. Root address
3. Issuer address
4. User address
5. User TPM public key (P-521)
6. TTL / expiry (absolute block number, u64)
7. Any additional immutable issuer-defined metadata

**Hash function**: `Blake2b-256` via `sp_core::blake2_256`. Computed on-chain at mint time.

### NFT Metadata Fields
`schema_version`, thumbprint, root address, issuer address, user address, user TPM public key, TTL/expiry (absolute block number), attestation statement, immutable issuer-defined metadata.

### Immutability Rules
- Certs are **monolithic** — no key rotation, no field updates.
- A compromised or lost cert requires reissuance; old cert is invalidated.

## Storage & State

### Lookup Table
Primary key: thumbprint (unique by construction).

Fields: thumbprint, schema_version, user address, issuer address, root address, `is_active` (bool), suspension reason (optional), suspension timestamp, mint block number, expiry block number, `purge_eligible_block` (computed at mint: `expiry_block + InactivePurgeBlocks`; updated on suspension/reactivation), storage deposit amount.

| `is_active` | In Table | Meaning |
|---|---|---|
| true | yes | Fully valid |
| false | yes | Suspended — pending reactivation or purge |
| — | no | Purged, invalidated, reissued, or self-discarded |

### Secondary Index — Purge Queue
`StorageMap` keyed by `purge_eligible_block` → list of thumbprints eligible for purge at that block. `purge_eligible_block` is computed at mint time (`expiry_block + InactivePurgeBlocks`) and stored in the `CertRecord`. For suspended certs, `purge_eligible_block` is set at suspension time (`suspension_block + InactivePurgeBlocks`) and cleared on reactivation. Piggyback cleanup and `purge_expired` check `current_block >= purge_eligible_block` — one comparison, no scanning.

### Secondary Index — Contract Offer Expiry
Same piggyback mechanism covers expired contract offers. Every mint grabs expired offers from an offer expiry index alongside cert entries. Storage deposits on expired offers claimable by whoever triggers purge.

### EK Registry
Separate on-chain map: `(root, EK hash) → active thumbprint`. Root-scoped deduplication — one active PoP cert per physical device **per root trust hierarchy**. Different roots are independent trust domains and may independently certify the same device. Within a single root's hierarchy, a device with an existing active PoP cert cannot mint a second PoP cert; reissuance is required, which atomically replaces the existing cert. This preserves Sybil resistance within each trust domain while allowing real-world institutions to independently certify the same user on the same hardware.

### Root Compromise Registry
Controlled by the advisory contract (via OpenGov). Three-state model: active, challenge, compromised. Write access restricted to governance extrinsics and advisory contract dispatch only.

### Retired Records
Separate `RetiredIssuers` / `RetiredRoots` storage maps keyed by `(AccountId, Thumbprint)`. Stores legacy cert records during renewal. No new issuance from retired records. Existing end-user certs anchored to retired records valid until their own NotAfter.

### User-Issuer Index
Newtype wrapper `UserIssuerKey { user: AccountId, issuer: AccountId }` for type safety. All code touching the index uses named field access. Prevents silent breakage from field reordering in storage migrations.

### Contract Offers
One active offer per issuer-user pair. When an issuer creates a new offer for a user where an unexpired offer already exists, the pallet atomically revokes the old offer and writes the new one. Old offer deposit returned, new deposit taken, in same execution. New offer gets a fresh nonce.

## Key Invariants — Never Violate These

1. **Atomicity**: all storage operations touching related state (lookup table, EK registry, NFT) must occur in the same execution. No partial updates.
2. **SCALE encoding**: thumbprint inputs are always SCALE-encoded. Raw byte concat is a bug.
3. **Replay prevention**: genesis contract offers have a unique block-bound nonce AND a block expiry. Both checks are required. Offer removal from `ContractOffers` is the nonce consumption mechanism — no separate `ConsumedNonces` map.
4. **Belt-and-suspenders validity**: a cert is valid only if it is both present in the lookup table AND `is_active = true` AND every cert in its chain (issuer cert, root cert) has a NotAfter that hasn't passed. Either condition alone is not sufficient.
5. **Write-once compromise fields**: `compromised_at_block` on issuer records and root records are write-once. Never overwrite.
6. **EK deduplication**: root-scoped. At mint, reject if EK is already mapped to an active PoP cert *under the same root*. Different roots are independent trust domains and may independently certify the same device. Within a single root's hierarchy a second PoP cert for the same device requires reissuance, not a fresh mint.
7. **NFT ownership**: issuers cannot burn a user's NFT. They can only remove the lookup table entry (invalidation) or flip `is_active = false` (suspension). Issuers CAN unilaterally reissue — the credential belongs to them.
8. **Schema version floor at reissuance**: the pallet refuses to mint any cert at a `schema_version` lower than `CURRENT_SCHEMA_VERSION`. Existing certs remain valid under their original schema until they expire via TTL. At reissuance, the new cert must be at the current version. This is the cryptographic migration lever — when `CURRENT_SCHEMA_VERSION` is bumped (e.g., to adopt post-quantum signatures), all new and renewed certs move to the new standard. Old certs age out. No flag day.
9. **X.509 TTL chain constraint**: a child cert's expiry cannot exceed its parent's expiry. Pallet enforces at mint time — hard check, not advisory.
10. **Cascading invalidation via NotAfter**: root expires → all issuer certs under it immediately invalid. Issuer cert expires → all end-user certs under it immediately invalid. Checked at point of use (extrinsic validation, RPC query), not via `on_initialize`.
11. **Compromise is a permanent disqualifier for re-anchoring**: a compromised issuer cannot re-anchor certs under a new identity.
12. **Proxy validation**: proxy relationship must already exist in Substrate's proxy pallet before `register_root` or `issue_issuer_cert` is accepted. Pallet checks `pallet_proxy` at call time.
13. **Role exclusivity**: an address cannot be both root and issuer simultaneously. Hard reject at registration.
14. **Reactivation guard**: `reactivate_cert` rejects if `expiry_block < current_block`. Reissuance is the only path for expired certs.
15. **Issuer cert suspension prohibited**: issuer certs cannot be suspended. Roots invalidate issuers, period. `suspend_cert` checks cert type and rejects issuer certs.

## TTL Hierarchy & Enforcement

| Tier | Max TTL | Set By | Constraint |
|---|---|---|---|
| Root | 5 years | Root at registration | Hard cap enforced by pallet |
| Issuer | Root-defined | Root at `issue_issuer_cert` | Cannot exceed root's NotAfter |
| End User | Issuer-defined | Issuer in contract offer | Cannot exceed issuer's NotAfter |

- TTL stored as **absolute block number**, not a duration.
- **No `on_initialize` for TTL enforcement.** Validity is checked at point of use — the cert is either valid when someone relies on it or it isn't. No background block scanning.
- Reissuance is the only way to extend validity.

## Trust Chain Renewal

- **Renewal before expiry is the clean path.** Same keypair, new cert, extended validity window. Successor binding signed by old keypair proves chain of custody continuity.
- **Issuer renews before expiry** → old cert moves to `retired` state. End-user certs re-anchored automatically. No re-KYC, no new TPM ceremony, no user involvement.
- **Issuer fails to renew before expiry** → end-user certs hard-invalidated per strict X.509 NotAfter. Users must re-KYC with issuer under new cert. Strong operational incentive for issuers to renew on time.

## Lookup Table Cleanup

**No `on_initialize` purge.** Three cleanup paths:

1. **Piggyback on mint**: every `mint_cert` grabs 2–5 expired entries from the secondary purge index and purges them as part of the same extrinsic. Includes expired contract offers from the offer expiry index. Free cleanup amortized across normal activity.
2. **Dedicated `purge_expired` extrinsic**: anyone can call it. Targets a batch of expired entries (bounded per call for weight predictability). Caller claims storage deposits as cleanup incentive. Can be run by bots watching for purge-eligible entries — that's by design.
3. **Self-discard**: user cleans up their own entry, gets deposit back immediately.

**Storage deposit model**: every write operation across the pallet requires a deposit sized to the storage weight of what's being written. Roots pay their own deposit at `register_root`. Roots also pay the issuer cert's deposit at `issue_issuer_cert` — the issuer hasn't signed anything at issuance, so the root (the extrinsic signer) is the only account that can bear the deposit; it's refunded to the same root on `deregister_root`'s clean-exit cascade. Issuers pay the offer deposit at `offer_contract`. Users pay the cert deposit at `mint_cert`. All deposits are refundable when the entry is removed. Piggyback purge claims abandoned deposits as cleanup incentive. Expired root and issuer deposits claimable by anyone via purge.

**30-day grace period**: suspended certs (issuer set `is_active = false`) have 30 days before becoming reapable via `cleanup()`. Gives the holder time to self-discard and recover the deposit. After 30 days, anyone can reap and claim the deposit.

**Expired certs**: `purge_eligible_block` is computed at mint time (`expiry_block + InactivePurgeBlocks`) and stored in the cert record. No runtime computation at purge time — just `current_block >= purge_eligible_block`. For suspended certs, `purge_eligible_block` is set at suspension time and cleared on reactivation.

## Cryptography

- **Cert keypairs (device-bound)**: P-521 (secp521r1). Natively supported inside TPM 2.0, Apple Secure Enclave, and Android StrongBox. 260-bit classical security, 130-bit post-Grover. Key never leaves secure hardware boundary for signing operations.
- **P-521 verifier**: RustCrypto `p521` crate with `ecdsa` feature. Pure Rust, `no_std` compatible, constant-time via `subtle`. Lives in `zk-pki-primitives`. **Audit caveat**: EC arithmetic is unaudited and constant-time behavior unverified against generated assembly. Acceptable for Paseo testnet. Independent audit required before Kusama/mainnet submission.
- **Substrate account keypairs**: sr25519/Ed25519. Separate from cert keypairs. Substrate-native, not secure enclave native. Protected at rest via enclave-wrapped encryption. Exposed to RAM only during signing, then cleared. Known hardware limitation shared with broader Substrate ecosystem.
- **Hash function**: Blake2b-256 for thumbprints.
- **Known quantum limitation**: no elliptic curve survives Shor's algorithm regardless of key size. P-521 is the strongest option available inside the secure hardware boundary today. Full quantum resistance is blocked on TPM and secure enclave hardware roadmaps.
- **Upgrade path**: `schema_version` is the migration mechanism. When PQ hardware ships, renewal cycles force the upgrade — the pallet validates the new scheme via schema version floor enforcement (invariant #8). Target PQ candidates: ML-DSA (CRYSTALS-Dilithium, FIPS 204) or SL-DSA (SPHINCS+) pending TCG silicon support.

## TPM / Attestation

- Physical TPM or secure enclave is **mandatory** for PoP eligibility.
- Private key **never leaves the device**.
- TOTP secret generated atomically with the keypair at genesis, transferred to local authenticator app. Cloud-synced authenticator is the user's operational risk, not a protocol flaw.
- Packed attestation (vKMS/software TPM): valid for machine/org identity only, **not PoP eligible**.
- EK deduplication: root-scoped — one active PoP cert per registered EK per root hierarchy. Multiple on-chain addresses on the same device is allowed by design. Independent roots may concurrently certify the same physical device.

### Android screen lock (client-side enforcement)

StrongBox keypair generation does **not** require a screen lock to be set. Without a lock, physical access to an unlocked device is sufficient to use the `cert_ec` key for signing and to read the TOTP secret from the authenticator app. The hardware binding guarantee — key never leaves StrongBox — is preserved either way; what is lost is the **user presence guarantee** that a signing operation requires a live human to authenticate.

The pallet **cannot** detect screen-lock state from the attestation chain. Android Key Attestation's `AuthorizationList` does not expose it for a StrongBox key unless that key was created with `userAuthenticationRequired = true`. This is enforced client-side:

- Dotwave blocks the ZK-PKI genesis ceremony when `KeyguardManager.isDeviceSecure` returns false
- The `cert_ec` key should be created with `userAuthenticationRequired = true` and an appropriate `userAuthenticationValidityDurationSeconds` so the OS enforces authentication on each signing call
- Removing the screen lock after the fact does not invalidate the cert — the protocol has no read-back into current device policy. Client-side messaging should encourage re-enabling.

Selecting "no screen lock" is a user operational risk, not a protocol flaw. Documented honestly so relying parties understand the threat model.

## Smart Contracts (ink!)

Two contracts, both multisig with cross-category quorum (TPM hardware specialists, independent security auditors, ZK-PKI governance body, OpenGov — no single category can dominate decisions):

- **EK trust chain registry**: known-good TPM manufacturer EK cert chain identifiers. Seeded at genesis with all currently known manufacturer root cert hashes. Maintained separately from the cross-category quorum — this is static reference data, not a governance mechanism. Used as a bot filter during `mint_cert` to verify the accepting user has a real physical TPM.
- **Compromised chain advisory**: append-only, write-once entries with block timestamp. Higher signature threshold than registry. Governs the root/issuer compromise state machine. Time-lock / challenge period before entries take full effect.

Both emit events consumed by off-chain workers for reputation scoring.

## Reputation Scoring

- Queries both advisory contracts when evaluating any cert or issuer.
- Positive weight: EK chain in known-good registry.
- Heavy negative weight: any part of EK chain in compromised advisory.
- `mint_block` vs `compromised_at_block` determines retroactive vs prospective treatment — preserves non-repudiation.
- New roots start with low reputation; climb with age, valid cert volume, low invalidation rate.
- Roots appearing shortly after a related compromise event start in negative territory.
- On-chain address lineage tracking: proxy account history, funding sources, association with previously compromised operators.
- Reputation is **advisory** — relying parties set their own thresholds. The pallet does not enforce a floor.

## Compromise Rules

### Issuer Compromise
- Root or advisory contract marks issuer compromised.
- `compromised_at_block` set on issuer record (write-once).
- Entire issuance history is suspect — no surgical cert rescue.
- Relying parties compare cert `mint_block` to issuer `compromised_at_block`.
- Compromised issuer permanently disqualified from re-anchoring.
- Pallet does not hard-block compromised issuer from calling extrinsics — events surface compromise context. Application layer presents this to users.

### Root Compromise
- Requires advisory contract write via OpenGov referendum — no single actor can trigger this, not even the root itself.
- No self-flag extrinsic. Voluntary self-disclosure routes through advisory contract quorum out of band.
- `compromised_at_block` is write-once.
- Certs minted **before** `compromised_at_block` remain in table — relying parties compare `mint_block`.
- Certs minted **on or after** `compromised_at_block` are invalid.
- Flagged root can contest (45-day challenge window). Falls back to compromised if unresolved.
- Compromised root can still call `invalidate_issuer` — event surfaces compromised root status alongside invalidation. RPC exposes it. Relying parties decide.

### Issuer Invalidation — Hybrid Cascade
When root calls `invalidate_issuer`:
- Issuer record immediately marked dead — no new certs from that block forward.
- Existing end-user certs remain in lookup table with `is_active: true`.
- Pallet does NOT cascade-flip them.
- RPC trust chain resolution synthesizes the full picture: advisory contract status + pallet state + reputation score.
- Developer obligation: use RPC trust chain resolution endpoint, not raw storage queries. Checking only `is_active` in isolation is accepted operational risk.

## JSON-RPC API (zk-pki-rpc)

Every cert resolution endpoint must return `expiry status`, `is_active`, `compromised_at_block`, compromise state (active/challenge/compromised), and **full chain validity** (parent cert status) **explicitly**.

Endpoints:
- Resolve cert by thumbprint
- Resolve all certs by issuer
- Resolve all certs by user address
- Resolve all certs by root
- Check root/issuer validity status (returns compromise state and `compromised_at_block` if set)
- Real-time cert status (OCSP equivalent) — must check full chain NotAfter, advisory contract, and reputation
- Check EK registry — active PoP thumbprint for a given EK hash

## Genesis Transaction Flow (summary)

1. Root generates TPM keypair (P-521) → becomes eligible root (5-year max TTL, self-determined). Storage deposit paid. Proxy relationship verified via `pallet_proxy`.
2. Root issues issuer cert to candidate (proxy account required, TTL ≤ root's NotAfter). Deposit paid.
3. Issuer generates TPM keypair → becomes eligible issuer.
4. Issuer offers contract → pallet generates contract with unique nonce + block expiry. TTL for end-user cert set by issuer (≤ issuer's NotAfter). Deposit paid. If offer already exists for this user, old offer atomically revoked, deposit returned.
5. User's TPM generates keypair AND TOTP secret atomically.
6. TOTP secret copied to authenticator app.
7. User submits TPM public key + OTP + contract nonce in single extrinsic before expiry. Storage deposit paid.
8. Pallet: verify OTP, verify nonce (offer exists + before expiry block) → reject replay.
9. Pallet: verify TPM attestation, extract EK, check EK against trust chain registry.
10. Pallet: SCALE-encode canonical fields, compute Blake2b-256 thumbprint.
11. Pallet: verify schema_version ≥ CURRENT_SCHEMA_VERSION.
12. Mint NFT to user address.
13. Atomically write lookup table entry + EK registry entry + purge index entry + remove offer.
14. Piggyback: purge 2–5 expired entries from purge index + offer expiry index.

## Extrinsic Summary

| Index | Extrinsic | Caller | Description |
|---|---|---|---|
| 0 | `register_root` | Anyone | Register as root CA. TPM attestation, proxy validation, 5yr max TTL, deposit. |
| 1 | `issue_issuer_cert` | Root | Issue issuer cert. TTL ≤ root NotAfter. Deposit. Max issuers per root enforced. |
| 2 | `offer_contract` | Issuer | Create contract offer for user. TTL ≤ issuer NotAfter. Replaces existing offer atomically. |
| 3 | `mint_cert` | User | Accept offer, mint cert NFT. Deposit. Piggyback cleanup. |
| 4 | `suspend_cert` | Issuer | Suspend end-user cert only. Issuer certs cannot be suspended. |
| 5 | `reactivate_cert` | Issuer | Reactivate suspended cert. Rejects if expired. |
| 6 | `invalidate_cert` | Issuer | Delete lookup entry. NFT remains as dead token. |
| 7 | `self_discard_cert` | User | User removes own cert. Deposit returned. |
| 8 | `invalidate_issuer` | Root | Mark issuer dead. Write-once `compromised_at_block`. No cascade to end-user certs. |
| 9 | `flag_root_compromised` | Governance | Advisory contract via OpenGov only. Write-once. Verifies target is a root. |
| 10 | `reissue_cert` | Issuer | Atomic: invalidate old cert + mint new cert. Issuer-initiated, unilateral. Deposit net-diff to issuer. |
| 11 | `renew_cert` | Root/Issuer | Successor binding. Old cert → retired. Old keypair signs new cert. |
| 12 | `deregister_root` | Root | Voluntary exit. Cascades to issuers (invalidated, deposits returned). End-user certs untouched. |
| 13 | `purge_expired` | Anyone | Batch purge expired entries. Caller claims deposits. |
| 14 | `challenge_compromise` | Flagged entity | Contest a compromise flag. 45-day window. |
| 15 | `resolve_challenge` | Governance | Resolve contest. Restores active or confirms compromised. |

## Definition of Done

- [ ] Pallet extrinsics for root, issuer, and user genesis flows
- [ ] `reissue_cert` — issuer-initiated unilateral atomic reissuance
- [ ] `renew_cert` with successor binding (old keypair signs new cert, old cert → retired)
- [ ] `deregister_root` — voluntary exit with issuer cascade
- [ ] `purge_expired` — anyone can call, deposits to caller
- [ ] `challenge_compromise` and `resolve_challenge` extrinsics
- [ ] TPM attestation verification (P-521) in pallet runtime
- [ ] EK extraction and on-chain EK deduplication registry
- [ ] SCALE-encoded canonical serialization for thumbprint inputs
- [ ] Blake2b-256 thumbprint computation at mint time
- [ ] `schema_version` field in all cert metadata — floor enforced at mint/reissuance
- [ ] NFT minting with all specified metadata fields
- [ ] Lookup table with all specified fields and query paths
- [ ] Secondary purge index keyed by `purge_eligible_block`
- [ ] Contract offer expiry index for piggyback cleanup
- [ ] Storage deposit model on all write operations — deposit at write, refund at removal
- [ ] Piggyback cleanup on mint (2–5 expired entries + expired offers per mint)
- [ ] 30-day grace period for suspended certs before reap eligibility
- [ ] Reactivation guard — reject if expired
- [ ] TTL enforcement at point of use — no `on_initialize` scanning
- [ ] X.509 NotAfter chain constraint enforced at mint time
- [ ] Cascading invalidation — parent expiry invalidates all children, checked at point of use
- [ ] Five-state model (active/retired/challenge/compromised/deregistered) with 45-day contest window
- [ ] Retired state for renewal continuity — no new issuance, existing certs valid until NotAfter
- [ ] Advisory contract integration for compromise state machine
- [ ] Axis of evil — compromised entities not hard-blocked, events surface context
- [ ] Re-anchoring prohibition for compromised issuers
- [ ] Hybrid issuer invalidation cascade — issuer marked dead, end-user certs untouched in storage, RPC synthesizes full picture
- [ ] Atomic contract offer replacement (one active offer per issuer-user pair)
- [ ] Block-bound nonce and block expiry on genesis contract offers — no `ConsumedNonces` map
- [ ] `compromised_at_block` on issuer records (write-once)
- [ ] Root compromise via advisory contract only — no self-flag extrinsic
- [ ] Proxy validation via `pallet_proxy` at registration
- [ ] Role exclusivity — address cannot be both root and issuer
- [ ] Issuer cert suspension prohibited — roots invalidate, period
- [ ] `MaxIssuersPerRoot` configurable runtime constant with hard pallet ceiling of 100
- [ ] `UserIssuerKey` newtype wrapper for index key safety
- [ ] Reputation scoring heuristics
- [ ] JSON-RPC API covering all query paths including EK, compromise state, full chain validity
- [ ] FIDO2 attestation format compliance

## Out of Scope

- DNS integration (see separate ZK-PKI DNS Integration Design Document)
- Universal trust enforcement — trust is contextual and relying-party-defined
- Key rotation — certs are monolithic by design
- PoP eligibility for VMs — TPM attestation and EK deduplication required
- Moral judgment on credential use — protocol provides signal, application provides judgment
