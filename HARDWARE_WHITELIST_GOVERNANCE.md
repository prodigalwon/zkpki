# ZK-PKI Hardware Whitelist Governance

**Status: Draft — Pre-Repository**
**Author: Anthony Czarnik**
**Last Updated: April 2026**

---

## Overview

The ZK-PKI hardware whitelist — `KNOWN_MANUFACTURER_INTERMEDIATES` — is the on-chain registry of trusted TPM and StrongBox manufacturer intermediate certificate hashes. A device whose attestation chain includes a recognized intermediate is eligible for `AttestationType::Tpm` and Proof of Personhood certification. A device whose chain is not recognized receives `AttestationType::Packed` — valid identity, not PoP eligible.

Adding an entry to the whitelist is a security-critical operation. An incorrect or malicious entry could allow non-genuine hardware to obtain PoP eligibility, undermining the Sybil resistance guarantees of the protocol. The governance model reflects this — entries are reviewed by domain experts, not decided by token-weighted voting.

This document describes who governs the whitelist, how decisions are made, and how the governance model evolves as the protocol matures.

---

## Governance Phases

### Phase 1 — Bootstrap (Paseo Testnet)

**Authority: Protocol Author**

During the Paseo testnet phase the protocol author — Anthony Czarnik — holds primary authority over the whitelist. Entries are added based on real hardware testing, manufacturer chain verification, and CRL confirmation. No submission process is required during this phase. The whitelist is hardcoded in `zk-pki-tpm/src/chain.rs` and updated via runtime upgrades.

This is appropriate during bootstrap. The protocol is under active development, the codebase is not yet public, and the author has the deepest understanding of what constitutes a valid manufacturer intermediate. Concentrated authority during bootstrap is honest stewardship, not permanent centralization.

**Current whitelist entries (as of April 2026):**
- Samsung S3K250AF — captured from SM-G986U (Galaxy S20+), verified against Google Hardware Attestation Root CA
- AMD fTPM PRG-RN — captured from AMD Ryzen laptop (Lucy), verified against CN=AMDTPM root

### Phase 2 — Council (Kusama)

**Authority: Protocol Author + Technical Council**

At Kusama deployment the whitelist migrates from a hardcoded constant to an on-chain ink! registry contract. The Technical Council is established — a small group of named, accountable domain experts appointed by the protocol author.

The council's mandate is narrow: evaluate hardware intermediate certificate submissions, verify chains, check manufacturer CRL status, and approve or reject entries. Nothing else. The council has no authority over protocol parameters, pallet upgrades, or economic decisions.

**Council composition:**
- 3 to 5 named individuals
- Domain expertise required: TPM hardware security, Android security, or PKI
- Appointed by the protocol author
- Publicly named and accountable — every approval is on-chain with the approver's identity

**Decision making:**
- Protocol author can approve unilaterally
- Council can approve by supermajority (3 of 4, or equivalent) if protocol author is unreachable
- Any council member can flag a submission for extended review — halts fast-track approval
- Protocol author retains veto during Phase 2

**Succession — what "unreachable" means:**
- No response to a pending submission after 14 consecutive days
- Council votes to activate succession — requires unanimous council agreement
- Supermajority council approval covers entries during succession
- Protocol author resuming activity automatically restores primary authority
- Succession activation is logged on-chain

### Phase 3 — Technical Committee (Mainnet Stable)

**Authority: Technical Committee**

After mainnet is stable and the protocol has demonstrated sustained operation, governance transitions to a self-sustaining Technical Committee. The protocol author's unilateral approval authority phases out. The veto is retired via a governance vote.

**Committee composition:**
- 7 to 11 named individuals
- Representation from: TPM hardware security researchers, Android security engineers, TCG member organizations, ZK-PKI core contributors, independent security auditors
- No token-weighted voting — domain expertise is the qualification, not DOT holdings
- Committee members can be removed by supermajority committee vote for inactivity or misconduct

**Decision making:**
- Simple majority for routine additions (known manufacturer, chain verified, CRL clean)
- Supermajority for non-standard entries or disputed submissions
- Any member can veto and escalate to full committee review
- Protocol author role becomes advisory — no special authority

**Protocol author's long-term role:**
- Advisory seat on the Technical Committee
- No special veto or unilateral authority
- One vote among equals

---

## Submission Process

### Who can submit

Anyone. A device manufacturer, a security researcher, a Dotwave user whose hardware wasn't recognized, a community member who tested new hardware. Submissions are permissionless. Review and approval are not.

### What a submission requires

1. **Intermediate certificate DER bytes** — the manufacturer intermediate cert from the device's attestation chain
2. **Device model and manufacturer** — what hardware was tested
3. **Chain verification** — confirmation that the intermediate chains to a recognized root (Google Hardware Attestation Root CA for Android, or the manufacturer's published root for TPM 2.0)
4. **CRL check** — confirmation the intermediate is not on the manufacturer's certificate revocation list
5. **Capture methodology** — how the cert was obtained (Dotwave ceremony output, `tpm2_getekcertificate`, Windows registry extraction, etc.)

### What the reviewer verifies

1. The intermediate certificate is genuine — chains to a known root
2. The manufacturer is a legitimate hardware security vendor
3. The intermediate is not revoked
4. The SPKI hash is computed correctly — Blake2b-256 of the SubjectPublicKeyInfo bytes
5. The entry is not a duplicate of an existing entry

### What the reviewer does NOT evaluate

- Whether the manufacturer's business practices are acceptable
- Whether the hardware meets some arbitrary security threshold beyond the baseline
- Whether the submitter is a known community member

The whitelist is about hardware provenance verification, not hardware quality ranking. If the chain is valid and the manufacturer is legitimate, the entry is approved.

---

## What the Whitelist Is Not

**Not a quality tier list.** All entries in `KNOWN_MANUFACTURER_INTERMEDIATES` grant `AttestationType::Tpm` eligibility. The whitelist is binary — recognized or not. Reputation scoring handles quality differentiation. A cert from a discrete Infineon TPM and a cert from an AMD fTPM both get `AttestationType::Tpm`. Their reputation scores may differ based on hardware security tier, but whitelist membership is not tiered.

**Not subject to token-weighted voting.** The whitelist is a technical security artifact. Decisions about what hardware is genuine are made by people who understand TPM attestation chains, not by DOT holders voting on their economic interests. OpenGov is not appropriate for this — the barrier to submission is too high, the voter base lacks domain expertise, and the incentives are misaligned.

**Not permanent.** An entry can be removed if the manufacturer's CA is compromised, the intermediate is revoked, or the hardware is found to be non-genuine. Removal requires the same review process as addition and is logged on-chain with the reason.

---

## The ink! Registry Contract

The on-chain registry contract that replaces the hardcoded constant at Kusama deployment has the following properties:

- **Append-only entries** — entries cannot be modified, only added or marked revoked
- **Write-once revocation** — a revoked entry cannot be un-revoked
- **Multisig controlled** — write access requires M-of-N signatures from the Technical Council
- **Separation of duties** — no single individual or organization can unilaterally add or remove entries
- **Transparent** — all entries, approvals, and rejections are on-chain and publicly readable
- **Event-driven** — all mutations emit events consumed by the reputation scoring off-chain worker

---

## Rationale

The governance model described here is deliberately conservative during bootstrap and deliberately expert-driven throughout. This is not an accident.

Hardware whitelist governance is a security-critical function. Getting it wrong — approving a fake manufacturer chain, missing a revoked intermediate, adding a compromised vendor — directly undermines the Sybil resistance guarantees that make ZK-PKI meaningful. The people making these decisions need to understand X.509 certificate chains, TPM attestation formats, and manufacturer CRL infrastructure. That is a small population.

Token-weighted voting concentrates decision-making power in the hands of large DOT holders whose interests are economic, not technical. A whale has no particular reason to evaluate an AMD fTPM intermediate certificate correctly. They have every reason to vote based on their portfolio interests. This is not the right governance body for a technical security registry.

The Technical Committee model puts decisions in the hands of people who have staked their professional reputation on getting it right. Their names are on every approval. That accountability is the governance mechanism — not tokens, not popularity, not politics.

---

## Contact

For whitelist submissions, governance questions, or council membership inquiries:

Anthony Czarnik
apollonius21@proton.me
substrate.icu

---

*This document will be maintained in the ZK-PKI repository once it is open sourced. The governance model described here is intentional and has been thought through from the protocol's inception. It reflects the security requirements of a hardware attestation whitelist, not convenience or convention.*
