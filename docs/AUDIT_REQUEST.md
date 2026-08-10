# Security audit request brief

This document is ready to attach to a request for proposal after the owner fills
in commercial contact details and desired dates. Technical scope should not be
silently reduced during proposal negotiation.

## Project

**Name:** CKB Crypto-Agile Account Reference v0.1

**Repository:**
https://github.com/toastmanAu/ckb-crypto-agile-account-reference-v0.1

**Audit target:** immutable tag `audit-v0.1.0-rc.2` and its associated source
commit. Confirm the resolved commit in the proposal before work begins.

**Stage:** feature-complete, pre-testnet, unaudited reference implementation

**License:** MIT

## Summary

The project implements a crypto-agile CKB account whose protected asset lock
args remain stable while signer sets, weighted thresholds, recovery policy, and
verifier code references rotate through a singleton Type ID state cell.

AccountLock contains no algorithm-specific cryptography. It computes a common
authorization digest and delegates proof validation through Verifier ABI v1
using CKB2023 spawn and one inherited request pipe. Included verifier profiles
are WebAuthn ES256/P-256, ML-DSA-65, and SLH-DSA SHA2-128s.

## Requested engagement

Please propose a manual security assessment covering:

- byte-for-byte conformance with the frozen v1 specification;
- AccountLock state identity, transitions, recovery, capability, and threshold
  behavior;
- canonical CKB sighash and common authorization-digest construction;
- CKB2023 spawn, pipe FD lifecycle, request framing, and child-exit semantics;
- all three verifier adapters and their exact algorithm/profile semantics;
- strict parsing, checked arithmetic, resource bounds, and denial of service;
- Rust/no_std, unsafe/syscall boundaries, allocator, compiler, linker, and
  RISC-V ELF considerations;
- cryptographic dependency integration and applicable advisories;
- host/VM differential risks and deployment-manifest integrity.

The detailed scope and high-priority questions are in `docs/AUDIT_SCOPE.md`; the
attacker model is in `docs/THREAT_MODEL.md`.

## Requested deliverables

1. Kickoff and scope confirmation against the immutable commit/archive.
2. Initial report with severity, exploitability, affected invariant, exact
   location, reproducer, and remediation guidance.
3. Reasonable remediation consultation during the fix period.
4. Retest of every finding against a fixed immutable commit.
5. Final report recording fixed, accepted, and unresolved findings.
6. Permission to publish the final report, with coordinated disclosure for any
   issue requiring delayed publication.

Please identify included person-days for initial review and retest separately.

## Existing evidence

- Pinned Rust/dependency/toolchain inputs and clean reproducible build guidance
- Deterministic release-candidate archive with CKB and SHA-256 manifests
- Strict parser mutation corpus and host digest/sighash tests
- Real Type ID creation and exact-outpoint lifecycle inside CKB-VM
- Real P-256, ML-DSA-65, and SLH-DSA verification inside CKB-VM
- Hybrid threshold, verifier upgrade, delayed recovery, and deletion tests
- Foreign state, unknown algorithm/ABI/flags, transaction mutation, and child
  nonzero-exit rejection tests
- Pinned GitHub CI, deterministic conformance vector, and debugger replay

Automated evidence is provided to accelerate review and is not represented as a
substitute for independent analysis.

## Known implementation deviations

- ML-DSA uses RustCrypto `ml-dsa` 0.1.1 rather than vendoring the referenced
  `toastmanAu/ckb-mldsa-lock` implementation.
- SLH-DSA uses RustCrypto `slh-dsa` 0.2.0-rc.5 rather than the exact audited
  Nervos implementation; the upstream audit does not transfer.
- WebAuthn `clientDataJSON` parsing intentionally supports a strict flat subset.

These deviations are explicitly in scope.

## Proposal response requested

Please provide:

- named team members and relevant CKB/Rust/PQ/WebAuthn experience;
- proposed scope changes, assumptions, and exclusions;
- manual/tool-assisted methodology;
- initial-review and retest person-days;
- earliest start, elapsed duration, and reporting schedule;
- fixed price or rate structure and payment milestones;
- NDA needs and public-report terms;
- secure communication and finding-delivery process.

## Owner-supplied commercial details

The repository owner must provide the organization/legal name, primary contact,
billing contact, jurisdiction, desired start/completion window, budget guidance,
and NDA preference directly to the selected auditor. Those details and any
private credentials must not be committed to this public repository.
