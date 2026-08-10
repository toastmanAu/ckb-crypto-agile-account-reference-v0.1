# Independent auditor shortlist

Prepared on 2026-08-11 for the AccountLockV1 audit candidate. Availability,
scope, schedule, and price must be confirmed directly with each provider.

## Recommended engagement order

### 1. Least Authority — primary full-scope candidate

Why first:

- Direct prior security-review experience with Nervos Network, including CKB,
  CKB-VM, transaction behavior, serialization, and cryptography.
- Publicly offers Rust, blockchain, distributed-system, and cryptographic
  protocol reviews.
- Its published process includes a fixed commit, proposal, code review,
  remediation support, retest, and optional public final report.

Request a proposal:

- https://leastauthority.com/security-consulting/request-a-proposal/
- `consulting@leastauthority.com`

Relevant evidence:

- https://leastauthority.com/blog/least-authoritys-review-of-the-nervos-network/
- https://leastauthority.com/security-consulting/

Suggested scope: the entire consensus-critical implementation and verifier ABI,
with focused review of Type ID state rules, CKB2023 spawn/pipe semantics,
transaction binding, all three verifier adapters, and dependency/configuration
risks.

### 2. NCC Group Cryptography Services — independent crypto-focused candidate

Why second:

- Published experience assessing RustCrypto libraries and Rust cryptographic
  implementations.
- Published work on threshold signatures and other cryptographic protocols,
  including engagements with explicit retest phases.
- Strong independence from this repository's SLH-DSA adapter lineage.

Relevant evidence and contact entry points:

- https://www.nccgroup.com/research/public-report-entropyrust-cryptography-review/
- https://www.nccgroup.com/research/public-report-zcash-frost-security-assessment/
- https://www.nccgroup.com/penetration-testing-services/

Suggested scope: verifier adapters, RustCrypto dependency integration, profile
and encoding semantics, side-channel assumptions, signature/key validation, and
the common authorization-digest boundary. A full CKB script review can also be
requested if the assigned team has CKB-VM experience.

### 3. Trail of Bits — PQ/Rust and blockchain specialist candidate

Why shortlisted:

- Maintains dedicated cryptography and blockchain review practices.
- Its cryptography team built the pure-Rust SLH-DSA implementation merged into
  RustCrypto and publicly offers post-quantum design and implementation review.
- Demonstrated work across Rust, compilers, blockchain systems, and complex
  cryptographic protocols.

Relevant evidence and contact entry point:

- https://blog.trailofbits.com/2024/08/15/we-wrote-the-code-and-the-code-won/
- https://trailofbits.com/

Suggested scope: PQ transition design, ML-DSA/SLH-DSA message profiles, adapter
correctness, Rust/RISC-V build behavior, and the verifier isolation boundary.
Because its team contributed to the upstream RustCrypto SLH-DSA implementation,
ask the proposal to state how reviewer independence and conflict separation will
be handled.

## Selection recommendation

If funding allows one engagement, request comparable full-scope proposals from
Least Authority and NCC Group, then select based on named reviewer experience
with CKB-style UTXO scripts, Rust/no_std, post-quantum signatures, and the
included retest effort. Least Authority is the default recommendation because
direct CKB/CKB-VM familiarity reduces protocol-onboarding risk.

If funding allows two complementary engagements:

1. Least Authority: full protocol, AccountLock, CKB-VM, and state-transition
   review.
2. NCC Group Cryptography Services: focused independent cryptographic adapter
   and RustCrypto integration review.

Do not split the codebase between reviewers without one firm retaining
end-to-end responsibility for the authorization boundary.

## Proposal comparison criteria

- Named reviewers and directly relevant prior work
- Person-days allocated to AccountLock/protocol versus cryptographic adapters
- CKB/UTXO, RISC-V/no_std Rust, WebAuthn, ML-DSA, and SLH-DSA experience
- Manual review and tool-assisted analysis plan
- Dependency and compiled-ELF review coverage
- Initial report, remediation consultation, retest, and final report included
- Permission and schedule for a public report
- Treatment of upstream-code conflicts or prior authorship
- Start date, elapsed schedule, total person-days, and fixed/variable cost
- Handling of scope changes and findings that require a protocol-version change

The audit should target an immutable tag and archive, not the moving `main`
branch. Use `docs/AUDIT_SCOPE.md` and `docs/AUDIT_REQUEST.md` as the technical
scope and proposal brief.
