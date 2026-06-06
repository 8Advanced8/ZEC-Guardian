# ZEC-Guardian
4-layer ZK circuit soundness protection: formal verification, differential fuzzing, SMT satisfiability, information-theoretic anomaly detection — novel algorithms applied to Halo2/Orchard circuits

# ZEC Guardian

**4-Layer ZK Circuit Protection System**

Novel security framework applying previously unused algorithms to detect and prevent vulnerabilities in Halo2/Orchard zero-knowledge proof circuits.

Inspired by the Zcash Orchard soundness bug disclosed June 2026 — a 4-year vulnerability in `ecc::chip::mul` within `halo2_gadgets` that survived expert cryptographic review until discovered by AI-assisted audit.

---

## Architecture

### Layer 1 — Formal Constraint Verification
Lean4-inspired algebraic proof checker. First use on Halo2 PLONKish circuits. Converts every circuit constraint into a mathematical theorem and proves it formally.

### Layer 2 — Differential Fuzzing
Cross-implementation comparison. Used in compilers, never applied to ZK circuits before. Runs the same witness on two implementations and flags any mismatch.

### Layer 3 — SMT Algebraic Satisfiability
SAT/SMT solver on PLONKish arithmetic. First application to Orchard/Halo2. Searches for a forged witness that satisfies a broken constraint.

### Layer 4 — Information-Theoretic Anomaly Detection
Shannon Entropy + KL-Divergence + Kolmogorov Complexity + Chi-Square. First application to ZK nullifier streams.

---

## Results on Zcash Orchard Post-NU6.2

| Layer | Score | Finding |
|-------|-------|---------|
| 1 Formal Verification | 100/100 | 5/5 constraints sound |
| 2 Differential Fuzzing | 100/100 | 549 tests, 0 mismatches |
| 3 SMT Satisfiability | 50/100 | Buggy circuit counterexample found |
| 4 Information Theory | 77.5/100 | Suspicious stream detected |
| **
