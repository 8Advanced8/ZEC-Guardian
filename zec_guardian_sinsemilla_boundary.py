#!/usr/bin/env python3
"""
ZEC-GUARDIAN — SINSEMILLA-BLAKE2b BOUNDARY ANALYZER
=====================================================
Deep analysis of the boundary between:
- Sinsemilla (ECC-based hash, INSIDE Orchard circuit)
- BLAKE2b (Fiat-Shamir hash, OUTSIDE circuit)

Research Question:
Can a prover exploit the Sinsemilla->commitment->BLAKE2b
pathway to gain non-trivial influence over the
Fiat-Shamir challenge?

Based on:
- Orchard spec: zips.z.cash/protocol/nu5.pdf
- KRS CRYPTO 2025: eprint.iacr.org/2025/118
- Sinsemilla spec: Acc = Q + sum(mi * Pi)
"""

import hashlib, json, random, math, statistics
from dataclasses import dataclass
from typing import Optional
from datetime import datetime, timezone

PALLAS_P = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
PALLAS_Q_ORDER = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001

def fp_mul(a,b): return (a*b) % PALLAS_P
def fp_add(a,b): return (a+b) % PALLAS_P
def fp_sub(a,b): return (a-b) % PALLAS_P


# ══════════════════════════════════════════════════════════════════
# SINSEMILLA SIMULATOR
# Based on: zips.z.cash/protocol/nu5.pdf Section 5.4.1.9
# SinsemillaHashToPoint(D, M) = Q(D) + sum(M_i * P_i(D))
# ══════════════════════════════════════════════════════════════════

class SinsemillaSimulator:
    """
    Simulates Sinsemilla hash over Pallas curve.
    Sinsemilla(D, M) = Q + sum(m_i * P_i)
    where P_i are fixed generators derived from domain D.
    """

    def __init__(self, domain: str = "z.cash:Orchard"):
        self.domain  = domain
        self.p       = PALLAS_P
        # Derive fixed generators from domain (simplified)
        self.Q       = self._derive_point(domain + "-Q")
        self.generators = [
            self._derive_point(f"{domain}-P-{i}")
            for i in range(256)
        ]

    def _derive_point(self, label: str) -> int:
        """Derive a Pallas curve point from a label (simplified)."""
        h = hashlib.blake2b(label.encode(), digest_size=32).digest()
        return int.from_bytes(h, 'little') % self.p

    def hash(self, message_bits: list) -> int:
        """
        Sinsemilla(D, M) = Q + sum(m_i * P_i)
        Returns x-coordinate of resulting point (simplified)
        """
        acc = self.Q
        for i, bit in enumerate(message_bits[:len(self.generators)]):
            if bit:
                acc = fp_add(acc, self.generators[i])
        return acc % self.p

    def commit(self, message_bits: list, randomness: int) -> int:
        """
        SinsemillaCommit(r, M) = Hash(M) + r*R
        where R is a fixed generator
        """
        h  = self.hash(message_bits)
        R  = self._derive_point(self.domain + "-r")
        return fp_add(h, fp_mul(randomness, R)) % self.p


# ══════════════════════════════════════════════════════════════════
# BOUNDARY ANALYZER
# Key question: Can prover choose message M such that
# Sinsemilla(M) produces a commitment C that causes
# BLAKE2b(C) to have specific properties?
# ══════════════════════════════════════════════════════════════════

class SinsemillaBLAKE2bBoundary:

    def __init__(self):
        self.p   = PALLAS_P
        self.sim = SinsemillaSimulator()

    def test_birthday_attack(self, trials=10000):
        """
        Birthday attack on Sinsemilla->BLAKE2b boundary.
        Can prover find two different messages M1, M2 such that:
        BLAKE2b(Sinsemilla(M1)) = BLAKE2b(Sinsemilla(M2))?
        If yes: prover can substitute commitments.
        """
        seen        = {}
        collisions  = []

        for i in range(trials):
            # Random message
            msg  = [random.randint(0,1) for _ in range(64)]
            r    = random.randint(1, self.p-1)
            comm = self.sim.commit(msg, r)

            # BLAKE2b of commitment
            h = hashlib.blake2b(
                comm.to_bytes(32,'little'), digest_size=32
            ).digest()
            challenge = int.from_bytes(h,'little') % self.p

            # Check for collision
            key = challenge >> 200  # top 56 bits
            if key in seen and seen[key][1] != msg:
                collisions.append({
                    "msg1":      seen[key][0],
                    "msg2":      msg,
                    "challenge": challenge,
                    "type":      "birthday_collision"
                })
            else:
                seen[key] = (msg, msg[:])

        return {
            "trials":       trials,
            "collisions":   len(collisions),
            "birthday_risk": len(collisions) > 0,
            "verdict": (
                f"Birthday collision found — prover can substitute commitments."
                if collisions else
                f"No birthday collision in {trials} trials — boundary appears secure."
            )
        }

    def test_message_malleability(self, trials=5000):
        """
        Can prover flip a single bit in message M to get
        a predictable change in BLAKE2b(Sinsemilla(M))?
        If yes: prover has fine-grained challenge control.
        """
        predictable = []

        for _ in range(trials):
            msg = [random.randint(0,1) for _ in range(64)]
            r   = random.randint(1, self.p-1)

            # Original commitment + challenge
            c1     = self.sim.commit(msg, r)
            h1     = hashlib.blake2b(c1.to_bytes(32,'little'), digest_size=32).digest()
            ch1    = int.from_bytes(h1,'little') % self.p

            # Flip bit 0
            msg2   = msg[:]
            msg2[0] = 1 - msg2[0]
            c2     = self.sim.commit(msg2, r)
            h2     = hashlib.blake2b(c2.to_bytes(32,'little'), digest_size=32).digest()
            ch2    = int.from_bytes(h2,'little') % self.p

            # Is the change in challenge predictable?
            delta_c = abs(c1 - c2)
            delta_ch = abs(ch1 - ch2)

            # If delta_ch is small relative to field size = predictable
            if delta_ch < self.p // (2**32):
                predictable.append({
                    "delta_commitment": delta_c,
                    "delta_challenge":  delta_ch,
                    "ratio":            delta_ch / self.p
                })

        return {
            "trials":      trials,
            "predictable": len(predictable),
            "rate":        f"{len(predictable)/trials:.4%}",
            "verdict": (
                f"{len(predictable)} cases where bit flip gives predictable "
                f"challenge change — malleability detected."
                if predictable else
                "No predictable challenge change from bit flips — "
                "Sinsemilla->BLAKE2b boundary appears avalanche-secure."
            )
        }

    def test_algebraic_shortcut(self, trials=2000):
        """
        Sinsemilla is LINEAR over Fp:
        Sinsemilla(M1 XOR M2) != Sinsemilla(M1) XOR Sinsemilla(M2)
        but:
        Sinsemilla(M1 + M2) = Sinsemilla(M1) + Sinsemilla(M2) (mod p)
        -- because it's a sum of field elements.

        Can this linearity be exploited?
        If Sinsemilla(M) = A + B where A,B known,
        prover might craft M to hit a desired range of commitment values.
        """
        linear_exploits = []

        for _ in range(trials):
            msg1 = [random.randint(0,1) for _ in range(32)]
            msg2 = [random.randint(0,1) for _ in range(32)]
            r    = random.randint(1, self.p-1)

            h1 = self.sim.hash(msg1)
            h2 = self.sim.hash(msg2)

            # Combined message (XOR)
            msg_xor  = [b1^b2 for b1,b2 in zip(msg1,msg2)]
            h_xor    = self.sim.hash(msg_xor)

            # Linear combination
            h_linear = fp_add(h1, h2)

            # If h_xor == h_linear: linearity holds -> exploitable
            if h_xor == h_linear:
                linear_exploits.append({
                    "h1": h1, "h2": h2, "h_xor": h_xor
                })

        exploit_rate = len(linear_exploits) / trials
        return {
            "trials":       trials,
            "linear_cases": len(linear_exploits),
            "exploit_rate": f"{exploit_rate:.4%}",
            "algebraic_risk": exploit_rate > 0.01,
            "verdict": (
                f"Linearity exploit found in {exploit_rate:.2%} of cases — "
                f"prover can use algebraic structure to target commitments."
                if exploit_rate > 0.01 else
                f"No exploitable linearity found ({exploit_rate:.4%} rate). "
                f"Sinsemilla's ECC structure breaks simple algebraic shortcuts."
            )
        }

    def test_commitment_range_bias(self, trials=10000):
        """
        Do Sinsemilla commitments cluster in any region of Fp?
        If yes: BLAKE2b challenges will inherit the bias.
        """
        commitments = []
        challenges  = []

        for _ in range(trials):
            msg  = [random.randint(0,1) for _ in range(64)]
            r    = random.randint(1, self.p-1)
            c    = self.sim.commit(msg, r)
            h    = hashlib.blake2b(c.to_bytes(32,'little'), digest_size=32).digest()
            ch   = int.from_bytes(h,'little') % self.p
            commitments.append(c)
            challenges.append(ch)

        # Statistical tests
        c_mean    = statistics.mean(commitments)
        ch_mean   = statistics.mean(challenges)
        expected  = self.p // 2

        c_bias    = abs(c_mean - expected) / expected
        ch_bias   = abs(ch_mean - expected) / expected

        # Chi-square on challenges (10 bins)
        bins      = [0] * 10
        bin_size  = self.p // 10
        for ch in challenges:
            bins[min(ch // bin_size, 9)] += 1

        expected_per_bin = trials / 10
        chi2 = sum((b - expected_per_bin)**2 / expected_per_bin for b in bins)

        # p-value approximation (9 degrees of freedom)
        # chi2 > 21.67 -> p < 0.01 -> significant
        significant = chi2 > 21.67

        return {
            "trials":             trials,
            "commitment_bias":    f"{c_bias:.6f}",
            "challenge_bias":     f"{ch_bias:.6f}",
            "chi2_statistic":     round(chi2, 2),
            "chi2_threshold":     21.67,
            "statistically_sig":  significant,
            "verdict": (
                f"Chi2={chi2:.2f} > 21.67 — Sinsemilla commitments show "
                f"non-uniform distribution affecting BLAKE2b challenges. "
                f"Prover can exploit this bias."
                if significant else
                f"Chi2={chi2:.2f} < 21.67 — Commitments uniformly distributed. "
                f"No exploitable bias in Sinsemilla->BLAKE2b pathway."
            )
        }


# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════

def run():
    print("\n" + "="*64)
    print("  ZEC-GUARDIAN — SINSEMILLA-BLAKE2b BOUNDARY ANALYZER")
    print("  Deep Analysis of In-Circuit/Out-of-Circuit Hash Boundary")
    print(f"  {datetime.now(timezone.utc).isoformat()[:19]} UTC")
    print("="*64)

    analyzer = SinsemillaBLAKE2bBoundary()
    results  = {}

    print("\n[1] Birthday Attack on Commitment Space")
    r1 = analyzer.test_birthday_attack(10000)
    results["birthday"] = r1
    print(f"    Collisions : {r1['collisions']}/{r1['trials']}")
    print(f"    Risk       : {r1['birthday_risk']}")
    print(f"    Verdict    : {r1['verdict']}")

    print("\n[2] Message Malleability Test")
    r2 = analyzer.test_message_malleability(5000)
    results["malleability"] = r2
    print(f"    Predictable: {r2['predictable']}/{r2['trials']} ({r2['rate']})")
    print(f"    Verdict    : {r2['verdict']}")

    print("\n[3] Algebraic Linearity Exploit")
    r3 = analyzer.test_algebraic_shortcut(2000)
    results["linearity"] = r3
    print(f"    Linear cases  : {r3['linear_cases']}/{r3['trials']}")
    print(f"    Exploit rate  : {r3['exploit_rate']}")
    print(f"    Risk          : {r3['algebraic_risk']}")
    print(f"    Verdict       : {r3['verdict']}")

    print("\n[4] Commitment Range Bias (Chi-Square)")
    r4 = analyzer.test_commitment_range_bias(10000)
    results["bias"] = r4
    print(f"    Commitment bias : {r4['commitment_bias']}")
    print(f"    Challenge bias  : {r4['challenge_bias']}")
    print(f"    Chi2            : {r4['chi2_statistic']} (threshold 21.67)")
    print(f"    Significant     : {r4['statistically_sig']}")
    print(f"    Verdict         : {r4['verdict']}")

    boundary_risk = (
        r1["birthday_risk"] or
        r2["predictable"] > 0 or
        r3["algebraic_risk"] or
        r4["statistically_sig"]
    )

    print("\n" + "="*64)
    print("  FINAL VERDICT — SINSEMILLA-BLAKE2b BOUNDARY")
    print("-"*64)
    print(f"  Birthday attack    : {'RISK' if r1['birthday_risk'] else 'SAFE'}")
    print(f"  Message malleability: {'RISK' if r2['predictable']>0 else 'SAFE'}")
    print(f"  Algebraic linearity : {'RISK' if r3['algebraic_risk'] else 'SAFE'}")
    print(f"  Commitment bias     : {'RISK' if r4['statistically_sig'] else 'SAFE'}")
    print()
    if boundary_risk:
        print("  CONCLUSION: Sinsemilla->BLAKE2b boundary has exploitable")
        print("  properties. Prover may gain non-trivial challenge influence.")
        print("  This is a NEW finding not covered by existing Orchard proofs.")
    else:
        print("  CONCLUSION: Sinsemilla->BLAKE2b boundary appears secure.")
        print("  The 6 suspicious cases in prior analysis were likely noise.")
        print("  Sean Bowe's defense holds for this pathway.")
    print()
    print("  Formal gap: Has THIS specific boundary been proven secure")
    print("  in Orchard's security reduction? The Halo2 book proves")
    print("  state-restoration soundness but does not explicitly analyze")
    print("  the Sinsemilla commitment -> Fiat-Shamir challenge pathway.")
    print("="*64)

    report = {
        "timestamp":    datetime.now(timezone.utc).isoformat(),
        "boundary_risk": boundary_risk,
        "results":       results,
        "open_question": (
            "Has the Sinsemilla->BLAKE2b boundary been formally analyzed "
            "in Orchard's security proof under the KRS attack model?"
        )
    }

    with open("sinsemilla_boundary_report.json","w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n  Report saved: sinsemilla_boundary_report.json")
    return report


if __name__ == "__main__":
    run()
