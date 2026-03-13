# Post-Quantum Cryptography Background

## Why PQC Matters Now

Classical public-key cryptography — RSA, ECDSA, ECDH, Diffie-Hellman — relies on the computational difficulty of integer factorization and discrete logarithm problems. A sufficiently powerful quantum computer running **Shor's Algorithm** can solve both in polynomial time, rendering all classical asymmetric cryptography broken.

While large-scale quantum computers do not exist today, the threat is **harvest now, decrypt later (HNDL)**: adversaries are already collecting encrypted TLS traffic and SSH sessions today, intending to decrypt them once quantum hardware matures. Any data that needs to remain confidential beyond 2030–2035 is at risk.

## NIST PQC Standardization Timeline

| Year | Event |
|------|-------|
| 2016 | NIST launches PQC standardization competition |
| 2022 | NIST announces first four PQC algorithm selections |
| **August 2024** | **FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) finalized** |
| March 2025 | HQC selected as backup KEM |
| **2030** | **NIST IR 8547: Deprecation of quantum-vulnerable algorithms** |
| **2035** | **NIST IR 8547: Full disallowment** |

## NIST PQC Algorithms

### ML-KEM — FIPS 203 (Key Encapsulation)
Replaces: RSA-KEM, ECDH, X25519  
Based on: Module Learning With Errors (MLWE) lattice problem  
Deployment: Via TLS hybrid groups (X25519MLKEM768, SecP256r1MLKEM768)

### ML-DSA — FIPS 204 (Digital Signatures)
Replaces: ECDSA, RSA signatures  
Based on: Module Learning With Errors (MLWE) lattice problem  
Deployment: Future TLS certificates, code signing

### SLH-DSA — FIPS 205 (Hash-based Signatures)
Replaces: ECDSA, RSA signatures (conservative option)  
Based on: Hash functions (no lattice assumptions)  
Deployment: Long-lived signatures, PKI

### FN-DSA — FIPS 206 (Digital Signatures, Draft)
Replaces: ECDSA  
Based on: NTRU lattice problem  
Status: Draft standard

## Grover's Algorithm and Symmetric Cryptography

Unlike asymmetric cryptography, symmetric algorithms (AES, ChaCha20) are not broken by quantum computers — they are only *weakened*:

- **AES-128**: Effective security reduced to ~64-bit quantum security (weak)
- **AES-256**: Effective security reduced to ~128-bit quantum security (adequate)

NIST's current guidance: **AES-256 is acceptable** for post-quantum use.

## TLS Hybrid Key Exchange

Since ML-KEM certificates are not yet widely issued by CAs, the transition strategy uses **hybrid key exchange** groups that combine a classical algorithm with a PQC algorithm:

| Hybrid Group | Classical | PQC | TLS Version Required |
|-------------|-----------|-----|---------------------|
| X25519MLKEM768 | X25519 | ML-KEM-768 | TLS 1.3 |
| SecP256r1MLKEM768 | P-256 | ML-KEM-768 | TLS 1.3 |
| X25519Kyber768 | X25519 | Kyber-768 | TLS 1.3 |

**TLS 1.3 is required** — hybrid PQC key exchange is not supported in TLS 1.2. This is why all TLS 1.2 endpoints are rated CRITICAL by AC Scanner.

## References

- [NIST PQC Project](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [FIPS 203 — ML-KEM](https://doi.org/10.6028/NIST.FIPS.203)
- [FIPS 204 — ML-DSA](https://doi.org/10.6028/NIST.FIPS.204)
- [FIPS 205 — SLH-DSA](https://doi.org/10.6028/NIST.FIPS.205)
- [NIST IR 8547 — Transition to PQC Standards](https://csrc.nist.gov/pubs/ir/8547/ipd)
- [NIST SP 800-52 Rev.2 — TLS Guidelines](https://doi.org/10.6028/NIST.SP.800-52r2)
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
