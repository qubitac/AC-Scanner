# Post-Quantum Cryptography — Crypto-BOM Summary

**Generated:** 2026-03-17 21:58:49 UTC

## Security Health Score

**Overall: 61 / 100** — Needs improvement

_Scan model: Web · NIST SP 800-30 adaptive weighted arithmetic mean_

| Component | Score | Weight | NIST Reference |
|-----------|-------|--------|----------------|
| TLS Hygiene | 100% | 35% | SP 800-52 Rev.2 |
| Certificate Health | 100% | 30% | SP 800-52 Rev.2 |
| PQC Readiness | 0% | 35% | IR 8547 / FIPS 203 |

**PQC Score Breakdown:** KEX Readiness 0% (weight 70%) · Signature Readiness 0% (weight 30%)

> KEX score: 100% only if hybrid PQC (X25519MLKEM768) is active. Signature score: 100% only if cert uses ML-DSA (FIPS 204).

**Severity Penalty:** -4.0 pts (High -0, Moderate -4, Low -0.0)

## Executive Summary

- **Total Assets Analyzed:** 4
- **PQC-Ready:** 0 (0.0%)
- **Quantum-Vulnerable:** 2 (50.0%)
- **HTTPS Endpoints:** 2 (TLS 1.3: 2, TLS 1.2: 0)
- **HTTP Endpoints (no encryption):** 2
- **SSH Endpoints:** 0
- **PQC Hybrid (X25519MLKEM768):** 0 of 2 HTTPS
- **Hosts Scanned:** 2

## PQC Readiness

- **PQC Ready:** 0%
- **Hybrid PQC (X25519MLKEM768):** 0
- **Classical (not yet PQC):** 2
- **Quantum Vulnerable:** 2

## Issues

| Severity | Count |
|----------|-------|
| Total | 2 |
| Critical | 0 |
| Warning | 2 |
| Info | 0 |

### Issue Detail

| Severity | Issue | Host | Port | Category |
|----------|-------|------|------|----------|
| Warning | HTTP port 80 open — no encryption | www.qubitac.com | 80 | Network |
| Warning | HTTP port 80 open — no encryption | qubitac.com | 80 | Network |

## Protocol Distribution

| Protocol/Version | Count | Percentage |
|------------------|-------|------------|
| NO_TLS | 2 | 50.0% |
| TLS13 | 2 | 50.0% |

## Certificate Summary

- **Total TLS Certificates:** 2
- **SSH Host Keys:** 0 (Ed25519: 0, ECDSA: 0, RSA: 0, DSA: 0)
- **ECC Certs:** 2, **RSA Certs:** 0
- **Expiring Critical (<30d):** 0
- **Expiring Warning (30–60d):** 0
- **Valid (>60d):** 2
- **Weak/Deprecated SSH Keys:** 0

## Algorithm Inventory

### Key Exchange Algorithms

| Algorithm | Count | PQC Status |
|-----------|-------|------------|
| X25519 | 2 | ✕ Quantum-Vulnerable |

### Cipher Algorithms

| Cipher Suite | Count |
|--------------|-------|
| TLS_AES_256_GCM_SHA384 | 2 |

### TLS Signature Algorithms

| Algorithm | Count |
|-----------|-------|
| ecdsa-with-SHA384 | 2 |

## Quantum-Vulnerable Algorithms

| Algorithm | Usage Count | Vulnerability | NIST Replacement |
|-----------|-------------|---------------|------------------|
| X25519 | 2 | Shor's Algorithm | ML-KEM (FIPS 203) via X25519MLKEM768 |
| ECDSA | 2 | Shor's Algorithm | ML-DSA (FIPS 204) |

## Host Summary

| Host | IP | OS | Open Ports | TLS | SSH Key | Cert Expiry | PQC | Issues | Status |
|------|----|----|------------|-----|---------|-------------|-----|--------|--------|
| qubitac.com | — | — | 80 443 | TLS13 | — | 89d | Classical | 1 | Warning |
| www.qubitac.com | — | — | 80 443 | TLS13 | — | 89d | Classical | 1 | Warning |

## Per-Endpoint Migration Priority

| Endpoint | Port | Priority | Score | Timeline | Complexity | Effort | KEX Safe | Cert Safe |
|----------|------|----------|-------|----------|------------|--------|----------|-----------|
| qubitac.com | 443 | CRITICAL | 100 | 2026-2027 | HIGH | Deploy hybrid PQC KEX (X25519MLKEM768) + migrate certificate to ML-DSA (FIPS 204) | ✕ | ✕ |
| www.qubitac.com | 443 | CRITICAL | 100 | 2026-2027 | HIGH | Deploy hybrid PQC KEX (X25519MLKEM768) + migrate certificate to ML-DSA (FIPS 204) | ✕ | ✕ |

## Migration Timeline Reference

> Timeline is derived from Priority score. NIST IR 8547 mandates deprecation of quantum-vulnerable algorithms after **2030** and full disallowment after **2035**.

| Priority | Score Range | Target Timeline | NIST Deadline | NIST Reference |
|----------|-------------|-----------------|---------------|----------------|
| CRITICAL | 80 – 100    | 2026 – 2027     | Deprecated after 2030 · Disallowed after 2035 | NIST IR 8547 |
| HIGH     | 60 – 79     | 2026 – 2028     | Deprecated after 2030 · Disallowed after 2035 | NIST IR 8547 |
| MEDIUM   | 20 – 59     | 2028 – 2030     | Must complete before 2030 deprecation         | NIST IR 8547 |
| LOW      | 0 – 19      | 2030 – 2032     | Must complete before 2035 disallowment        | NIST IR 8547 |

> **TLS Override:** TLS 1.0/1.1 endpoints are always CRITICAL regardless of score (classically broken today — NIST SP 800-52 Rev.2). TLS 1.2 endpoints are always CRITICAL — TLS 1.3 is required for PQC.

## PQC Migration Timeline

### Phase 1: Phase 1 — Inventory & Assessment

Scan all endpoints, catalog algorithms, identify quantum-vulnerable assets.

**Status:** Complete

### Phase 2: Phase 2 — Hybrid PQC Deployment

Enable hybrid key exchange (X25519MLKEM768) on TLS 1.3 endpoints. Currently 0 of 2 HTTPS endpoints migrated.

**Status:** In Progress

### Phase 3: Phase 3 — Upgrade Legacy TLS

Upgrade all TLS 1.2 endpoints to TLS 1.3. TLS 1.2 blocks PQC key exchange — hybrid PQC (X25519MLKEM768) requires TLS 1.3. Replace RSA certificates with ECDSA as an interim step; final target is ML-DSA (FIPS 204) once CAs offer it.

**Status:** Pending

### Phase 4: Phase 4 — SSH PQC Transition

Migrate SSH to PQC-safe algorithms. Remove DSA keys. Deploy hybrid SSH key exchange.

**Status:** Pending

### Phase 5: Phase 5 — Full PQC Certificates

Adopt ML-DSA for TLS cert signatures once CAs support it. Achieve 100% PQC coverage.

**Status:** Future

## Recommendations

Sorted by priority · 2 recommendations

### [P1] Close or redirect HTTP port 80

2 endpoint(s) serve plaintext HTTP with zero encryption.

**Affected:** www:80, qubitac:80

### [P3] Enable hybrid PQC on remaining HTTPS

2 endpoint(s) still use classical key exchange.

**Migration:** `X25519 / ECDHE` → `X25519 + ML-KEM-768`

**Affected:** qubitac:443, www:443

## Migration Priority Distribution

| Priority | Count | Timeline |
|----------|-------|----------|
| CRITICAL | 2 | 2026-2027 |

## Recommended Actions

1. **Immediate (2026–2027):**
   - Upgrade 2 critical endpoint(s) immediately
   - Upgrade all TLS 1.2 endpoints to TLS 1.3 (required for PQC)
   - Begin PQC testing with hybrid key exchange (X25519MLKEM768)

2. **Short-term (2027–2028):**
   - Deploy X25519MLKEM768 hybrid KEX in production
   - Migrate high-priority systems
   - Obtain PQC certificates using ML-DSA (FIPS 204) once available from CAs

3. **Medium-term (2028–2030):**
   - Complete migration of all systems before NIST 2030 deprecation deadline
   - Move to pure PQC mode (disable classical fallback)
   - Achieve full quantum-safe compliance ahead of 2035 disallowment

## References

- NIST PQC Standards: https://csrc.nist.gov/projects/post-quantum-cryptography
- ML-KEM (Kyber): FIPS 203 — Finalized August 2024
- ML-DSA (Dilithium): FIPS 204 — Finalized August 2024
- SLH-DSA (SPHINCS+): FIPS 205 — Finalized August 2024
- FN-DSA (Falcon): FIPS 206 — **Draft** (not yet finalized)
- HQC: Selected March 2025 — pending standard
- NIST IR 8547: Deprecation (2030) and Disallowment (2035) of quantum-vulnerable algorithms
- NIST SP 800-52 Rev.2: TLS guidelines (TLS 1.0/1.1 disallowed, TLS 1.3 required)
