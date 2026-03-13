# Changelog

All notable changes to AC Scanner will be documented in this file.

## [1.0.0] - 2026-03-13

### Initial Release

#### TLS Scanner
- OpenSSL-based TLS handshake analysis (no third-party scanning dependencies)
- Detects TLS version, cipher suite, key exchange group, and certificate chain
- PQC hybrid group detection: X25519MLKEM768, SecP256r1MLKEM768, X25519Kyber768, SecP384r1MLKEM1024
- Quantum-vulnerable curve registry: X25519, P-256, P-384, P-521 with NIST replacements
- Legacy cipher blocklist: RC4, 3DES, NULL, export-grade, CBC+SHA1
- HTTP fallback probing with OS fingerprinting from Server headers
- Probe status classification: success, partial, incomplete, no_tls, failed
- Data quality flags per scan result
- Flush-after-write for crash-safe JSONL output

#### SSH Scanner
- TCP pre-check before ssh-audit to avoid unnecessary timeouts
- PQC-safe KEX pattern matching: sntrup761, mlkem, kyber, ntru, frodokem
- Weak cipher detection: 3DES, RC4, Blowfish
- Weak MAC detection: SHA-1, MD5
- Legacy host key detection: DSA, RSA <2048-bit
- CDN bypass via DNS subdomain probing, MX records, and SPF ip4: directives
- CBOM-compatible JSONL output schema

#### CBOM Engine
- Three-component PQC vulnerability scoring: KEX (70%) + signature (30%) + symmetric
- NIST IR 8547 aligned migration priorities: CRITICAL / HIGH / MEDIUM / LOW
- TLS 1.2 auto-CRITICAL (required for PQC upgrade path enforcement)
- Five-phase migration roadmap generation
- CBOM JSON + Markdown summary output
- NIST SP 800-52 Rev.2 and PCI-DSS compliance references

#### Orchestrator
- Dependency checker with auto-install prompting
- Subdomain enumeration via subfinder
- DNS resolution via dnsx
- Live host detection via httpx
- Port classification: web vs SSH vs non-HTTP
- Live progress bars with ETA estimation
- Timestamped scan output per domain
- Diff-friendly directory structure for tracking migration progress over time
- Port presets: --web (80, 443, 8080, 8443), --ssh (22, 2222), --all
