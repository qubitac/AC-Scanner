```
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║    ██████  ██    ██ ██████  ██ ████████  █████   ██████    ║
║   ██    ██ ██    ██ ██   ██ ██    ██    ██   ██ ██         ║
║   ██    ██ ██    ██ ██████  ██    ██    ███████ ██         ║
║   ██ ▄▄ ██ ██    ██ ██   ██ ██    ██    ██   ██ ██         ║
║    ██████   ██████  ██████  ██    ██    ██   ██  ██████    ║
║       ▀▀                                                   ║
║                                                            ║
║    Post-Quantum Cryptography Scanner                       ║
║    https://qubitac.com                                     ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
```

# AC Scanner — Post-Quantum Cryptography Exposure Assessment

**Scan. Discover. Secure.**

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.8+-blue)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20WSL-lightgrey)
![NIST](https://img.shields.io/badge/NIST-IR%208547%20Aligned-orange)


![AC Scanner Demo](qubitac_web.gif)

**🎬 YouTube Demo**
* [AC Scanner Demo](https://youtu.be/egUzG88v9Wo) — `sh scan.sh qubitac.com --web`
  <br>Scans all standard web ports (80, 443, 8080, 8443, 9443) and generates a Crypto Bill of Materials (CBOM) with a clean summary report.

* [AC Scanner Verbose Demo](https://youtu.be/YOUR_SECOND_VIDEO_ID) — `sh scan.sh qubitac.com --web -v`
  <br>Same web scan with verbose output enabled.
  
* [AC Scanner Port Demo](https://youtu.be/YOUR_SECOND_VIDEO_ID) — `sh scan.sh qubitac.com -p 443`
  <br>Targets one or more specific ports for a focused cryptographic audit — useful when you know exactly which endpoints to assess against NIST post-quantum standards. Multiple ports can be passed as a comma-separated list, e.g. `-p 443,8443,9443`.
  
* [AC Scanner SSH Demo](https://youtu.be/YOUR_SECOND_VIDEO_ID) — `sh scan.sh qubitac.com --ssh`
  <br>Audits SSH service configuration, identifying quantum-vulnerable key exchange algorithms and host key types across your SSH endpoints.

* [AC Scanner Web + SSH Demo](https://youtu.be/YOUR_SECOND_VIDEO_ID) — `sh scan.sh qubitac.com --all`
  <br>Full-surface scan combining web and SSH discovery in a single run — maps your entire cryptographic attack surface and outputs a unified CBOM ready for dashboard upload.


AC Scanner is an open-source pipeline that maps your full cryptographic attack surface across TLS endpoints and SSH services, assesses every asset against NIST post-quantum standards, and generates a structured **Cryptographic Bill of Materials (CBOM)** — in a single command.

> With NIST finalizing ML-KEM (FIPS 203), ML-DSA (FIPS 204), and SLH-DSA (FIPS 205) in 2024, and NIST IR 8547 mandating deprecation of quantum-vulnerable algorithms by **2030**, organizations need to inventory their cryptographic assets now. AC Scanner automates that process from discovery to compliance-ready reporting.

🔗 **Dashboard:** [qubitac.com/dashboard](https://qubitac.com/dashboard)

---

## What It Does

```
bash scan.sh example.com --all
```

One command. Four stages:

| Stage | What Happens |
|-------|-------------|
| **Discovery** | Subdomain enumeration, DNS resolution, web & SSH service detection |
| **Scanning** | OpenSSL TLS handshake analysis + SSH auditing per host |
| **Analysis** | PQC vulnerability scoring, NIST deadline mapping, CBOM generation |
| **Reporting** | JSONL + JSON + Markdown output, ready to upload to the dashboard |

---

## Key Features

- **TLS scanning** — Captures TLS version, cipher suite, certificate chain, EC curve, key exchange group, and PQC hybrid detection (X25519MLKEM768, SecP256r1MLKEM768, etc.)
- **SSH auditing** — Classifies KEX algorithms against PQC-safe patterns (sntrup761, mlkem, kyber, ntru, frodokem), flags weak ciphers (3DES, DES, RC4, arcfour, Blowfish) and weak MACs (SHA-1, MD5, RIPEMD), detects quantum-vulnerable host keys (RSA, ECDSA, Ed25519, Ed448, DSA) with per-algorithm ML-DSA replacement guidance, and factors OpenSSH version into migration priority (7.x = CRITICAL, 8.x = HIGH, 9.x = MEDIUM)
- **PQC scoring** — Per-endpoint quantum vulnerability score across three components: key exchange (70%), certificate signature (30%), and symmetric cipher (Grover's impact)
- **Migration priorities** — CRITICAL / HIGH / MEDIUM / LOW tiers aligned to NIST IR 8547 deadlines (2030 deprecation, 2035 disallowment)
- **CBOM output** — Structured Cryptographic Bill of Materials in JSON, ready for auditors, CISOs, and compliance frameworks (NIST, PCI-DSS)
- **CDN bypass** — SSH scanner probes subdomain records, MX, and SPF ip4: directives to find real IPs behind CDNs
- **HTTP fallback** — When TLS fails, falls back to HTTP probing for server fingerprinting and OS detection
- **Legacy cipher detection** — Flags RC4, 3DES, NULL, export-grade, and CBC+SHA1 ciphers as non-PQC-ready regardless of key exchange
- **Data quality flags** — Each result includes a probe status and data quality flags indicating exactly what was and wasn't captured, enabling the CBOM engine to accurately score only endpoints with sufficient data
- **No cloud dependency** — Runs entirely on your own infrastructure; suitable for air-gapped environments
- **Timestamped scan history** — Compare scan runs over time to track PQC migration progress

---

## Supported Algorithms

### Quantum-Vulnerable (detected and flagged)
| Algorithm | Type | Broken By | NIST Replacement |
|-----------|------|-----------|-----------------|
| X25519, P-256, P-384, P-521 | TLS Key Exchange | Shor's Algorithm | ML-KEM (FIPS 203) |
| RSA, ECDSA, DSA, Ed25519, Ed448 | SSH Host Keys / Signatures | Shor's Algorithm | ML-DSA (FIPS 204) |
| 3DES, DES, RC4, arcfour, Blowfish | SSH Ciphers | Classically weak | AES-256-GCM |
| SHA-1, MD5, RIPEMD | SSH MACs | Classically weak | SHA-256 / Poly1305 |
| AES-128 | Symmetric | Grover's Algorithm | AES-256 |

### PQC-Safe (detected as compliant)
| Group | Classical Component | PQC Component | Security Level |
|-------|-------------------|---------------|---------------|
| X25519MLKEM768 | X25519 | ML-KEM-768 | 128-bit quantum-safe |
| SecP256r1MLKEM768 | P-256 | ML-KEM-768 | 128-bit quantum-safe |
| X25519Kyber768 | X25519 | Kyber-768 | 128-bit quantum-safe |
| SecP384r1MLKEM1024 | P-384 | ML-KEM-1024 | 192-bit quantum-safe |

---

## Installation

### Requirements

- Linux or macOS (Windows via WSL)
- Python 3.8+
- OpenSSL 3.x (for PQC hybrid group detection)

### Install Dependencies

```bash
# macOS
brew install subfinder dnsx httpx jq openssl
pip3 install ssh-audit

# Ubuntu / Debian
sudo apt install jq openssl dnsutils
pip3 install ssh-audit

# subfinder, dnsx, httpx (Go-based tools)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

> AC Scanner will check for all dependencies on startup and offer to install missing ones automatically.

---

## Quick Start

```bash
# Clone the repo
https://github.com/qubitac/AC-Scanner.git
chmod +x scan.sh

# Scan a domain (web ports only)
bash scan.sh example.com

# Scan web + SSH
bash scan.sh example.com --web --ssh

# Scan everything
bash scan.sh example.com --all

# Custom ports
bash scan.sh example.com -p 443,8443

# With verbose output
bash scan.sh example.com --all -v
```

---

## Port Presets

| Flag | Ports |
|------|-------|
| `--web` | 80, 443, 8080, 8443 |
| `--ssh` | 22, 2222 |
| `--all` | All of the above |
| `-p` | Custom comma-separated ports |

---

## Output

Each scan produces three output files under `<domain>/<timestamp>/`:

```
example.com/
└── 2026-03-13T120000/
    ├── cbom/
    │   ├── crypto-bom.json     ← CBOM for dashboard upload
    │   └── summary.md          ← Human-readable scan summary
    └── reports/
        └── scan_stats.json     ← Machine-readable scan statistics
```

### CBOM JSON (excerpt)
```json
{
  "host": "api.example.com",
  "port": 443,
  "tls_version": "tls13",
  "cipher": "TLS_AES_256_GCM_SHA384",
  "pqc_hybrid": false,
  "pqc_ready": false,
  "migration_priority": "CRITICAL",
  "vulnerabilities": [
    {
      "component": "Key Exchange",
      "algorithm": "X25519",
      "quantum_vulnerable": true,
      "broken_by": "Shor's Algorithm",
      "replacement": "ML-KEM (FIPS 203) via X25519MLKEM768"
    }
  ]
}
```

### Dashboard
Upload `crypto-bom.json` to [qubitac.com/dashboard](https://qubitac.com/dashboard) to visualize your PQC readiness score, filter by TLS version, cipher suite, and migration priority, and export findings for auditors.

---

## Migration Priority Scoring

Each endpoint receives a score (0–100) based on NIST IR 8547:

| Priority | Score | Target Timeline | NIST Deadline |
|----------|-------|-----------------|---------------|
| **CRITICAL** | 80–100 | 2026–2027 | Deprecated after 2030 |
| **HIGH** | 60–79 | 2026–2028 | Deprecated after 2030 |
| **MEDIUM** | 20–59 | 2028–2030 | Must complete before 2030 |
| **LOW** | 0–19 | 2030–2032 | Must complete before 2035 |

> **Note:** TLS 1.2 endpoints are always forced to CRITICAL — TLS 1.3 is required for PQC hybrid key exchange.

---

## Architecture

```
scan.sh (orchestrator)
├── Discovery
│   ├── subfinder    → subdomain enumeration
│   ├── dnsx         → DNS resolution
│   └── httpx        → live host detection
│
├── TLS Scanner (openssl_scanner.py)
│   ├── openssl s_client per host
│   ├── Certificate parsing (x509)
│   ├── PQC hybrid group detection
│   └── HTTP fallback probing
│
├── SSH Scanner (ssh_scanner.py)
│   ├── TCP pre-check
│   ├── ssh-audit per host
│   ├── CDN bypass (DNS/MX/SPF)
│   ├── PQC KEX classification (sntrup761, mlkem, kyber, ntru, frodokem)
│   ├── Weak cipher/MAC detection (3DES, RC4, SHA-1, MD5, RIPEMD)
│   ├── Host key vulnerability mapping (RSA/ECDSA/Ed25519 → ML-DSA)
│   └── OpenSSH version-based priority scoring
│
└── CBOM Engine (pqc_cbom.py)
    ├── Vulnerability scoring
    ├── Migration priority mapping
    ├── CBOM JSON generation
    └── Markdown summary + migration roadmap
```

---

## NIST PQC Standards Reference

| Standard | Algorithm | Status | Role |
|----------|-----------|--------|------|
| FIPS 203 | ML-KEM (Kyber) | ✅ Finalized Aug 2024 | Key Encapsulation |
| FIPS 204 | ML-DSA (Dilithium) | ✅ Finalized Aug 2024 | Digital Signatures |
| FIPS 205 | SLH-DSA (SPHINCS+) | ✅ Finalized Aug 2024 | Hash-based Signatures |
| FIPS 206 | FN-DSA (Falcon) | 🔄 Draft | Digital Signatures |
| — | HQC | 🔄 Selected Mar 2025 | Key Encapsulation (backup) |

**NIST IR 8547 Timeline:**
- **2030** — Deprecation of quantum-vulnerable algorithms
- **2035** — Full disallowment

---

## Use Cases

- **Blue teams** — Inventory cryptographic assets before the 2030 NIST deadline
- **Security architects** — Identify which endpoints need TLS 1.3 upgrades before PQC can be deployed
- **Compliance engineers** — Generate CBOM evidence for auditors aligned to NIST and PCI-DSS
- **Pentesters** — Identify weak cipher suites, expiring certificates, and legacy TLS in scope
- **Air-gapped environments** — No API keys or cloud services required

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SCAN_TIMEOUT` | `10` | Connection timeout in seconds |
| `VERBOSE` | `0` | Set to `1` for verbose output |
| `DEBUG` | `0` | Set to `1` for raw OpenSSL output |

```bash
SCAN_TIMEOUT=30 VERBOSE=1 bash scan.sh example.com --all
```

---

## Platform Support

| Platform | Support |
|----------|---------|
| Linux | ✅ Full support |
| macOS | ✅ Full support |
| Windows (WSL) | ✅ Supported |
| Windows (Git Bash) | ✅ `bash scan.sh` |
| Windows (native) | ❌ Not supported |

---

## License

MIT License — see [LICENSE](LICENSE)

---

## Acknowledgements

AC Scanner builds on top of excellent open-source tools:
- [OpenSSL](https://www.openssl.org/) — TLS handshake and certificate parsing
- [ssh-audit](https://github.com/jtesta/ssh-audit) — SSH configuration auditing
- [subfinder](https://github.com/projectdiscovery/subfinder) — Subdomain enumeration
- [dnsx](https://github.com/projectdiscovery/dnsx) — DNS resolution
- [httpx](https://github.com/projectdiscovery/httpx) — HTTP probing

---

*Built by [QubitAC](https://qubitac.com) · [Dashboard](https://qubitac.com/dashboard) · [X](https://x.com/qubitac)*
