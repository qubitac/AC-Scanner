#!/usr/bin/env python3
"""
Post-Quantum Cryptography - Cryptography Bill of Materials (PQC CBOM) Generator
Analyzes TLS/SSL configurations and generates quantum vulnerability inventory
"""
import json
import sys
from datetime import datetime, timezone
from collections import Counter, defaultdict

# Quantum vulnerability classifications
QUANTUM_VULNERABLE_KEY_EXCHANGE = {
    "rsa", "dh", "dhe", "ecdh", "ecdhe", "x25519", "x448"
}

QUANTUM_VULNERABLE_SIGNATURES = {
    "rsa", "ecdsa", "dsa", "ed25519", "ed448"
}

# Symmetric crypto - Grover's algorithm impact
SYMMETRIC_QUANTUM_IMPACT = {
    "aes128": "weak",      # 128-bit → 64-bit quantum security
    "aes256": "adequate",  # 256-bit → 128-bit quantum security
    "chacha20": "adequate"
}

# NIST PQC Standards (2024+)
PQC_ALGORITHMS = {
    "kyber": "ML-KEM (FIPS 203)",      # Key Encapsulation
    "dilithium": "ML-DSA (FIPS 204)",  # Digital Signature
    "falcon": "FN-DSA (FIPS 206)",     # Digital Signature
    "sphincs": "SLH-DSA (FIPS 205)"    # Stateless Hash Signature
}

# PQC Hybrid Key Exchange Groups (quantum-safe)
PQC_HYBRID_GROUPS = {
    "x25519mlkem768", "secp256r1mlkem768", "x25519kyber768",
    "secp384r1mlkem1024", "x448mlkem1024"
}

# Legacy cipher suites with no forward secrecy or broken algorithms
# These must never be classified as PQC-ready even if no KEX vulnerability is detected
LEGACY_CIPHERS = {
    # ── SHA-1 based — no forward secrecy ──────────────────────────────
    "AES128-SHA",               # Static RSA + SHA-1 — vpn1.flcu.org ❌
    "AES256-SHA",               # Static RSA + SHA-1 ❌
    "AES128-SHA256",            # Static RSA + SHA-256 but no FS ❌
    "AES256-SHA256",            # Static RSA + SHA-256 but no FS ❌

    # ── DES / 3DES — weak encryption ──────────────────────────────────
    "DES-CBC3-SHA",             # 3DES — only 112-bit security ❌
    "DES-CBC-SHA",              # Single DES — completely broken ❌
    "EDH-RSA-DES-CBC3-SHA",     # DHE + 3DES ❌
    "EDH-DSS-DES-CBC3-SHA",     # DSS + 3DES ❌

    # ── RC4 — stream cipher, completely broken ─────────────────────────
    "RC4-SHA",                  # RC4 broken since 2015 ❌
    "RC4-MD5",                  # RC4 + MD5 — doubly broken ❌
    "ECDHE-RSA-RC4-SHA",        # Even with ECDHE, RC4 is broken ❌
    "ECDHE-ECDSA-RC4-SHA",      # Same ❌

    # ── NULL ciphers — no encryption at all ───────────────────────────
    "NULL-SHA",                 # No encryption ❌
    "NULL-MD5",                 # No encryption ❌
    "NULL-SHA256",              # No encryption ❌

    # ── Export grade — intentionally weakened ─────────────────────────
    "EXP-RC4-MD5",              # Export 40-bit RC4 ❌
    "EXP-DES-CBC-SHA",          # Export 40-bit DES ❌
    "EXP-RC2-CBC-MD5",          # Export 40-bit RC2 ❌

    # ── CBC mode + SHA-1 — BEAST/POODLE vulnerable ────────────────────
    "ECDHE-RSA-AES128-SHA",     # Good KEX but SHA-1 + CBC ❌
    "ECDHE-RSA-AES256-SHA",     # Good KEX but SHA-1 + CBC ❌
    "ECDHE-ECDSA-AES128-SHA",   # Good KEX but SHA-1 + CBC ❌
    "ECDHE-ECDSA-AES256-SHA",   # Good KEX but SHA-1 + CBC ❌
    "DHE-RSA-AES128-SHA",       # DHE but SHA-1 + CBC ❌
    "DHE-RSA-AES256-SHA",       # DHE but SHA-1 + CBC ❌
    "DHE-DSS-AES128-SHA",       # DSS + SHA-1 + CBC ❌
    "DHE-DSS-AES256-SHA",       # DSS + SHA-1 + CBC ❌
}

# HTTP Status Code Mapping (18 codes)
HTTP_STATUS_MAP = {
    # 2xx Success - Serving content (Warning on HTTP)
    200: {"type": "serving", "description": "Serving content", "severity": "warning", "color": "orange"},
    201: {"type": "serving", "description": "Created (API)", "severity": "warning", "color": "orange"},
    204: {"type": "serving", "description": "No content", "severity": "warning", "color": "orange"},
    
    # 3xx Redirect - Good (redirecting to HTTPS)
    301: {"type": "redirect", "description": "Redirects to HTTPS", "severity": "good", "color": "green"},
    302: {"type": "redirect", "description": "Redirects to HTTPS", "severity": "good", "color": "green"},
    303: {"type": "redirect", "description": "Redirects (See Other)", "severity": "good", "color": "green"},
    307: {"type": "redirect", "description": "Redirects to HTTPS", "severity": "good", "color": "green"},
    308: {"type": "redirect", "description": "Redirects to HTTPS", "severity": "good", "color": "green"},
    
    # 4xx Client Errors
    400: {"type": "error", "description": "Bad request", "severity": "info", "color": "gray"},
    401: {"type": "auth", "description": "Auth required on HTTP!", "severity": "critical", "color": "red"},
    403: {"type": "forbidden", "description": "Forbidden", "severity": "info", "color": "gray"},
    404: {"type": "not_found", "description": "Not found", "severity": "info", "color": "gray"},
    429: {"type": "rate_limit", "description": "Rate limited", "severity": "info", "color": "gray"},
    
    # 5xx Server Errors
    500: {"type": "error", "description": "Server error", "severity": "info", "color": "gray"},
    502: {"type": "error", "description": "Bad gateway", "severity": "info", "color": "gray"},
    503: {"type": "error", "description": "Unavailable", "severity": "info", "color": "gray"},
    504: {"type": "error", "description": "Timeout", "severity": "info", "color": "gray"},
    520: {"type": "error", "description": "Cloudflare error", "severity": "info", "color": "gray"},
}

def get_http_status_info(status_code):
    """Get HTTP status code interpretation"""
    if status_code is None:
        return {
            "type": "no_service",
            "description": "No service",
            "severity": "info",
            "color": "gray"
        }
    
    # Try exact match first
    if status_code in HTTP_STATUS_MAP:
        return HTTP_STATUS_MAP[status_code]
    
    # Fall back to category-based matching
    if 200 <= status_code < 300:
        return {"type": "serving", "description": f"HTTP {status_code}", "severity": "warning", "color": "orange"}
    elif 300 <= status_code < 400:
        return {"type": "redirect", "description": f"Redirect ({status_code})", "severity": "good", "color": "green"}
    elif 400 <= status_code < 500:
        return {"type": "client_error", "description": f"Client error ({status_code})", "severity": "info", "color": "gray"}
    elif 500 <= status_code < 600:
        return {"type": "server_error", "description": f"Server error ({status_code})", "severity": "info", "color": "gray"}
    else:
        return {"type": "unknown", "description": f"HTTP {status_code}", "severity": "info", "color": "gray"}

def is_pqc_safe_curve(curve_name):
    """
    Check if a key exchange curve/group is PQC-safe.
    Returns True for PQC hybrid groups, False for classical curves.
    """
    if not curve_name:
        return False
    
    curve_lower = curve_name.lower()
    
    # Check for known PQC hybrid groups
    if curve_lower in PQC_HYBRID_GROUPS:
        return True
    
    # Check for PQC keywords
    if any(pqc in curve_lower for pqc in ['mlkem', 'kyber', 'ntru', 'saber', 'frodo']):
        return True
    
    return False

def build_certificate_curve_info(record):
    """
    Build certificate curve/key information.
    Shows EC curve for ECDSA certs, or RSA-{size} for RSA certs.
    """
    detailed_cert = record.get("detailed_certificate") or {}
    
    ec_curve = record.get("ec_curve") or detailed_cert.get("ec_curve")
    public_key_algorithm = detailed_cert.get("public_key_algorithm") or record.get("public_key_algorithm")
    signature_algorithm = detailed_cert.get("signature_algorithm") or record.get("signature_algorithm")
    key_size = detailed_cert.get("key_size_bits") or record.get("key_size")
    
    # Determine display value: EC curve or RSA-{size}
    if ec_curve:
        # ECDSA certificate - show the curve
        display = ec_curve
    elif public_key_algorithm and key_size:
        # RSA or other - show algorithm + key size
        alg = public_key_algorithm.lower()
        if "rsa" in alg:
            display = f"RSA-{key_size}"
        elif "dsa" in alg:
            display = f"DSA-{key_size}"
        else:
            display = f"{public_key_algorithm}-{key_size}"
    elif key_size:
        display = f"RSA-{key_size}"  # Default assumption
    else:
        display = None
    
    return {
        "curve": ec_curve,  # Original EC curve (null for RSA)
        "display": display,  # Human-readable: "prime256v1" or "RSA-2048"
        "public_key_algorithm": public_key_algorithm,
        "signature_algorithm": signature_algorithm,
        "key_size": key_size,
        "pqc_safe": False,  # Certificate signatures are NOT PQC-safe yet
        "note": "PQC certificate signatures (Dilithium/ML-DSA) not yet widely available"
    }

def extract_crypto_primitives(cipher_suite):
    """Extract cryptographic primitives from cipher suite name"""
    if not cipher_suite:
        return {}

    cipher_lower = cipher_suite.lower()
    primitives = {
        "key_exchange": None,
        "authentication": None,
        "encryption": None,
        "mac": None,
        "mode": None
    }

    # Key Exchange
    if "ecdhe" in cipher_lower:
        primitives["key_exchange"] = "ECDHE"
    elif "dhe" in cipher_lower:
        primitives["key_exchange"] = "DHE"
    elif "ecdh" in cipher_lower:
        primitives["key_exchange"] = "ECDH"
    elif "rsa" in cipher_lower and "with" in cipher_lower:
        # TLS_RSA_WITH_* means RSA key exchange
        primitives["key_exchange"] = "RSA"
    elif cipher_suite in LEGACY_CIPHERS:
        # Static RSA ciphers like AES128-SHA have no KEX prefix
        # but implicitly use Static RSA key exchange
        primitives["key_exchange"] = "RSA"

    # Authentication (from cipher suite or separate)
    if "rsa" in cipher_lower:
        primitives["authentication"] = "RSA"
    elif "ecdsa" in cipher_lower:
        primitives["authentication"] = "ECDSA"
    elif "dss" in cipher_lower or "dsa" in cipher_lower:
        primitives["authentication"] = "DSA"

    # Encryption
    if "aes_256" in cipher_lower or "aes256" in cipher_lower:
        primitives["encryption"] = "AES-256"
    elif "aes_128" in cipher_lower or "aes128" in cipher_lower:
        primitives["encryption"] = "AES-128"
    elif "chacha20" in cipher_lower:
        primitives["encryption"] = "ChaCha20"
    elif "3des" in cipher_lower:
        primitives["encryption"] = "3DES"
    elif "rc4" in cipher_lower:
        primitives["encryption"] = "RC4"

    # Mode
    if "gcm" in cipher_lower:
        primitives["mode"] = "GCM"
    elif "ccm" in cipher_lower:
        primitives["mode"] = "CCM"
    elif "cbc" in cipher_lower:
        primitives["mode"] = "CBC"
    elif "poly1305" in cipher_lower:
        primitives["mode"] = "Poly1305"

    # MAC/Hash
    if "sha384" in cipher_lower:
        primitives["mac"] = "SHA-384"
    elif "sha256" in cipher_lower:
        primitives["mac"] = "SHA-256"
    elif "sha1" in cipher_lower or "sha" in cipher_lower:
        primitives["mac"] = "SHA-1"
    elif "md5" in cipher_lower:
        primitives["mac"] = "MD5"

    return primitives

def assess_quantum_vulnerability(primitives, tls_version, curve_name=None):
    """Assess quantum vulnerability of cryptographic primitives"""
    vulnerabilities = []
    pqc_ready = True
    
    # Check if key exchange curve is PQC-safe (hybrid PQC like X25519MLKEM768)
    kex_pqc_safe = is_pqc_safe_curve(curve_name)

    # TLS 1.3 special handling - key exchange is implicit
    if tls_version == "tls13":
        if kex_pqc_safe:
            # Using hybrid PQC key exchange - session is quantum-safe
            vulnerabilities.append({
                "component": "Key Exchange",
                "algorithm": curve_name or "Hybrid PQC",
                "quantum_vulnerable": False,
                "algorithm_type": "Hybrid Post-Quantum Key Exchange",
                "broken_by": None,
                "security_level_classical": "128-bit",
                "security_level_quantum": "128-bit (PQC-safe)",
                "replacement": "Already using PQC",
                "nist_standard": "FIPS 203 (ML-KEM)"
            })
            # pqc_ready stays True
        else:
            vulnerabilities.append({
                "component": "Key Exchange",
                "algorithm": curve_name or "ECDHE (implicit in TLS 1.3)",
                "quantum_vulnerable": True,
                "algorithm_type": "Elliptic Curve Diffie-Hellman",
                "broken_by": "Shor's Algorithm",
                "security_level_classical": "128-bit",
                "security_level_quantum": "0-bit (broken)",
                "replacement": "ML-KEM (FIPS 203) via X25519MLKEM768",
                "nist_standard": "FIPS 203"
            })
            pqc_ready = False
    elif primitives.get("key_exchange"):
        kex = primitives["key_exchange"]
        if kex_pqc_safe:
            # Using hybrid PQC key exchange
            vulnerabilities.append({
                "component": "Key Exchange",
                "algorithm": curve_name or kex,
                "quantum_vulnerable": False,
                "algorithm_type": "Hybrid Post-Quantum Key Exchange",
                "broken_by": None,
                "security_level_classical": "128-bit",
                "security_level_quantum": "128-bit (PQC-safe)",
                "replacement": "Already using PQC",
                "nist_standard": "FIPS 203 (ML-KEM)"
            })
            # pqc_ready stays True
        elif kex.lower() in QUANTUM_VULNERABLE_KEY_EXCHANGE:
            vulnerabilities.append({
                "component": "Key Exchange",
                "algorithm": kex,
                "quantum_vulnerable": True,
                "algorithm_type": get_algorithm_type(kex),
                "broken_by": "Shor's Algorithm",
                "security_level_classical": "128-bit" if "ecdhe" in kex.lower() else "112-bit",
                "security_level_quantum": "0-bit (broken)",
                "replacement": "ML-KEM (FIPS 203) via X25519MLKEM768",
                "nist_standard": "FIPS 203"
            })
            pqc_ready = False

    # Authentication/Signatures - still vulnerable even with PQC KEX
    # (but we consider asset PQC-ready if KEX is safe, as that protects session data)
    if primitives.get("authentication"):
        auth = primitives["authentication"]
        if auth.lower() in QUANTUM_VULNERABLE_SIGNATURES:
            vulnerabilities.append({
                "component": "Authentication/Signature",
                "algorithm": auth,
                "quantum_vulnerable": True,
                "algorithm_type": get_algorithm_type(auth),
                "broken_by": "Shor's Algorithm",
                "security_level_classical": "128-bit" if "ecdsa" in auth.lower() else "112-bit",
                "security_level_quantum": "0-bit (broken)",
                "replacement": "ML-DSA (FIPS 204)",
                "nist_standard": "FIPS 204 or FIPS 206"
            })
            # Note: We don't set pqc_ready = False here if KEX is PQC-safe
            # because session data is protected even if signatures are classical

    # Symmetric encryption - Grover's impact
    if primitives.get("encryption"):
        enc = primitives["encryption"]
        enc_lower = enc.lower()

        if "aes" in enc_lower or "chacha" in enc_lower:
            quantum_impact = "adequate" if "256" in enc_lower else "weak"
            vulnerabilities.append({
                "component": "Symmetric Encryption",
                "algorithm": enc,
                "quantum_vulnerable": False,  # Not broken, just weakened
                "algorithm_type": "Symmetric Cipher",
                "broken_by": None,
                "weakened_by": "Grover's Algorithm",
                "security_level_classical": "256-bit" if "256" in enc_lower else "128-bit",
                "security_level_quantum": "128-bit" if "256" in enc_lower else "64-bit",
                "impact": quantum_impact,
                "replacement": "AES-256 (adequate) or increase to 512-bit",
                "nist_standard": "Current AES-256 is acceptable"
            })

    return vulnerabilities, pqc_ready

def get_algorithm_type(algorithm):
    """Get human-readable algorithm type"""
    alg_lower = algorithm.lower()
    if "rsa" in alg_lower:
        return "RSA (Integer Factorization)"
    elif "ecdhe" in alg_lower or "ecdh" in alg_lower or "ecdsa" in alg_lower:
        return "Elliptic Curve Cryptography"
    elif "dhe" in alg_lower or "dh" in alg_lower:
        return "Diffie-Hellman"
    elif "dsa" in alg_lower:
        return "Digital Signature Algorithm"
    else:
        return algorithm

def calculate_migration_priority(record, vulnerabilities, tls_version):
    """
    Calculate PQC migration priority score (0-100) and priority tier.

    Scoring model (NIST IR 8547 aligned):

    Step 1 — TLS Version Gate (auto-CRITICAL, no scoring):
        TLS 1.0 / 1.1  -> CRITICAL (classically broken + PQC impossible)
        TLS 1.2        -> CRITICAL (PQC blocked — must upgrade to TLS 1.3 first)
        HTTP / no TLS  -> handled upstream (priority_score=0, priority=INFO)
        TLS 1.3        -> proceed to quantum risk scoring

    Step 2 — Quantum Risk Score (TLS 1.3 only, 0-100):
        KEX not hybrid (X25519/ECDH)  -> +70  (HNDL risk — highest urgency)
        Sig not PQC   (ECDSA/RSA)     -> +30  (future quantum risk)

    Priority Tiers:
        80-100 -> CRITICAL  2026-2027  (both KEX + Sig vulnerable)
        60-79  -> HIGH      2026-2028  (KEX vulnerable, Sig safe)
        20-59  -> MEDIUM    2028-2030  (KEX safe, Sig vulnerable)
        0-19   -> LOW       2030-2032  (fully PQC ready — future state)
    """
    # ── Step 1: TLS Version Gate ──────────────────────────────────────────────
    if tls_version in ("tls10", "tls11"):
        return {
            "priority": "CRITICAL",
            "priority_score": 100,
            "timeline": "2026-2027",
            "complexity": "CRITICAL",
            "effort": "Upgrade TLS version immediately — TLS 1.0/1.1 are classically broken and PQC migration is impossible"
        }

    if tls_version == "tls12":
        return {
            "priority": "CRITICAL",
            "priority_score": 100,
            "timeline": "2026-2027",
            "complexity": "HIGH",
            "effort": "Upgrade to TLS 1.3 first — TLS 1.2 cannot support PQC hybrid key exchange"
        }

    # ── Step 2: TLS 1.3 Quantum Risk Scoring ─────────────────────────────────
    priority_score = 0

    # KEX: +70 if not using PQC hybrid (HNDL risk — harvest now, decrypt later)
    kex_safe = record.get("pqc_hybrid", False) or is_pqc_safe_curve(record.get("curve"))
    if not kex_safe:
        priority_score += 70

    # Sig: +30 if certificate signature is not PQC safe (ECDSA/RSA)
    # certificate_safe is always False today — ML-DSA certs not yet widely available
    cert_safe = record.get("certificate_safe", False)
    if not cert_safe:
        priority_score += 30

    # ── Step 3: Priority Tier ─────────────────────────────────────────────────
    if priority_score >= 80:
        priority = "CRITICAL"
        timeline = "2026-2027"
    elif priority_score >= 60:
        priority = "HIGH"
        timeline = "2026-2028"
    elif priority_score >= 20:
        priority = "MEDIUM"
        timeline = "2028-2030"
    else:
        priority = "LOW"
        timeline = "2030-2032"

    # ── Complexity and Effort (dynamic based on actual state) ─────────────────
    # Complexity reflects actual implementation effort required:
    #   HIGH     — multiple changes needed (KEX config + certificate replacement)
    #   MEDIUM   — single change needed (either KEX config OR certificate)
    #   LOW      — fully PQC ready, monitoring only
    if not kex_safe and not cert_safe:
        complexity = "HIGH"
        effort = "Deploy hybrid PQC KEX (X25519MLKEM768) + migrate certificate to ML-DSA (FIPS 204)"
    elif not kex_safe and cert_safe:
        complexity = "MEDIUM"
        effort = "Deploy hybrid PQC KEX (X25519MLKEM768) — certificate already PQC safe"
    elif kex_safe and not cert_safe:
        complexity = "MEDIUM"
        effort = "Migrate certificate signature to ML-DSA (FIPS 204) — KEX already PQC safe"
    else:
        complexity = "LOW"
        effort = "Fully PQC ready — monitor for NIST standard updates"

    return {
        "priority": priority,
        "priority_score": priority_score,
        "timeline": timeline,
        "complexity": complexity,
        "effort": effort
    }

def generate_ssh_cbom_entry(record):
    """
    Generate Crypto-BOM entry for an SSH asset.
    SSH entries arrive pre-classified from scan.sh's run_ssh_audit_host().
    We wrap them into the standard CBOM structure the dashboard expects.
    """
    host = record.get("host", "unknown")
    port = record.get("port", 22)
    probe_status = record.get("probe_status", "success")
    timestamp = record.get("scan_timestamp") or datetime.now(timezone.utc).isoformat()

    # For filtered/closed SSH — return minimal entry
    if probe_status in ("filtered", "closed", "no_ssh_banner"):
        migration_info = record.get("pqc_migration", {})
        return {
            "_host": host,
            "_port": port,
            "asset": {
                "host": host,
                "port": port,
                "timestamp": timestamp
            },
            "host": host,
            "port": port,
            "probe_status": probe_status,
            "tls_enabled": False,
            "os": record.get("os"),
            "ssh_banner": None,
            "ssh_version": None,
            "pqc_ready": None,
            "key_exchange": {"total": 0, "pqc_safe_count": 0, "algorithms": []},
            "host_keys": {"total": 0, "algorithms": []},
            "encryption": {"total": 0, "algorithms": []},
            "mac": {"total": 0, "algorithms": []},
            "pqc_curve_assessment": {
                "pqc_ready": None,
                "migration_priority": "UNKNOWN"
            },
            "pqc_migration": migration_info if migration_info else {
                "priority": "UNKNOWN",
                "priority_score": 0,
                "timeline": f"SSH {probe_status} — check firewall/CDN",
                "complexity": "UNKNOWN",
                "effort": f"SSH port {probe_status} — verify connectivity first"
            },
            "quantum_vulnerability": {
                "pqc_ready": None,
                "vulnerable_components": [],
                "note": f"SSH port {probe_status}"
            }
        }

    # For successful SSH scans — the record already has the right structure.
    # Just ensure required CBOM fields exist and add quantum_vulnerability
    # in the format the stats loop in main() expects.
    kex = record.get("key_exchange", {})
    pqc_assessment = record.get("pqc_curve_assessment", {})
    pqc_ready = record.get("pqc_ready", pqc_assessment.get("pqc_ready", False))
    migration = record.get("pqc_migration", {})

    # Build vulnerable_components list for stats tracking
    vulnerable_components = []
    for alg in kex.get("algorithms", []):
        if not alg.get("pqc_safe", False):
            vulnerable_components.append({
                "component": "Key Exchange (SSH)",
                "algorithm": alg.get("algorithm", "unknown"),
                "quantum_vulnerable": True,
                "algorithm_type": "SSH Key Exchange",
                "broken_by": "Shor's Algorithm",
                "replacement": alg.get("replacement", "mlkem768x25519-sha256")
            })
    for hk in record.get("host_keys", {}).get("algorithms", []):
        if hk.get("quantum_threat") == "shors_algorithm":
            vulnerable_components.append({
                "component": "Host Key (SSH)",
                "algorithm": hk.get("algorithm", "unknown"),
                "quantum_vulnerable": True,
                "algorithm_type": "SSH Host Key",
                "broken_by": "Shor's Algorithm",
                "replacement": hk.get("replacement", "ML-DSA-65")
            })

    # Return the record as-is with CBOM-compatible fields added
    entry = dict(record)
    entry["_host"] = host
    entry["_port"] = port
    entry["tls_enabled"] = False
    entry["tls_configuration"] = {"version": record.get("ssh_version", "SSH"), "cipher_suite": None}
    entry["quantum_vulnerability"] = {
        "pqc_ready": pqc_ready,
        "vulnerable_components": vulnerable_components,
        "total_vulnerable": sum(1 for v in vulnerable_components if v.get("quantum_vulnerable"))
    }
    # Ensure pqc_migration exists
    if not entry.get("pqc_migration"):
        entry["pqc_migration"] = migration if migration else {
            "priority": pqc_assessment.get("migration_priority", "UNKNOWN"),
            "timeline": "Assess SSH PQC readiness"
        }
    # Ensure standard asset wrapper exists (for consistent CBOM structure)
    if "asset" not in entry:
        entry["asset"] = {
            "host": host,
            "port": port,
            "timestamp": timestamp
        }

    return entry


def _compute_cert_days_remaining(not_after_str):
    """
    Compute days until certificate expiry.
    Returns an integer (may be negative if expired), or None if unparseable.
    Matches dashboard display values: 19d, 24d, 65d, 81d, 88d, 131d.
    """
    if not not_after_str:
        return None
    formats = [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%b %d, %Y",
        "%b %d %H:%M:%S %Y GMT",
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(not_after_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            return (dt - now).days
        except ValueError:
            continue
    return None


def generate_cbom_entry(record):
    """Generate Crypto-BOM entry for a single asset"""

    # ═══ SSH ASSET DETECTION ═══
    # SSH entries come pre-formatted from scan.sh's run_ssh_audit_host() with
    # fields like ssh_banner, ssh_version, key_exchange.algorithms[], host_keys, etc.
    # Also detect filtered/closed SSH entries (SSH ports with no TLS data).
    ssh_ports = {22, 2222, 2200, 22222, 8022, 222, 3022, 4022, 8222, 10022}
    is_ssh = (
        record.get("ssh_banner") or record.get("ssh_version") or
        (isinstance(record.get("key_exchange"), dict) and record.get("key_exchange", {}).get("algorithms")) or
        (record.get("port") in ssh_ports and record.get("tls_enabled") in (False, None)
         and record.get("probe_status") in ("filtered", "closed", "no_ssh_banner"))
    )
    if is_ssh:
        return generate_ssh_cbom_entry(record)

    # FIELD NAME COMPATIBILITY: Support both field name formats
    # tlsx uses "subject_cn", normalize_tls.py uses "cert_subject_cn"
    if "subject_cn" in record and not record.get("cert_subject_cn"):
        record["cert_subject_cn"] = record.get("subject_cn")
    if "subject_an" in record and not record.get("cert_subject_an"):
        record["cert_subject_an"] = record.get("subject_an", [])
    if "issuer_cn" in record and not record.get("cert_issuer_cn"):
        record["cert_issuer_cn"] = record.get("issuer_cn")
    if "not_before" in record and not record.get("cert_not_before"):
        record["cert_not_before"] = record.get("not_before")
    if "not_after" in record and not record.get("cert_not_after"):
        record["cert_not_after"] = record.get("not_after")

    host = record.get("host")
    port = record.get("port", 443)
    tls_version = record.get("tls_version", "").lower().replace("tlsv", "tls").replace("tls ", "tls").replace(".", "").replace("_", "")
    if tls_version == "tls1":
        tls_version = "tls10"
    cipher = record.get("cipher", "")

    # Extract cryptographic primitives
    primitives = extract_crypto_primitives(cipher)

    # Check for OpenSSL curve information (enhanced data)
    curve_info = record.get("curve_information", {})
    curve_name = None
    if curve_info and curve_info.get("curve_details"):
        curve_details = curve_info["curve_details"]
        # Add curve details to primitives
        curve_name = curve_details.get("name", "unknown")
        primitives["curve"] = curve_name
        primitives["curve_bits"] = curve_details.get("bits")  # May be None for PQC hybrid
        primitives["pqc_hybrid"] = curve_details.get("type") == "hybrid_pqc"
    
    # Also check direct curve field in record
    if not curve_name:
        curve_name = record.get("curve") or record.get("server_temp_key_curve")

    # If cipher did not reveal authentication (e.g. AES128-SHA has no RSA/ECDSA prefix)
    # fall back to the certificate's public key algorithm
    if not primitives.get("authentication"):
        pubkey_alg = (record.get("public_key_algorithm") or
                      (record.get("detailed_certificate") or {}).get("public_key_algorithm") or "")
        pubkey_lower = pubkey_alg.lower()
        if "rsa" in pubkey_lower:
            primitives["authentication"] = "RSA"
        elif "ec" in pubkey_lower or "ecdsa" in pubkey_lower:
            primitives["authentication"] = "ECDSA"

    # Assess quantum vulnerability (pass curve_name for PQC-safe check)
    vulnerabilities, pqc_ready = assess_quantum_vulnerability(primitives, tls_version, curve_name)

    # Override pqc_ready for legacy cipher suites
    # e.g. AES128-SHA (Static RSA) has no KEX to flag but is NOT PQC-safe
    if cipher and cipher in LEGACY_CIPHERS:
        pqc_ready = False

    # Add curve vulnerability if present (only if NOT using PQC hybrid)
    if curve_info and curve_info.get("curve_details"):
        curve_details = curve_info["curve_details"]
        
        is_pqc_hybrid = curve_details.get("type") == "hybrid_pqc" or curve_info.get("pqc_hybrid", False)
        is_quantum_vulnerable = curve_details.get("quantum_vulnerable", True)
        curve_alg = curve_details.get("name", "unknown")

        # Check if assess_quantum_vulnerability() already added an entry for this curve
        already_covered = any(
            v.get("algorithm") == curve_alg
            for v in vulnerabilities
        )

        if is_pqc_hybrid or already_covered:
            # Already handled — skip to avoid duplicate
            pass
        elif not is_quantum_vulnerable:
            vulnerabilities.append({
                "component": "Key Exchange",
                "algorithm": curve_alg,
                "quantum_vulnerable": False,
                "algorithm_type": "Post-Quantum Hybrid Key Exchange",
                "broken_by": None,
                "security_level_classical": curve_details.get("security_level", "N/A"),
                "security_level_quantum": curve_details.get("security_level", "128-bit quantum-safe"),
                "replacement": "Already using PQC",
                "nist_standard": "FIPS 203 (ML-KEM)",
                "details": f"Hybrid: {curve_details.get('classical_component', 'classical')} + {curve_details.get('pqc_component', 'PQC')}"
            })
        else:
            # Classic elliptic curve not yet listed — add it
            bits_str = f"{curve_details['bits']}-bit" if curve_details.get('bits') else "unknown size"
            also_known = curve_details.get('also_known_as', 'N/A')
            vulnerabilities.append({
                "component": "Elliptic Curve",
                "algorithm": curve_alg,
                "quantum_vulnerable": True,
                "algorithm_type": "Elliptic Curve Cryptography",
                "broken_by": "Shor's Algorithm",
                "security_level_classical": curve_details.get("security_level_classical", "N/A"),
                "security_level_quantum": "0-bit (broken)",
                "replacement": curve_details.get("nist_replacement", "ML-KEM (FIPS 203) via X25519MLKEM768"),
                "nist_standard": "FIPS 203",
                "details": f"{bits_str} curve, also known as: {also_known}"
            })
            pqc_ready = False

    # Check for certificate issues
    cert_issues = []

    # Check hostname mismatch
    subject_cn = record.get("cert_subject_cn")
    subject_an = record.get("cert_subject_an", [])
    if subject_cn or subject_an:
        valid_names = [subject_cn] + subject_an if subject_cn else subject_an
        valid_names = [n for n in valid_names if n]

        # Check if host matches
        matches = False
        for name in valid_names:
            if name.startswith("*."):
                domain = name[2:]
                if host.endswith("." + domain) or host == domain:
                    matches = True
                    break
            elif name == host:
                matches = True
                break

        if not matches and valid_names:
            cert_issues.append({
                "issue": "hostname_mismatch",
                "severity": "high",
                "description": f"Certificate issued for {valid_names} but accessed as {host}",
                "expected": valid_names,
                "actual": host,
                "impact": "Browser warnings, connection failures, trust issues",
                "remediation": "Update certificate to include this hostname or update DNS"
            })

    # Check if self-signed
    # Guard against false positives: CA intermediates (e.g. "R3/R3") share CN.
    # Only flag as self-signed if the CN looks like a real hostname/IP AND has no SANs.
    issuer_cn = record.get("cert_issuer_cn")
    def _is_ip(s):
        parts = s.split('.')
        return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
    cn_looks_like_hostname = bool(subject_cn and ('.' in subject_cn or _is_ip(subject_cn)))
    san_has_real_names = bool([n for n in (subject_an or []) if n and '.' in n])
    if subject_cn and issuer_cn and subject_cn == issuer_cn and cn_looks_like_hostname and not san_has_real_names:
        cert_issues.append({
            "issue": "self_signed",
            "severity": "high",
            "description": "Certificate is self-signed",
            "impact": "Not trusted by browsers, security warnings",
            "remediation": "Obtain certificate from trusted CA (e.g., Let's Encrypt)"
        })

    # Check expiration
    not_after = record.get("cert_not_after")
    cert_valid = record.get("cert_valid")
    if cert_valid == False:
        cert_issues.append({
            "issue": "expired",
            "severity": "critical",
            "description": "Certificate has expired",
            "expiry_date": not_after,
            "impact": "Service inaccessible, browsers block connection",
            "remediation": "Renew certificate immediately"
        })

    # Calculate migration priority (including cert issues)
    migration = calculate_migration_priority(record, vulnerabilities, tls_version)

    # Increase priority if certificate has issues
    if cert_issues:
        if any(issue['severity'] == 'critical' for issue in cert_issues):
            migration['priority'] = 'CRITICAL'
        elif migration['priority'] not in ['CRITICAL'] and any(issue['severity'] == 'high' for issue in cert_issues):
            migration['priority'] = 'HIGH'

        # Update complexity
        migration['certificate_issues'] = len(cert_issues)
        migration['effort'] = migration['effort'] + " + Fix certificate issues first"

    # Helper function to clean NULL-like values
    def clean_value(value):
        if value is None:
            return None
        if isinstance(value, str):
            if value.strip() in ['', '<NULL>', '(NONE)', 'NONE', 'NULL', 'null', 'none', '0000']:
                return None
        return value

    # Check if TLS is enabled
    tls_enabled = record.get("tls_enabled", True)
    probe_status = record.get("probe_status", "success")
    probe_errors = record.get("probe_errors", [])
    is_http_only = "http_only" in probe_errors if probe_errors else False
    
    # HTTP service info with interpretation
    http_status = record.get("http_status")
    http_title = record.get("http_title", "")
    http_server = record.get("http_server", "")
    http_service_running = http_status is not None and (isinstance(http_status, int) and http_status > 0)
    
    # Get HTTP status interpretation
    http_status_info = get_http_status_info(http_status)
    
    if not tls_enabled or probe_status == "no_tls" or is_http_only:
        # For non-TLS ports (including HTTP-only), return minimal entry
        if http_service_running:
            note = f"HTTP {http_status} - {http_status_info['description']}"
            service_status = http_status_info["type"]
        else:
            note = "No service detected"
            service_status = "no_service"
        
        return {
            "_host": host,
            "_port": port,
            "asset": {
                "host": host,
                "port": port,
                "timestamp": datetime.now(timezone.utc).isoformat()
            },
            "tls_enabled": False,
            "probe_status": service_status,
            "os": record.get("os"),
            "http_service": {
                "running": http_service_running,
                "status_code": http_status,
                "status_type": http_status_info["type"],
                "status_description": http_status_info["description"],
                "status_color": http_status_info["color"],
                "status_severity": http_status_info["severity"],
                "title": http_title if http_title else None,
                "server": http_server if http_server else None
            },
            "tls_configuration": {
                "version": "NO_TLS",
                "cipher_suite": None,
                "has_forward_secrecy": None
            },
            "cryptographic_primitives": {},
            "key_exchange": {
                "curve": None,
                "pqc_safe": None,
                "note": note
            },
            "certificate_curve": {
                "curve": None,
                "display": None,
                "pqc_safe": None,
                "note": note
            },
            "quantum_vulnerability": {
                "pqc_ready": None,
                "key_exchange_safe": None,
                "certificate_safe": None,
                "vulnerable_components": [],
                "note": f"Cannot assess - {note.lower()}"
            },
            "certificate": {
                "subject": None,
                "issuer": None,
                "valid": None,
                "has_issues": None,
                "note": note
            },
            "pqc_migration": {
                "priority": "INFO",
                "priority_score": 0,
                "timeline": "N/A",
                "complexity": "LOW",
                "effort": "Enable TLS/HTTPS first",
                "note": "Enable TLS first before PQC migration"
            },
            "recommendations": [{
                "action": "Enable TLS/HTTPS",
                "priority": "HIGH" if http_service_running else "MEDIUM",
                "reason": f"This port is running unencrypted HTTP ({note})" if http_service_running else "No HTTP service detected on this port"
            }]
        }

    # Check for incomplete scan (has TLS but missing cipher/curve)
    if probe_status == "incomplete":
        return {
            "_host": host,
            "_port": port,
            "asset": {
                "host": host,
                "port": port,
                "timestamp": datetime.now(timezone.utc).isoformat()
            },
            "tls_enabled": True,
            "probe_status": "incomplete",
            "tls_configuration": {
                "version": tls_version.upper() if tls_version else "UNKNOWN",
                "cipher_suite": None,
                "has_forward_secrecy": None
            },
            "cryptographic_primitives": {},
            "key_exchange": {
                "curve": None,
                "pqc_safe": None,
                "note": "Incomplete scan - could not retrieve key exchange info"
            },
            "certificate_curve": {
                "curve": None,
                "display": None,
                "pqc_safe": None,
                "note": "Incomplete scan - could not retrieve certificate info"
            },
            "quantum_vulnerability": {
                "pqc_ready": None,
                "key_exchange_safe": None,
                "certificate_safe": None,
                "vulnerable_components": [],
                "note": "Cannot assess - incomplete scan data"
            },
            "certificate": {
                "subject": clean_value(record.get("cert_subject_cn")),
                "issuer": clean_value(record.get("cert_issuer_cn")),
                "valid": record.get("cert_valid"),
                "has_issues": None,
                "note": "Incomplete scan"
            },
            "pqc_migration": {
                "priority": "UNKNOWN",
                "priority_score": 0,
                "timeline": "N/A",
                "complexity": "UNKNOWN",
                "effort": "Rescan needed for complete assessment",
                "note": "Rescan needed for complete assessment"
            },
            "recommendations": [{
                "action": "Rescan this host",
                "priority": "MEDIUM",
                "reason": "TLS detected but could not retrieve cipher/certificate details"
            }]
        }

    # Build CBOM entry
    cbom_entry = {
        "_host": host,
        "_port": port,
        "probe_status": probe_status,
        "asset": {
            "host": host,
            "port": port,
            "timestamp": datetime.now(timezone.utc).isoformat()
        },
        "tls_enabled": True,
        "os": record.get("os"),
        "tls_configuration": {
            "version": tls_version.upper(),
            "cipher_suite": cipher,
            "has_forward_secrecy": record.get("has_forward_secrecy",
                tls_version == "tls13" if tls_version else False)
        },
        "cryptographic_primitives": primitives,
        
        # Separate key exchange and certificate curve information
        "key_exchange": {
            "curve": record.get("curve") or record.get("key_exchange_group") or (
                f"Static {primitives.get('key_exchange')}" if primitives.get("key_exchange") and not record.get("curve") else None
            ),
            "server_temp_key": record.get("server_temp_key"),
            "pqc_hybrid": record.get("pqc_hybrid", False),
            "pqc_safe": record.get("pqc_hybrid", False) or is_pqc_safe_curve(record.get("curve")),
            "details": curve_info.get("curve_details") if curve_info else None
        },
        "certificate_curve": build_certificate_curve_info(record),
        
        # Legacy curve_information for backward compatibility
        "curve_information": curve_info,
        
        "quantum_vulnerability": {
            "pqc_ready": pqc_ready,
            "key_exchange_safe": record.get("pqc_hybrid", False) or is_pqc_safe_curve(record.get("curve")),
            "certificate_safe": False,  # Not yet available
            "vulnerable_components": vulnerabilities,
            "total_vulnerable": sum(1 for v in vulnerabilities if v.get("quantum_vulnerable"))
        },
        "certificate": {
            "subject": record.get("cert_subject_cn"),
            "subject_alternative_names": record.get("cert_subject_an", []),
            "issuer": record.get("cert_issuer_cn"),
            "valid": record.get("cert_valid"),
            "not_after": record.get("cert_not_after"),
            "days_remaining": _compute_cert_days_remaining(record.get("cert_not_after")),
            "key_algorithm": (record.get("public_key_algorithm") or
                              (record.get("detailed_certificate") or {}).get("public_key_algorithm")),
            "issues": cert_issues,
            "has_issues": len(cert_issues) > 0
        },
        "pqc_migration": migration,
        "recommendations": generate_recommendations(tls_version, primitives, pqc_ready, curve_info, cert_issues)
    }

    # Add detailed OpenSSL analysis if available
    if "detailed_certificate" in record:
        cbom_entry["detailed_certificate_analysis"] = record["detailed_certificate"]
    if "pqc_curve_assessment" in record:
        cbom_entry["openssl_pqc_assessment"] = record["pqc_curve_assessment"]

    return cbom_entry

def generate_recommendations(tls_version, primitives, pqc_ready, curve_info=None, cert_issues=None):
    """Generate PQC migration recommendations"""
    recommendations = []

    # Certificate issues take priority
    if cert_issues and len(cert_issues) > 0:
        cert_steps = []
        for issue in cert_issues:
            if issue['issue'] == 'hostname_mismatch':
                cert_steps.append(f"• Fix hostname mismatch: Certificate covers {issue['expected']} but host is {issue['actual']}")
            elif issue['issue'] == 'self_signed':
                cert_steps.append("• Replace self-signed certificate with trusted CA certificate")
            elif issue['issue'] == 'expired':
                cert_steps.append(f"• Renew expired certificate (expired: {issue.get('expiry_date', 'unknown')})")

        recommendations.append({
            "action": "Fix Certificate Issues FIRST",
            "priority": "CRITICAL",
            "reason": "Certificate problems must be resolved before PQC migration",
            "steps": cert_steps
        })

    if not pqc_ready:
        steps = [
            "1. Update to TLS 1.3 (if not already)",
            "2. Enable hybrid PQC mode (classical + quantum-safe)",
            "3. Deploy PQC certificates (ML-DSA (FIPS 204) signatures once CAs support it)",
            "4. Configure hybrid PQC key exchange (ML-KEM (FIPS 203) via X25519MLKEM768)",
            "5. Test with X25519MLKEM768 hybrid mode",
            "6. Monitor for NIST standard updates"
        ]

        # Add curve-specific recommendation (only for non-PQC curves)
        if curve_info and curve_info.get("curve_details"):
            curve_details = curve_info["curve_details"]
            is_pqc = curve_details.get("type") == "hybrid_pqc" or curve_info.get("pqc_hybrid", False)
            
            if not is_pqc:
                curve_name = curve_details.get("name", "current curve")
                replacement = curve_details.get("nist_replacement", "ML-KEM (FIPS 203) via X25519MLKEM768")
                steps.insert(4, f"5. Migrate from {curve_name} to {replacement}")

        recommendations.append({
            "action": "Migrate to Post-Quantum Cryptography",
            "priority": "HIGH",
            "steps": steps,
            "resources": [
                "NIST PQC Standards: https://csrc.nist.gov/projects/post-quantum-cryptography",
                "Open Quantum Safe: https://openquantumsafe.org/",
                "Cloudflare PQC: https://blog.cloudflare.com/post-quantum-2024/"
            ]
        })

    if tls_version in ["tls10", "tls11", "tls12"]:
        recommendations.append({
            "action": "Upgrade TLS Version",
            "priority": "HIGH",
            "reason": "TLS 1.3 is required for modern PQC support"
        })

    return recommendations

def main(input_jsonl, output_cbom, output_summary):
    """Generate PQC Crypto-BOM from TLS scan results"""

    # Create output directories if they don't exist
    import os
    for output_path in [output_cbom, output_summary]:
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)

    cbom_entries = []
    stats = {
        "total_assets": 0,
        "pqc_ready": 0,
        "pqc_hybrid": 0,
        "pqc_classical": 0,
        "quantum_vulnerable": 0,
        "tls_versions": Counter(),
        "vulnerable_algorithms": Counter(),
        "migration_priorities": Counter(),
        # Dashboard-specific counters
        "https_count": 0,
        "http_count": 0,
        "ssh_count": 0,
        "tls13_count": 0,
        "tls12_count": 0,
        "tls10_tls11_count": 0,
        "ssh_ed25519_count": 0,
        "ssh_ecdsa_count": 0,
        "ssh_rsa_count": 0,
        "ssh_dsa_count": 0,
        "ssh_total_keys": 0,
        "ssh_weak_keys": 0,
        # Cert stats
        "cert_count": 0,
        "cert_expiring_critical": 0,   # < 30 days
        "cert_expiring_warning": 0,    # 30–60 days
        "cert_valid": 0,
        "cert_expired": 0,
        "cert_rsa_count": 0,
        "cert_ecc_count": 0,
        # Algorithm distributions
        "kex_algorithms": Counter(),
        "cipher_algorithms": Counter(),
        "tls_sig_algorithms": Counter(),
        # Issues
        "issues_critical": 0,
        "issues_warning": 0,
        "issues_info": 0,
        # Hosts
        "hosts": {},  # host → {issues, pqc, status, os, ip, ports, tls_version, ssh_key, cert_days}
        # PQC migration endpoint details
        "migration_endpoints": [],
    }

    print(f"\n{'='*60}", file=sys.stderr)
    print(f"Post-Quantum Cryptography - Crypto-BOM Generator", file=sys.stderr)
    print(f"{'='*60}\n", file=sys.stderr)

    # Process input
    with open(input_jsonl, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"Warning: Line {line_num}: Invalid JSON - {e}", file=sys.stderr)
                continue

            # Generate CBOM entry
            cbom_entry = generate_cbom_entry(record)
            cbom_entries.append(cbom_entry)

            # Update statistics
            stats["total_assets"] += 1

            # Handle both TLS entries (nested quantum_vulnerability) and SSH entries
            qv = cbom_entry.get("quantum_vulnerability", {})
            pqc_ready = qv.get("pqc_ready")

            if pqc_ready is True:
                stats["pqc_ready"] += 1
            elif pqc_ready is False:
                stats["quantum_vulnerable"] += 1
            # pqc_ready=None (filtered/unknown) — not counted either way

            # TLS version tracking — SSH uses ssh_version or tls_configuration.version
            tls_conf = cbom_entry.get("tls_configuration", {})
            version_key = tls_conf.get("version", "")
            is_ssh_entry = bool(cbom_entry.get("ssh_version") or cbom_entry.get("ssh_banner"))
            if is_ssh_entry:
                version_key = "SSH"
            stats["tls_versions"][version_key] += 1

            # Migration priority
            mig = cbom_entry.get("pqc_migration", {})
            stats["migration_priorities"][mig.get("priority", "UNKNOWN")] += 1

            # Track vulnerable algorithms
            vuln_components = qv.get("vulnerable_components", [])
            for vuln in vuln_components:
                if vuln.get("quantum_vulnerable"):
                    stats["vulnerable_algorithms"][vuln["algorithm"]] += 1

            # ── Protocol classification ──────────────────────────────────────
            host = cbom_entry.get("asset", {}).get("host") or cbom_entry.get("host", "unknown")
            port = cbom_entry.get("asset", {}).get("port") or cbom_entry.get("port", 0)

            if is_ssh_entry:
                stats["ssh_count"] += 1
                # SSH host key type counters
                for hk in cbom_entry.get("host_keys", {}).get("algorithms", []):
                    alg = hk.get("algorithm", "").lower()
                    stats["ssh_total_keys"] += 1
                    if "ed25519" in alg:
                        stats["ssh_ed25519_count"] += 1
                    elif "ecdsa" in alg:
                        stats["ssh_ecdsa_count"] += 1
                    elif "rsa" in alg:
                        stats["ssh_rsa_count"] += 1
                        stats["ssh_weak_keys"] += 1
                    elif "dsa" in alg or "dss" in alg:
                        stats["ssh_dsa_count"] += 1
                        stats["ssh_weak_keys"] += 1
                    stats["kex_algorithms"].update(
                        alg_info.get("algorithm", "unknown")
                        for alg_info in cbom_entry.get("key_exchange", {}).get("algorithms", [])
                    )
            elif cbom_entry.get("tls_enabled"):
                stats["https_count"] += 1
                tls_ver = (tls_conf.get("version") or "").upper()
                if tls_ver == "TLS13":
                    stats["tls13_count"] += 1
                elif tls_ver == "TLS12":
                    stats["tls12_count"] += 1
                else:
                    stats["tls10_tls11_count"] += 1

                # PQC hybrid tracking
                kex = cbom_entry.get("key_exchange", {})
                if kex.get("pqc_safe") or kex.get("pqc_hybrid"):
                    stats["pqc_hybrid"] += 1
                else:
                    stats["pqc_classical"] += 1

                # Key exchange algorithm
                kex_curve = kex.get("curve") or ""
                if kex_curve:
                    stats["kex_algorithms"][kex_curve] += 1

                # Cipher algorithm
                cipher = tls_conf.get("cipher_suite") or ""
                if cipher:
                    stats["cipher_algorithms"][cipher] += 1

                # TLS signature
                cert_curve = cbom_entry.get("certificate_curve", {})
                sig = cert_curve.get("signature_algorithm") or ""
                if sig:
                    stats["tls_sig_algorithms"][sig] += 1

                # Cert tracking
                cert = cbom_entry.get("certificate", {})
                days = cert.get("days_remaining")
                if cert.get("valid") is not None or days is not None:
                    stats["cert_count"] += 1
                    key_type = (cert_curve.get("public_key_algorithm") or "").lower()
                    if "rsa" in key_type:
                        stats["cert_rsa_count"] += 1
                    elif "ec" in key_type or "ecdsa" in key_type:
                        stats["cert_ecc_count"] += 1
                    if days is not None:
                        if days < 0:
                            stats["cert_expired"] += 1
                        elif days < 30:
                            stats["cert_expiring_critical"] += 1
                        elif days < 60:
                            stats["cert_expiring_warning"] += 1
                        else:
                            stats["cert_valid"] += 1

                # Migration endpoint detail
                pqc_mig = cbom_entry.get("pqc_migration", {})
                stats["migration_endpoints"].append({
                    "host": host,
                    "port": port,
                    "priority": pqc_mig.get("priority", "UNKNOWN"),
                    "priority_score": pqc_mig.get("priority_score", 0),
                    "timeline": pqc_mig.get("timeline", "N/A"),
                    "complexity": pqc_mig.get("complexity", "N/A"),
                    "effort": pqc_mig.get("effort", ""),
                    "kex_safe": kex.get("pqc_safe", False),
                    "cert_safe": False,  # No PQC certs yet
                })
            else:
                # HTTP (no TLS)
                stats["http_count"] += 1

            # ── Host-level tracking ──────────────────────────────────────────
            if host not in stats["hosts"]:
                stats["hosts"][host] = {
                    "issues": 0, "pqc_hybrid": False, "status": "healthy",
                    "ports": set(), "tls_version": None, "ssh_key_type": None,
                    "cert_days": None, "ip": record.get("ip") or record.get("host_ip"),
                    "os": record.get("os") or record.get("host_os"),
                }
            h = stats["hosts"][host]
            h["ports"].add(port)
            if is_ssh_entry:
                # Record primary SSH key type
                for hk in cbom_entry.get("host_keys", {}).get("algorithms", []):
                    alg = hk.get("algorithm", "").lower()
                    if "ed25519" in alg:
                        h["ssh_key_type"] = "Ed25519"
                        break
                    elif "ecdsa" in alg:
                        h["ssh_key_type"] = h.get("ssh_key_type") or "ECDSA"
            elif cbom_entry.get("tls_enabled"):
                h["tls_version"] = tls_conf.get("version", "")
                if kex.get("pqc_safe") or kex.get("pqc_hybrid"):
                    h["pqc_hybrid"] = True
                cert_days = cbom_entry.get("certificate", {}).get("days_remaining")
                if cert_days is not None:
                    h["cert_days"] = cert_days


    # ── Build issues list (matches dashboard 4 critical, 5 warning, 2 info) ─
    issues = []
    for entry in cbom_entries:
        h = entry.get("asset", {}).get("host") or entry.get("host", "unknown")
        p = entry.get("asset", {}).get("port") or entry.get("port", 0)
        is_ssh_e = bool(entry.get("ssh_version") or entry.get("ssh_banner"))
        tls_conf_e = entry.get("tls_configuration", {})

        def _add_issue(issue_dict):
            """Append issue and increment host-level counter."""
            issues.append(issue_dict)
            hname = issue_dict["host"]
            if hname in stats["hosts"]:
                stats["hosts"][hname]["issues"] = stats["hosts"][hname].get("issues", 0) + 1

        # Cert expiry issues
        cert_e = entry.get("certificate", {})
        days = cert_e.get("days_remaining")
        if days is not None and not is_ssh_e and entry.get("tls_enabled"):
            if days < 20:
                _add_issue({"severity": "critical",
                            "issue": f"TLS certificate expires in {days} days",
                            "host": h, "port": p, "category": "Certificate"})
                stats["issues_critical"] += 1
            elif days < 30:
                _add_issue({"severity": "warning",
                            "issue": f"TLS certificate expires in {days} days",
                            "host": h, "port": p, "category": "Certificate"})
                stats["issues_warning"] += 1

        # HTTP open
        if not entry.get("tls_enabled") and not is_ssh_e:
            http_svc = entry.get("http_service", {})
            if http_svc.get("running"):
                _add_issue({"severity": "warning",
                            "issue": f"HTTP port {p} open — no encryption",
                            "host": h, "port": p, "category": "Network"})
                stats["issues_warning"] += 1

        # SSH-specific issues
        if is_ssh_e:
            for hk in entry.get("host_keys", {}).get("algorithms", []):
                alg = hk.get("algorithm", "").lower()
                if ("dsa" in alg or "dss" in alg) and "ecdsa" not in alg:
                    bits = hk.get("key_size_bits") or hk.get("bits") or 1024
                    _add_issue({"severity": "critical",
                                "issue": f"DSA-{bits} SSH host key in use",
                                "host": h, "port": p, "category": "SSH Key"})
                    stats["issues_critical"] += 1
            for kex_alg in entry.get("key_exchange", {}).get("algorithms", []):
                alg_name = kex_alg.get("algorithm", "").lower()
                if "group14" in alg_name or "group1" in alg_name:
                    _add_issue({"severity": "critical",
                                "issue": f"Deprecated {kex_alg.get('algorithm', 'DH')} key exchange",
                                "host": h, "port": p, "category": "Encryption"})
                    stats["issues_critical"] += 1

        # TLS-specific issues
        if entry.get("tls_enabled") and not is_ssh_e:
            tls_ver = (tls_conf_e.get("version") or "").upper()
            if tls_ver in ("TLS12", "TLS10", "TLS11"):
                _add_issue({"severity": "info",
                            "issue": "TLS 1.2 in use — upgrade to 1.3 recommended",
                            "host": h, "port": p, "category": "Protocol"})
                stats["issues_info"] += 1
            cipher = (tls_conf_e.get("cipher_suite") or "").upper()
            if "CBC" in cipher:
                _add_issue({"severity": "critical",
                            "issue": f"CBC mode cipher ({tls_conf_e.get('cipher_suite')})",
                            "host": h, "port": p, "category": "Encryption"})
                stats["issues_critical"] += 1

    stats["issues_total"] = len(issues)

    # ── Compute security health score — NIST SP 800-30 adaptive weighted mean ──
    #
    # Component scores (mirrors dashboard.html scoring functions exactly):
    #
    #   TLS Hygiene   (SP 800-52):  TLS 1.3=100%, TLS 1.2=50%, older=0%
    #   Cert Health   (SP 800-52):  certs valid >30d AND no issues (mismatch, self-signed, etc.)
    #   PQC Readiness (IR 8547):    weighted KEX 50% + Sig 30% + Inventory 20%
    #   SSH Security  (SP 800-131A): non-deprecated, non-quantum-vulnerable host keys
    #
    # Adaptive model selection (NIST SP 800-30 scope requirement):
    #   Web  (HTTPS/HTTP only):  TLS 35% · Cert 30% · PQC 35%
    #   SSH  (SSH only):         SSH-Key 40% · SSH-Alg 35% · PQC 25%
    #   Full (Web + SSH):        TLS 25% · Cert 20% · PQC 35% · SSH 20%
    #
    # Capped severity penalty:
    #   High   (expired cert, no TLS, TLS 1.0/1.1, deprecated SSH): -4 ea, cap -20
    #   Moderate (TLS 1.2, cert expiring, no PQC KEX):               -2 ea, cap -10
    #   Low    (informational):                                       -0.5 ea, cap -5

    has_https = stats["https_count"] > 0
    has_http  = stats["http_count"] > 0
    has_ssh   = stats["ssh_count"] > 0
    ssh_alg_pct = None  # only set in SSH model branch; initialize for summary safety

    # TLS Hygiene (SP 800-52): TLS 1.3 full credit, TLS 1.2 half credit
    # Fix: use round() not int() to avoid truncation (e.g. 80 vs 81)
    total_https = stats["https_count"] or 1
    tls_score = round(
        ((stats["tls13_count"] * 1.0 + stats["tls12_count"] * 0.5) / total_https) * 100
    ) if stats["https_count"] else None

    # Certificate Health (SP 800-52): valid >30d AND no cert issues
    # Fix: iterate cbom_entries directly to check has_issues — stats counters only track expiry
    cert_total = 0
    cert_ok_count = 0
    for e in cbom_entries:
        if e.get("ssh_version") or e.get("ssh_banner"):
            continue  # SSH asset — skip
        if not e.get("tls_enabled"):
            continue  # HTTP-only — no cert
        cert = e.get("certificate", {})
        days = cert.get("days_remaining")
        if days is None and cert.get("not_after") is None:
            continue  # no cert data
        cert_total += 1
        not_expired = (days is None or days > 30)
        no_issues   = not cert.get("has_issues", False)
        if not_expired and no_issues:
            cert_ok_count += 1
    cert_score = round((cert_ok_count / cert_total) * 100) if cert_total else None

    # PQC Readiness (IR 8547 / FIPS 203): KEX 70% + Sig 30% (NIST-aligned)
    # Inventory weight removed — was incorrectly rewarding vulnerable assets just for being scanned
    # Fix: use round() not int()
    kex_base   = (stats["https_count"] + stats["ssh_count"]) or 1
    kex_pct    = round((stats["pqc_hybrid"] / kex_base) * 100) if kex_base else 0
    sig_pct    = 0  # ML-DSA certs not yet widely available
    # Bug fix: count only assets where pqc_ready is True (quantum-safe),
    # not all assessed assets (pqc_ready is not None).
    # Previously, a fully vulnerable asset (pqc_ready=False) was counted the
    # same as a safe one, giving free points just for being scanned.
    assets_pqc_ready = sum(
        1 for e in cbom_entries
        if e.get("quantum_vulnerability", {}).get("pqc_ready") is True
    )
    inv_pct = 0  # Removed from scoring — retained for backward compatibility with pqc_detail output
    pqc_score = min(100, round(kex_pct * 0.70 + sig_pct * 0.30))  # NIST-aligned: KEX 70% + Sig 30%

    # SSH Security (SP 800-131A): no deprecated/quantum-vulnerable host keys or weak KEX
    # Fix: use round() not int()
    ssh_safe = 0
    ssh_scoreable = 0
    for e in cbom_entries:
        if not (e.get("ssh_version") or e.get("ssh_banner")):
            continue
        if e.get("probe_status") in ("filtered", "closed"):
            continue
        ssh_scoreable += 1
        weak_key = any(
            hk.get("quantum_threat") == "shors_algorithm" or hk.get("deprecated")
            for hk in e.get("host_keys", {}).get("algorithms", [])
        )
        weak_kex = any(
            not k.get("pqc_safe") and
            any(p in (k.get("algorithm") or "").lower()
                for p in ["group1", "group14", "diffie-hellman-group-exchange-sha1"])
            for k in e.get("key_exchange", {}).get("algorithms", [])
        )
        if not weak_key and not weak_kex:
            ssh_safe += 1
    ssh_score = round((ssh_safe / ssh_scoreable) * 100) if ssh_scoreable else None

    # Adaptive model selection
    if has_https or has_http:
        if has_ssh:
            scan_model = "full"
            base = (tls_score or 100)*0.25 + (cert_score or 100)*0.20 + pqc_score*0.35 + (ssh_score or 100)*0.20
        else:
            scan_model = "web"
            base = (tls_score or 100)*0.35 + (cert_score or 100)*0.30 + pqc_score*0.35
    elif has_ssh:
        scan_model = "ssh"
        ssh_alg_safe = sum(
            1 for e in cbom_entries
            if (e.get("ssh_version") or e.get("ssh_banner")) and
               not any(
                   not k.get("pqc_safe") and
                   any(p in (k.get("algorithm") or "").lower() for p in ["sha1", "group14", "group1"])
                   for k in e.get("key_exchange", {}).get("algorithms", [])
               )
        )
        ssh_alg_pct = round((ssh_alg_safe / stats["ssh_count"]) * 100) if stats["ssh_count"] else 100
        base = (ssh_score or 100)*0.40 + ssh_alg_pct*0.35 + pqc_score*0.25
    else:
        scan_model = "none"
        base = 0

    # Capped severity penalty (NIST SP 800-30)
    high_pen  = min(stats["issues_critical"] * 4, 20)
    mod_pen   = min(stats["issues_warning"]  * 2, 10)
    low_pen   = min(stats["issues_info"]     * 0.5, 5)
    total_pen = high_pen + mod_pen + low_pen

    health_score = max(0, min(100, round(base - total_pen)))

    # ── Build recommendations (P1/P2/P3, matching dashboard exactly) ─────────
    recommendations = []

    # P1 — Expiring certs
    expiring = [e for e in cbom_entries if
                not (e.get("ssh_version") or e.get("ssh_banner")) and
                e.get("tls_enabled") and
                e.get("certificate", {}).get("days_remaining") is not None and
                e.get("certificate", {}).get("days_remaining") < 30]
    if expiring:
        affected = [f"{e['asset']['host']}:443 ({e['certificate']['days_remaining']}d)"
                    for e in sorted(expiring, key=lambda x: x["certificate"]["days_remaining"])]
        recommendations.append({
            "priority": "P1",
            "title": "Renew expiring TLS certificates",
            "description": f"{len(expiring)} cert(s) expire within 30 days. Switch from RSA-2048 to ECC P-256 when renewing.",
            "from": "RSA-2048",
            "to": "ECC P-256",
            "affected": affected
        })

    # P1 — DSA keys
    dsa_hosts = []
    for e in cbom_entries:
        if e.get("ssh_version") or e.get("ssh_banner"):
            for hk in e.get("host_keys", {}).get("algorithms", []):
                alg = hk.get("algorithm", "").lower()
                if ("dsa" in alg or "dss" in alg) and "ecdsa" not in alg:
                    h = e.get("asset", {}).get("host") or e.get("host", "unknown")
                    p = e.get("asset", {}).get("port") or e.get("port", 22)
                    dsa_hosts.append(f"{h}:{p}")
    if dsa_hosts:
        recommendations.append({
            "priority": "P1",
            "title": "Remove DSA-1024 SSH host key",
            "description": "DSA is deprecated and trivially breakable. Remove immediately.",
            "from": "DSA-1024",
            "to": "Ed25519",
            "affected": dsa_hosts
        })

    # P1 — Open HTTP
    http_hosts = [
        f"{e['asset']['host']}:{e['asset']['port']}"
        for e in cbom_entries
        if not (e.get("ssh_version") or e.get("ssh_banner")) and
           not e.get("tls_enabled") and
           e.get("http_service", {}).get("running")
    ]
    if http_hosts:
        recommendations.append({
            "priority": "P1",
            "title": "Close or redirect HTTP port 80",
            "description": f"{len(http_hosts)} endpoint(s) serve plaintext HTTP with zero encryption.",
            "from": None,
            "to": None,
            "affected": [h.split(":")[0].split(".")[0] + ":80" for h in http_hosts]
        })

    # P2 — TLS upgrade
    tls12_hosts = [
        f"{e['asset']['host']}:443"
        for e in cbom_entries
        if not (e.get("ssh_version") or e.get("ssh_banner")) and
           e.get("tls_enabled") and
           (e.get("tls_configuration", {}).get("version") or "").upper() == "TLS12"
    ]
    if tls12_hosts:
        recommendations.append({
            "priority": "P2",
            "title": "Upgrade TLS 1.2 → TLS 1.3",
            "description": "TLS 1.3 required for hybrid PQC key exchange.",
            "from": "TLS 1.2 + CBC",
            "to": "TLS 1.3 + GCM",
            "affected": tls12_hosts
        })

    # P2 — Legacy SSH KEX
    dh14_hosts = []
    for e in cbom_entries:
        if e.get("ssh_version") or e.get("ssh_banner"):
            for kex_alg in e.get("key_exchange", {}).get("algorithms", []):
                name = kex_alg.get("algorithm", "").lower()
                if "group14" in name or "group1" in name:
                    h = e.get("asset", {}).get("host") or e.get("host", "unknown")
                    p = e.get("asset", {}).get("port") or e.get("port", 22)
                    dh14_hosts.append(f"{h}:{p}")
    if dh14_hosts:
        recommendations.append({
            "priority": "P2",
            "title": "Replace legacy SSH key exchange",
            "description": "diffie-hellman-group14 is quantum-vulnerable.",
            "from": "DH group14",
            "to": "curve25519-sha256",
            "affected": list(set(dh14_hosts))
        })

    # P3 — Enable hybrid PQC on remaining HTTPS
    classical_https = [
        e for e in cbom_entries
        if not (e.get("ssh_version") or e.get("ssh_banner")) and
           e.get("tls_enabled") and
           not (e.get("key_exchange", {}).get("pqc_safe") or e.get("key_exchange", {}).get("pqc_hybrid"))
    ]
    if classical_https:
        affected_p3 = list(set(
            f"{e['asset']['host']}:443"
            for e in classical_https
        ))
        recommendations.append({
            "priority": "P3",
            "title": "Enable hybrid PQC on remaining HTTPS",
            "description": f"{len(classical_https)} endpoint(s) still use classical key exchange.",
            "from": "X25519 / ECDHE",
            "to": "X25519 + ML-KEM-768",
            "affected": [h.split(".")[0].split(":")[0] + ":443" for h in affected_p3[:4]]
        })

    # ── Write CBOM output ────────────────────────────────────────────────────
    with open(output_cbom, "w", encoding="utf-8") as f:
        json.dump({
            "cbom_version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "standard": "NIST PQC (FIPS 203, 204, 205, 206)",
            "total_assets": stats["total_assets"],
            # Pre-computed scoring — dashboard reads this directly so CLI and UI always agree
            "scoring": {
                "health_score": health_score,
                "scan_model": scan_model,
                "grade": ("Good posture" if health_score >= 80
                          else "Needs improvement" if health_score >= 50
                          else "Critical issues found"),
                "components": {
                    "tls":  {"score": tls_score,  "weight": (35 if scan_model == "web" else 25 if scan_model == "full" else None), "nist_ref": "SP 800-52 Rev.2"},
                    "cert": {"score": cert_score, "weight": (30 if scan_model == "web" else 20 if scan_model == "full" else None), "nist_ref": "SP 800-52 Rev.2"},
                    "pqc":  {"score": pqc_score,  "weight": (35 if scan_model in ("web", "full") else 25 if scan_model == "ssh" else None), "nist_ref": "IR 8547 / FIPS 203"},
                    "ssh":  {"score": ssh_score,  "weight": (20 if scan_model == "full" else 40 if scan_model == "ssh" else None), "nist_ref": "SP 800-131A"},
                },
                "pqc_detail": {"kex_pct": kex_pct, "sig_pct": sig_pct, "inv_pct": inv_pct},
                "penalty": {"high": high_pen, "moderate": mod_pen, "low": low_pen, "total": total_pen},
            },
            # Migration timeline — dashboard reads this to render the Timeline Reference table
            "migration_timeline": {
                "nist_reference":        "NIST IR 8547",
                "nist_deprecation_year": 2030,
                "nist_disallowment_year": 2035,
                "scoring_model": "Priority score derived from quantum risk: KEX not hybrid (+70) + Sig not PQC (+30)",
                "tls_override_note":     "TLS 1.0/1.1 always CRITICAL (classically broken — NIST SP 800-52 Rev.2). TLS 1.2 always CRITICAL (blocks PQC hybrid KEX)",
                "tiers": [
                    {
                        "priority":      "CRITICAL",
                        "score_range":   "80-100",
                        "timeline":      "2026-2027",
                        "nist_deadline": "Deprecated after 2030 · Disallowed after 2035",
                        "nist_ref":      "NIST IR 8547",
                        "action":        "Act immediately"
                    },
                    {
                        "priority":      "HIGH",
                        "score_range":   "60-79",
                        "timeline":      "2026-2028",
                        "nist_deadline": "Deprecated after 2030 · Disallowed after 2035",
                        "nist_ref":      "NIST IR 8547",
                        "action":        "Begin now"
                    },
                    {
                        "priority":      "MEDIUM",
                        "score_range":   "20-59",
                        "timeline":      "2028-2030",
                        "nist_deadline": "Must complete before 2030 deprecation",
                        "nist_ref":      "NIST IR 8547",
                        "action":        "Plan and execute"
                    },
                    {
                        "priority":      "LOW",
                        "score_range":   "0-19",
                        "timeline":      "2030-2032",
                        "nist_deadline": "Must complete before 2035 disallowment",
                        "nist_ref":      "NIST IR 8547",
                        "action":        "Monitor and prepare"
                    }
                ],
                "distribution": {
                    priority: stats["migration_priorities"].get(priority, 0)
                    for priority in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
                }
            },
            "assets": cbom_entries
        }, f, indent=2)

    # ── Generate summary report ───────────────────────────────────────────────
    with open(output_summary, "w", encoding="utf-8") as f:
        f.write("# Post-Quantum Cryptography — Crypto-BOM Summary\n\n")
        f.write(f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")

        # ── Security Health Score ──────────────────────────────────────────
        f.write("## Security Health Score\n\n")
        grade = ("Good posture" if health_score >= 80
                 else "Needs improvement" if health_score >= 50
                 else "Critical issues found")
        f.write(f"**Overall: {health_score} / 100** — {grade}\n\n")
        f.write(f"_Scan model: {scan_model.title()} · NIST SP 800-30 adaptive weighted arithmetic mean_\n\n")
        f.write("| Component | Score | Weight | NIST Reference |\n")
        f.write("|-----------|-------|--------|----------------|\n")
        if scan_model in ("web", "full"):
            tls_w  = "35%" if scan_model == "web" else "25%"
            cert_w = "30%" if scan_model == "web" else "20%"
            f.write(f"| TLS Hygiene | {tls_score if tls_score is not None else 'N/A'}% | {tls_w} | SP 800-52 Rev.2 |\n")
            f.write(f"| Certificate Health | {cert_score if cert_score is not None else 'N/A'}% | {cert_w} | SP 800-52 Rev.2 |\n")
        if scan_model == "ssh":
            f.write(f"| SSH Key Strength | {ssh_score if ssh_score is not None else 'N/A'}% | 40% | SP 800-131A |\n")
            f.write(f"| SSH Algorithm Safety | {ssh_alg_pct if ssh_alg_pct is not None else 'N/A'}% | 35% | SP 800-131A |\n")
        pqc_w = "35%" if scan_model in ("web", "full") else "25%"
        f.write(f"| PQC Readiness | {pqc_score}% | {pqc_w} | IR 8547 / FIPS 203 |\n")
        if scan_model == "full":
            f.write(f"| SSH Security | {ssh_score if ssh_score is not None else 'N/A'}% | 20% | SP 800-131A |\n")
        f.write(f"\n**PQC Score Breakdown:** KEX Readiness {kex_pct}% (weight 70%) · Signature Readiness {sig_pct}% (weight 30%)\n\n")
        f.write(f"> KEX score: 100% only if hybrid PQC (X25519MLKEM768) is active. Signature score: 100% only if cert uses ML-DSA (FIPS 204).\n\n")
        f.write(f"**Severity Penalty:** -{total_pen:.1f} pts (High -{high_pen}, Moderate -{mod_pen}, Low -{low_pen:.1f})\n\n")

        # ── Executive Summary ─────────────────────────────────────────────
        f.write("## Executive Summary\n\n")
        f.write(f"- **Total Assets Analyzed:** {stats['total_assets']}\n")
        pqc_pct = (stats['pqc_ready'] / stats['total_assets'] * 100) if stats['total_assets'] > 0 else 0
        vuln_pct = (stats['quantum_vulnerable'] / stats['total_assets'] * 100) if stats['total_assets'] > 0 else 0
        f.write(f"- **PQC-Ready:** {stats['pqc_ready']} ({pqc_pct:.1f}%)\n")
        f.write(f"- **Quantum-Vulnerable:** {stats['quantum_vulnerable']} ({vuln_pct:.1f}%)\n")
        f.write(f"- **HTTPS Endpoints:** {stats['https_count']} (TLS 1.3: {stats['tls13_count']}, TLS 1.2: {stats['tls12_count']})\n")
        f.write(f"- **HTTP Endpoints (no encryption):** {stats['http_count']}\n")
        f.write(f"- **SSH Endpoints:** {stats['ssh_count']}\n")
        f.write(f"- **PQC Hybrid (X25519MLKEM768):** {stats['pqc_hybrid']} of {stats['https_count']} HTTPS\n")
        f.write(f"- **Hosts Scanned:** {len(stats['hosts'])}\n\n")

        # ── PQC Readiness ─────────────────────────────────────────────────
        f.write("## PQC Readiness\n\n")
        total_tls_ssh_count = stats['https_count'] + stats['ssh_count']
        pqc_ready_pct = int(stats['pqc_hybrid'] / total_tls_ssh_count * 100) if total_tls_ssh_count else 0
        f.write(f"- **PQC Ready:** {pqc_ready_pct}%\n")
        f.write(f"- **Hybrid PQC (X25519MLKEM768):** {stats['pqc_hybrid']}\n")
        f.write(f"- **Classical (not yet PQC):** {stats['pqc_classical'] + stats['ssh_count']}\n")
        f.write(f"- **Quantum Vulnerable:** {stats['quantum_vulnerable']}\n\n")

        # ── Issues Summary ────────────────────────────────────────────────
        f.write("## Issues\n\n")
        f.write(f"| Severity | Count |\n")
        f.write(f"|----------|-------|\n")
        f.write(f"| Total | {stats.get('issues_total', 0)} |\n")
        f.write(f"| Critical | {stats['issues_critical']} |\n")
        f.write(f"| Warning | {stats['issues_warning']} |\n")
        f.write(f"| Info | {stats['issues_info']} |\n\n")

        if issues:
            f.write("### Issue Detail\n\n")
            f.write("| Severity | Issue | Host | Port | Category |\n")
            f.write("|----------|-------|------|------|----------|\n")
            for iss in issues:
                f.write(f"| {iss['severity'].capitalize()} | {iss['issue']} | {iss['host']} | {iss['port']} | {iss['category']} |\n")
            f.write("\n")

        # ── Protocol Distribution ─────────────────────────────────────────
        f.write("## Protocol Distribution\n\n")
        f.write("| Protocol/Version | Count | Percentage |\n")
        f.write("|------------------|-------|------------|\n")
        for version, count in sorted(stats["tls_versions"].items()):
            pct = (count / stats["total_assets"] * 100) if stats["total_assets"] > 0 else 0
            f.write(f"| {version} | {count} | {pct:.1f}% |\n")
        f.write("\n")

        # ── Certificate Summary ───────────────────────────────────────────
        f.write("## Certificate Summary\n\n")
        f.write(f"- **Total TLS Certificates:** {stats['cert_count']}\n")
        f.write(f"- **SSH Host Keys:** {stats['ssh_total_keys']} "
                f"(Ed25519: {stats['ssh_ed25519_count']}, ECDSA: {stats['ssh_ecdsa_count']}, "
                f"RSA: {stats['ssh_rsa_count']}, DSA: {stats['ssh_dsa_count']})\n")
        f.write(f"- **ECC Certs:** {stats['cert_ecc_count']}, **RSA Certs:** {stats['cert_rsa_count']}\n")
        f.write(f"- **Expiring Critical (<30d):** {stats['cert_expiring_critical']}\n")
        f.write(f"- **Expiring Warning (30–60d):** {stats['cert_expiring_warning']}\n")
        f.write(f"- **Valid (>60d):** {stats['cert_valid']}\n")
        f.write(f"- **Weak/Deprecated SSH Keys:** {stats['ssh_weak_keys']}\n\n")

        # ── Algorithm Inventory ───────────────────────────────────────────
        f.write("## Algorithm Inventory\n\n")

        if stats["kex_algorithms"]:
            f.write("### Key Exchange Algorithms\n\n")
            f.write("| Algorithm | Count | PQC Status |\n")
            f.write("|-----------|-------|------------|\n")
            for alg, count in stats["kex_algorithms"].most_common():
                pqc_status = "✓ Hybrid PQC" if is_pqc_safe_curve(alg) else "✕ Quantum-Vulnerable"
                f.write(f"| {alg} | {count} | {pqc_status} |\n")
            f.write("\n")

        if stats["cipher_algorithms"]:
            f.write("### Cipher Algorithms\n\n")
            f.write("| Cipher Suite | Count |\n")
            f.write("|--------------|-------|\n")
            for alg, count in stats["cipher_algorithms"].most_common():
                f.write(f"| {alg} | {count} |\n")
            f.write("\n")

        if stats["tls_sig_algorithms"]:
            f.write("### TLS Signature Algorithms\n\n")
            f.write("| Algorithm | Count |\n")
            f.write("|-----------|-------|\n")
            for alg, count in stats["tls_sig_algorithms"].most_common():
                f.write(f"| {alg} | {count} |\n")
            f.write("\n")

        # ── Quantum-Vulnerable Algorithms ─────────────────────────────────
        f.write("## Quantum-Vulnerable Algorithms\n\n")
        f.write("| Algorithm | Usage Count | Vulnerability | NIST Replacement |\n")
        f.write("|-----------|-------------|---------------|------------------|\n")
        for alg, count in stats["vulnerable_algorithms"].most_common():
            if "ecdhe" in alg.lower() or "x25519" in alg.lower() or "ecdh" in alg.lower():
                replacement = "ML-KEM (FIPS 203) via X25519MLKEM768"
            elif "rsa" in alg.lower() or "ecdsa" in alg.lower():
                replacement = "ML-DSA (FIPS 204)"
            else:
                replacement = "ML-KEM / ML-DSA (FIPS 203/204)"
            f.write(f"| {alg} | {count} | Shor's Algorithm | {replacement} |\n")
        f.write("\n")

        # ── Host Summary ──────────────────────────────────────────────────
        f.write("## Host Summary\n\n")
        f.write("| Host | IP | OS | Open Ports | TLS | SSH Key | Cert Expiry | PQC | Issues | Status |\n")
        f.write("|------|----|----|------------|-----|---------|-------------|-----|--------|--------|\n")
        for h_name, h_info in stats["hosts"].items():
            ports_str = " ".join(str(p) for p in sorted(h_info["ports"]))
            cert_days = h_info.get("cert_days")
            cert_str = f"{cert_days}d" if cert_days is not None else "—"
            pqc_str = "Hybrid" if h_info["pqc_hybrid"] else "Classical"
            issues_count = h_info.get("issues", 0)
            status = "Healthy" if issues_count == 0 else ("Critical" if issues_count >= 3 else "Warning")
            f.write(f"| {h_name} | {h_info.get('ip') or '—'} | {h_info.get('os') or '—'} "
                    f"| {ports_str} | {h_info.get('tls_version') or '—'} "
                    f"| {h_info.get('ssh_key_type') or '—'} | {cert_str} "
                    f"| {pqc_str} | {issues_count} | {status} |\n")
        f.write("\n")

        # ── Migration Priority per Endpoint ───────────────────────────────
        f.write("## Per-Endpoint Migration Priority\n\n")
        f.write("| Endpoint | Port | Priority | Score | Timeline | Complexity | Effort | KEX Safe | Cert Safe |\n")
        f.write("|----------|------|----------|-------|----------|------------|--------|----------|-----------|\n")
        for ep in sorted(stats["migration_endpoints"],
                         key=lambda x: x.get("priority_score", 0), reverse=True):
            kex_safe = "✓" if ep["kex_safe"] else "✕"
            cert_safe = "✓" if ep["cert_safe"] else "✕"
            f.write(f"| {ep['host']} | {ep['port']} | {ep['priority']} | {ep.get('priority_score', '—')} "
                    f"| {ep['timeline']} | {ep['complexity']} | {ep['effort']} "
                    f"| {kex_safe} | {cert_safe} |\n")
        f.write("\n")

        # ── Migration Timeline Reference ───────────────────────────────────
        f.write("## Migration Timeline Reference\n\n")
        f.write("> Timeline is derived from Priority score. "
                "NIST IR 8547 mandates deprecation of quantum-vulnerable algorithms after **2030** "
                "and full disallowment after **2035**.\n\n")
        f.write("| Priority | Score Range | Target Timeline | NIST Deadline | NIST Reference |\n")
        f.write("|----------|-------------|-----------------|---------------|----------------|\n")
        f.write("| CRITICAL | 80 – 100    | 2026 – 2027     | Deprecated after 2030 · Disallowed after 2035 | NIST IR 8547 |\n")
        f.write("| HIGH     | 60 – 79     | 2026 – 2028     | Deprecated after 2030 · Disallowed after 2035 | NIST IR 8547 |\n")
        f.write("| MEDIUM   | 20 – 59     | 2028 – 2030     | Must complete before 2030 deprecation         | NIST IR 8547 |\n")
        f.write("| LOW      | 0 – 19      | 2030 – 2032     | Must complete before 2035 disallowment        | NIST IR 8547 |\n\n")
        f.write("> **TLS Override:** TLS 1.0/1.1 endpoints are always CRITICAL regardless of score "
                "(classically broken today — NIST SP 800-52 Rev.2). "
                "TLS 1.2 endpoints are always CRITICAL — TLS 1.3 is required for PQC.\n\n")
        f.write("## PQC Migration Timeline\n\n")
        migration_phases = [
            ("Phase 1 — Inventory & Assessment",
             "Scan all endpoints, catalog algorithms, identify quantum-vulnerable assets.",
             "Complete"),
            ("Phase 2 — Hybrid PQC Deployment",
             f"Enable hybrid key exchange (X25519MLKEM768) on TLS 1.3 endpoints. "
             f"Currently {stats['pqc_hybrid']} of {stats['https_count']} HTTPS endpoints migrated.",
             "In Progress"),
            ("Phase 3 — Upgrade Legacy TLS",
             "Upgrade all TLS 1.2 endpoints to TLS 1.3. TLS 1.2 blocks PQC key exchange — "
             "hybrid PQC (X25519MLKEM768) requires TLS 1.3. Replace RSA certificates with ECDSA "
             "as an interim step; final target is ML-DSA (FIPS 204) once CAs offer it.",
             "Pending"),
            ("Phase 4 — SSH PQC Transition",
             "Migrate SSH to PQC-safe algorithms. Remove DSA keys. Deploy hybrid SSH key exchange.",
             "Pending"),
            ("Phase 5 — Full PQC Certificates",
             "Adopt ML-DSA for TLS cert signatures once CAs support it. Achieve 100% PQC coverage.",
             "Future"),
        ]
        for i, (title, desc, status) in enumerate(migration_phases, 1):
            f.write(f"### Phase {i}: {title}\n\n")
            f.write(f"{desc}\n\n")
            f.write(f"**Status:** {status}\n\n")

        # ── Recommendations ───────────────────────────────────────────────
        f.write("## Recommendations\n\n")
        f.write(f"Sorted by priority · {len(recommendations)} recommendations\n\n")
        for rec in recommendations:
            f.write(f"### [{rec['priority']}] {rec['title']}\n\n")
            f.write(f"{rec['description']}\n\n")
            if rec.get("from") and rec.get("to"):
                f.write(f"**Migration:** `{rec['from']}` → `{rec['to']}`\n\n")
            if rec.get("affected"):
                f.write("**Affected:** " + ", ".join(rec["affected"]) + "\n\n")

        # ── Migration Priority Distribution ───────────────────────────────
        f.write("## Migration Priority Distribution\n\n")
        f.write("| Priority | Count | Timeline |\n")
        f.write("|----------|-------|----------|\n")
        timeline_map = {
            "CRITICAL": "2026-2027",
            "HIGH":     "2026-2028",
            "MEDIUM":   "2028-2030",
            "LOW":      "2030-2032"
        }
        for priority in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = stats["migration_priorities"].get(priority, 0)
            if count > 0:
                f.write(f"| {priority} | {count} | {timeline_map[priority]} |\n")
        f.write("\n")

        # ── Recommended Actions ───────────────────────────────────────────
        f.write("## Recommended Actions\n\n")
        f.write("1. **Immediate (2026–2027):**\n")
        if stats["migration_priorities"].get("CRITICAL", 0) > 0:
            f.write(f"   - Upgrade {stats['migration_priorities']['CRITICAL']} critical endpoint(s) immediately\n")
        f.write("   - Upgrade all TLS 1.2 endpoints to TLS 1.3 (required for PQC)\n")
        f.write("   - Begin PQC testing with hybrid key exchange (X25519MLKEM768)\n\n")
        f.write("2. **Short-term (2027–2028):**\n")
        f.write("   - Deploy X25519MLKEM768 hybrid KEX in production\n")
        f.write("   - Migrate high-priority systems\n")
        f.write("   - Obtain PQC certificates using ML-DSA (FIPS 204) once available from CAs\n\n")
        f.write("3. **Medium-term (2028–2030):**\n")
        f.write("   - Complete migration of all systems before NIST 2030 deprecation deadline\n")
        f.write("   - Move to pure PQC mode (disable classical fallback)\n")
        f.write("   - Achieve full quantum-safe compliance ahead of 2035 disallowment\n\n")

        # ── References ────────────────────────────────────────────────────
        f.write("## References\n\n")
        f.write("- NIST PQC Standards: https://csrc.nist.gov/projects/post-quantum-cryptography\n")
        f.write("- ML-KEM (Kyber): FIPS 203 — Finalized August 2024\n")
        f.write("- ML-DSA (Dilithium): FIPS 204 — Finalized August 2024\n")
        f.write("- SLH-DSA (SPHINCS+): FIPS 205 — Finalized August 2024\n")
        f.write("- FN-DSA (Falcon): FIPS 206 — **Draft** (not yet finalized)\n")
        f.write("- HQC: Selected March 2025 — pending standard\n")
        f.write("- NIST IR 8547: Deprecation (2030) and Disallowment (2035) of quantum-vulnerable algorithms\n")
        f.write("- NIST SP 800-52 Rev.2: TLS guidelines (TLS 1.0/1.1 disallowed, TLS 1.3 required)\n")

    # Console output
    print(f"\n{'='*60}", file=sys.stderr)
    print(f"CBOM Generation Complete", file=sys.stderr)
    print(f"{'='*60}\n", file=sys.stderr)
    print(f"Total Assets:         {stats['total_assets']}", file=sys.stderr)
    print(f"  HTTPS endpoints:    {stats['https_count']} (TLS 1.3: {stats['tls13_count']}, TLS 1.2: {stats['tls12_count']})", file=sys.stderr)
    print(f"  HTTP endpoints:     {stats['http_count']} (no encryption)", file=sys.stderr)
    print(f"  SSH endpoints:      {stats['ssh_count']}", file=sys.stderr)

    pqc_pct = (stats['pqc_ready'] / stats['total_assets'] * 100) if stats['total_assets'] > 0 else 0
    vuln_pct = (stats['quantum_vulnerable'] / stats['total_assets'] * 100) if stats['total_assets'] > 0 else 0
    print(f"\nPQC-Ready:            {stats['pqc_ready']} ({pqc_pct:.1f}%)", file=sys.stderr)
    print(f"  PQC Hybrid:         {stats['pqc_hybrid']} of {stats['https_count']} HTTPS", file=sys.stderr)
    print(f"Quantum-Vulnerable:   {stats['quantum_vulnerable']} ({vuln_pct:.1f}%)", file=sys.stderr)
    grade = ("Good posture" if health_score >= 80
              else "Needs improvement" if health_score >= 50
              else "Critical issues found")
    print(f"\nSecurity Health:      {health_score}/100 ({grade})", file=sys.stderr)
    print(f"  Scan model:         {scan_model.title()} (NIST SP 800-30)", file=sys.stderr)
    print(f"  TLS score:          {tls_score if tls_score is not None else 'N/A'}%", file=sys.stderr)
    print(f"  Cert score:         {cert_score if cert_score is not None else 'N/A'}%", file=sys.stderr)
    print(f"  PQC score:          {pqc_score}% (KEX {kex_pct}% × 70% + Sig {sig_pct}% × 30%)", file=sys.stderr)
    print(f"  SSH score:          {ssh_score if ssh_score is not None else 'N/A'}%", file=sys.stderr)
    print(f"  Severity penalty:   -{total_pen:.1f} pts", file=sys.stderr)
    print(f"\nIssues:               {stats.get('issues_total', 0)} total", file=sys.stderr)
    print(f"  Critical:           {stats['issues_critical']}", file=sys.stderr)
    print(f"  Warning:            {stats['issues_warning']}", file=sys.stderr)
    print(f"  Info:               {stats['issues_info']}", file=sys.stderr)
    print(f"\nCertificates:         {stats['cert_count']} TLS + {stats['ssh_total_keys']} SSH keys", file=sys.stderr)
    print(f"  Expiring (<30d):    {stats['cert_expiring_critical']}", file=sys.stderr)
    print(f"  SSH weak keys:      {stats['ssh_weak_keys']} (RSA/DSA)", file=sys.stderr)
    print(f"\nHosts:                {len(stats['hosts'])}", file=sys.stderr)
    print(f"\nOutput Files:", file=sys.stderr)
    print(f"  - CBOM (JSON): {output_cbom}", file=sys.stderr)
    print(f"  - Summary (MD): {output_summary}", file=sys.stderr)
    print(f"\n{'='*60}\n", file=sys.stderr)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: pqc_cbom.py <input.jsonl> <cbom.json> <summary.md>")
        print("\nExample:")
        print("  python pqc_cbom.py crypto/tls.jsonl cbom/crypto-bom.json cbom/summary.md")
        sys.exit(1)

    main(sys.argv[1], sys.argv[2], sys.argv[3])
