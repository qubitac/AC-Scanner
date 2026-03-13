#!/usr/bin/env python3
"""
OpenSSL-based Crypto Scanner for PQC CBOM (Enhanced Version)
Extracts ALL TLS/certificate information including:
- TLS version, cipher suite
- Certificate dates, subject, issuer, SANs
- Elliptic curves and PQC vulnerability assessment

This replaces both tlsx AND the previous openssl_scanner.py
"""
import subprocess
import json
import sys
import re
import os
import time
from datetime import datetime, timezone

# Configuration - Can be overridden by environment variable
SCAN_TIMEOUT = int(os.getenv('SCAN_TIMEOUT', '10'))
PARALLEL_SCANS = int(os.getenv('PARALLEL_SCANS', '1'))  # For future parallelization
DEBUG = os.getenv('DEBUG', '0') == '1'  # Set DEBUG=1 to see raw OpenSSL output

# Quantum-vulnerable curves
VULNERABLE_CURVES = {
    'prime256v1': {'bits': 256, 'also_known_as': 'secp256r1, P-256', 'nist_replacement': 'Kyber-768'},
    'secp256r1': {'bits': 256, 'also_known_as': 'prime256v1, P-256', 'nist_replacement': 'Kyber-768'},
    'secp384r1': {'bits': 384, 'also_known_as': 'P-384', 'nist_replacement': 'Kyber-1024'},
    'secp521r1': {'bits': 521, 'also_known_as': 'P-521', 'nist_replacement': 'Kyber-1024'},
    'X25519': {'bits': 256, 'also_known_as': 'Curve25519', 'nist_replacement': 'Kyber-768'},
    'x25519': {'bits': 256, 'also_known_as': 'Curve25519', 'nist_replacement': 'Kyber-768'},
    'X448': {'bits': 448, 'also_known_as': 'Curve448', 'nist_replacement': 'Kyber-1024'},
    'x448': {'bits': 448, 'also_known_as': 'Curve448', 'nist_replacement': 'Kyber-1024'},
}

# Post-Quantum Hybrid Key Exchange Groups (NOT vulnerable)
PQC_HYBRID_GROUPS = {
    'X25519MLKEM768': {'classical': 'X25519', 'pqc': 'ML-KEM-768', 'security': '128-bit quantum-safe'},
    'SecP256r1MLKEM768': {'classical': 'P-256', 'pqc': 'ML-KEM-768', 'security': '128-bit quantum-safe'},
    'X25519Kyber768': {'classical': 'X25519', 'pqc': 'Kyber-768', 'security': '128-bit quantum-safe'},
    'SecP384r1MLKEM1024': {'classical': 'P-384', 'pqc': 'ML-KEM-1024', 'security': '192-bit quantum-safe'},
}

# Legacy cipher suites with no forward secrecy or broken algorithms
# These must never be classified as PQC-ready even if no KEX vulnerability is detected
LEGACY_CIPHERS = {
    # ── SHA-1 based — no forward secrecy ──────────────────────────────
    'AES128-SHA',               # Static RSA + SHA-1 — vpn1.flcu.org ❌
    'AES256-SHA',               # Static RSA + SHA-1 ❌
    'AES128-SHA256',            # Static RSA + SHA-256 but no FS ❌
    'AES256-SHA256',            # Static RSA + SHA-256 but no FS ❌

    # ── DES / 3DES — weak encryption ──────────────────────────────────
    'DES-CBC3-SHA',             # 3DES — only 112-bit security ❌
    'DES-CBC-SHA',              # Single DES — completely broken ❌
    'EDH-RSA-DES-CBC3-SHA',     # DHE + 3DES ❌
    'EDH-DSS-DES-CBC3-SHA',     # DSS + 3DES ❌

    # ── RC4 — stream cipher, completely broken ─────────────────────────
    'RC4-SHA',                  # RC4 broken since 2015 ❌
    'RC4-MD5',                  # RC4 + MD5 — doubly broken ❌
    'ECDHE-RSA-RC4-SHA',        # Even with ECDHE, RC4 is broken ❌
    'ECDHE-ECDSA-RC4-SHA',      # Same ❌

    # ── NULL ciphers — no encryption at all ───────────────────────────
    'NULL-SHA',                 # No encryption ❌
    'NULL-MD5',                 # No encryption ❌
    'NULL-SHA256',              # No encryption ❌

    # ── Export grade — intentionally weakened ─────────────────────────
    'EXP-RC4-MD5',              # Export 40-bit RC4 ❌
    'EXP-DES-CBC-SHA',          # Export 40-bit DES ❌
    'EXP-RC2-CBC-MD5',          # Export 40-bit RC2 ❌

    # ── CBC mode + SHA-1 — BEAST/POODLE vulnerable ────────────────────
    'ECDHE-RSA-AES128-SHA',     # Good KEX but SHA-1 + CBC ❌
    'ECDHE-RSA-AES256-SHA',     # Good KEX but SHA-1 + CBC ❌
    'ECDHE-ECDSA-AES128-SHA',   # Good KEX but SHA-1 + CBC ❌
    'ECDHE-ECDSA-AES256-SHA',   # Good KEX but SHA-1 + CBC ❌
    'DHE-RSA-AES128-SHA',       # DHE but SHA-1 + CBC ❌
    'DHE-RSA-AES256-SHA',       # DHE but SHA-1 + CBC ❌
    'DHE-DSS-AES128-SHA',       # DSS + SHA-1 + CBC ❌
    'DHE-DSS-AES256-SHA',       # DSS + SHA-1 + CBC ❌
}


def run_openssl_s_client(host, port=443):
    """
    Run OpenSSL s_client to get connection details
    Returns raw stdout output
    """
    try:
        cmd = [
            'openssl', 's_client',
            '-connect', f'{host}:{port}',
            '-servername', host,
            '-showcerts',
        ]

        result = subprocess.run(
            cmd,
            input='',
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=SCAN_TIMEOUT,
            text=True
        )

        return result.stdout, result.stderr

    except subprocess.TimeoutExpired:
        print(f"Timeout: {host}:{port}", file=sys.stderr)
        return None, None
    except Exception as e:
        print(f"Error {host}:{port}: {e}", file=sys.stderr)
        return None, None


def extract_os_from_server_header(server_header):
    """
    Infer OS from HTTP Server header (e.g. 'Apache/2.4.41 (Ubuntu)').
    Returns OS string or None.
    """
    if not server_header:
        return None
    h = server_header.lower()
    if "ubuntu" in h:   return "Ubuntu"
    if "debian" in h:   return "Debian"
    if "centos" in h:   return "CentOS"
    if "rhel" in h:     return "RHEL"
    if "fedora" in h:   return "Fedora"
    if "alpine" in h:   return "Alpine"
    if "freebsd" in h:  return "FreeBSD"
    if "win" in h:      return "Windows"
    return None


def probe_http(host, port):
    """
    Probe a port for HTTP service when TLS handshake fails.
    Returns dict with http_status, http_title, http_server or None if no HTTP service.
    """
    import urllib.request
    import urllib.error
    import socket

    url = f"http://{host}:{port}/"
    try:
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        opener = urllib.request.build_opener(NoRedirect)
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'Mozilla/5.0 QubitAC-Scanner'},
        )

        with opener.open(req, timeout=SCAN_TIMEOUT) as resp:
            http_status = resp.status
            http_server = resp.headers.get('Server', '')
            content = resp.read(4096).decode('utf-8', errors='ignore')
            title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
            http_title = title_match.group(1).strip()[:200] if title_match else ''
            return {
                'http_status': http_status,
                'http_title': http_title,
                'http_server': http_server,
            }

    except urllib.error.HTTPError as e:
        http_server = e.headers.get('Server', '') if e.headers else ''
        return {
            'http_status': e.code,
            'http_title': '',
            'http_server': http_server,
        }
    except (urllib.error.URLError, socket.timeout, ConnectionRefusedError, OSError):
        return None


def clean_null_values(value):
    """
    Clean NULL/empty values from OpenSSL output.
    Returns None for invalid values, otherwise returns the cleaned value.
    """
    if value is None:
        return None
    
    if isinstance(value, str):
        # Strip whitespace
        value = value.strip()
        
        # Check for NULL-like values
        null_values = ['<NULL>', '(NONE)', 'NONE', 'NULL', 'null', '', '0000', 'none']
        if value in null_values or value.upper() in ['<NULL>', 'NULL', 'NONE']:
            return None
        
        return value
    
    return value


def run_openssl_x509(cert_pem):
    """
    Parse certificate using openssl x509
    Returns parsed certificate text
    """
    try:
        cmd = ['openssl', 'x509', '-noout', '-text']

        result = subprocess.run(
            cmd,
            input=cert_pem,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=max(5, SCAN_TIMEOUT // 2),
            text=True
        )

        return result.stdout if result.returncode == 0 else None

    except Exception:
        return None


def extract_certificate_pem(s_client_output):
    """Extract the first certificate PEM from s_client output"""
    if not s_client_output:
        return None

    match = re.search(
        r'(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)',
        s_client_output,
        re.DOTALL
    )
    return match.group(1) if match else None


def parse_date_to_iso(date_str):
    """
    Parse OpenSSL date format to ISO format
    Input:  "Dec  9 07:17:16 2025 GMT" or "Dec 9 07:17:16 2025 GMT"
    Output: "2025-12-09T07:17:16Z"
    """
    if not date_str:
        return None

    # Common OpenSSL date formats
    formats = [
        "%b %d %H:%M:%S %Y %Z",      # Dec  9 07:17:16 2025 GMT
        "%b  %d %H:%M:%S %Y %Z",     # Dec  9 07:17:16 2025 GMT (double space)
        "%Y-%m-%dT%H:%M:%SZ",        # Already ISO
        "%Y-%m-%d %H:%M:%S",         # Simple format
    ]

    # Normalize whitespace
    date_str = ' '.join(date_str.split())

    for fmt in formats:
        try:
            dt = datetime.strptime(date_str, fmt)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue

    return date_str  # Return original if parsing fails


def parse_connection_info(s_client_output):
    """
    Parse OpenSSL s_client output for connection details
    Extracts: protocol, cipher, curve, server temp key
    """
    if not s_client_output:
        return {}

    info = {}

    # Extract TLS version (Protocol)
    # COMMENT: IN THE NEW TLS WE HAVE OUTPUT LIKE New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
    version_match = re.search(r'Protocol\s*:\s*(\S+)', s_client_output)
    if version_match:
        protocol = version_match.group(1)
        # Normalize: "TLSv1.3" -> "tls13", "TLSv1.2" -> "tls12"
        # Special case: some OpenSSL versions report "TLSv1" (no .0) for TLS 1.0.
        # normalize_tls.py WEAK_TLS expects "tls10" not "tls1", so map explicitly.
        normalized = protocol.lower().replace('v', '').replace('.', '')
        if normalized == 'tls1':
            normalized = 'tls10'
        info['tls_version'] = normalized
        info['tls_version_raw'] = protocol

    # Extract cipher suite - try multiple patterns
    cipher = None
    
    # Pattern 1: "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384"
    cipher_match = re.search(r'Cipher is\s+(\S+)', s_client_output)
    if cipher_match:
        cipher = cipher_match.group(1).strip()
    
    # Pattern 2: "Cipher    : TLS_AES_256_GCM_SHA384" (in SSL-Session block)
    if not cipher:
        cipher_match = re.search(r'Cipher\s*:\s*(\S+)', s_client_output)
        if cipher_match:
            cipher = cipher_match.group(1).strip()
    
    # Pattern 3: Check SSL-Session block specifically
    if not cipher:
        session_match = re.search(r'SSL-Session:.*?Cipher\s*:\s*(\S+)', s_client_output, re.DOTALL)
        if session_match:
            cipher = session_match.group(1).strip()
    
    # Ignore placeholder values
    if cipher and cipher not in ['0000', '(NONE)', 'NONE', '']:
        info['cipher'] = cipher

    # Extract Server Temp Key (shows curve for ECDHE)
    # Format 1 (OpenSSL 1.x/3.x TLS 1.2): "Server Temp Key: X25519, 253 bits"
    # Format 2 (OpenSSL 3.x TLS 1.3): "Negotiated TLS1.3 group: X25519MLKEM768"
    temp_key = None
    
    # Try TLS 1.3 format first (OpenSSL 3.x)
    tls13_group_match = re.search(r'Negotiated TLS1\.3 group:\s*(\S+)', s_client_output)
    if tls13_group_match:
        temp_key = tls13_group_match.group(1).strip()
        info['server_temp_key'] = temp_key
        info['key_exchange_group'] = temp_key
        
        # Parse curve info from TLS 1.3 group
        curve_name = temp_key
        info['curve'] = curve_name
        
        # Check if it's a known PQC hybrid group
        if curve_name in PQC_HYBRID_GROUPS:
            pqc_info = PQC_HYBRID_GROUPS[curve_name]
            info['pqc_hybrid'] = True
            info['curve_details'] = {
                'name': curve_name,
                'quantum_vulnerable': False,
                'type': 'hybrid_pqc',
                'classical_component': pqc_info['classical'],
                'pqc_component': pqc_info['pqc'],
                'security_level': pqc_info['security'],
                'description': 'Post-Quantum Hybrid Key Exchange'
            }
        # Check if it contains PQC keywords (for unknown hybrid groups)
        elif any(pqc in temp_key.upper() for pqc in ['MLKEM', 'KYBER', 'NTRU', 'SABER']):
            info['pqc_hybrid'] = True
            info['curve_details'] = {
                'name': curve_name,
                'quantum_vulnerable': False,
                'type': 'hybrid_pqc',
                'description': 'Post-Quantum Hybrid Key Exchange'
            }
        # Check if it's a known vulnerable curve
        elif curve_name in VULNERABLE_CURVES:
            curve_data = VULNERABLE_CURVES[curve_name]
            info['curve_bits'] = curve_data.get('bits', 256)
            info['curve_details'] = {
                'name': curve_name,
                'bits': curve_data['bits'],
                'quantum_vulnerable': True,
                'also_known_as': curve_data['also_known_as'],
                'nist_replacement': curve_data['nist_replacement'],
                'broken_by': "Shor's Algorithm",
                'security_level_classical': f"{curve_data['bits']}-bit",
                'security_level_quantum': '0-bit (broken)'
            }
    
    # Try older format (OpenSSL 1.x or TLS 1.2)
    # Format: "Server Temp Key: X25519, 253 bits" OR "Peer Temp Key: ECDH, prime256v1, 256 bits"
    if not temp_key:
        temp_key_match = re.search(r'(?:Server|Peer) Temp Key:\s*(.+)', s_client_output)
        if temp_key_match:
            temp_key = temp_key_match.group(1).strip()
            info['server_temp_key'] = temp_key

            # Parse curve from temp key (e.g., "ECDH, prime256v1, 256 bits" or "X25519, 253 bits")
            curve_match = re.search(r'(?:ECDH[E]?,\s*)?([^,]+),\s*(\d+)\s*bits', temp_key)
            if curve_match:
                curve_name = curve_match.group(1).strip()
                curve_bits = int(curve_match.group(2))
                info['curve'] = curve_name
                info['curve_bits'] = curve_bits

                # Add vulnerability details if known curve
                if curve_name in VULNERABLE_CURVES:
                    info['curve_details'] = {
                        'name': curve_name,
                        'bits': curve_bits,
                        'quantum_vulnerable': True,
                        'also_known_as': VULNERABLE_CURVES[curve_name]['also_known_as'],
                        'nist_replacement': VULNERABLE_CURVES[curve_name]['nist_replacement'],
                        'broken_by': "Shor's Algorithm",
                        'security_level_classical': f'{curve_bits}-bit',
                        'security_level_quantum': '0-bit (broken)'
                    }

    # Extract Peer signature type
    peer_sig_match = re.search(r'Peer signature type:\s*(.+)', s_client_output)
    if peer_sig_match:
        info['peer_signature_type'] = peer_sig_match.group(1).strip()

    # Extract signature digest
    sig_digest_match = re.search(r'Peer signature digest:\s*(.+)', s_client_output)
    if sig_digest_match:
        info['peer_signature_digest'] = sig_digest_match.group(1).strip()

    # Extract Server public key size
    pubkey_match = re.search(r'Server public key is (\d+) bit', s_client_output)
    if pubkey_match:
        info['server_public_key_bits'] = int(pubkey_match.group(1))

    return info


def parse_certificate_info(x509_output):
    """
    Parse openssl x509 -text output for certificate details
    Extracts: subject, issuer, dates, SANs, key info
    """
    if not x509_output:
        return {}

    info = {}

    # Extract Subject CN
    # Subject: C = US, ST = California, L = San Francisco, O = Company, CN = example.com
    subject_cn_match = re.search(r'Subject:.*?CN\s*=\s*([^,\n/]+)', x509_output)
    if subject_cn_match:
        info['subject_cn'] = subject_cn_match.group(1).strip()

    # Extract Issuer CN
    issuer_cn_match = re.search(r'Issuer:.*?CN\s*=\s*([^,\n/]+)', x509_output)
    if issuer_cn_match:
        info['issuer_cn'] = issuer_cn_match.group(1).strip()

    # Extract Issuer Organization (useful for identifying CA)
    issuer_o_match = re.search(r'Issuer:.*?O\s*=\s*([^,\n/]+)', x509_output)
    if issuer_o_match:
        info['issuer_org'] = issuer_o_match.group(1).strip()

    # Extract Not Before date
    not_before_match = re.search(r'Not Before:\s*(.+)', x509_output)
    if not_before_match:
        info['not_before'] = parse_date_to_iso(not_before_match.group(1).strip())

    # Extract Not After date
    not_after_match = re.search(r'Not After\s*:\s*(.+)', x509_output)
    if not_after_match:
        info['not_after'] = parse_date_to_iso(not_after_match.group(1).strip())

    # Extract Subject Alternative Names (SANs)
    # Look for the SAN extension block
    san_section_match = re.search(
        r'X509v3 Subject Alternative Name:\s*\n\s*(.+?)(?:\n\s*X509v3|\n\s*Signature|$)',
        x509_output,
        re.DOTALL
    )
    if san_section_match:
        san_line = san_section_match.group(1).strip()
        # Extract DNS names: DNS:example.com, DNS:*.example.com
        dns_sans = re.findall(r'DNS:([^\s,]+)', san_line)
        # Extract IP addresses: IP Address:1.2.3.4
        ip_sans = re.findall(r'IP Address:([^\s,]+)', san_line)
        info['subject_an'] = dns_sans + ip_sans

    # Extract Public Key Algorithm
    pubkey_alg_match = re.search(r'Public Key Algorithm:\s*(.+)', x509_output)
    if pubkey_alg_match:
        info['public_key_algorithm'] = pubkey_alg_match.group(1).strip()

    # Extract RSA key size
    rsa_match = re.search(r'(?:RSA Public-Key|Public-Key):\s*\((\d+)\s*bit', x509_output)
    if rsa_match:
        info['key_size'] = int(rsa_match.group(1))

    # Extract EC curve from certificate (if EC key)
    ec_curve_match = re.search(r'ASN1 OID:\s*(.+)', x509_output)
    if ec_curve_match:
        info['ec_curve'] = ec_curve_match.group(1).strip()

    # Extract Signature Algorithm
    sig_alg_match = re.search(r'Signature Algorithm:\s*(.+)', x509_output)
    if sig_alg_match:
        info['signature_algorithm'] = sig_alg_match.group(1).strip()

    return info


def assess_pqc_readiness(conn_info, cert_info):
    """
    Assess Post-Quantum Cryptography readiness
    Returns vulnerability assessment
    """
    vulnerabilities = []

    # Check if using PQC hybrid key exchange (not vulnerable)
    if conn_info.get('pqc_hybrid'):
        # PQC hybrid is quantum-safe, no key exchange vulnerability
        pass
    # Check curve vulnerability (key exchange) - only if NOT using PQC
    elif conn_info.get('curve_details'):
        curve_detail = conn_info['curve_details']
        if curve_detail.get('quantum_vulnerable', True):
            vulnerabilities.append({
                'component': 'Key Exchange Curve',
                'algorithm': curve_detail.get('name', 'Unknown'),
                'quantum_vulnerable': True,
                'broken_by': "Shor's Algorithm",
                'nist_replacement': curve_detail.get('nist_replacement', 'ML-KEM (Kyber)'),
                'details': f"{curve_detail.get('bits', 'unknown')}-bit elliptic curve",
                'standard': 'FIPS 203 (ML-KEM/Kyber)'
            })
    elif conn_info.get('curve'):
        # Curve detected but not in our known list
        vulnerabilities.append({
            'component': 'Key Exchange Curve',
            'algorithm': conn_info['curve'],
            'quantum_vulnerable': True,
            'broken_by': "Shor's Algorithm",
            'nist_replacement': 'Kyber (ML-KEM)',
            'details': f"{conn_info.get('curve_bits', 'unknown')}-bit curve",
            'standard': 'FIPS 203 (ML-KEM/Kyber)'
        })

    # Check signature algorithm
    sig_alg = cert_info.get('signature_algorithm', '')
    if sig_alg and ('RSA' in sig_alg or 'ecdsa' in sig_alg.lower() or 'ECDSA' in sig_alg):
        vulnerabilities.append({
            'component': 'Certificate Signature',
            'algorithm': sig_alg,
            'quantum_vulnerable': True,
            'broken_by': "Shor's Algorithm",
            'nist_replacement': 'Dilithium (ML-DSA) or Falcon (FN-DSA)',
            'details': f'Current: {sig_alg}',
            'standard': 'FIPS 204 (ML-DSA) or FIPS 206 (FN-DSA)'
        })

    # Check public key algorithm
    # Use case-insensitive matching: openssl x509 reports 'rsaEncryption' (lowercase 'rsa'),
    # so 'RSA' in pubkey_alg would silently miss all RSA public keys.
    pubkey_alg = cert_info.get('public_key_algorithm', '')
    pubkey_alg_lower = pubkey_alg.lower()
    if pubkey_alg and ('rsa' in pubkey_alg_lower or 'ec' in pubkey_alg_lower or 'id-ecPublicKey' in pubkey_alg):
        key_size = cert_info.get('key_size', 0)
        vulnerabilities.append({
            'component': 'Public Key',
            'algorithm': pubkey_alg,
            'quantum_vulnerable': True,
            'broken_by': "Shor's Algorithm",
            'nist_replacement': 'Dilithium (ML-DSA) or Falcon (FN-DSA)',
            'details': f'{key_size}-bit key' if key_size else 'EC key',
            'standard': 'FIPS 204/206'
        })

    # Determine migration priority (aligned with pqc_cbom.py scoring model)
    #
    # Step 1 — TLS Version Gate (auto-CRITICAL):
    #   TLS 1.0/1.1 → CRITICAL (classically broken + PQC impossible)
    #   TLS 1.2     → CRITICAL (PQC blocked — must upgrade to TLS 1.3 first)
    #
    # Step 2 — TLS 1.3 Quantum Risk Score (0-100):
    #   KEX not hybrid → +70 (HNDL risk — highest urgency per NIST IR 8547)
    #   Sig not PQC   → +30 (future quantum risk)
    #
    # Priority Tiers:
    #   80-100 → CRITICAL  (both KEX + Sig vulnerable)
    #   60-79  → HIGH      (KEX vulnerable, Sig safe)
    #   20-59  → MEDIUM    (KEX safe, Sig vulnerable)
    #   0-19   → LOW       (fully PQC ready — future state)

    tls_version = conn_info.get('tls_version', '').lower()

    if tls_version in ('tls10', 'tls11'):
        priority = 'CRITICAL'
    elif tls_version == 'tls12':
        priority = 'CRITICAL'
    else:
        # TLS 1.3 — score based on quantum risk
        priority_score = 0
        kex_safe = conn_info.get('pqc_hybrid', False)
        if not kex_safe:
            priority_score += 70
        # Sig: certificate_safe is always False today — ML-DSA certs not yet widely available
        sig_safe = False
        if not sig_safe:
            priority_score += 30

        if priority_score >= 80:
            priority = 'CRITICAL'
        elif priority_score >= 60:
            priority = 'HIGH'
        elif priority_score >= 20:
            priority = 'MEDIUM'
        else:
            priority = 'LOW'

    return {
        'pqc_ready': len(vulnerabilities) == 0 and conn_info.get('cipher') not in LEGACY_CIPHERS,
        'vulnerabilities': vulnerabilities,
        'vulnerability_count': len(vulnerabilities),
        'migration_priority': priority
    }


def scan_host(host, port=443):
    """
    Complete scan of a single host
    Returns combined data compatible with both normalize_tls.py and pqc_cbom.py
    """
    # Run s_client
    s_client_output, s_client_stderr = run_openssl_s_client(host, port)

    if not s_client_output:
        return None

    # Debug: print raw output
    if DEBUG:
        print(f"\n{'='*60}", file=sys.stderr)
        print(f"DEBUG: Raw OpenSSL output for {host}:{port}", file=sys.stderr)
        print(f"{'='*60}", file=sys.stderr)
        print(s_client_output[:2000], file=sys.stderr)  # First 2000 chars
        print(f"{'='*60}\n", file=sys.stderr)

    # Check for connection errors in stderr
    if s_client_stderr and 'connect:' in s_client_stderr.lower():
        return None

    # Parse connection info
    conn_info = parse_connection_info(s_client_output)

    # Extract and parse certificate
    cert_pem = extract_certificate_pem(s_client_output)
    cert_info = {}
    if cert_pem:
        x509_output = run_openssl_x509(cert_pem)
        if x509_output:
            cert_info = parse_certificate_info(x509_output)

    # Assess PQC readiness
    pqc_assessment = assess_pqc_readiness(conn_info, cert_info)

    # Determine probe status based on data quality
    probe_status = 'success'
    probe_errors = []
    http_info = {}

    # Clean NULL values from raw data first
    raw_cipher = conn_info.get('cipher')
    raw_curve = conn_info.get('curve')
    raw_tls_version = conn_info.get('tls_version')
    
    # Check if cipher/curve contain NULL-like values
    null_values = [None, '', '<NULL>', '(NONE)', 'NONE', '0000', 'none', 'null']
    cipher_is_null = raw_cipher in null_values or (isinstance(raw_cipher, str) and raw_cipher.upper() in ['<NULL>', '(NONE)', 'NONE'])
    curve_is_null = raw_curve in null_values or (isinstance(raw_curve, str) and raw_curve.upper() in ['<NULL>', '(NONE)', 'NONE'])

    # Check for missing critical data
    has_tls_version = bool(raw_tls_version)
    has_cipher = bool(raw_cipher) and not cipher_is_null
    has_curve = bool(raw_curve) and not curve_is_null
    has_certificate = bool(cert_info.get('subject_cn') or cert_info.get('not_after'))
    has_cert_dates = bool(cert_info.get('not_before') and cert_info.get('not_after'))

    # CRITICAL: If we have "TLS version" but NO cipher AND NO certificate, 
    # the TLS handshake actually FAILED - this is NOT a TLS server
    # OpenSSL reports the protocol IT tried, not what the server supports
    tls_handshake_failed = has_tls_version and not has_cipher and not has_certificate

    # Determine if TLS is actually enabled on this port
    # TLS is only truly enabled if we got a cipher OR a certificate
    tls_enabled = (has_cipher or has_certificate) and not tls_handshake_failed

    if not has_tls_version:
        probe_errors.append('no_tls_version')
    if not has_cipher:
        probe_errors.append('no_cipher')
    if not has_curve:
        probe_errors.append('no_curve')
    if not has_certificate:
        probe_errors.append('no_certificate')
    if not has_cert_dates:
        probe_errors.append('no_cert_dates')
    if tls_handshake_failed:
        probe_errors.append('tls_handshake_failed')

    # Determine overall status
    if tls_handshake_failed or not tls_enabled:
        probe_status = 'no_tls'
        tls_enabled = False

    # Compute cert_valid: True if cert dates are present and not_after is in the future
    cert_valid = None
    if cert_info.get('not_after'):
        try:
            from datetime import timezone as _tz
            not_after_dt = datetime.fromisoformat(cert_info['not_after'].replace('Z', '+00:00'))
            cert_valid = not_after_dt > datetime.now(_tz.utc)
        except Exception:
            cert_valid = None

    # Determine final probe_status and probe for HTTP fallback if TLS failed
    if tls_handshake_failed or not tls_enabled:
        http_info = probe_http(host, port) or {}
        if http_info:
            probe_errors.append('http_only')
            probe_errors = [e for e in probe_errors if e != 'tls_handshake_failed']
    elif not has_tls_version and not has_certificate:
        probe_status = 'failed'
    elif has_tls_version and not has_cipher and not has_curve:
        probe_status = 'incomplete'
    elif not has_certificate:
        probe_status = 'partial_no_cert'
    elif not has_cipher or not has_cert_dates:
        probe_status = 'partial'
    else:
        probe_status = 'success'

    # Clean NULL values from connection info
    def get_clean(data, key, default=None):
        """Get value and clean NULL-like strings.
        Always runs clean_null_values on the retrieved value so that an empty
        string stored under a key (value == default == '') is still cleaned to
        None, rather than being silently passed through to the output record.
        """
        value = data.get(key, default)
        cleaned = clean_null_values(value)
        # If cleaning turned a real value into None, return None (not the default).
        # Only return default when the key was genuinely absent from the dict.
        if key not in data:
            return default
        return cleaned

    # Build unified output record
    # This format is compatible with BOTH normalize_tls.py AND pqc_cbom.py
    record = {
        # Core fields (used by normalize_tls.py)
        'host': host,
        'port': int(port),
        'tls_enabled': tls_enabled,
        'tls_version': get_clean(conn_info, 'tls_version', ''),
        'cipher': get_clean(conn_info, 'cipher', ''),
        'not_before': get_clean(cert_info, 'not_before'),
        'not_after': get_clean(cert_info, 'not_after'),
        'subject_cn': get_clean(cert_info, 'subject_cn'),
        'subject_an': cert_info.get('subject_an', []),
        'issuer_cn': get_clean(cert_info, 'issuer_cn'),

        # Extended certificate info
        'issuer_org': get_clean(cert_info, 'issuer_org'),
        'public_key_algorithm': get_clean(cert_info, 'public_key_algorithm'),
        'signature_algorithm': get_clean(cert_info, 'signature_algorithm'),
        'key_size': cert_info.get('key_size'),
        'ec_curve': get_clean(cert_info, 'ec_curve'),

        # Connection details
        'tls_version_raw': get_clean(conn_info, 'tls_version_raw'),
        'server_temp_key': get_clean(conn_info, 'server_temp_key'),
        'server_public_key_bits': conn_info.get('server_public_key_bits'),
        'peer_signature_type': get_clean(conn_info, 'peer_signature_type'),
        'peer_signature_digest': get_clean(conn_info, 'peer_signature_digest'),

        # Curve/PQC fields (used by pqc_cbom.py)
        'curve': get_clean(conn_info, 'curve'),
        'curve_bits': conn_info.get('curve_bits'),
        'curve_details': conn_info.get('curve_details'),
        'key_exchange_group': get_clean(conn_info, 'key_exchange_group'),
        'pqc_hybrid': conn_info.get('pqc_hybrid', False),

        # Nested structures for pqc_cbom.py compatibility
        'curve_information': {
            'curve': get_clean(conn_info, 'curve'),
            'curve_bits': conn_info.get('curve_bits'),
            'curve_details': conn_info.get('curve_details'),
            'server_temp_key': get_clean(conn_info, 'server_temp_key'),
            'key_exchange_group': get_clean(conn_info, 'key_exchange_group'),
            'pqc_hybrid': conn_info.get('pqc_hybrid', False),
        },
        'detailed_certificate': {
            'public_key_algorithm': get_clean(cert_info, 'public_key_algorithm'),
            'signature_algorithm': get_clean(cert_info, 'signature_algorithm'),
            'key_size_bits': cert_info.get('key_size'),
            'ec_curve': get_clean(cert_info, 'ec_curve'),
        },
        'pqc_curve_assessment': pqc_assessment,

        # Metadata
        'scan_timestamp': datetime.now(timezone.utc).isoformat(),
        'probe_status': probe_status,
        'probe_errors': probe_errors if probe_errors else None,
        'cert_valid': cert_valid,

        # HTTP service info (populated when TLS handshake fails but HTTP is detected)
        'http_status': http_info.get('http_status'),
        'http_title': http_info.get('http_title'),
        'http_server': http_info.get('http_server'),
        'os': extract_os_from_server_header(http_info.get('http_server')),
        
        # Data quality flags
        'data_quality': {
            'has_tls_version': has_tls_version,
            'has_cipher': has_cipher,
            'has_certificate': has_certificate,
            'has_cert_dates': has_cert_dates,
            'complete': probe_status == 'success',
        },
    }

    # Forward secrecy: TLS 1.3 always has it; TLS 1.2 needs ECDHE/DHE cipher or temp key
    tls_ver = (get_clean(conn_info, 'tls_version') or '').lower()
    cipher_str = (get_clean(conn_info, 'cipher') or '').upper()
    record['has_forward_secrecy'] = (
        tls_ver == 'tls13' or
        'ECDHE' in cipher_str or
        'DHE' in cipher_str or
        bool(conn_info.get('server_temp_key'))
    )

    return record


def scan_from_file(input_file, output_file):
    """
    Scan multiple hosts from a file
    Input: file with host:port or just host per line
    Output: JSONL file compatible with normalize_tls.py and pqc_cbom.py
    """
    # Read hosts
    hosts = []
    try:
        with open(input_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                # Parse host:port — use rfind so common IPv6 forms are handled safely.
                # Bracketed IPv6 "[2001:db8::1]:443" works correctly (last segment "443").
                # Bare IPv6 "2001:db8::1" is inherently ambiguous (last segment "1" looks
                # like a port); use brackets in input files for IPv6 addresses.
                last_colon = line.rfind(':')
                if last_colon != -1 and line[last_colon + 1:].isdigit():
                    host = line[:last_colon]
                    port = int(line[last_colon + 1:])
                else:
                    host = line
                    port = 443

                hosts.append((host, port))
    except FileNotFoundError:
        print(f"Error: input file not found: {input_file}", file=sys.stderr)
        sys.exit(1)

    total = len(hosts)
    if total == 0:
        print("    No hosts to scan", file=sys.stderr)
        with open(output_file, 'w') as f:
            pass  # Create empty file
        return

    print(f"    Scanning {total} host(s)...", file=sys.stderr)

    # Track timing and statistics
    start_time = time.time()
    success_count = 0
    partial_count = 0
    fail_count = 0
    connection_fail_count = 0
    
    # Track probe statuses
    probe_status_counts = {}

    with open(output_file, 'w') as f_out:
        for idx, (host, port) in enumerate(hosts, 1):
            # Progress indicator
            elapsed = time.time() - start_time
            if idx > 1 and total > 5:
                avg_time = elapsed / (idx - 1)
                eta = avg_time * (total - idx + 1)
                eta_min = int(eta // 60)
                eta_sec = int(eta % 60)
                print(f"    [{idx}/{total}] {host}:{port} (ETA: {eta_min}m {eta_sec}s)", file=sys.stderr)
            elif total > 5:
                print(f"    [{idx}/{total}] {host}:{port}", file=sys.stderr)

            # Scan host
            result = scan_host(host, port)

            if result:
                f_out.write(json.dumps(result) + '\n')
                f_out.flush()  # ensure record reaches disk even if process is killed mid-scan
                
                # Track probe status
                status = result.get('probe_status', 'unknown')
                probe_status_counts[status] = probe_status_counts.get(status, 0) + 1
                
                if status == 'success':
                    success_count += 1
                elif status.startswith('partial'):
                    partial_count += 1
                else:
                    fail_count += 1
            else:
                connection_fail_count += 1

    # Summary
    elapsed_total = time.time() - start_time
    elapsed_min = int(elapsed_total // 60)
    elapsed_sec = int(elapsed_total % 60)

    print(f"\n    === Scan Summary ===", file=sys.stderr)
    print(f"    Duration: {elapsed_min}m {elapsed_sec}s", file=sys.stderr)
    print(f"    Total hosts: {total}", file=sys.stderr)
    print(f"    Connection failed: {connection_fail_count}", file=sys.stderr)
    print(f"    Scan results:", file=sys.stderr)
    
    for status, count in sorted(probe_status_counts.items()):
        pct = (count / total * 100)
        print(f"      - {status}: {count} ({pct:.1f}%)", file=sys.stderr)
    
    print(f"    Output: {output_file}", file=sys.stderr)


def analyze_single_host(host, port=443):
    """
    Analyze a single host and print detailed results
    """
    print(f"\n{'='*60}", file=sys.stderr)
    print(f"Analyzing: {host}:{port}", file=sys.stderr)
    print(f"{'='*60}\n", file=sys.stderr)

    result = scan_host(host, port)

    if result:
        # Pretty print
        print(json.dumps(result, indent=2))
        return 0
    else:
        print(f"Failed to connect to {host}:{port}", file=sys.stderr)
        return 1


def print_usage():
    """Print usage information"""
    print("""
OpenSSL TLS Scanner (Enhanced) - Replaces tlsx + previous openssl_scanner.py

Usage:
  python3 openssl_scanner.py scan <hosts.txt> <output.jsonl>
      Scan hosts from file (one host or host:port per line)
      Output is compatible with normalize_tls.py and pqc_cbom.py

  python3 openssl_scanner.py analyze <hostname> [port]
      Analyze a single host and print detailed results

Environment Variables:
  SCAN_TIMEOUT     - Connection timeout in seconds (default: 10)
  PARALLEL_SCANS   - Reserved for future parallel scanning (default: 1)

Examples:
  python3 openssl_scanner.py scan live/hosts_ports.txt crypto/tls.jsonl
  python3 openssl_scanner.py analyze example.com
  python3 openssl_scanner.py analyze example.com 8443
  SCAN_TIMEOUT=30 python3 openssl_scanner.py scan hosts.txt output.jsonl

Output Format:
  JSONL with fields compatible with both:
  - normalize_tls.py (security findings)
  - pqc_cbom.py (quantum vulnerability assessment)
""")


def main():
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    command = sys.argv[1]

    if command == 'scan':
        if len(sys.argv) != 4:
            print("Usage: python3 openssl_scanner.py scan <hosts.txt> <output.jsonl>")
            sys.exit(1)
        scan_from_file(sys.argv[2], sys.argv[3])

    elif command == 'analyze':
        if len(sys.argv) < 3:
            print("Usage: python3 openssl_scanner.py analyze <hostname> [port]")
            sys.exit(1)
        host = sys.argv[2]
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 443
        sys.exit(analyze_single_host(host, port))

    elif command in ['-h', '--help', 'help']:
        print_usage()
        sys.exit(0)

    else:
        print(f"Unknown command: {command}")
        print_usage()
        sys.exit(1)


if __name__ == '__main__':
    main()
