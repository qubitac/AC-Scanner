#!/usr/bin/env python3
"""
QubitAC SSH Scanner
Standalone SSH security scanner with Post-Quantum Cryptography assessment.

Replaces the SSH scanning logic embedded inside scan.sh.
Output is fully compatible with normalize_tls.py and pqc_cbom.py.

Dependencies:
  - ssh-audit   (pip3 install ssh-audit)
  - dig         (apt install dnsutils / brew install bind)

Usage:
  python3 ssh_scanner.py scan <hosts.txt> <output.jsonl>
  python3 ssh_scanner.py analyze <hostname> [port]
"""

import subprocess
import json
import sys
import re
import os
import time
from datetime import datetime, timezone

# ═══════════════════════════════════════════════════════════════════════════════
# Configuration — overridable via environment variables
# ═══════════════════════════════════════════════════════════════════════════════

SCAN_TIMEOUT  = int(os.getenv("SCAN_TIMEOUT",  "10"))
DEBUG         = os.getenv("DEBUG", "0") == "1"

# Known SSH ports (same list as scan.sh) — used for port range documentation
# and by normalize_tls.py's is_ssh detection (not directly iterated here)
SSH_PORT_LIST = [22, 2222, 2200, 22222, 8022, 222, 3022, 4022, 8222, 10022]

# PQC-safe KEX pattern substrings (case-insensitive match)
# Used directly in classify_kex() via contains_any()
PQC_KEX_PATTERNS = ["sntrup761", "mlkem", "kyber", "ntru", "frodokem"]

# PQC-safe host key algorithms
# Used directly in classify_host_keys() via contains_any()
PQC_HOSTKEY_PATTERNS = ["dilithium", "mldsa", "sphincs", "falcon"]

# Reference lists — documented here for visibility but cipher/MAC classification
# uses explicit inline checks in classify_ciphers() / classify_macs() for
# precision (e.g. ordering guards, word-boundary matching)
WEAK_CIPHER_PATTERNS = ["3des", "des", "blowfish", "arcfour", "rc4"]
WEAK_MAC_PATTERNS    = ["sha1", "md5", "ripemd"]

# DNS prefixes to try when looking for real IP behind a CDN
CDN_BYPASS_PREFIXES = [
    "ssh", "direct", "origin", "real", "mail",
    "ftp", "vpn", "admin", "mgmt", "bastion"
]


# ═══════════════════════════════════════════════════════════════════════════════
# Utility
# ═══════════════════════════════════════════════════════════════════════════════

def debug(msg):
    """Print debug message to stderr when DEBUG=1"""
    if DEBUG:
        print(f"[DEBUG] {msg}", file=sys.stderr)


def utc_now():
    """Return current UTC time as ISO string"""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def contains_any(text, patterns):
    """Return True if text contains any of the given substrings (case-insensitive)"""
    text_lower = text.lower()
    return any(p in text_lower for p in patterns)


# ═══════════════════════════════════════════════════════════════════════════════
# Step 1 — Port pre-check via TCP connect
# ═══════════════════════════════════════════════════════════════════════════════

def check_port_tcp(host, port):
    """
    Use a direct TCP connect to check if a port is open or closed/filtered.
    Returns: 'open' | 'filtered'
    Pure Python — no nmap dependency required.
    """
    import socket
    try:
        with socket.create_connection((host, port), timeout=SCAN_TIMEOUT):
            debug(f"TCP connect {host}:{port} → open")
            return "open"
    except socket.timeout:
        debug(f"TCP connect {host}:{port} → filtered (timeout)")
        return "filtered"
    except ConnectionRefusedError:
        debug(f"TCP connect {host}:{port} → filtered (refused)")
        return "filtered"
    except OSError as e:
        debug(f"TCP connect {host}:{port} → filtered ({e})")
        return "filtered"


# ═══════════════════════════════════════════════════════════════════════════════
# Step 2 — Real IP discovery (CDN/WAF bypass)
# ═══════════════════════════════════════════════════════════════════════════════

def run_dig(args):
    """Run a dig command and return stdout. Returns empty string on failure."""
    try:
        result = subprocess.run(
            ["dig"] + args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=SCAN_TIMEOUT,
            text=True
        )
        return result.stdout
    except Exception:
        return ""


def dig_a(hostname):
    """Return first A record IP for a hostname, or None"""
    output = run_dig(["+short", hostname, "A"])
    for line in output.splitlines():
        line = line.strip()
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", line):
            return line
    return None


def try_resolve_real_ip(host):
    """
    Try to find the real server IP when SSH is filtered (possible CDN/WAF).
    Uses three methods:
      1. Common subdomain prefixes (ssh., origin., bastion., etc.)
      2. MX record IPs (mail servers often bypass CDN)
      3. SPF record ip4: directives

    Returns a deduplicated list of candidate IPs (may be empty).
    """
    ips = []

    # Method 1 — common subdomains that bypass CDN
    for prefix in CDN_BYPASS_PREFIXES:
        candidate = f"{prefix}.{host}"
        ip = dig_a(candidate)
        if ip:
            debug(f"Found candidate IP via {candidate}: {ip}")
            ips.append(ip)

    # Method 2 — MX records
    mx_output = run_dig(["+short", host, "MX"])
    for line in mx_output.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2:
            mx_host = parts[1].rstrip(".")
            mx_ip = dig_a(mx_host)
            if mx_ip:
                debug(f"Found candidate IP via MX ({mx_host}): {mx_ip}")
                ips.append(mx_ip)

    # Method 3 — SPF TXT record ip4: directives
    txt_output = run_dig(["+short", host, "TXT"])
    for line in txt_output.splitlines():
        if "v=spf1" in line.lower():
            for match in re.finditer(r"ip4:(\d+\.\d+\.\d+\.\d+)", line):
                ip = match.group(1)
                debug(f"Found candidate IP via SPF: {ip}")
                ips.append(ip)

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            unique.append(ip)

    return unique


# ═══════════════════════════════════════════════════════════════════════════════
# Step 3 — Run ssh-audit
# ═══════════════════════════════════════════════════════════════════════════════

def run_ssh_audit(host, port):
    """
    Run ssh-audit -jj on host:port and return parsed JSON dict.
    Returns None if ssh-audit fails, times out, or returns invalid JSON.
    """
    try:
        result = subprocess.run(
            ["ssh-audit", "-jj", "-p", str(port), host],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=SCAN_TIMEOUT,
            text=True
        )

        stdout = result.stdout.strip()
        if not stdout:
            debug(f"ssh-audit returned empty output for {host}:{port}")
            return None

        parsed = json.loads(stdout)
        debug(f"ssh-audit succeeded for {host}:{port} ({len(stdout)} bytes)")
        return parsed

    except FileNotFoundError:
        print("Error: ssh-audit not found. Install with: pip3 install ssh-audit", file=sys.stderr)
        sys.exit(1)
    except subprocess.TimeoutExpired:
        debug(f"ssh-audit timed out for {host}:{port}")
        return None
    except json.JSONDecodeError as e:
        debug(f"ssh-audit returned invalid JSON for {host}:{port}: {e}")
        return None
    except Exception as e:
        debug(f"ssh-audit error for {host}:{port}: {e}")
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# Step 4 — Transform ssh-audit JSON into CBOM-compatible format
# ═══════════════════════════════════════════════════════════════════════════════

def classify_kex(kex_list):
    """
    Classify each key exchange algorithm.
    Returns list of dicts with algorithm, pqc_safe, quantum_threat, replacement.
    """
    results = []
    for item in kex_list:
        alg = item.get("algorithm", "")
        alg_lower = alg.lower()

        pqc_safe = contains_any(alg_lower, PQC_KEX_PATTERNS)

        if pqc_safe:
            quantum_threat = "none"
            replacement = "Already PQC-Safe"
        elif "diffie-hellman" in alg_lower:
            quantum_threat = "shors_algorithm"
            replacement = "mlkem768x25519-sha256"
        elif any(x in alg_lower for x in ["ecdh", "curve25519", "curve448"]):
            quantum_threat = "shors_algorithm"
            replacement = "mlkem768x25519-sha256"
        else:
            quantum_threat = "unknown"
            replacement = "mlkem768x25519-sha256"

        results.append({
            "algorithm":      alg,
            "pqc_safe":       pqc_safe,
            "quantum_threat": quantum_threat,
            "replacement":    replacement,
        })

    return results


def classify_host_keys(key_list):
    """
    Classify each host key algorithm.
    Returns list of dicts with algorithm, keysize, quantum_threat, replacement.
    """
    results = []
    for item in key_list:
        alg = item.get("algorithm", "")
        alg_lower = alg.lower()
        keysize = item.get("keysize")

        if contains_any(alg_lower, PQC_HOSTKEY_PATTERNS):
            quantum_threat = "none"
            replacement = "Already PQC-Safe"
        elif any(x in alg_lower for x in ["rsa", "ecdsa", "ed25519", "ed448", "dsa", "dss"]):
            quantum_threat = "shors_algorithm"
            if "rsa" in alg_lower:
                replacement = "ML-DSA-65 / Ed25519"
            elif "ecdsa" in alg_lower:
                replacement = "ML-DSA-65"
            elif any(x in alg_lower for x in ["ed25519", "ed448"]):
                replacement = "ML-DSA-65 (when available)"
            else:
                replacement = "ML-DSA-65"
        else:
            quantum_threat = "unknown"
            replacement = "ML-DSA-65"

        results.append({
            "algorithm":      alg,
            "keysize":        keysize,
            "quantum_threat": quantum_threat,
            "replacement":    replacement,
        })

    return results


def classify_ciphers(enc_list):
    """
    Classify each encryption cipher.
    Returns list of dicts with algorithm and quantum_threat.
    """
    results = []
    for item in enc_list:
        alg = item.get("algorithm", "")
        alg_lower = alg.lower()

        if "256" in alg_lower or "chacha20" in alg_lower:
            quantum_threat = "grovers_adequate"
        elif "128" in alg_lower:
            quantum_threat = "grovers_reduced"
        elif (
            "3des" in alg_lower or
            "blowfish" in alg_lower or
            "arcfour" in alg_lower or
            "rc4" in alg_lower or
            # Match bare "des" only when not part of a larger word like "chacha20-poly1305"
            re.search(r'\bdes\b', alg_lower)
        ):
            quantum_threat = "classically_weak"
        else:
            quantum_threat = "unknown"

        results.append({
            "algorithm":      alg,
            "quantum_threat": quantum_threat,
        })

    return results


def classify_macs(mac_list):
    """
    Classify each MAC algorithm.
    Returns list of dicts with algorithm and quantum_threat.
    """
    results = []
    for item in mac_list:
        alg = item.get("algorithm", "")
        alg_lower = alg.lower()

        # Order matters: check safe MACs first so sha2-* is never caught by sha1/md5 checks.
        # Matches scan.sh jq logic exactly: sha1/md5/ripemd → classically_weak, no exceptions.
        if any(x in alg_lower for x in ["sha2-256", "sha2-512", "poly1305", "gcm"]):
            quantum_threat = "grovers_adequate"
        elif any(x in alg_lower for x in ["sha1", "md5", "ripemd"]):
            quantum_threat = "classically_weak"
        else:
            quantum_threat = "grovers_adequate"

        results.append({
            "algorithm":      alg,
            "quantum_threat": quantum_threat,
        })

    return results


def calculate_priority(sw, pqc_count, has_weak_cipher):
    """
    Calculate migration priority based on software version and findings.
    Returns: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
    """
    sw_lower = (sw or "").lower()

    if has_weak_cipher:
        return "CRITICAL"

    if pqc_count > 0:
        # Already has PQC — check if it's the latest OpenSSH
        if re.search(r"openssh[_ ](1[0-9]|9\.9)", sw_lower):
            return "LOW"
        return "MEDIUM"

    # No PQC — assess by OpenSSH version
    if re.search(r"openssh[_ ][1-7]\.", sw_lower):
        return "CRITICAL"
    if re.search(r"openssh[_ ]8\.", sw_lower):
        return "HIGH"
    if re.search(r"openssh[_ ]9\.", sw_lower):
        return "MEDIUM"

    return "HIGH"


def extract_os_from_banner(banner_str):
    """
    Infer OS from SSH banner (e.g. 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6').
    Returns OS string or None.
    """
    if not banner_str:
        return None
    b = banner_str.lower()
    if "ubuntu" in b:    return "Ubuntu"
    if "debian" in b:    return "Debian"
    if "raspbian" in b:  return "Raspbian"
    if "centos" in b:    return "CentOS"
    if "rhel" in b:      return "RHEL"
    if "fedora" in b:    return "Fedora"
    if "alpine" in b:    return "Alpine"
    if "freebsd" in b:   return "FreeBSD"
    if "windows" in b:   return "Windows"
    return None


def transform_ssh_audit(raw_json, original_host, resolved_ip, port):
    """
    Transform raw ssh-audit JSON into a CBOM-compatible record.
    This is the Python equivalent of the large jq block in scan.sh.

    Returns a dict ready to be written as a JSONL line.
    """
    banner       = raw_json.get("banner", {}) or {}
    raw_banner   = banner.get("raw")    or "unknown"
    sw           = banner.get("software") or "unknown"
    protocol     = banner.get("protocol") or "2.0"

    # Classify all algorithm categories
    kex     = classify_kex(raw_json.get("kex", []))
    hkeys   = classify_host_keys(raw_json.get("key", []))
    ciphers = classify_ciphers(raw_json.get("enc", []))
    macs    = classify_macs(raw_json.get("mac", []))

    # Counts
    pqc_count       = sum(1 for k in kex if k["pqc_safe"])
    total_kex       = len(kex)
    has_weak_cipher = any(c["quantum_threat"] == "classically_weak" for c in ciphers)
    weak_ciphers    = [c["algorithm"] for c in ciphers if c["quantum_threat"] == "classically_weak"]
    weak_macs       = [m["algorithm"] for m in macs    if m["quantum_threat"] == "classically_weak"]

    # Priority and migration timeline
    priority = calculate_priority(sw, pqc_count, has_weak_cipher)

    if pqc_count > 0:
        timeline = "✓ PQC KEX in place — monitor for ML-DSA signatures"
    elif has_weak_cipher:
        timeline = "IMMEDIATE — remove weak ciphers, upgrade OpenSSH"
    else:
        timeline = "Upgrade to OpenSSH 9.0+ for PQC KEX"

    # Vulnerability list (flat, for dashboard)
    vulnerabilities = []
    for k in kex:
        if not k["pqc_safe"]:
            vulnerabilities.append({
                "component": "key_exchange",
                "algorithm": k["algorithm"],
                "threat":    k["quantum_threat"],
                "severity":  "high",
            })
    for hk in hkeys:
        if hk["quantum_threat"] == "shors_algorithm":
            vulnerabilities.append({
                "component": "host_key",
                "algorithm": hk["algorithm"],
                "threat":    hk["quantum_threat"],
                "severity":  "medium",
            })
    for c in ciphers:
        if c["quantum_threat"] == "classically_weak":
            vulnerabilities.append({
                "component": "cipher",
                "algorithm": c["algorithm"],
                "threat":    c["quantum_threat"],
                "severity":  "critical",
            })
    for m in macs:
        if m["quantum_threat"] == "classically_weak":
            vulnerabilities.append({
                "component": "mac",
                "algorithm": m["algorithm"],
                "threat":    m["quantum_threat"],
                "severity":  "critical",
            })

    return {
        "host":          original_host,
        "port":          int(port),
        "probe_status":  "success",
        "tls_enabled":   False,
        "ssh_banner":    raw_banner,
        "ssh_version":   sw,
        "ssh_protocol":  protocol,
        "pqc_ready":     pqc_count > 0,
        "os":            extract_os_from_banner(raw_banner),

        "key_exchange": {
            "total":                    total_kex,
            "pqc_safe_count":           pqc_count,
            "quantum_vulnerable_count": total_kex - pqc_count,
            "algorithms":               kex,
            "pqc_algorithms":           [k["algorithm"] for k in kex if k["pqc_safe"]],
            "vulnerable_algorithms":    [k["algorithm"] for k in kex if not k["pqc_safe"]],
        },

        "host_keys": {
            "total":      len(hkeys),
            "algorithms": hkeys,
        },

        "encryption": {
            "total":            len(ciphers),
            "algorithms":       ciphers,
            "has_weak_ciphers": has_weak_cipher,
            "weak_ciphers":     weak_ciphers,
        },

        "mac": {
            "total":      len(macs),
            "algorithms": macs,
            "weak_macs":  weak_macs,
        },

        "pqc_curve_assessment": {
            "pqc_ready":          pqc_count > 0,
            "migration_priority": priority,
            "vulnerabilities":    vulnerabilities,
        },

        "pqc_migration": {
            "priority": priority,
            "timeline": timeline,
        },

        "resolved_ip":     resolved_ip,
        "scan_timestamp":  utc_now(),
        "probe_errors":    [],
    }


def make_filtered_entry(host, port, reason="filtered"):
    """
    Create a placeholder record for filtered/closed/unreachable SSH ports.
    Equivalent to ssh_filtered_entry() in scan.sh.
    """
    if reason == "filtered":
        timeline = "SSH port filtered — check firewall/CDN"
    elif reason == "closed":
        timeline = "SSH port closed"
    else:
        timeline = "SSH unreachable"

    return {
        "host":         host,
        "port":         int(port),
        "probe_status": reason,
        "tls_enabled":  False,
        "ssh_banner":   None,
        "ssh_version":  None,
        "pqc_ready":    None,
        "os":           None,

        "key_exchange": {"total": 0, "pqc_safe_count": 0, "algorithms": []},
        "host_keys":    {"total": 0, "algorithms": []},
        "encryption":   {"total": 0, "algorithms": []},
        "mac":          {"total": 0, "algorithms": []},
        "probe_errors": [],

        "pqc_curve_assessment": {
            "pqc_ready":          None,
            "migration_priority": "UNKNOWN",
            "vulnerabilities":    [],
        },
        "pqc_migration": {
            "priority": "UNKNOWN",
            "timeline": timeline,
        },

        "scan_timestamp": utc_now(),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Step 5 — Scan a single host:port (full pipeline)
# ═══════════════════════════════════════════════════════════════════════════════

def scan_host(host, port, skip_nmap=False):
    """
    Full pipeline for a single host:port:
      A. TCP port pre-check
      B. ssh-audit
      C. fallback to parent domain
      D. fallback to resolved IP
      E. CDN bypass attempt if filtered

    Always returns a CBOM-compatible dict. Unreachable hosts return a
    make_filtered_entry() record rather than None.
    """
    # ── A: Port pre-check ──
    port_state = "open" if skip_nmap else check_port_tcp(host, port)
    debug(f"Port state for {host}:{port} → {port_state}")

    if port_state == "closed":
        debug(f"Port {port} closed on {host} — skipping")
        return make_filtered_entry(host, port, "closed")

    if port_state == "filtered":
        print(f"  ⚠  SSH filtered: {host}:{port} — trying alternatives...", file=sys.stderr)

        # ── E: CDN bypass — try alternate IPs ──
        alt_ips = try_resolve_real_ip(host)
        for alt_ip in alt_ips:
            debug(f"Trying alternative IP {alt_ip} for {host}:{port}")
            alt_state = check_port_tcp(alt_ip, port) if not skip_nmap else "open"
            if alt_state == "open":
                raw = run_ssh_audit(alt_ip, port)
                if raw:
                    print(f"  ✓  SSH found via alt IP {alt_ip} for {host}:{port}", file=sys.stderr)
                    return transform_ssh_audit(raw, host, alt_ip, port)

        # No alternative found — record as filtered
        return make_filtered_entry(host, port, "filtered")

    # ── B: Port is open — run ssh-audit directly ──
    raw = run_ssh_audit(host, port)

    # ── C: Fallback to parent domain ──
    if raw is None:
        parts = host.split(".", 1)
        if len(parts) == 2 and "." in parts[1]:
            parent = parts[1]
            debug(f"ssh-audit failed on {host} — retrying on parent domain {parent}")
            print(f"  ⚠  SSH fallback: {host} → {parent} (parent domain)", file=sys.stderr)
            raw = run_ssh_audit(parent, port)

    # ── D: Fallback to resolved IP ──
    fallback_ip = None
    if raw is None:
        fallback_ip = dig_a(host)
        if fallback_ip:
            debug(f"ssh-audit failed on {host} — retrying on resolved IP {fallback_ip}")
            raw = run_ssh_audit(fallback_ip, port)

    if raw is None:
        # Port was open but no valid SSH service found
        return make_filtered_entry(host, port, "no_ssh_banner")

    # Use already-resolved IP if we have it, otherwise look it up once
    resolved_ip = fallback_ip or dig_a(host) or host
    return transform_ssh_audit(raw, host, resolved_ip, port)


# ═══════════════════════════════════════════════════════════════════════════════
# scan command — scan many hosts from a file
# ═══════════════════════════════════════════════════════════════════════════════

def scan_from_file(input_file, output_file):
    """
    Scan multiple hosts from a text file.
    Input:  one host or host:port per line
    Output: JSONL file compatible with normalize_tls.py and pqc_cbom.py
    """
    # Parse host list
    targets = []
    try:
        with open(input_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Only treat "host:port" as a port split if the part after the
                # last colon is a pure integer — guards against IPv6 literals
                # (2001:db8::1) and hostnames that happen to contain colons.
                last_colon = line.rfind(":")
                if last_colon != -1 and line[last_colon + 1:].isdigit():
                    host = line[:last_colon]
                    port = int(line[last_colon + 1:])
                else:
                    host = line
                    port = 22
                targets.append((host, port))
    except FileNotFoundError:
        print(f"Error: input file not found: {input_file}", file=sys.stderr)
        sys.exit(1)

    total = len(targets)
    if total == 0:
        print("  No hosts to scan", file=sys.stderr)
        with open(output_file, "w") as f:
            pass
        return

    print(f"  Scanning {total} host(s)...", file=sys.stderr)

    # Counters
    start_time    = time.time()
    success_count = 0
    filtered_count = 0
    closed_count  = 0
    failed_count  = 0
    pqc_ready_count = 0

    with open(output_file, "w") as f_out:
        for idx, (host, port) in enumerate(targets, 1):

            # Progress with ETA
            elapsed = time.time() - start_time
            if idx > 1 and total > 5:
                avg    = elapsed / (idx - 1)
                eta    = avg * (total - idx + 1)
                eta_m  = int(eta // 60)
                eta_s  = int(eta % 60)
                print(f"  [{idx}/{total}] {host}:{port} (ETA: {eta_m}m {eta_s}s)", file=sys.stderr)
            else:
                print(f"  [{idx}/{total}] {host}:{port}", file=sys.stderr)

            result = scan_host(host, port)

            if result:
                f_out.write(json.dumps(result) + "\n")
                f_out.flush()  # ensure record is on disk even if process is killed mid-scan

                status = result.get("probe_status", "unknown")
                if status == "success":
                    success_count += 1
                    if result.get("pqc_ready"):
                        pqc_ready_count += 1
                elif status == "filtered":
                    filtered_count += 1
                elif status == "closed":
                    closed_count += 1
                else:
                    # no_ssh_banner or any other non-success probe status
                    failed_count += 1

    # Summary
    elapsed_total = time.time() - start_time
    elapsed_m = int(elapsed_total // 60)
    elapsed_s = int(elapsed_total % 60)

    print(f"\n  {'='*50}", file=sys.stderr)
    print(f"  SSH Scan Summary", file=sys.stderr)
    print(f"  {'='*50}", file=sys.stderr)
    print(f"  Duration:    {elapsed_m}m {elapsed_s}s", file=sys.stderr)
    print(f"  Total:       {total}", file=sys.stderr)
    print(f"  Open:        {success_count}", file=sys.stderr)
    print(f"  Filtered:    {filtered_count}", file=sys.stderr)
    print(f"  Closed:      {closed_count}", file=sys.stderr)
    print(f"  Failed:      {failed_count}", file=sys.stderr)
    print(f"  PQC Ready:   {pqc_ready_count}", file=sys.stderr)
    print(f"  Output:      {output_file}", file=sys.stderr)
    print(f"  {'='*50}\n", file=sys.stderr)


# ═══════════════════════════════════════════════════════════════════════════════
# analyze command — inspect a single host interactively
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_single_host(host, port):
    """
    Analyze a single host and print a detailed human-readable report.
    Useful for manual inspection and debugging.
    """
    print(f"\n{'='*60}", file=sys.stderr)
    print(f"  Analyzing: {host}:{port}", file=sys.stderr)
    print(f"{'='*60}\n", file=sys.stderr)

    result = scan_host(host, port)
    status = result.get("probe_status")

    if status == "success":
        sw       = result.get("ssh_version", "unknown")
        banner   = result.get("ssh_banner",  "unknown")
        pqc      = result.get("pqc_ready", False)
        priority = result.get("pqc_migration", {}).get("priority", "UNKNOWN")
        timeline = result.get("pqc_migration", {}).get("timeline", "")
        kex      = result.get("key_exchange", {})

        print(f"  Banner:       {banner}", file=sys.stderr)
        print(f"  Software:     {sw}", file=sys.stderr)
        print(f"  PQC Ready:    {'✓ YES' if pqc else '✗ NO'}", file=sys.stderr)
        print(f"  Priority:     {priority}", file=sys.stderr)
        print(f"  Timeline:     {timeline}", file=sys.stderr)
        print(file=sys.stderr)
        print(f"  Key Exchange ({kex.get('total', 0)} algorithms):", file=sys.stderr)
        for alg in kex.get("algorithms", []):
            safe = "✓" if alg["pqc_safe"] else "✗"
            print(f"    {safe} {alg['algorithm']} ({alg['quantum_threat']})", file=sys.stderr)
        print(file=sys.stderr)

        vuln = result.get("pqc_curve_assessment", {}).get("vulnerabilities", [])
        if vuln:
            print(f"  Vulnerabilities ({len(vuln)}):", file=sys.stderr)
            for v in vuln:
                print(f"    • [{v['severity'].upper()}] {v['component']}: {v['algorithm']} → {v['threat']}", file=sys.stderr)
        else:
            print("  Vulnerabilities: None found ✓", file=sys.stderr)

    elif status == "filtered":
        print(f"  Result: SSH port filtered (firewall/CDN)", file=sys.stderr)
    elif status == "closed":
        print(f"  Result: SSH port closed", file=sys.stderr)
    else:
        print(f"  Result: {status}", file=sys.stderr)

    print(file=sys.stderr)
    print("  Full JSON output:", file=sys.stderr)
    print(json.dumps(result, indent=2))

    return 0


# ═══════════════════════════════════════════════════════════════════════════════
# Usage
# ═══════════════════════════════════════════════════════════════════════════════

def print_usage():
    print("""
QubitAC SSH Scanner — Standalone PQC SSH Assessment Tool
https://qubitac.com

Usage:
  python3 ssh_scanner.py scan <hosts.txt> <output.jsonl>
      Scan hosts from file (one host or host:port per line)
      Output is compatible with normalize_tls.py and pqc_cbom.py

  python3 ssh_scanner.py analyze <hostname> [port]
      Analyze a single host and print detailed results (default port: 22)

Environment Variables:
  SCAN_TIMEOUT   Connection timeout in seconds (default: 10)
  DEBUG          Set to 1 for verbose debug output (default: 0)

Examples:
  python3 ssh_scanner.py scan live/domains.txt crypto/ssh.jsonl
  python3 ssh_scanner.py analyze example.com
  python3 ssh_scanner.py analyze example.com 2222
  SCAN_TIMEOUT=30 python3 ssh_scanner.py scan hosts.txt output.jsonl
  DEBUG=1 python3 ssh_scanner.py analyze example.com

Input File Format (hosts.txt):
  example.com           (uses default port 22)
  example.com:22        (explicit port)
  example.com:2222      (non-standard port)

Output Format:
  JSONL — one JSON record per host, compatible with:
    normalize_tls.py  →  findings/findings.jsonl
    pqc_cbom.py       →  cbom/crypto-bom.json

Dependencies:
  ssh-audit    pip3 install ssh-audit
  dig          apt install dnsutils  /  brew install bind
""")


# ═══════════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    command = sys.argv[1]

    if command == "scan":
        if len(sys.argv) != 4:
            print("Usage: python3 ssh_scanner.py scan <hosts.txt> <output.jsonl>")
            sys.exit(1)
        scan_from_file(sys.argv[2], sys.argv[3])

    elif command == "analyze":
        if len(sys.argv) < 3:
            print("Usage: python3 ssh_scanner.py analyze <hostname> [port]")
            sys.exit(1)
        host = sys.argv[2]
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 22
        sys.exit(analyze_single_host(host, port))

    elif command in ["-h", "--help", "help"]:
        print_usage()
        sys.exit(0)

    else:
        print(f"Unknown command: {command}")
        print_usage()
        sys.exit(1)


if __name__ == "__main__":
    main()
