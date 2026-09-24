#!/usr/bin/env python3
"""scripts/build_attestation.py

Standalone fallback attestation assembler for the Phase 1 disposable sandbox
(see ARCHITECTURE.md and .github/workflows/dynamic-sandbox.yml).

TODO(attestation.rs): this script exists only because `src/attestation.rs`
and an `aur-sentry attest` CLI subcommand did not exist yet when the dynamic
sandbox workflow was written. Once that CLI lands, prefer it (see the
`aur-sentry attest --help` check in scripts/dynamic_sandbox.sh) and treat
this script as a break-glass fallback / reference for the JSON shape,
matching schemas/attestation.schema.json.

Best-effort only:
  - Behavior classification of static findings is a small heuristic keyword
    map, not the real rule_id -> Behavior taxonomy the Rust types will own.
  - Network telemetry is IP:port only; strace does not resolve hostnames,
    so "destination" is the raw IP the traced process connected to. This
    script does a best-effort DNS lookup of PKGBUILD-declared source hosts
    to build an "expected" IP allowlist for the undeclared-network check.
  - No signature (Phase 3 will add Sigstore/cosign or ed25519).
"""

import argparse
import hashlib
import json
import re
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

# Heuristic rule_id/description keyword -> schema `behavior` enum mapping.
BEHAVIOR_KEYWORDS = [
    (("OBFUSCAT", "BASE64", "HEX"), "OBFUSCATION"),
    (("CREDENTIAL", "SSH", "AWS", "GCLOUD", "KUBE", "PASSWORD", "TOKEN", "BROWSER"), "CREDENTIAL_ACCESS"),
    (("CURL", "WGET", "NETWORK", "DOWNLOAD", "HTTP", "WEBHOOK", "C2", "EXFIL"), "NETWORK_ACCESS"),
    (("CRON", "SYSTEMD", "AUTOSTART", "PERSIST", "BASHRC", "PROFILE.D"), "PERSISTENCE"),
    (("SUID", "SUDO", "ROOT", "PRIVILEGE"), "PRIVILEGE_ESCALATION"),
    (("SERVICE", "SYSTEMCTL"), "SERVICE_MANIPULATION"),
    (("PACMAN", "MAKEPKG", "INSTALL"), "PACKAGE_INSTALLATION"),
    (("CHMOD", "RM ", "WRITE", "DD ", "/DEV/"), "ARBITRARY_FILESYSTEM_WRITE"),
    (("EVAL", "PIPE", "SH -C", "BASH -C", "EXEC"), "SHELL_EXECUTION"),
]

FINDING_BLOCK_RE = re.compile(
    r"\[(?P<sev>[A-Z]+)\]\s+(?P<rule>\S+)\s*\n"
    r"\s*(?P<desc>.+?)\s*\n"
    r"\s*line (?P<line>\d+): (?P<matched>.*)",
)

STRACE_CONNECT_RE = re.compile(
    r'(?:connect|sendto)\(.*?sin_port=htons\((?P<port>\d+)\).*?sin_addr=inet_addr\("(?P<ip>[\d.]+)"\)'
)
STRACE_OPEN_RE = re.compile(r'open(?:at)?\([^)]*"(?P<path>[^"]+)"')


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path):
    p = Path(path)
    if not p.is_file():
        return None
    h = hashlib.sha256()
    h.update(p.read_bytes())
    return h.hexdigest()


def classify_behavior(rule_id: str, description: str) -> str:
    hay = f"{rule_id} {description}".upper()
    for keywords, behavior in BEHAVIOR_KEYWORDS:
        if any(k in hay for k in keywords):
            return behavior
    return "SHELL_EXECUTION"  # conservative default — something matched a rule at all


def parse_static_findings(log_path):
    findings = []
    if not log_path:
        return findings
    p = Path(log_path)
    if not p.is_file():
        return findings
    text = p.read_text(errors="replace")
    for m in FINDING_BLOCK_RE.finditer(text):
        sev = m.group("sev")
        if sev not in SEVERITIES:
            continue
        rule_id = m.group("rule")
        desc = m.group("desc").strip()
        findings.append(
            {
                "behavior": classify_behavior(rule_id, desc),
                "file": "PKGBUILD",
                "line": int(m.group("line")),
                "severity": sev,
                "description": f"[{rule_id}] {desc}",
            }
        )
    return findings


def declared_source_ips(pkgbuild_path):
    """Best-effort: resolve hostnames from PKGBUILD source=() URLs to an
    allowlist of IPs, so we can flag telemetry connections that don't match
    any declared source."""
    ips = set()
    if not pkgbuild_path:
        return ips
    p = Path(pkgbuild_path)
    if not p.is_file():
        return ips
    text = p.read_text(errors="replace")
    for url in re.findall(r"https?://[^\s\"'()]+", text):
        host = urlparse(url).hostname
        if not host:
            continue
        try:
            ips.add(socket.gethostbyname(host))
        except OSError:
            continue
    return ips


def parse_telemetry(telemetry_path, allowed_ips):
    processes, network, filesystem = [], [], []
    if not telemetry_path:
        return processes, network, filesystem
    p = Path(telemetry_path)
    if not p.is_file() or p.stat().st_size == 0:
        return processes, network, filesystem
    text = p.read_text(errors="replace")

    seen_net = set()
    for m in STRACE_CONNECT_RE.finditer(text):
        ip, port = m.group("ip"), int(m.group("port"))
        key = (ip, port)
        if key in seen_net:
            continue
        seen_net.add(key)
        flagged = ip not in allowed_ips and not ip.startswith("127.")
        network.append(
            {
                "destination": ip,
                "port": port,
                "protocol": "undeclared" if flagged else "declared-source",
                "timestamp": now_iso(),
            }
        )

    seen_fs = set()
    for m in STRACE_OPEN_RE.finditer(text):
        path = m.group("path")
        if "id_fake" not in path and ".aws/credentials" not in path:
            continue
        if path in seen_fs:
            continue
        seen_fs.add(path)
        filesystem.append(
            {"path": path, "operation": "canary_access", "timestamp": now_iso()}
        )

    return processes, network, filesystem


def determine_verdict(static_findings, network, filesystem, strace_available, makepkg_exit):
    if filesystem:
        return "MALICIOUS"  # canary secret was touched — confirmed exfiltration attempt
    if any(n["protocol"] == "undeclared" for n in network):
        return "SUSPICIOUS"
    if any(f["severity"] == "CRITICAL" for f in static_findings):
        return "MALICIOUS"
    if any(f["severity"] == "HIGH" for f in static_findings):
        return "SUSPICIOUS"
    if static_findings:
        return "SUSPICIOUS"
    if makepkg_exit not in (0, None):
        return "BUILD_FAILED"
    if not strace_available:
        return "INCONCLUSIVE"
    return "VERIFIED"


def build(args):
    if args.analysis_failed:
        obj = {
            "schema_version": "1.0",
            "package": {"name": args.package, "version": args.version, "arch": args.arch},
            "source": {"aur_commit": "", "pkgbuild_sha256": "0" * 64, "install_sha256": None},
            "analyzed_at": now_iso(),
            "scanner_version": args.scanner_version,
            "static_findings": [],
            "dynamic_evidence": {"collected": False, "processes": [], "network": [], "filesystem": []},
            "package_analysis": {"file_count": 0, "elf_object_count": 0},
            "reproducibility": "NOT_ATTEMPTED",
            "external_intelligence": [{"source": "dynamic-sandbox", "summary": args.note or "analysis failed", "url": None}],
            "verdict": "ANALYSIS_FAILED",
        }
        return obj

    pkgbuild_sha = sha256_file(args.pkgbuild) or "0" * 64
    install_sha = None
    for install_path in args.install_glob or []:
        s = sha256_file(install_path)
        if s:
            install_sha = s
            break

    static_findings = parse_static_findings(args.static_log)
    allowed_ips = declared_source_ips(args.pkgbuild)
    strace_available = str(args.strace_available).lower() == "true"
    processes, network, filesystem = parse_telemetry(args.telemetry_log, allowed_ips) if strace_available else ([], [], [])

    makepkg_exit = args.makepkg_exit
    verdict = determine_verdict(static_findings, network, filesystem, strace_available, makepkg_exit)

    obj = {
        "schema_version": "1.0",
        "package": {"name": args.package, "version": args.version, "arch": args.arch},
        "source": {
            "aur_commit": args.aur_commit or "",
            "pkgbuild_sha256": pkgbuild_sha,
            "install_sha256": install_sha,
        },
        "analyzed_at": now_iso(),
        "scanner_version": args.scanner_version,
        "static_findings": static_findings,
        "dynamic_evidence": {
            "collected": strace_available,
            "processes": processes,
            "network": network,
            "filesystem": filesystem,
        },
        "package_analysis": {"file_count": 0, "elf_object_count": 0},
        "reproducibility": "NOT_ATTEMPTED",
        "external_intelligence": [],
        "verdict": verdict,
    }
    return obj


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--package", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--arch", default="x86_64")
    ap.add_argument("--aur-commit", default="")
    ap.add_argument("--pkgbuild")
    ap.add_argument("--install-glob", nargs="*", default=[])
    ap.add_argument("--static-log")
    ap.add_argument("--telemetry-log")
    ap.add_argument("--strace-available", default="false")
    ap.add_argument("--makepkg-exit", type=int, default=None)
    ap.add_argument("--scanner-version", default="aur-sentry-dynamic-sandbox-fallback/1.0")
    ap.add_argument("--analysis-failed", action="store_true")
    ap.add_argument("--note", default=None)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    obj = build(args)

    # evidence_hash over the canonical object, excluding evidence_hash/signature
    canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    obj["evidence_hash"] = hashlib.sha256(canonical.encode()).hexdigest()
    obj["signature"] = None  # Phase 3: Sigstore/cosign or ed25519

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")
    print(f"wrote {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
