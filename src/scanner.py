"""
Static analysis heuristics engine for PKGBUILD and .install files.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, List, Optional


@dataclass
class Finding:
    rule_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    line_number: int
    matched_text: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class PKGBUILDScanner:
    """
    Scans PKGBUILD scripts and install hooks for known malicious signatures,
    anti-analysis obfuscation, suspicious networking, and packaging anomalies.
    """

    RULES = [
        {
            "id": "RULE_OBFUSCATED_BASE64",
            "severity": "CRITICAL",
            "pattern": r"(?:echo|printf)\s+['\"][A-Za-z0-9+/=]{20,}['\"]\s*\|\s*base64\s+(?:-d|--decode)\s*\|\s*(?:bash|sh|perl|python)",
            "description": "Obfuscated base64 payload piped directly to an interpreter.",
        },
        {
            "id": "RULE_HEX_EXEC",
            "severity": "CRITICAL",
            "pattern": r"(?:xxd\s+-r|-p\s+.*\|\s*(?:bash|sh)|echo\s+['\"][\\x[0-9a-fA-F]{2}]+['\"]\s*\|\s*(?:bash|sh))",
            "description": "Hex-encoded payload decoded and piped directly to shell execution.",
        },
        {
            "id": "RULE_DISCORD_WEBHOOK",
            "severity": "CRITICAL",
            "pattern": r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+",
            "description": "Hardcoded Discord webhook URL (often used for token/credential exfiltration).",
        },
        {
            "id": "RULE_TELEGRAM_BOT_EXFIL",
            "severity": "CRITICAL",
            "pattern": r"https://api\.telegram\.org/bot[0-9]+:[A-Za-z0-9_-]+",
            "description": "Telegram bot API endpoint (common C2 / exfiltration channel).",
        },
        {
            "id": "RULE_REVERSE_SHELL",
            "severity": "CRITICAL",
            "pattern": r"(?:/dev/tcp/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+|nc\s+(?:-[a-zA-Z]*e\s+|[0-9.]+)\s+\d+|mkfifo\s+/tmp/[a-z0-9]+;\s*cat\s+/tmp/)",
            "description": "Classic reverse shell payload (/dev/tcp, netcat -e, or fifo pipe).",
        },
        {
            "id": "RULE_RAW_IP_DOWNLOAD",
            "severity": "HIGH",
            "pattern": r"https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?/[^\s'\"]*",
            "description": "Direct download from raw IP address instead of domain name.",
        },
        {
            "id": "RULE_CURL_PIPE_EXEC",
            "severity": "HIGH",
            "pattern": r"(?:curl|wget)\s+[^|\n]+(?:\|\s*(?:sudo\s+)?(?:bash|sh|python|perl))",
            "description": "Remote network download piped directly into an interpreter without validation.",
        },
        {
            "id": "RULE_PASTEBIN_DOWNLOAD",
            "severity": "HIGH",
            "pattern": r"https?://(?:pastebin\.com/raw/|hastebin\.com/raw/|ghostbin\.co/|transfer\.sh/|catbox\.moe/)",
            "description": "Downloading unversioned, mutable payload from pastebin or temporary file host.",
        },
        {
            "id": "RULE_SENSITIVE_FS_ACCESS",
            "severity": "HIGH",
            "pattern": r"(?:~/\.ssh|\$HOME/\.ssh|/etc/shadow|/etc/sudoers|/boot/vmlinuz|~/\.gnupg)",
            "description": "Direct access to sensitive credentials, system security files, or kernel.",
        },
        {
            "id": "RULE_ROOT_PERSISTENCE",
            "severity": "HIGH",
            "pattern": r"(?:/etc/cron\.(?:daily|hourly|weekly|d)/|/var/spool/cron/|/etc/systemd/system/)",
            "description": "Modification of system crontab or persistence directories directly in script.",
        },
        {
            "id": "RULE_SKIP_HASH_REMOTE",
            "severity": "MEDIUM",
            "pattern": r"(?:sha256sums|sha512sums|md5sums)(?:_[a-z0-9_]+)?=\s*\([^\)]*['\"]SKIP['\"][^\)]*\)",
            "description": "Integrity checksum verification explicitly bypassed ('SKIP') for source files.",
        },
    ]

    def __init__(self, popular_packages: Optional[list[str]] = None) -> None:
        if popular_packages is not None:
            self.popular_packages = set(popular_packages)
        else:
            self.popular_packages = set()
            data_file = Path(__file__).resolve().parent.parent / "data" / "popular_packages.json"
            if data_file.exists():
                try:
                    import json
                    self.popular_packages = set(json.loads(data_file.read_text(encoding="utf-8")))
                except Exception:
                    pass

    def scan_pkgbuild(self, content: str, pkgname: Optional[str] = None) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()

        # 1. Rule-based static pattern scanning
        for rule in self.RULES:
            regex = re.compile(rule["pattern"], re.IGNORECASE)
            for idx, line in enumerate(lines, start=1):
                stripped = line.strip()
                # Skip comments
                if stripped.startswith("#"):
                    continue

                match = regex.search(line)
                if match:
                    findings.append(
                        Finding(
                            rule_id=rule["id"],
                            severity=rule["severity"],
                            description=rule["description"],
                            line_number=idx,
                            matched_text=match.group(0)[:120],
                        )
                    )

        # 2. Typosquatting check
        if pkgname and self.popular_packages and pkgname not in self.popular_packages:
            typo_target = self._check_typosquatting(pkgname)
            if typo_target:
                findings.append(
                    Finding(
                        rule_id="RULE_TYPOSQUATTING",
                        severity="MEDIUM",
                        description=f"Package name '{pkgname}' closely resembles high-popularity package '{typo_target}'.",
                        line_number=1,
                        matched_text=f"{pkgname} -> {typo_target}",
                    )
                )

        return findings

    def _check_typosquatting(self, candidate: str) -> Optional[str]:
        if len(candidate) < 4:
            return None
        candidate_clean = candidate.lower().replace("-bin", "").replace("-git", "")
        for popular in self.popular_packages:
            target_clean = popular.lower().replace("-bin", "").replace("-git", "")
            if candidate_clean == target_clean:
                continue
            if abs(len(candidate_clean) - len(target_clean)) <= 2:
                dist = self._damerau_levenshtein(candidate_clean, target_clean)
                if dist <= 1 or (len(candidate_clean) >= 8 and dist <= 2):
                    return popular
        return None

    @staticmethod
    def _damerau_levenshtein(s1: str, s2: str) -> int:
        d = {}
        len1 = len(s1)
        len2 = len(s2)
        for i in range(-1, len1 + 1):
            d[(i, -1)] = i + 1
        for j in range(-1, len2 + 1):
            d[(-1, j)] = j + 1

        for i in range(len1):
            for j in range(len2):
                cost = 0 if s1[i] == s2[j] else 1
                d[(i, j)] = min(
                    d[(i - 1, j)] + 1,        # deletion
                    d[(i, j - 1)] + 1,        # insertion
                    d[(i - 1, j - 1)] + cost  # substitution
                )
                if i > 0 and j > 0 and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                    d[(i, j)] = min(d[(i, j)], d[(i - 2, j - 2)] + 1)  # transposition

        return d[(len1 - 1, len2 - 1)]
