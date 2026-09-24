"""
Main entry point for AUR-Sentry CLI and Autopilot scheduled pipeline.
"""

from __future__ import annotations

import argparse
import datetime
import json
import logging
import sys
from pathlib import Path
from typing import List

from .aur_client import AURClient
from .report import Advisory, ReportGenerator
from .scanner import PKGBUILDScanner

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("aur-sentry")


def update_readme_table(repo_root: Path, advisories: list[dict]) -> None:
    readme_path = repo_root / "README.md"
    if not readme_path.exists():
        return

    content = readme_path.read_text(encoding="utf-8")
    start_tag = "<!-- AUTOPILOT_TABLE_START -->"
    end_tag = "<!-- AUTOPILOT_TABLE_END -->"

    if start_tag not in content or end_tag not in content:
        return

    if not advisories:
        table_md = "\n*No active high-severity threats currently recorded in the radar.*\n"
    else:
        table_lines = [
            "\n| Severity | Package | Version | Maintainer | Triggers | Link |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
        for adv in advisories[:15]:
            sev_badge = f"`{adv['highest_severity']}`"
            if adv['highest_severity'] == "CRITICAL":
                sev_badge = "🔴 **CRITICAL**"
            elif adv['highest_severity'] == "HIGH":
                sev_badge = "🟠 **HIGH**"
            elif adv['highest_severity'] == "MEDIUM":
                sev_badge = "🟡 **MEDIUM**"

            triggers = ", ".join(f"`{f['rule_id']}`" for f in adv["findings"][:2])
            link = f"[AUR]({adv['aur_url']})"
            table_lines.append(
                f"| {sev_badge} | `{adv['package']}` | {adv['version']} | {adv.get('maintainer', 'orphan')} | {triggers} | {link} |"
            )
        table_md = "\n" + "\n".join(table_lines) + "\n"

    new_content = (
        content[: content.index(start_tag) + len(start_tag)]
        + table_md
        + content[content.index(end_tag) :]
    )
    readme_path.write_text(new_content, encoding="utf-8")


def run_autopilot(repo_root: Path, limit: int = 50) -> int:
    logger.info("Starting AUR-Sentry Autopilot run...")
    client = AURClient()
    scanner = PKGBUILDScanner()
    reporter = ReportGenerator(repo_root)

    # 1. Fetch recently updated packages via search terms or keyword rotations
    candidates = []
    # Test broad search rotation terms to find recently pushed packages
    search_keywords = ["bin", "git", "tools", "app", "theme", "daemon"]
    seen_names = set()

    for kw in search_keywords:
        results = client.search_recent(kw)
        for pkg in results:
            name = pkg.get("Name")
            if name and name not in seen_names:
                seen_names.add(name)
                candidates.append(pkg)
            if len(candidates) >= limit:
                break
        if len(candidates) >= limit:
            break

    logger.info("Analyzing %d package candidates...", len(candidates))
    new_advisories = []

    for pkg in candidates:
        name = pkg.get("Name")
        version = pkg.get("Version", "unknown")
        maintainer = pkg.get("Maintainer", "orphan") or "orphan"
        aur_url = f"https://aur.archlinux.org/packages/{name}"

        pkgbuild_content = client.fetch_pkgbuild(name)
        if not pkgbuild_content:
            continue

        findings = scanner.scan_pkgbuild(pkgbuild_content, pkgname=name)
        if findings:
            severities = [f.severity for f in findings]
            highest_sev = "CRITICAL" if "CRITICAL" in severities else ("HIGH" if "HIGH" in severities else "MEDIUM")
            logger.warning("Flagged %s (%s) with %d findings!", name, highest_sev, len(findings))

            new_advisories.append(
                Advisory(
                    package=name,
                    version=version,
                    maintainer=maintainer,
                    highest_severity=highest_sev,
                    detected_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    findings=[f.to_dict() for f in findings],
                    aur_url=aur_url,
                )
            )

    reporter.save_advisories(new_advisories)
    all_advisories = reporter.load_existing_advisories()
    update_readme_table(repo_root, all_advisories)
    logger.info("Autopilot complete. Total active advisories: %d", len(all_advisories))
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="AUR-Sentry: Supply-Chain Watchdog for the AUR")
    subparsers = parser.add_subparsers(dest="command")

    # Command: scan-file
    file_parser = subparsers.add_parser("scan-file", help="Scan a local PKGBUILD file")
    file_parser.add_argument("path", type=Path, help="Path to PKGBUILD")

    # Command: scan-pkg
    pkg_parser = subparsers.add_parser("scan-pkg", help="Scan a remote package on the AUR")
    pkg_parser.add_argument("pkgname", type=str, help="AUR package name")

    # Command: autopilot
    auto_parser = subparsers.add_parser("autopilot", help="Run scheduled autopilot scan and update advisories")
    auto_parser.add_argument("--repo-root", type=Path, default=Path("."), help="Path to repo root")
    auto_parser.add_argument("--limit", type=int, default=40, help="Number of packages to inspect")

    args = parser.parse_args()

    if args.command == "scan-file":
        if not args.path.exists():
            print(f"Error: {args.path} does not exist", file=sys.stderr)
            sys.exit(1)
        content = args.path.read_text(encoding="utf-8", errors="replace")
        scanner = PKGBUILDScanner()
        findings = scanner.scan_pkgbuild(content)
        if findings:
            print(f"[!] {len(findings)} suspicious finding(s) detected:")
            for f in findings:
                print(f"  - [{f.severity}] {f.rule_id}: {f.description} (line {f.line_number})")
                print(f"    Snippet: {f.matched_text}")
            sys.exit(2)
        else:
            print("[+] Clean: No suspicious patterns found.")
            sys.exit(0)

    elif args.command == "scan-pkg":
        client = AURClient()
        scanner = PKGBUILDScanner()
        print(f"[*] Fetching PKGBUILD for '{args.pkgname}' from AUR...")
        content = client.fetch_pkgbuild(args.pkgname)
        if not content:
            print(f"[-] Could not find or download PKGBUILD for '{args.pkgname}'", file=sys.stderr)
            sys.exit(1)
        findings = scanner.scan_pkgbuild(content, pkgname=args.pkgname)
        if findings:
            print(f"[!] WARNING: {len(findings)} finding(s) in '{args.pkgname}':")
            for f in findings:
                print(f"  - [{f.severity}] {f.rule_id}: {f.description} (line {f.line_number})")
                print(f"    Match: {f.matched_text}")
            sys.exit(2)
        else:
            print(f"[+] '{args.pkgname}' passed static analysis cleanly.")
            sys.exit(0)

    elif args.command == "autopilot":
        sys.exit(run_autopilot(args.repo_root, limit=args.limit))

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
