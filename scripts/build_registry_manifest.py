#!/usr/bin/env python3
"""scripts/build_registry_manifest.py

Walks data/attestations/<package>/<version>.json and emits a flat manifest at
docs/data/manifest.json for the static GitHub Pages registry UI to fetch.

No third-party dependencies (stdlib only), so it runs anywhere a bare python3
is available -- including a plain GitHub Actions runner with no extra setup.

Output shape (list, newest-analyzed-first within each package):
[
  {
    "package": "example-verified-pkg",
    "version": "1.2.3-1",
    "verdict": "VERIFIED",
    "analyzed_at": "2026-09-20T04:12:00Z",
    "arch": "x86_64",
    "path": "data/attestations/example-verified-pkg/1.2.3-1.json"
  },
  ...
]

Malformed attestation files are skipped with a warning on stderr rather than
aborting the whole build -- one bad file shouldn't take the registry down.
"""

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ATTESTATIONS_DIR = REPO_ROOT / "data" / "attestations"
OUTPUT_PATH = REPO_ROOT / "docs" / "data" / "manifest.json"

REQUIRED_FIELDS = ("package", "verdict", "analyzed_at")


def load_attestation(path: Path):
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"warning: skipping {path}: {exc}", file=sys.stderr)
        return None

    package = data.get("package") or {}
    name = package.get("name")
    version = package.get("version")
    arch = package.get("arch")
    verdict = data.get("verdict")
    analyzed_at = data.get("analyzed_at")

    if not name or not version or not verdict or not analyzed_at:
        print(f"warning: skipping {path}: missing required field(s)", file=sys.stderr)
        return None

    source = data.get("source") or {}
    pkgbuild_sha256 = source.get("pkgbuild_sha256") or ""
    aur_commit = source.get("aur_commit") or ""

    static_findings = data.get("static_findings") or []
    findings_count = len(static_findings)

    sig_file = Path(str(path) + ".sig")
    has_signature = bool(data.get("signature")) or sig_file.is_file()

    deps = (
        data.get("dependencies")
        or (data.get("package_analysis") or {}).get("dependencies")
        or []
    )
    dependencies_count = len(deps) if isinstance(deps, (list, dict)) else 0

    return {
        "package": name,
        "version": version,
        "verdict": verdict,
        "analyzed_at": analyzed_at,
        "arch": arch,
        "path": str(path.relative_to(REPO_ROOT)),
        "pkgbuild_sha256": pkgbuild_sha256,
        "aur_commit": aur_commit,
        "findings_count": findings_count,
        "has_signature": has_signature,
        "dependencies_count": dependencies_count,
    }


def main():
    entries = []
    if ATTESTATIONS_DIR.is_dir():
        for pkg_dir in sorted(ATTESTATIONS_DIR.iterdir()):
            if not pkg_dir.is_dir():
                continue
            for version_file in sorted(pkg_dir.glob("*.json")):
                entry = load_attestation(version_file)
                if entry is not None:
                    entries.append(entry)

    entries.sort(key=lambda e: (e["package"], e["analyzed_at"]), reverse=False)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(entries, indent=2, sort_keys=True) + "\n")
    print(f"wrote {OUTPUT_PATH} ({len(entries)} attestation(s))", file=sys.stderr)


if __name__ == "__main__":
    main()
