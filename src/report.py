"""
Reporting module for generating advisories.json, RSS feed, and README alert tables.
"""

from __future__ import annotations

import datetime
import html
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, List


@dataclass
class Advisory:
    package: str
    version: str
    maintainer: str
    highest_severity: str
    detected_at: str
    findings: list[dict[str, Any]]
    aur_url: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ReportGenerator:
    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self.advisories_file = output_dir / "advisories.json"
        self.feed_file = output_dir / "advisories.xml"

    def load_existing_advisories(self) -> list[dict[str, Any]]:
        if not self.advisories_file.exists():
            return []
        try:
            with open(self.advisories_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("advisories", [])
        except Exception:
            return []

    def save_advisories(self, new_advisories: list[Advisory]) -> None:
        existing = {adv["package"]: adv for adv in self.load_existing_advisories()}

        for adv in new_advisories:
            existing[adv.package] = adv.to_dict()

        sorted_advisories = sorted(
            existing.values(),
            key=lambda x: (
                0 if x["highest_severity"] == "CRITICAL" else 1 if x["highest_severity"] == "HIGH" else 2,
                x.get("detected_at", ""),
            ),
        )

        payload = {
            "version": "1.0",
            "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "total_flagged": len(sorted_advisories),
            "advisories": sorted_advisories,
        }

        with open(self.advisories_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        self._generate_rss(sorted_advisories)

    def _generate_rss(self, advisories: list[dict[str, Any]]) -> None:
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
        items = []
        for adv in advisories[:30]:
            title = html.escape(f"[{adv['highest_severity']}] Suspicious pattern in {adv['package']} ({adv['version']})")
            desc = html.escape(f"Maintainer: {adv['maintainer']}<br>Rules triggered: {', '.join(f['rule_id'] for f in adv['findings'])}")
            items.append(f"""    <item>
      <title>{title}</title>
      <link>{html.escape(adv['aur_url'])}</link>
      <description>{desc}</description>
      <pubDate>{html.escape(adv.get('detected_at', now))}</pubDate>
      <guid>{html.escape(adv['aur_url'])}#{html.escape(adv['version'])}</guid>
    </item>""")

        rss_content = f"""<?xml version="1.0" encoding="UTF-8" ?>
<rss version="2.0">
  <channel>
    <title>AUR-Sentry Security Advisories</title>
    <link>https://github.com/rebizzz/aur-sentry</link>
    <description>Automated supply-chain security alerts for Arch User Repository (AUR) packages</description>
    <lastBuildDate>{now}</lastBuildDate>
{chr(10).join(items)}
  </channel>
</rss>"""

        with open(self.feed_file, "w", encoding="utf-8") as f:
            f.write(rss_content)
