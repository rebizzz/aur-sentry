/* Shared helpers for the AUR Sentry static registry pages. No dependencies. */

const VERDICT_COPY = {
  VERIFIED: "Verified",
  SUSPICIOUS: "Suspicious",
  MALICIOUS: "Malicious",
  INCONCLUSIVE: "Inconclusive",
  BUILD_FAILED: "Build failed",
  ANALYSIS_FAILED: "Analysis failed",
  STALE: "Out of date",
  UNSUPPORTED: "Unsupported",
};

function verdictLabel(verdict) {
  return VERDICT_COPY[verdict] || verdict;
}

function badgeHtml(verdict) {
  const cls = `badge badge-${verdict}`;
  return `<span class="${cls}">${escapeHtml(verdictLabel(verdict))}</span>`;
}

function escapeHtml(str) {
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function formatTimestamp(iso) {
  if (!iso) return "unknown time";
  try {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return d.toLocaleString(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return iso;
  }
}

/* Resolves manifest.json relative to the current page so this works whether
   the site is served at the repo root or under a GitHub Pages project path
   (e.g. https://user.github.io/aur-sentry/). */
function manifestUrl() {
  return new URL("data/manifest.json", document.baseURI).toString();
}

function packagePageUrl(name) {
  return `package.html?name=${encodeURIComponent(name)}`;
}

async function fetchManifest() {
  const res = await fetch(manifestUrl(), { cache: "no-store" });
  if (!res.ok) {
    throw new Error(`manifest.json request failed: ${res.status}`);
  }
  return res.json();
}

/* Given the flat manifest list, collapse to one entry per package: the most
   recently analyzed version. */
function latestPerPackage(entries) {
  const latest = new Map();
  for (const entry of entries) {
    const existing = latest.get(entry.package);
    if (!existing || entry.analyzed_at > existing.analyzed_at) {
      latest.set(entry.package, entry);
    }
  }
  return [...latest.values()].sort((a, b) => a.package.localeCompare(b.package));
}
