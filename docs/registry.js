/* AUR Sentry — Modern Static Registry Frontend Logic
   Zero dependencies. Offline-resilient, reactive client-side search, theming, and attestation rendering. */

const RAW_BASE = "https://raw.githubusercontent.com/rebizzz/aur-sentry/main/";

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

const VERDICT_EXPLANATION = {
  VERIFIED: "The build succeeded and nothing in static or dynamic analysis looked suspicious. Cryptographic and structural verification passed.",
  SUSPICIOUS: "Something in this package's behavior doesn't match what a normal build/install should do. Review the evidence carefully before installing.",
  MALICIOUS: "This package showed confirmed malicious behavior, such as touching planted canary credentials, reverse shell execution, or exfiltrating data. Do not install.",
  INCONCLUSIVE: "Analysis completed but the evidence was insufficient to reach a definitive verdict.",
  BUILD_FAILED: "The package failed to build in the disposable sandbox, so full dynamic verification could not be completed.",
  ANALYSIS_FAILED: "The analysis pipeline itself encountered an error for this package version.",
  STALE: "The AUR source repository has updated since this attestation was generated. Treat this verdict as out of date.",
  UNSUPPORTED: "This package uses an architecture or build system not currently supported by the scanner.",
};

const BEHAVIOR_COPY = {
  NETWORK_ACCESS: "Made a network connection",
  SHELL_EXECUTION: "Ran a shell command",
  CREDENTIAL_ACCESS: "Accessed credential material",
  PERSISTENCE: "Configured persistence mechanism",
  PRIVILEGE_ESCALATION: "Attempted privilege escalation",
  OBFUSCATION: "Used obfuscated or encoded code",
  DYNAMIC_DOWNLOAD: "Downloaded and ran remote code at build/install",
  ARBITRARY_FILESYSTEM_WRITE: "Wrote outside package build root",
  PACKAGE_INSTALLATION: "Attempted external package installation",
  SERVICE_MANIPULATION: "Modified system service or daemon",
};

/* SVG Icons Dictionary */
const ICONS = {
  sun: `<svg class="theme-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>`,
  moon: `<svg class="theme-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`,
  shieldCheck: `<svg class="badge-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>`,
  alertTriangle: `<svg class="badge-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
  skull: `<svg class="badge-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="9" cy="12" r="1"/><circle cx="15" cy="12" r="1"/><path d="M8 20v2h8v-2"/><path d="M12.5 17l-.5-1-.5 1"/><path d="M16 20a3 3 0 0 0 1.2-2.3 8 8 0 1 0-10.4 0A3 3 0 0 0 8 20"/></svg>`,
  wrench: `<svg class="badge-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>`,
  infoCircle: `<svg class="badge-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`,
  copy: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`,
  check: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="20 6 9 17 4 12"/></svg>`,
  cross: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`,
  search: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>`,
  extLink: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>`,
  arrowLeft: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></svg>`,
};

function verdictLabel(verdict) {
  return VERDICT_COPY[verdict] || verdict;
}

function getVerdictIconSvg(verdict) {
  switch (verdict) {
    case "VERIFIED":
      return ICONS.shieldCheck;
    case "SUSPICIOUS":
      return ICONS.alertTriangle;
    case "MALICIOUS":
      return ICONS.skull;
    case "BUILD_FAILED":
    case "ANALYSIS_FAILED":
      return ICONS.wrench;
    default:
      return ICONS.infoCircle;
  }
}

function badgeHtml(verdict) {
  const cls = `badge badge-${verdict}`;
  const icon = getVerdictIconSvg(verdict);
  return `<span class="${cls}">${icon}<span>${escapeHtml(verdictLabel(verdict))}</span></span>`;
}

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
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

function manifestUrl() {
  return new URL("data/manifest.json", document.baseURI).toString();
}

function packagePageUrl(name, version) {
  let url = `package.html?name=${encodeURIComponent(name)}`;
  if (version) {
    url += `&version=${encodeURIComponent(version)}`;
  }
  return url;
}

/* Offline-resilient attestation fetcher:
   1. Try relative URL from baseURI (works in local previews and copy-to-docs)
   2. Try parent-relative "../" + path (works when serving repo root or docs/)
   3. Fallback to GitHub raw CDN */
async function fetchAttestationData(path) {
  // Attempt 1: relative to current baseURI
  try {
    const relUrl = new URL(path, document.baseURI).toString();
    const res = await fetch(relUrl, { cache: "no-store" });
    if (res.ok) return await res.json();
  } catch (_) {}

  // Attempt 2: sibling relative
  try {
    const siblingUrl = new URL("../" + path, document.baseURI).toString();
    const res = await fetch(siblingUrl, { cache: "no-store" });
    if (res.ok) return await res.json();
  } catch (_) {}

  // Attempt 3: GitHub Raw CDN
  const rawUrl = RAW_BASE + path;
  const res = await fetch(rawUrl, { cache: "no-store" });
  if (!res.ok) {
    throw new Error(`Failed to load attestation from both local relative paths and remote CDN (HTTP ${res.status})`);
  }
  return await res.json();
}

async function fetchManifest() {
  // Attempt 1: standard relative URL
  try {
    const res = await fetch(manifestUrl(), { cache: "no-store" });
    if (res.ok) return await res.json();
  } catch (_) {}

  // Attempt 2: sibling relative
  try {
    const fallbackUrl = new URL("../docs/data/manifest.json", document.baseURI).toString();
    const res = await fetch(fallbackUrl, { cache: "no-store" });
    if (res.ok) return await res.json();
  } catch (_) {}

  // Attempt 3: remote GitHub CDN
  const cdnUrl = RAW_BASE + "docs/data/manifest.json";
  const res = await fetch(cdnUrl, { cache: "no-store" });
  if (!res.ok) {
    throw new Error(`Could not load manifest.json (HTTP ${res.status})`);
  }
  return await res.json();
}

/* Collapse full manifest list to one entry per package: newest analyzed_at. */
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

const OTHER_VERDICTS = ["INCONCLUSIVE", "BUILD_FAILED", "ANALYSIS_FAILED", "STALE", "UNSUPPORTED"];

function verdictBreakdown(packages) {
  const counts = { total: packages.length, VERIFIED: 0, SUSPICIOUS: 0, MALICIOUS: 0, OTHER: 0 };
  for (const pkg of packages) {
    if (pkg.verdict === "VERIFIED" || pkg.verdict === "SUSPICIOUS" || pkg.verdict === "MALICIOUS") {
      counts[pkg.verdict] += 1;
    } else {
      counts.OTHER += 1;
    }
  }
  return counts;
}

/* Copy to clipboard utility with visual button feedback */
async function copyToClipboard(text, btnElement) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
    } else {
      const textarea = document.createElement("textarea");
      textarea.value = text;
      textarea.style.position = "fixed";
      textarea.style.opacity = "0";
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      document.body.removeChild(textarea);
    }

    if (btnElement) {
      const originalHtml = btnElement.innerHTML;
      btnElement.classList.add("copied");
      btnElement.innerHTML = `${ICONS.check} Copied!`;
      setTimeout(() => {
        btnElement.classList.remove("copied");
        btnElement.innerHTML = originalHtml;
      }, 1800);
    }
  } catch (err) {
    console.error("Clipboard copy failed:", err);
  }
}

/* Theme Management */
function initThemeToggle() {
  const toggleBtn = document.getElementById("theme-toggle");
  if (!toggleBtn) return;

  function updateButton(theme) {
    const isDark = theme === "dark";
    toggleBtn.innerHTML = isDark
      ? `${ICONS.sun}<span>Light</span>`
      : `${ICONS.moon}<span>Dark</span>`;
    toggleBtn.setAttribute("aria-label", `Switch to ${isDark ? "light" : "dark"} theme`);
    toggleBtn.title = `Switch to ${isDark ? "light" : "dark"} theme`;
  }

  const currentTheme = document.documentElement.getAttribute("data-theme") ||
    (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");

  updateButton(currentTheme);

  toggleBtn.addEventListener("click", () => {
    const active = document.documentElement.getAttribute("data-theme") ||
      (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    const next = active === "dark" ? "light" : "dark";

    document.documentElement.setAttribute("data-theme", next);
    try {
      localStorage.setItem("aur-sentry-theme", next);
    } catch (_) {}
    updateButton(next);
  });

  // Listen to system theme change if no manual preference stored
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", (e) => {
    if (!localStorage.getItem("aur-sentry-theme")) {
      const newSystem = e.matches ? "dark" : "light";
      document.documentElement.setAttribute("data-theme", newSystem);
      updateButton(newSystem);
    }
  });
}

/* Hero Verdict Info Generator */
function getHeroVerdictData(verdict) {
  const icon = getVerdictIconSvg(verdict);
  let title = "Verdict Pending";
  let tag = verdictLabel(verdict);

  switch (verdict) {
    case "VERIFIED":
      title = "Verified Package";
      break;
    case "SUSPICIOUS":
      title = "Suspicious Behavior Detected";
      break;
    case "MALICIOUS":
      title = "Confirmed Malicious Package";
      break;
    case "BUILD_FAILED":
      title = "Build Failed in Sandbox";
      break;
    case "ANALYSIS_FAILED":
      title = "Analysis Incomplete";
      break;
    case "STALE":
      title = "Outdated Attestation";
      break;
    default:
      title = `Status: ${tag}`;
  }

  const desc = VERDICT_EXPLANATION[verdict] || "Evidence-based verification outcome recorded by AUR Sentry.";
  return { title, tag, desc, icon };
}
