//! Client for interacting with the Arch User Repository.
//!
//! Supports:
//! - RPC v5 info/search
//! - Raw PKGBUILD fetch via cgit
//! - Full metadata dump (`packages-meta-ext-v1.json.gz`) for bulk scanning

use serde::Deserialize;
use serde::de::Deserializer;
use std::io::Read;

const AUR_RPC: &str = "https://aur.archlinux.org/rpc/v5";
const AUR_CGIT_RAW: &str = "https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h=";
const AUR_CGIT_INSTALL: &str = "https://aur.archlinux.org/cgit/aur.git/plain/";
const AUR_META_DUMP: &str = "https://aur.archlinux.org/packages-meta-ext-v1.json.gz";

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct AURPackage {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "Maintainer", default)]
    pub maintainer: Option<String>,
    #[serde(rename = "LastModified", default)]
    pub last_modified: Option<i64>,
    #[serde(rename = "NumVotes", default)]
    pub num_votes: Option<u32>,
    #[serde(rename = "Popularity", default)]
    pub popularity: Option<f64>,
    #[serde(rename = "OutOfDate", default)]
    pub out_of_date: Option<i64>,
    #[serde(rename = "FirstSubmitted", default)]
    pub first_submitted: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct RpcResponse {
    results: Vec<AURPackage>,
}

pub struct AURClient {
    agent: ureq::Agent,
}

impl AURClient {
    pub fn new() -> Self {
        let config = ureq::config::Config::builder()
            .timeout_global(Some(std::time::Duration::from_secs(15)))
            .build();
        let agent = ureq::Agent::new_with_config(config);
        Self { agent }
    }

    /// Fetch package info by name from AUR RPC.
    pub fn get_package_info(&self, pkgname: &str) -> Option<AURPackage> {
        let url = format!("{AUR_RPC}/info/{pkgname}");
        let resp: RpcResponse = self
            .agent
            .get(&url)
            .call()
            .ok()?
            .body_mut()
            .read_json()
            .ok()?;
        resp.results.into_iter().next()
    }

    /// Search packages via AUR RPC.
    pub fn search(&self, query: &str) -> Vec<AURPackage> {
        let url = format!("{AUR_RPC}/search/{query}");
        match self.agent.get(&url).call() {
            Ok(mut resp) => resp
                .body_mut()
                .read_json::<RpcResponse>()
                .map(|r| r.results)
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    }

    /// Fetch raw PKGBUILD content from AUR cgit.
    pub fn fetch_pkgbuild(&self, pkgname: &str) -> Option<String> {
        let url = format!("{AUR_CGIT_RAW}{pkgname}");
        self.agent
            .get(&url)
            .call()
            .ok()?
            .body_mut()
            .read_to_string()
            .ok()
    }

    /// Fetch .install file from AUR cgit.
    pub fn fetch_install_file(&self, pkgname: &str, filename: &str) -> Option<String> {
        let url = format!("{AUR_CGIT_INSTALL}{filename}?h={pkgname}");
        self.agent
            .get(&url)
            .call()
            .ok()?
            .body_mut()
            .read_to_string()
            .ok()
    }

    /// Download the FULL AUR metadata dump (~90k packages).
    /// Returns all packages sorted by last-modified descending.
    pub fn fetch_full_metadata(&self) -> Vec<AURPackage> {
        eprintln!("[*] Downloading full AUR metadata dump (this may take a moment)...");
        match self.agent.get(AUR_META_DUMP).call() {
            Ok(mut resp) => {
                let gz_bytes = match resp
                    .body_mut()
                    .with_config()
                    .limit(150 * 1024 * 1024)
                    .read_to_vec()
                {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("[!] Failed to read metadata dump: {e}");
                        return Vec::new();
                    }
                };
                let mut decoder = flate2::read::GzDecoder::new(&gz_bytes[..]);
                let mut json_str = String::new();
                if decoder.read_to_string(&mut json_str).is_err() {
                    eprintln!("[!] Failed to decompress metadata dump");
                    return Vec::new();
                }
                match serde_json::from_str::<Vec<AURPackage>>(&json_str) {
                    Ok(mut pkgs) => {
                        pkgs.sort_by(|a, b| {
                            b.last_modified
                                .unwrap_or(0)
                                .cmp(&a.last_modified.unwrap_or(0))
                        });
                        eprintln!("[+] Loaded {} packages from AUR metadata dump", pkgs.len());
                        pkgs
                    }
                    Err(e) => {
                        eprintln!("[!] Failed to parse metadata dump: {e}");
                        Vec::new()
                    }
                }
            }
            Err(e) => {
                eprintln!("[!] Failed to download metadata dump: {e}");
                Vec::new()
            }
        }
    }

    /// Get recently modified packages from the metadata dump within the last N hours.
    /// Streams directly from the gzip decoder with in-flight cutoff filtering to avoid
    /// allocating 120,000+ unused package structs in memory.
    pub fn get_recently_modified(&self, hours: u64) -> Vec<AURPackage> {
        let cutoff = chrono::Utc::now().timestamp() - (hours as i64 * 3600);
        eprintln!("[*] Downloading and streaming AUR metadata dump (filtering last {hours}h)...");

        let mut resp = match self.agent.get(AUR_META_DUMP).call() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[!] Failed to download metadata dump: {e}");
                return Vec::new();
            }
        };

        let gz_bytes = match resp
            .body_mut()
            .with_config()
            .limit(150 * 1024 * 1024)
            .read_to_vec()
        {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[!] Failed to read metadata dump: {e}");
                return Vec::new();
            }
        };

        let decoder = flate2::read::GzDecoder::new(&gz_bytes[..]);
        let reader = std::io::BufReader::with_capacity(128 * 1024, decoder);

        let mut deserializer = serde_json::Deserializer::from_reader(reader);
        let mut recent_pkgs = deserializer
            .deserialize_seq(StreamFilterVisitor { cutoff })
            .unwrap_or_else(|e| {
                eprintln!("[!] Failed to parse metadata stream: {e}");
                Vec::new()
            });

        recent_pkgs.sort_by(|a, b| {
            b.last_modified
                .unwrap_or(0)
                .cmp(&a.last_modified.unwrap_or(0))
        });

        eprintln!(
            "[+] Filtered {} packages modified in the last {hours}h (skipped ~{} stale packages)",
            recent_pkgs.len(),
            120_000usize.saturating_sub(recent_pkgs.len())
        );

        recent_pkgs
    }

    /// Fetch remote threat advisory feed from GitHub.
    pub fn fetch_remote_advisories(&self) -> Option<Vec<crate::report::Advisory>> {
        let url = "https://raw.githubusercontent.com/rebizzz/aur-sentry/main/advisories.json";
        let mut resp = self.agent.get(url).call().ok()?;
        let feed: crate::report::AdvisoryFeed = resp.body_mut().read_json().ok()?;
        Some(feed.advisories)
    }
}

struct StreamFilterVisitor {
    cutoff: i64,
}

impl<'de> serde::de::Visitor<'de> for StreamFilterVisitor {
    type Value = Vec<AURPackage>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a JSON array of AUR packages")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut pkgs = Vec::new();
        while let Some(pkg) = seq.next_element::<AURPackage>()? {
            if pkg.last_modified.unwrap_or(0) >= self.cutoff {
                pkgs.push(pkg);
            }
        }
        Ok(pkgs)
    }
}

impl Default for AURClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_aur_package_metadata_json() {
        let raw = r#"[
            {
                "Name": "test-pkg",
                "Version": "1.0.0-1",
                "Maintainer": "archuser",
                "LastModified": 1711234567,
                "NumVotes": 42,
                "Popularity": 3.14,
                "OutOfDate": null,
                "FirstSubmitted": 1600000000
            },
            {
                "Name": "orphan-pkg",
                "Version": "0.1-1",
                "Maintainer": null,
                "LastModified": 1711230000
            }
        ]"#;

        let pkgs: Vec<AURPackage> =
            serde_json::from_str(raw).expect("Failed to deserialize AUR packages");
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name, "test-pkg");
        assert_eq!(pkgs[0].maintainer.as_deref(), Some("archuser"));
        assert_eq!(pkgs[0].num_votes, Some(42));
        assert_eq!(pkgs[1].name, "orphan-pkg");
        assert_eq!(pkgs[1].maintainer, None);
    }

    #[test]
    fn filters_recently_modified_from_json_array() {
        let raw = r#"[
            {
                "Name": "old-pkg",
                "Version": "1.0-1",
                "LastModified": 1000
            },
            {
                "Name": "new-pkg",
                "Version": "2.0-1",
                "LastModified": 2000
            }
        ]"#;

        let mut deserializer = serde_json::Deserializer::from_str(raw);
        let pkgs = deserializer
            .deserialize_seq(StreamFilterVisitor { cutoff: 1500 })
            .expect("stream deserialization succeeds");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "new-pkg");
    }
}
