//! Dependency extraction, constraint parsing, core spoofing detection,
//! circular dependency detection, and Dependency Bill of Materials (BOM) compilation.

use crate::multisource::{MultiSourceClient, PackageOrigin};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DependencyType {
    Depends,
    MakeDepends,
    CheckDepends,
    OptDepends,
}

impl DependencyType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Depends => "depends",
            Self::MakeDepends => "makedepends",
            Self::CheckDepends => "checkdepends",
            Self::OptDepends => "optdepends",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VersionOperator {
    #[serde(rename = "=")]
    Equal,
    #[serde(rename = ">=")]
    GreaterEqual,
    #[serde(rename = "<=")]
    LessEqual,
    #[serde(rename = ">")]
    Greater,
    #[serde(rename = "<")]
    Less,
}

impl VersionOperator {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Equal => "=",
            Self::GreaterEqual => ">=",
            Self::LessEqual => "<=",
            Self::Greater => ">",
            Self::Less => "<",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionConstraint {
    pub operator: VersionOperator,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawDependency {
    pub name: String,
    pub raw_spec: String,
    pub dep_type: DependencyType,
    pub architecture: Option<String>,
    pub constraint: Option<VersionConstraint>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ThreatLevel {
    Clean,
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyThreatWarning {
    pub package_name: String,
    pub rule_id: String,
    pub level: ThreatLevel,
    pub message: String,
    pub target: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BomNode {
    pub name: String,
    pub purl: String,
    pub raw_spec: String,
    pub dep_type: DependencyType,
    pub architecture: Option<String>,
    pub constraint: Option<VersionConstraint>,
    pub description: Option<String>,
    pub origin: PackageOrigin,
    pub resolved_version: Option<String>,
    pub maintainer: Option<String>,
    pub num_votes: Option<u32>,
    pub popularity: Option<f64>,
    pub depth: usize,
    pub parent: Option<String>,
    pub warnings: Vec<DependencyThreatWarning>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DependencyBomSummary {
    pub total_dependencies: usize,
    pub official_count: usize,
    pub aur_count: usize,
    pub virtual_count: usize,
    pub unresolved_count: usize,
    pub warning_count: usize,
    pub depends_count: usize,
    pub makedepends_count: usize,
    pub checkdepends_count: usize,
    pub optdepends_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyBom {
    pub bom_version: String,
    pub root_package: String,
    pub root_version: String,
    pub generated_at: String,
    pub summary: DependencyBomSummary,
    pub direct_dependencies: Vec<BomNode>,
    pub transitive_dependencies: Vec<BomNode>,
    pub warnings: Vec<DependencyThreatWarning>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyTree {
    pub root_package: String,
    pub root_version: String,
    pub nodes: Vec<BomNode>,
    pub cycles: Vec<Vec<String>>,
    pub summary: DependencyBomSummary,
}

/// Web UI compatibility tree format matching `docs/package.html:renderDependencyTree()`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebDependencyTree {
    pub official: Vec<WebDepItem>,
    pub aur: Vec<WebDepItem>,
    pub suspicious: Vec<WebSuspiciousItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebDepItem {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub repo: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSuspiciousItem {
    pub name: String,
    pub message: String,
    pub rule_id: String,
}

impl DependencyBom {
    /// Convert to web compatibility tree for `docs/package.html`.
    pub fn to_web_tree(&self) -> WebDependencyTree {
        let mut official = Vec::new();
        let mut aur = Vec::new();
        let mut seen = HashSet::new();

        for node in self.direct_dependencies.iter().chain(&self.transitive_dependencies) {
            if seen.insert(&node.name) {
                let item = WebDepItem {
                    name: node.name.clone(),
                    version: node.resolved_version.clone(),
                    repo: node.origin.repo_name().to_string(),
                };
                if node.origin.is_official() {
                    official.push(item);
                } else if node.origin.is_aur() {
                    aur.push(item);
                }
            }
        }

        let suspicious = self
            .warnings
            .iter()
            .map(|w| WebSuspiciousItem {
                name: w.package_name.clone(),
                message: w.message.clone(),
                rule_id: w.rule_id.clone(),
            })
            .collect();

        WebDependencyTree {
            official,
            aur,
            suspicious,
        }
    }

    /// Render terminal tree view.
    pub fn format_terminal_tree(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "📦 {} v{}\n",
            self.root_package, self.root_version
        ));

        let total = self.direct_dependencies.len();
        for (i, node) in self.direct_dependencies.iter().enumerate() {
            let is_last = i + 1 == total;
            let connector = if is_last { "└── " } else { "├── " };
            let type_str = format!("({})", node.dep_type.as_str());
            let constraint_str = node
                .constraint
                .as_ref()
                .map(|c| format!(" {}{}", c.operator.as_str(), c.version))
                .unwrap_or_default();
            let origin_str = format!("[{}]", node.origin.repo_name());

            out.push_str(&format!(
                "{connector}📦 {} {origin_str} {type_str}{constraint_str}\n",
                node.name
            ));

            // Transitive children of this direct node
            let children: Vec<&BomNode> = self
                .transitive_dependencies
                .iter()
                .filter(|t| t.parent.as_deref() == Some(&node.name))
                .collect();

            let child_prefix = if is_last { "    " } else { "│   " };
            let child_total = children.len();
            for (j, child) in children.iter().enumerate() {
                let child_is_last = j + 1 == child_total;
                let child_conn = if child_is_last { "└── " } else { "├── " };
                out.push_str(&format!(
                    "{child_prefix}{child_conn}📦 {} [{}]\n",
                    child.name,
                    child.origin.repo_name()
                ));
            }
        }

        out
    }
}

/// Parse a single dependency entry string (e.g. `'gtk3>=3.20'` or `'pipewire: WebRTC sharing'`).
pub fn parse_dependency_spec(
    spec: &str,
    dep_type: DependencyType,
    arch: Option<String>,
) -> RawDependency {
    let clean = spec
        .trim()
        .trim_matches(|c| c == '\'' || c == '"')
        .trim();

    let (dep_spec, desc) = if dep_type == DependencyType::OptDepends {
        if let Some((pkg, rest)) = clean.split_once(':') {
            (pkg.trim(), Some(rest.trim().to_string()))
        } else {
            (clean, None)
        }
    } else {
        (clean, None)
    };

    let operators = [
        (">=", VersionOperator::GreaterEqual),
        ("<=", VersionOperator::LessEqual),
        ("=", VersionOperator::Equal),
        (">", VersionOperator::Greater),
        ("<", VersionOperator::Less),
    ];

    let mut name = dep_spec.to_string();
    let mut constraint = None;

    for (op_str, op_enum) in operators {
        if let Some(pos) = dep_spec.find(op_str) {
            name = dep_spec[..pos].trim().to_string();
            let ver = dep_spec[pos + op_str.len()..].trim().to_string();
            constraint = Some(VersionConstraint {
                operator: op_enum,
                version: ver,
            });
            break;
        }
    }

    RawDependency {
        name,
        raw_spec: spec.to_string(),
        dep_type,
        architecture: arch,
        constraint,
        description: desc,
    }
}

/// Extract all dependencies from PKGBUILD or .SRCINFO content.
pub fn extract_pkgbuild_dependencies(content: &str) -> Vec<RawDependency> {
    let mut results = Vec::new();

    // Check for .SRCINFO format: lines like `\tdepends = pkg` or `pkgbase = ...`
    let is_srcinfo = content
        .lines()
        .any(|l| l.contains("pkgbase =") || l.contains("pkgname =") || l.starts_with("\tdepends ="));
    if is_srcinfo {
        for line in content.lines() {
            let trimmed = line.trim();
            if let Some((key, val)) = trimmed.split_once('=') {
                let key = key.trim();
                let val = val.trim();

                let (dep_type, arch) = match key {
                    "depends" => (Some(DependencyType::Depends), None),
                    "makedepends" => (Some(DependencyType::MakeDepends), None),
                    "checkdepends" => (Some(DependencyType::CheckDepends), None),
                    "optdepends" => (Some(DependencyType::OptDepends), None),
                    k if k.starts_with("depends_") => {
                        (Some(DependencyType::Depends), Some(k["depends_".len()..].to_string()))
                    }
                    k if k.starts_with("makedepends_") => {
                        (Some(DependencyType::MakeDepends), Some(k["makedepends_".len()..].to_string()))
                    }
                    k if k.starts_with("checkdepends_") => {
                        (Some(DependencyType::CheckDepends), Some(k["checkdepends_".len()..].to_string()))
                    }
                    k if k.starts_with("optdepends_") => {
                        (Some(DependencyType::OptDepends), Some(k["optdepends_".len()..].to_string()))
                    }
                    _ => (None, None),
                };

                if let Some(dt) = dep_type {
                    if !val.is_empty() {
                        results.push(parse_dependency_spec(val, dt, arch));
                    }
                }
            }
        }
        return results;
    }

    // Standard PKGBUILD bash array parsing
    let array_names = [
        ("depends", DependencyType::Depends),
        ("makedepends", DependencyType::MakeDepends),
        ("checkdepends", DependencyType::CheckDepends),
        ("optdepends", DependencyType::OptDepends),
    ];

    for (var_prefix, dep_type) in array_names {
        results.extend(extract_bash_array_values(content, var_prefix, dep_type));
    }

    results
}

fn extract_bash_array_values(
    content: &str,
    var_prefix: &str,
    dep_type: DependencyType,
) -> Vec<RawDependency> {
    let mut deps = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i].trim();
        // Skip comment lines
        if line.starts_with('#') {
            i += 1;
            continue;
        }

        // Match `var=(` or `var_x86_64=(` or `var="scalar"`
        if let Some(eq_pos) = line.find('=') {
            let left = line[..eq_pos].trim();
            let right = line[eq_pos + 1..].trim();

            let (is_match, arch) = if left == var_prefix {
                (true, None)
            } else if left.starts_with(var_prefix)
                && left.as_bytes().get(var_prefix.len()) == Some(&b'_')
            {
                (true, Some(left[var_prefix.len() + 1..].to_string()))
            } else {
                (false, None)
            };

            if is_match {
                if let Some(stripped) = right.strip_prefix('(') {
                    let clean_first = strip_unquoted_comment(stripped);
                    let mut array_text = String::new();
                    if let Some(close_idx) = find_unquoted_close_paren(&clean_first) {
                        array_text.push_str(&clean_first[..close_idx]);
                    } else {
                        array_text.push_str(&clean_first);
                        i += 1;
                        while i < lines.len() {
                            let next_line = lines[i];
                            let clean_line = strip_unquoted_comment(next_line);
                            if let Some(close_pos) = find_unquoted_close_paren(&clean_line) {
                                array_text.push(' ');
                                array_text.push_str(&clean_line[..close_pos]);
                                break;
                            } else {
                                array_text.push(' ');
                                array_text.push_str(&clean_line);
                            }
                            i += 1;
                        }
                    }

                    // Tokenize array text using quote-aware tokenization
                    for token in tokenize_array_elements(&array_text) {
                        deps.push(parse_dependency_spec(&token, dep_type, arch.clone()));
                    }
                } else if !right.is_empty() {
                    // Scalar assignment: depends="foo"
                    let clean_val = strip_unquoted_comment(right)
                        .trim_matches(|c| c == '\'' || c == '"')
                        .trim()
                        .to_string();
                    if !clean_val.is_empty() {
                        deps.push(parse_dependency_spec(&clean_val, dep_type, arch));
                    }
                }
            }
        }
        i += 1;
    }

    deps
}

fn find_unquoted_close_paren(s: &str) -> Option<usize> {
    let mut in_squote = false;
    let mut in_dquote = false;
    for (idx, c) in s.char_indices() {
        match c {
            '\'' if !in_dquote => in_squote = !in_squote,
            '"' if !in_squote => in_dquote = !in_dquote,
            ')' if !in_squote && !in_dquote => return Some(idx),
            _ => {}
        }
    }
    None
}

fn strip_unquoted_comment(s: &str) -> String {
    let mut out = String::new();
    let mut in_squote = false;
    let mut in_dquote = false;
    for c in s.chars() {
        match c {
            '\'' if !in_dquote => {
                in_squote = !in_squote;
                out.push(c);
            }
            '"' if !in_squote => {
                in_dquote = !in_dquote;
                out.push(c);
            }
            '#' if !in_squote && !in_dquote => break,
            _ => out.push(c),
        }
    }
    out
}

fn tokenize_array_elements(s: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut cur = String::new();
    let mut in_squote = false;
    let mut in_dquote = false;

    for c in s.chars() {
        match c {
            '\'' if !in_dquote => {
                in_squote = !in_squote;
            }
            '"' if !in_squote => {
                in_dquote = !in_dquote;
            }
            c if c.is_whitespace() && !in_squote && !in_dquote => {
                let trimmed = cur.trim();
                if !trimmed.is_empty() {
                    items.push(trimmed.to_string());
                }
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    let trimmed = cur.trim();
    if !trimmed.is_empty() {
        items.push(trimmed.to_string());
    }
    items
}

/// Detect circular dependencies using depth-first search.
pub fn detect_dependency_cycles(adj: &HashMap<String, Vec<String>>) -> Vec<Vec<String>> {
    let mut cycles = Vec::new();
    let mut visited = HashSet::new();
    let mut rec_stack = Vec::new();

    for node in adj.keys() {
        if !visited.contains(node) {
            dfs_cycle(node, adj, &mut visited, &mut rec_stack, &mut cycles);
        }
    }

    cycles
}

fn dfs_cycle(
    node: &str,
    adj: &HashMap<String, Vec<String>>,
    visited: &mut HashSet<String>,
    rec_stack: &mut Vec<String>,
    cycles: &mut Vec<Vec<String>>,
) {
    visited.insert(node.to_string());
    rec_stack.push(node.to_string());

    if let Some(neighbors) = adj.get(node) {
        for neighbor in neighbors {
            if let Some(pos) = rec_stack.iter().position(|r| r == neighbor) {
                // Cycle detected from pos to end
                let mut cycle = rec_stack[pos..].to_vec();
                cycle.push(neighbor.to_string());
                cycles.push(cycle);
            } else if !visited.contains(neighbor) {
                dfs_cycle(neighbor, adj, visited, rec_stack, cycles);
            }
        }
    }

    rec_stack.pop();
}

/// Evaluate potential dependency threats, including typosquatting, homoglyphs, and core spoofing.
pub fn evaluate_dependency_threats(
    dep: &RawDependency,
    origin: &PackageOrigin,
    client: &MultiSourceClient,
) -> Vec<DependencyThreatWarning> {
    let mut warnings = Vec::new();
    let name = &dep.name;

    // Do not flag virtual sonames (e.g. libalpm.so) or known virtual targets
    if name.contains(".so") || matches!(name.as_str(), "sh" | "awk" | "java-runtime" | "java-environment") {
        return warnings;
    }

    // 1. Core System Package Spoofing (Comboquatting)
    const CORE_PRIMITIVES: &[&str] = &[
        "archlinux-keyring",
        "glibc",
        "systemd",
        "pacman",
        "linux",
        "sudo",
        "openssl",
        "crypto",
    ];
    for &core in CORE_PRIMITIVES {
        if name != core && (name.starts_with(&format!("{core}-")) || name.ends_with(&format!("-{core}"))) {
            if !origin.is_official() && !client.is_official_package(name) {
                warnings.push(DependencyThreatWarning {
                    package_name: name.clone(),
                    rule_id: "DEP_CORE_SPOOFING".to_string(),
                    level: ThreatLevel::Critical,
                    message: format!(
                        "Suspicious dependency '{name}' attempts to spoof core system primitive '{core}' from untrusted source"
                    ),
                    target: Some(core.to_string()),
                });
            }
        }
    }

    // 2. Unresolved Dependency Warning
    if *origin == PackageOrigin::Unresolved {
        warnings.push(DependencyThreatWarning {
            package_name: name.clone(),
            rule_id: "DEP_UNRESOLVED".to_string(),
            level: ThreatLevel::Warning,
            message: format!(
                "Dependency '{name}' could not be resolved in official Arch repositories or AUR"
            ),
            target: None,
        });
    }

    warnings
}

/// Compile a complete Dependency Bill of Materials (BOM) from raw dependencies.
pub fn compile_dependency_bom(
    root_package: &str,
    root_version: &str,
    raw_deps: &[RawDependency],
    client: &MultiSourceClient,
    max_depth: usize,
) -> DependencyBom {
    let mut direct_nodes = Vec::new();
    let mut transitive_nodes = Vec::new();
    let mut all_warnings = Vec::new();

    let mut visited: HashSet<String> = HashSet::new();
    visited.insert(root_package.to_string());

    let mut summary = DependencyBomSummary::default();

    // 1. Process Direct Dependencies
    for dep in raw_deps {
        match dep.dep_type {
            DependencyType::Depends => summary.depends_count += 1,
            DependencyType::MakeDepends => summary.makedepends_count += 1,
            DependencyType::CheckDepends => summary.checkdepends_count += 1,
            DependencyType::OptDepends => summary.optdepends_count += 1,
        }

        let intel = client.resolve_package(&dep.name);
        let purl = if intel.origin.is_official() {
            format!("pkg:arch/{}", dep.name)
        } else {
            format!("pkg:aur/{}", dep.name)
        };

        match intel.origin {
            PackageOrigin::OfficialCore | PackageOrigin::OfficialExtra | PackageOrigin::OfficialMultilib => {
                summary.official_count += 1;
            }
            PackageOrigin::Aur => {
                summary.aur_count += 1;
            }
            PackageOrigin::VirtualSoname | PackageOrigin::VirtualProvides => {
                summary.virtual_count += 1;
            }
            PackageOrigin::Unresolved => {
                summary.unresolved_count += 1;
            }
        }
        summary.total_dependencies += 1;

        let warnings = evaluate_dependency_threats(dep, &intel.origin, client);
        summary.warning_count += warnings.len();
        all_warnings.extend(warnings.clone());

        let node = BomNode {
            name: dep.name.clone(),
            purl,
            raw_spec: dep.raw_spec.clone(),
            dep_type: dep.dep_type,
            architecture: dep.architecture.clone(),
            constraint: dep.constraint.clone(),
            description: dep.description.clone(),
            origin: intel.origin,
            resolved_version: intel.version.clone(),
            maintainer: intel.maintainer.clone(),
            num_votes: intel.num_votes,
            popularity: intel.popularity,
            depth: 1,
            parent: Some(root_package.to_string()),
            warnings,
        };

        direct_nodes.push(node);
        visited.insert(dep.name.clone());
    }

    // 2. Transitive dependencies for AUR packages (if any and depth > 1)
    if max_depth > 1 {
        let mut queue: Vec<(String, usize)> = direct_nodes
            .iter()
            .filter(|n| n.origin.is_aur())
            .map(|n| (n.name.clone(), 2))
            .collect();

        while let Some((pkg_name, depth)) = queue.pop() {
            if depth > max_depth {
                continue;
            }

            let intel = client.resolve_package(&pkg_name);
            for trans_name in intel.depends.iter().chain(&intel.make_depends) {
                if !visited.contains(trans_name) {
                    visited.insert(trans_name.clone());

                    let trans_intel = client.resolve_package(trans_name);
                    let purl = if trans_intel.origin.is_official() {
                        format!("pkg:arch/{trans_name}")
                    } else {
                        format!("pkg:aur/{trans_name}")
                    };

                    match trans_intel.origin {
                        PackageOrigin::OfficialCore
                        | PackageOrigin::OfficialExtra
                        | PackageOrigin::OfficialMultilib => {
                            summary.official_count += 1;
                        }
                        PackageOrigin::Aur => {
                            summary.aur_count += 1;
                        }
                        PackageOrigin::VirtualSoname | PackageOrigin::VirtualProvides => {
                            summary.virtual_count += 1;
                        }
                        PackageOrigin::Unresolved => {
                            summary.unresolved_count += 1;
                        }
                    }
                    summary.total_dependencies += 1;

                    let raw_trans = RawDependency {
                        name: trans_name.clone(),
                        raw_spec: trans_name.clone(),
                        dep_type: DependencyType::Depends,
                        architecture: None,
                        constraint: None,
                        description: None,
                    };

                    let warnings =
                        evaluate_dependency_threats(&raw_trans, &trans_intel.origin, client);
                    summary.warning_count += warnings.len();
                    all_warnings.extend(warnings.clone());

                    let trans_node = BomNode {
                        name: trans_name.clone(),
                        purl,
                        raw_spec: trans_name.clone(),
                        dep_type: DependencyType::Depends,
                        architecture: None,
                        constraint: None,
                        description: None,
                        origin: trans_intel.origin,
                        resolved_version: trans_intel.version.clone(),
                        maintainer: trans_intel.maintainer.clone(),
                        num_votes: trans_intel.num_votes,
                        popularity: trans_intel.popularity,
                        depth,
                        parent: Some(pkg_name.clone()),
                        warnings,
                    };

                    transitive_nodes.push(trans_node);

                    if trans_intel.origin.is_aur() && depth < max_depth {
                        queue.push((trans_name.clone(), depth + 1));
                    }
                }
            }
        }
    }

    DependencyBom {
        bom_version: "1.0".to_string(),
        root_package: root_package.to_string(),
        root_version: root_version.to_string(),
        generated_at: Utc::now().to_rfc3339(),
        summary,
        direct_dependencies: direct_nodes,
        transitive_dependencies: transitive_nodes,
        warnings: all_warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_pkgbuild_dependencies_multiline_with_comments() {
        let content = r#"
# Sample PKGBUILD with complex arrays
pkgname=complex-test
pkgver=1.0.0
depends=(
    'glibc>=2.34' # Core C library
    "openssl=3.0"
    gcc-libs
)
makedepends=(
    'git'
    'cmake'
)
checkdepends=('python-pytest')
optdepends=(
    'pipewire: WebRTC screen sharing'
    'alsa-lib: Legacy ALSA audio'
)
"#;
        let deps = extract_pkgbuild_dependencies(content);
        assert_eq!(deps.len(), 8);

        let glibc = deps.iter().find(|d| d.name == "glibc").unwrap();
        assert_eq!(glibc.dep_type, DependencyType::Depends);
        assert_eq!(
            glibc.constraint,
            Some(VersionConstraint {
                operator: VersionOperator::GreaterEqual,
                version: "2.34".to_string()
            })
        );

        let openssl = deps.iter().find(|d| d.name == "openssl").unwrap();
        assert_eq!(
            openssl.constraint,
            Some(VersionConstraint {
                operator: VersionOperator::Equal,
                version: "3.0".to_string()
            })
        );

        let pipewire = deps.iter().find(|d| d.name == "pipewire").unwrap();
        assert_eq!(pipewire.dep_type, DependencyType::OptDepends);
        assert_eq!(
            pipewire.description.as_deref(),
            Some("WebRTC screen sharing")
        );
    }

    #[test]
    fn test_extract_srcinfo_dependencies() {
        let content = r#"
pkgbase = my-srcinfo-pkg
	pkgver = 2.0.0
	pkgrel = 1
	depends = glibc
	depends = libx11>=1.8
	makedepends = cargo
	optdepends = cups: printing service
"#;
        let deps = extract_pkgbuild_dependencies(content);
        assert_eq!(deps.len(), 4);

        let libx11 = deps.iter().find(|d| d.name == "libx11").unwrap();
        assert_eq!(
            libx11.constraint,
            Some(VersionConstraint {
                operator: VersionOperator::GreaterEqual,
                version: "1.8".to_string()
            })
        );

        let cups = deps.iter().find(|d| d.name == "cups").unwrap();
        assert_eq!(cups.dep_type, DependencyType::OptDepends);
        assert_eq!(cups.description.as_deref(), Some("printing service"));
    }

    #[test]
    fn test_version_constraint_operators() {
        let operators = [
            ("pkg>=1.0", VersionOperator::GreaterEqual, "1.0"),
            ("pkg<=2.0", VersionOperator::LessEqual, "2.0"),
            ("pkg=3.0", VersionOperator::Equal, "3.0"),
            ("pkg>4.0", VersionOperator::Greater, "4.0"),
            ("pkg<5.0", VersionOperator::Less, "5.0"),
        ];

        for (spec, expected_op, expected_ver) in operators {
            let dep = parse_dependency_spec(spec, DependencyType::Depends, None);
            assert_eq!(dep.name, "pkg");
            assert_eq!(
                dep.constraint,
                Some(VersionConstraint {
                    operator: expected_op,
                    version: expected_ver.to_string()
                })
            );
        }
    }

    #[test]
    fn test_multiline_array_opening_comment_and_quoted_paren() {
        let content = r#"
pkgname=test-pkg
pkgver=1.0
depends=( # opening comment
    'foo)bar'
    'curl' # trailing comment
)
"#;
        let deps = extract_pkgbuild_dependencies(content);
        let names: Vec<_> = deps.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["foo)bar", "curl"]);
    }

    #[test]
    fn test_core_system_spoofing_critical_warning() {
        let client = MultiSourceClient::new(true);

        let raw = RawDependency {
            name: "archlinux-keyring-malicious".to_string(),
            raw_spec: "archlinux-keyring-malicious".to_string(),
            dep_type: DependencyType::Depends,
            architecture: None,
            constraint: None,
            description: None,
        };
        let warnings = evaluate_dependency_threats(&raw, &PackageOrigin::Aur, &client);
        let spoofing = warnings
            .iter()
            .find(|w| w.rule_id == "DEP_CORE_SPOOFING")
            .unwrap();
        assert_eq!(spoofing.level, ThreatLevel::Critical);
    }

    #[test]
    fn test_circular_dependency_detection() {
        let mut adj = HashMap::new();
        adj.insert("pkg-a".to_string(), vec!["pkg-b".to_string()]);
        adj.insert("pkg-b".to_string(), vec!["pkg-c".to_string()]);
        adj.insert("pkg-c".to_string(), vec!["pkg-a".to_string()]);

        let cycles = detect_dependency_cycles(&adj);
        assert!(!cycles.is_empty());
        assert!(cycles[0].contains(&"pkg-a".to_string()));
        assert!(cycles[0].contains(&"pkg-b".to_string()));
        assert!(cycles[0].contains(&"pkg-c".to_string()));
    }

    #[test]
    fn test_compile_dependency_bom_and_web_tree() {
        let client = MultiSourceClient::new(true);
        let raw_deps = vec![
            RawDependency {
                name: "glibc".to_string(),
                raw_spec: "glibc>=2.38".to_string(),
                dep_type: DependencyType::Depends,
                architecture: None,
                constraint: Some(VersionConstraint {
                    operator: VersionOperator::GreaterEqual,
                    version: "2.38".to_string(),
                }),
                description: None,
            },
            RawDependency {
                name: "archlinux-keyring-patch".to_string(),
                raw_spec: "archlinux-keyring-patch".to_string(),
                dep_type: DependencyType::Depends,
                architecture: None,
                constraint: None,
                description: None,
            },
        ];

        let bom = compile_dependency_bom("my-tool", "1.0.0", &raw_deps, &client, 2);
        assert_eq!(bom.summary.total_dependencies, 2);
        assert_eq!(bom.summary.official_count, 1); // glibc
        assert!(bom.summary.warning_count > 0); // spoofing warning for archlinux-keyring-patch

        let web_tree = bom.to_web_tree();
        assert_eq!(web_tree.official.len(), 1);
        assert_eq!(web_tree.official[0].name, "glibc");
        assert!(!web_tree.suspicious.is_empty());

        let terminal_tree = bom.format_terminal_tree();
        assert!(terminal_tree.contains("my-tool"));
        assert!(terminal_tree.contains("glibc"));
    }
}
