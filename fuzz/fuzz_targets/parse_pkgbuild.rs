#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let scanner = aur_sentry::scanner::PKGBUILDScanner::new();
        let _ = scanner.scan(s, Some("fuzz-target"));
        let _ = aur_sentry::analyzer::analyze_pipeline_structure(s);
        let _ = aur_sentry::analyzer::analyze_entropy(s);
        let _ = aur_sentry::evidence::strace::declared_source_ips(s);
        let _ = aur_sentry::scanner::join_continued_lines(s);
    }
});
