use std::path::Path;

use crate::Diagnostic;

// Diagnostic rendering utilities.
//
// This module converts byte-span diagnostics into human-readable output with:
// - file:line:column metadata
// - source line preview
// - caret underline

/// Render a single diagnostic with source context.
///
/// Output style:
/// - `[oilc] <level> [stage] message`
/// - ` --> file:line:col`
/// - source line with caret underline
pub fn format_diagnostic(
    file: &Path,
    source: &str,
    diagnostic: &Diagnostic,
    level: &str,
) -> String {
    let header = format!(
        "[oilc] {level} [{}] {}",
        diagnostic.stage, diagnostic.message
    );

    let Some(span) = diagnostic.span.clone() else {
        // Some diagnostics are global/prelude-level and do not point to user spans.
        return header;
    };

    if source.is_empty() {
        return format!("{header}\n --> {}", file.display());
    }

    let start = span.start.min(source.len());
    let mut end = span.end.min(source.len());
    // Normalize malformed/empty spans so rendering always works.
    if end < start {
        end = start;
    }
    if end == start {
        end = (start + 1).min(source.len());
    }

    let line_start = find_line_start(source, start);
    let line_end = find_line_end(source, start);
    let line_text = &source[line_start..line_end];

    let line_no = line_number_at(source, line_start);
    let col_start = column_number_at(source, line_start, start);
    let col_end = if end <= line_end {
        column_number_at(source, line_start, end)
    } else {
        // Clamp highlight to current line for single-line snippet rendering.
        column_number_at(source, line_start, line_end)
    };

    let caret_pad = " ".repeat(col_start.saturating_sub(1));
    let caret_len = col_end.saturating_sub(col_start).max(1);
    let carets = "^".repeat(caret_len);

    let gutter = line_no.to_string();
    let margin = " ".repeat(gutter.len());

    format!(
        "{header}\n --> {}:{}:{}\n {margin} |\n {gutter} | {line_text}\n {margin} | {caret_pad}{carets}",
        file.display(),
        line_no,
        col_start
    )
}

// Byte index helpers used to compute snippet windows.
fn find_line_start(source: &str, index: usize) -> usize {
    source[..index].rfind('\n').map(|i| i + 1).unwrap_or(0)
}

fn find_line_end(source: &str, index: usize) -> usize {
    source[index..]
        .find('\n')
        .map(|off| index + off)
        .unwrap_or(source.len())
}

fn line_number_at(source: &str, line_start: usize) -> usize {
    // Count `\n` before line start; display is 1-based.
    source[..line_start].bytes().filter(|b| *b == b'\n').count() + 1
}

fn column_number_at(source: &str, line_start: usize, index: usize) -> usize {
    // Column is displayed in Unicode scalar count, 1-based.
    source[line_start..index].chars().count() + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_with_snippet() {
        let src = "a = 1\nb = c + 2\n";
        let d = Diagnostic {
            stage: "resolve",
            is_error: false,
            message: "unknown identifier 'c'".to_string(),
            span: Some(10..11),
        };
        let out = format_diagnostic(Path::new("x.oil"), src, &d, "warning");
        assert!(out.contains("x.oil:2:5"));
        assert!(out.contains("b = c + 2"));
        assert!(out.contains("^"));
    }
}
