//! Deterministic, line-based output paging.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const DEFAULT_TOKEN_BUDGET: usize = 8_500;
pub const DEFAULT_LINES: usize = 200;

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct Page {
    /// One-based line offset.
    pub offset: Option<usize>,
    /// Maximum lines returned; defaults to 200.
    pub limit: Option<usize>,
}

pub fn paginate(text: &str, page: &Page) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let start = page.offset.unwrap_or(1).max(1) - 1;
    let limit = page.limit.unwrap_or(DEFAULT_LINES).clamp(1, 2_000);
    let end = (start + limit).min(lines.len());
    let mut output = if start < lines.len() {
        lines[start..end].join("\n")
    } else {
        String::new()
    };
    if !output.is_empty() {
        output.push('\n');
    }
    if end < lines.len() {
        output.push_str(&format!(
            "(Partial: lines {}-{} shown. Continue with offset={}.)",
            start + 1,
            end,
            end + 1
        ));
    } else {
        output.push_str(&format!("(Complete: all {} lines shown.)", lines.len()));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn continuation_is_one_based_and_stable() {
        assert_eq!(
            paginate(
                "a\nb\nc",
                &Page {
                    offset: Some(2),
                    limit: Some(1)
                }
            ),
            "b\n(Partial: lines 2-2 shown. Continue with offset=3.)"
        );
    }
}
