use std::path::Path;

use anyhow::{Context, Result};

pub fn read_text_file(path: &Path, label: &str) -> Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("reading {label}: {}", path.display()))
}

pub fn read_inline_or_file_argument(value: &str, label: &str) -> Result<String> {
    if let Some(path) = value.strip_prefix('@') {
        read_text_file(Path::new(path), label)
    } else {
        Ok(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_or_file_argument_reads_at_prefixed_paths_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tx.json");
        std::fs::write(&path, "from-file").unwrap();

        let inline = read_inline_or_file_argument("inline-json", "tx file").unwrap();
        let from_file =
            read_inline_or_file_argument(&format!("@{}", path.display()), "tx file").unwrap();
        let missing = read_inline_or_file_argument("@/nonexistent/tx.json", "tx file").unwrap_err();

        assert_eq!(inline, "inline-json");
        assert_eq!(from_file, "from-file");
        assert!(
            missing.to_string().starts_with("reading tx file: "),
            "{missing}"
        );
    }
}
