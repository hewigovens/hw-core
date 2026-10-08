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

    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_file_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("hw-cli-{name}-{}-{nanos}.txt", std::process::id()))
    }

    #[test]
    fn read_inline_or_file_argument_returns_inline_text() {
        let value = read_inline_or_file_argument("inline-json", "tx file").unwrap();
        assert_eq!(value, "inline-json");
    }

    #[test]
    fn read_inline_or_file_argument_reads_prefixed_file() {
        let path = temp_file_path("inline-or-file");
        std::fs::write(&path, "from-file").unwrap();

        let value =
            read_inline_or_file_argument(&format!("@{}", path.display()), "tx file").unwrap();
        assert_eq!(value, "from-file");

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn read_text_file_reads_utf8_contents() {
        let path = temp_file_path("read-text-file");
        std::fs::write(&path, "{\"ok\":true}").unwrap();

        let value = read_text_file(&path, "typed-data file").unwrap();
        assert_eq!(value, "{\"ok\":true}");

        let _ = std::fs::remove_file(path);
    }
}
