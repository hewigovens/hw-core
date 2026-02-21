use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use camino::Utf8PathBuf;
use clap::Parser;
use uniffi_bindgen::bindings::{self, GenerateOptions, TargetLanguage};

#[derive(Parser, Debug)]
#[command(
    name = "generate-bindings",
    about = "Generate Swift and Kotlin bindings for the hw-ffi crate",
    version,
    disable_help_subcommand = true
)]
struct Args {
    /// Path to the compiled hw-ffi dynamic library.
    #[arg(long, value_name = "PATH", conflicts_with = "auto")]
    lib: Option<PathBuf>,

    /// Force auto-discovery of the compiled library in target/{debug,release}.
    #[arg(long, conflicts_with = "lib")]
    auto: bool,

    /// Output directory for Swift bindings.
    #[arg(value_name = "SWIFT_OUT")]
    swift_out: PathBuf,

    /// Output directory for Kotlin bindings.
    #[arg(value_name = "KOTLIN_OUT")]
    kotlin_out: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let lib_path = match args.lib {
        Some(path) => to_utf8_path(path, "library path")?,
        None => find_default_library().with_context(|| {
            if args.auto {
                "auto-detecting hw-ffi library (--auto)"
            } else {
                "auto-detecting hw-ffi library (pass --lib <path> to override)"
            }
        })?,
    };

    let swift_out = to_utf8_path(args.swift_out, "Swift output directory")?;
    let kotlin_out = to_utf8_path(args.kotlin_out, "Kotlin output directory")?;

    bindings::generate(GenerateOptions {
        languages: vec![TargetLanguage::Swift],
        source: lib_path.clone(),
        out_dir: swift_out,
        config_override: None,
        format: false,
        crate_filter: None,
        metadata_no_deps: false,
    })
    .context("generating Swift bindings")?;

    bindings::generate(GenerateOptions {
        languages: vec![TargetLanguage::Kotlin],
        source: lib_path,
        out_dir: kotlin_out,
        config_override: None,
        format: false,
        crate_filter: None,
        metadata_no_deps: false,
    })
    .context("generating Kotlin bindings")?;

    Ok(())
}

fn to_utf8_path(value: PathBuf, what: &str) -> Result<Utf8PathBuf> {
    Utf8PathBuf::from_path_buf(value).map_err(|_| anyhow!("{what} must be valid UTF-8 path"))
}

fn find_default_library() -> Result<Utf8PathBuf> {
    let candidates = [
        "target/debug/libhwcore.dylib",
        "target/debug/libhwcore.so",
        "target/debug/hwcore.dll",
        "target/release/libhwcore.dylib",
        "target/release/libhwcore.so",
        "target/release/hwcore.dll",
    ];

    for candidate in candidates {
        let path = Utf8PathBuf::from(candidate);
        if path.exists() {
            return Ok(path);
        }
    }

    Err(anyhow!(
        "could not locate compiled hw-ffi library in target/{{debug,release}}"
    ))
}
