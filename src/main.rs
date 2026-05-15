//! `minidump-2-core` CLI compatible with Breakpad's tool.
//!
//! Reads a Linux/Android minidump file and writes a corresponding ELF core
//! file to standard output (or to `--output`).

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use md2core::Md2CoreError;
use md2core::augment::augment_process;
use md2core::core_writer::write_core;
use md2core::rust_minidump::{ConvertOptions, read_process_from_path};

/// Convert a Breakpad minidump (Linux/Android) into an ELF core file readable
/// by gdb. Mirrors the original C++ tool's command-line surface.
#[derive(Debug, Parser)]
#[command(
    name = "minidump-2-core",
    about = "Convert a Linux/Android minidump into an ELF core file",
    version,
    disable_help_flag = false
)]
struct Cli {
    /// Verbose stream traversal output to stderr (currently unused but
    /// accepted for command-line compatibility with the C++ tool).
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Substitute module file names with `<sobasedir>` + basename.
    #[arg(long = "sobasedir")]
    so_base_dir: Option<String>,

    /// Mangle module names by prefixing them with their build-id GUID and
    /// stripping the original directory.
    #[arg(long = "mangle-sonames", value_parser = parse_mangle_flag, default_value = "0")]
    mangle_sonames: bool,

    /// Path to write the ELF core file to. Defaults to standard output.
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,

    /// Input minidump file.
    minidump: PathBuf,
}

fn parse_mangle_flag(value: &str) -> Result<bool, String> {
    match value {
        "0" => Ok(false),
        "1" => Ok(true),
        other => Err(format!("expected 0 or 1, got {other}")),
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("minidump-2-core: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<(), Md2CoreError> {
    let options = ConvertOptions {
        mangle_sonames: cli.mangle_sonames,
        so_base_dir: cli.so_base_dir.clone(),
        verbose: cli.verbose,
    };

    let mut process = read_process_from_path(&cli.minidump, &options)?;
    augment_process(&mut process, cli.verbose)?;

    if let Some(path) = &cli.output {
        let file = File::create(path)?;
        let mut out = BufWriter::new(file);
        write_core(&process, &mut out)?;
        out.flush()?;
    } else {
        let stdout = io::stdout();
        let mut out = BufWriter::new(stdout.lock());
        write_core(&process, &mut out)?;
        out.flush()?;
    }
    Ok(())
}
