//! Offline review tool for a netune trace bundle.
//!
//! Usage:
//!   netune-diagnose inspect `<bundle-dir>`
//!   netune-diagnose diff `<left-bundle-dir>` `<right-bundle-dir>`
//!
//! The tool reads only the bundle's `trace.json` and `diagnosis.txt`. It never
//! opens a socket and never writes into the bundle.

use std::path::Path;
use std::process::ExitCode;

use netune_trace::TraceSnapshot;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [command, directory] if command == "inspect" => inspect(directory),
        [command, left, right] if command == "diff" => diff(left, right),
        _ => {
            eprintln!("usage: netune-diagnose inspect <bundle-dir>");
            eprintln!("       netune-diagnose diff <left-bundle-dir> <right-bundle-dir>");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("netune-diagnose: {error}");
            ExitCode::FAILURE
        }
    }
}

fn inspect(directory: &str) -> Result<(), Box<dyn std::error::Error>> {
    let rendered = Path::new(directory).join("diagnosis.txt");
    if rendered.exists() {
        print!("{}", std::fs::read_to_string(rendered)?);
        return Ok(());
    }
    let snapshot = read_snapshot(directory)?;
    print!("{}", snapshot.diagnose().render_text());
    Ok(())
}

fn diff(left: &str, right: &str) -> Result<(), Box<dyn std::error::Error>> {
    let left = read_snapshot(left)?;
    let right = read_snapshot(right)?;
    print!("{}", netune_trace::diff(&left, &right).render_text());
    Ok(())
}

fn read_snapshot(directory: &str) -> Result<TraceSnapshot, Box<dyn std::error::Error>> {
    let path = Path::new(directory).join("trace.json");
    let text = std::fs::read_to_string(&path)?;
    Ok(serde_json::from_str(&text)?)
}
