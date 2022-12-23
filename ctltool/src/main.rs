use std::{fs::File, path::PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand};
use windows_ctl::CertificateTrustList;

fn main() -> Result<()> {
    let args = Cli::parse();

    match args.command {
        Commands::Dump(args) => dump(args),
        Commands::Fetch(args) => fetch(args),
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Dump the given CTL file as JSON.
    Dump(DumpArgs),
    /// Retrieve the certificates listed and create a PEM store from them.
    Fetch(FetchArgs),
}

#[derive(Args, Debug)]
struct DumpArgs {
    /// The CTL file (in CAB or DER format)
    input: PathBuf,
}

#[derive(Args, Debug)]
struct FetchArgs {
    /// The CTL file (in CAB or DER format)
    input: PathBuf,
    /// The output file to write to (must not exist)
    output: PathBuf,
}

fn get_ctl(input: PathBuf) -> Result<CertificateTrustList> {
    let file = File::open(&input)?;

    match input.extension().and_then(|s| s.to_str()) {
        Some("der") | Some("stl") => {
            CertificateTrustList::from_der(file).context("failed to load CTL from PKCS#7 input")
        }
        Some("cab") => {
            let mut cabinet = cab::Cabinet::new(file).context("failed to parse cabinet")?;

            unimplemented!()
        }
        Some(other) => Err(anyhow!("unexpected file extension: {}", other)),
        None => Err(anyhow!("missing or invalid file extension")),
    }
}

fn dump(args: DumpArgs) -> Result<()> {
    let ctl = get_ctl(args.input)?;

    unimplemented!();
}

fn fetch(args: FetchArgs) -> Result<()> {
    let ctl = get_ctl(args.input)?;

    unimplemented!();
}
