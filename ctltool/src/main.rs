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
            CertificateTrustList::from_der(file).context("failed to load CTL from PKCS#7")
        }
        Some("cab") => {
            let mut cabinet = cab::Cabinet::new(file).context("failed to parse cabinet")?;

            // For the time being, we only bother to look for authroot.stl.
            // If you have a disallowedcertstl.cab, you should just extract it first.
            CertificateTrustList::from_der(
                cabinet
                    .read_file("authroot.stl")
                    .context("failed to extract STL from cabinet")?,
            )
            .context("failed to load CTL from PKCS#7")
        }
        Some(other) => Err(anyhow!("unexpected file extension: {}", other)),
        None => Err(anyhow!("missing or invalid file extension")),
    }
}

fn dump(args: DumpArgs) -> Result<()> {
    let ctl = get_ctl(args.input)?;

    for entry in ctl.trusted_subjects.iter().flatten() {
        println!("{:x?}", entry.cert_id());
        println!(
            "\t EKUs: {:?}",
            entry
                .extended_key_usages()
                .collect::<Result<Vec<_>, _>>()
                .context("unexpected EKU format")?
        )
    }

    Ok(())
}

fn fetch(args: FetchArgs) -> Result<()> {
    let ctl = get_ctl(args.input)?;

    unimplemented!();
}
