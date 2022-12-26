use std::{fs::File, io::stdout, path::PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand};
use pem_rfc7468::PemLabel;
use windows_ctl::CertificateTrustList;
use x509_cert::{der::Decode, Certificate};

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

    #[arg(short, long = "purpose", value_name = "PURPOSE")]
    purposes: Vec<String>,

    /// The output file to write to (must not exist)
    output: PathBuf,
}

fn load_ctl(input: PathBuf) -> Result<CertificateTrustList> {
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
    let ctl = load_ctl(args.input)?;
    let entries = ctl.trusted_subjects.iter().flatten().collect::<Vec<_>>();

    serde_json::to_writer(stdout(), &entries)?;

    Ok(())
}

fn fetch(args: FetchArgs) -> Result<()> {
    let ctl = load_ctl(args.input)?;

    println!("{:?}", args.purposes);

    for entry in ctl.trusted_subjects.iter().flatten().take(1) {
        let id = hex::encode(entry.cert_id());
        let url = format!(
            "http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/{}.crt",
            id
        );

        eprintln!("attempting to retrieve: {url}");

        let contents = reqwest::blocking::get(url)?.bytes()?;
        let cert = Certificate::from_der(&contents)?;

        println!(
            "{}",
            pem_rfc7468::encode_string(
                Certificate::PEM_LABEL,
                pem_rfc7468::LineEnding::LF,
                &contents,
            )?
        );
    }

    unimplemented!();
}
