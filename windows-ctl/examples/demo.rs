use std::env;

use windows_ctl::CertificateTrustList;

fn main() {
    // Use: demo <file>
    // Example: demo 'authrootstl.cab'
    let path = env::args().nth(1).expect("usage: demo <file>");
    let file = std::fs::File::open(&path).expect("error: couldn't open file");

    let ctl = if path.ends_with(".stl") || path.ends_with(".der") {
        CertificateTrustList::from_der(file).expect("failed to load CTL")
    } else {
        panic!("unexpected input (expected .der or .stl): {}", path);
    };

    for entry in ctl.trusted_subjects.iter().flatten() {
        println!("{:x?}", entry.cert_id());
        println!(
            "\t EKUs: {:?}",
            entry.extended_key_usages().collect::<Vec<_>>()
        )
    }
}
