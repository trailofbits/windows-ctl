use std::env;

use windows_ctl::Ctl;

fn main() {
    // Use: demo <file>
    // Example: demo 'authrootstl.cab'
    let path = env::args().nth(1).expect("usage: demo <file>");
    let file = std::fs::File::open(&path).expect("error: couldn't open file");

    let ctl = if path.ends_with(".stl") {
        Ctl::from_der(file).expect("failed to load CTL")
    } else if path.ends_with(".cab") {
        Ctl::from_cab(file).expect("failed to load CTL")
    } else {
        panic!("unexpected input (expected .cab or .stl): {}", path);
    };

    for entry in ctl.cert_list.iter() {
        println!("{:?}", entry.cert_id());
    }
}
