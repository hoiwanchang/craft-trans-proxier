fn main() {
    let argv: Vec<String> = std::env::args().collect();
    std::process::exit(trans_proxier::cli::run(argv) as i32);
}
