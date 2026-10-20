//! `runeward-browser`: the in-sandbox stateful browser driver.

fn main() {
    std::process::exit(runeward_browser::cli::main(
        std::env::args().skip(1).collect(),
    ));
}
