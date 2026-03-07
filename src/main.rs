use btc_block_parser_rust::{emit_error, run_cli};

fn main() {
    if let Err(err) = run_cli() {
        emit_error(&err);
        std::process::exit(1);
    }
}
