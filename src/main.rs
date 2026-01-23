use std::{env};
use std::fs;
use std::u32;
// use btc_block_parser_rust::read_transaction;

fn main() {
    // We will take the command line arguments and store them in a vector
    let cmds: Vec<String> = env::args().collect();

    let file_path = cmds.get(1).expect("Error reading files");
    let content = fs::read(file_path).expect("Not UTF-8");

}