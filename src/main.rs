
use std::{env, fs};
use btc_block_parser_rust::{ count_blocks};
// use btc_block_parser_rust::read_transaction;

fn main() {
    // We will take the command line arguments and store them in a vector
    let cmds: Vec<String> = env::args().collect();
if cmds.len() <2 {
    print!("Please provide a file path as an argument.");
    return;
}
    let file_path = cmds.get(1).expect("Error reading files");
    let content = fs::read(file_path).expect("Not UTF-8");
}