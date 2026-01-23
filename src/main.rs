use std::{env};
use std::fs;
use btc_block_parser_rust::{read_varint, parse_block};
// use btc_block_parser_rust::read_transaction;

fn main() {
    // We will take the command line arguments and store them in a vector
    let cmds: Vec<String> = env::args().collect();

    let file_path = cmds.get(1).expect("Error reading files");
    let content = fs::read(file_path).expect("Not UTF-8");


    let block = parse_block(&content, 0);
    print!("\n=== Parsed Block ===");
    println!("Header : {:?}", block.header);
    println!("Transaction Count : {}", block.tx_count);
    for (i, tx) in block.txns.iter().enumerate() {
        println!("--- Transaction {} ---", i + 1);
        println!("Version: {}", tx.version);
        println!("Data ({} bytes): {:02x?}", tx.data.len(), tx.data);
    }   


}