use ratchet::count_blocks;
use std::{env, fs};


fn main() {
    // We will take the command line arguments and store them in a vector
    let cmds: Vec<String> = env::args().collect();
    if cmds.len() < 2 {
        print!("Please provide a file path as an argument.");
        return;
    }
    let file_path = cmds.get(1).expect("Error reading files");
    let content = fs::read(file_path).expect("Not UTF-8");
}
