use std::io::{Error, ErrorKind};

fn read_u32_le(data: &[u8], offset: usize) -> Result<u32, Error> {
       let bytes: [u8; 4] = data
        .get(offset..offset + 4)
        .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "Not enough data"))?
        .try_into()
        .unwrap();
    Ok(u32::from_le_bytes(bytes))
}

pub struct Block {
    pub header: Blockheader,
    pub tx_count: u64,
    pub txns: Vec<transaction>,
}

pub struct transaction {
    pub version: u8,
    pub data : Vec<u8>
}
pub fn match_block(content: &[u8]) {
    let mut offset = 0usize;

    while offset + 4 <= content.len() {
        if !match_magic_bytes(content, offset) {
            println!("Magic bytes not matched!");
            break;
        }

        let size = read_u32_le(content, offset + 4).unwrap() as usize;

        if offset + 8 + size > content.len() {
            println!("Incomplete block data!");
            break;
        }
        let block_size = read_u32_le(content, offset+size).unwrap() as usize;

         let header = parse_header(&content[offset + 8..offset + 88]);

        println!("\n=== Block at offset {} ===", offset);
        println!("Block size: {} bytes", block_size);
        println!("Version: {}", header.version);
        print!("Previous block: ");
        print_hash_hex(&header.prev_block);
        print!("Merkle root: ");
        print_hash_hex(&header.merkle_root);
        println!("Timestamp: {}", header.time);
        println!("Bits: 0x{:08x}", header.bits);
        println!("Nonce: {}", header.nonce);

        offset += 8 + block_size;
    }
}

fn match_magic_bytes(content: &[u8], offset: usize) -> bool {
    let MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];
    let magic_array = &content[offset..offset + 4];
    if magic_array != MAGIC {
        return false;
    }
    true
}


fn read_32_bytes(data: &[u8], offset: usize) -> [u8; 32] {
    data[offset..offset + 32]
        .try_into()
        .expect("slice must be 32 bytes")
}

#[derive(Debug)]
pub struct Blockheader {
    version: u32,
    prev_block: [u8; 32],
    merkle_root: [u8; 32],
    time: u32,
    bits: u32, // target at the time of block mined
    nonce: u32,
}

fn parse_header(header: &[u8])-> Blockheader {
 Blockheader {
     version : read_u32_le(header, 0).unwrap(),
     prev_block : read_32_bytes(header, 4),
     merkle_root : read_32_bytes(header, 36),
     time : read_u32_le(header, 68).unwrap(),
     bits : read_u32_le(header, 72).unwrap(),
     nonce : read_u32_le(header, 76).unwrap()
}
}
/*
1️⃣ Help you write a correct read_varint
2️⃣ Add debug hex printing for hashes
3️⃣ Refactor into a clean BlockIterator
 */
pub fn read_varint(data: &[u8], offset: usize)-> (u64, usize) {
let first = &data[offset];
match first  {
    0x00..=0xfc => {
     (*first as u64, offset+1)
    }
    0xfd => {
        let byte:[u8;2] = data[offset+1..offset+3].try_into().unwrap();
        let value = u16::from_le_bytes(byte);
         (value as u64, offset+3)
    }
     0xfe => {
            let bytes: [u8; 4] = data[offset + 1..offset + 5]
                .try_into()
                .unwrap();
            let value = u32::from_le_bytes(bytes);
            (value as u64, offset + 5)
        }
        0xff => {
            let bytes: [u8; 8] = data[offset + 1..offset + 9]
                .try_into()
                .unwrap();
            let value = u64::from_le_bytes(bytes);
            (value, offset + 9)
        }
}
}
fn print_hash_hex(hash: &[u8;32]) {
    for byte in hash.iter().rev() {
        print!("{:02x}", byte);
    }
    println!();
}

pub fn parse_block(data: &[u8], offset: usize) -> Block {
    let header = parse_header(&data[offset..offset + 80]);

    // Transaction count comes right after header (at offset + 80)
    let (tx_count, mut tx_offset) = read_varint(data, offset + 80);

    println!("Transaction count: {}", tx_count);

    // For now, just skip transaction parsing
    let txns = Vec::new();

    Block {
        header,
        tx_count,
        txns,
    }
}