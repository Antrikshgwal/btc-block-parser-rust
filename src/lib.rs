use std::{
    io::{Error, ErrorKind},
};
mod cursor;
mod iter;
use crate::cursor::Cursor;

#[derive(Debug)]
pub struct Blockheader {
    version: u32,
    prev_block: [u8; 32],
    merkle_root: [u8; 32],
    time: u32,
    bits: u32, // target at the time of block mined
    nonce: u32,
}

pub struct Block {
    pub header: Blockheader,
    pub tx_count: u64,
    pub txns: Vec<Transaction>,
}

pub struct Transaction {
    pub version: u32,
    pub data: Vec<u8>,
}

/*
* Reads the first 4 bytes from the given offset and interprets them as a little-endian u32. Returns an *error if there isn't enough data.
*/
fn read_u32_le(cur: &mut Cursor) -> Result<u32, Error> {
    let bytes: [u8; 4] = cur.buf
        .get(cur.pos..cur.pos + 4)
        .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "Not enough data"))?
        .try_into()
        .unwrap();
    cur.pos += 4; // Move the cursor forward by 4 bytes
    Ok(u32::from_le_bytes(bytes))
}

pub fn match_block(cur: &mut Cursor) {
    let len = cur.buf.len();
    while cur.pos + 8 <= len {
        if !match_magic_bytes(cur) {
            println!("Magic bytes not matched!");
            break;
        }

        let size = read_u32_le(cur).unwrap() as usize;
        let payload_start = cur.pos;  // transactions
        if cur.pos + size > len {
            println!("Incomplete block data!");
            break;
        }

        let header = parse_header(cur).unwrap();

        println!("\n=== Block at offset {} ===", cur.pos - 8);
        println!("Block size: {} bytes", size);
        println!("Version: {}", header.version);
        print!("Previous block: ");
        print_hash_hex(&header.prev_block);
        print!("Merkle root: ");
        print_hash_hex(&header.merkle_root);
        println!("Timestamp: {}", header.time);
        println!("Bits: 0x{:08x}", header.bits);
        println!("Nonce: {}", header.nonce);
        //  after header parsing skip to the next block
        cur.pos = payload_start + size ; //  Skip block payload(transactions)
    }
}

fn match_magic_bytes(cur: &mut Cursor) -> bool {
    let magic: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];
    let magic_array = &cur.buf[cur.pos..cur.pos + 4];
    cur.pos += 4;
    if magic_array != magic {
        return false;
    }
    true
}

fn read_32_bytes(cur: &mut Cursor) -> [u8; 32] {
    let bytes = cur.buf[cur.pos..cur.pos + 32]
        .try_into()
        .expect("slice must be 32 bytes");
    cur.pos += 32;
    bytes
}

fn parse_header(cur: &mut Cursor) -> Result<Blockheader, Error>{
    let header = Blockheader {
        version: read_u32_le(cur).unwrap(),
        prev_block: read_32_bytes(cur),
        merkle_root: read_32_bytes(cur),
        time: read_u32_le(cur).unwrap(),
        bits: read_u32_le(cur).unwrap(),
        nonce: read_u32_le(cur).unwrap(),
    };
    Ok(header)
}

pub fn read_varint(cur: &mut Cursor) -> u64 {
    let first = &cur.buf[cur.pos];
    match first {
        0x00..=0xfc => {
            cur.pos += 1; // Move the cursor forward by 1 byte
            *first as u64
        },
        0xfd => {
            let byte: [u8; 2] = cur.buf[cur.pos + 1..cur.pos + 3].try_into().unwrap();
            let value = u16::from_le_bytes(byte);
            cur.pos += 3;
            value as u64
        }
        0xfe => {
            let bytes: [u8; 4] = cur.buf[cur.pos + 1..cur.pos + 5].try_into().unwrap();
            let value = u32::from_le_bytes(bytes);
            cur.pos += 5;
            value as u64
        }
        0xff => {
            let bytes: [u8; 8] = cur.buf[cur.pos + 1..cur.pos + 9].try_into().unwrap();
            let value = u64::from_le_bytes(bytes);
            cur.pos += 9;
            value as u64
        }
    }
}
fn print_hash_hex(hash: &[u8; 32]) {
    for byte in hash.iter().rev() {
        print!("{:02x}", byte);
    }
    println!();
}

pub fn parse_block(data: &[u8], offset: usize) -> Block {
    let mut cur = Cursor { buf: data, pos: offset };
    let header = parse_header(&mut cur).unwrap();

    // Transaction count comes right after header (at offset + 80)
    let tx_count = read_varint(&mut cur);

    // For now, just skip transaction parsing
    let txns = Vec::new();

    Block {
        header,
        tx_count,
        txns,
    }
}

fn read_block_framing(cur: &mut Cursor)-> Result<(usize, usize),Error> {
let len = cur.buf.len();

if cur.pos + 8 > len {
    return Err(Error::new(ErrorKind::UnexpectedEof, "Not enough bytes"));
}

// Check magic bytes
if !match_magic_bytes(cur) {
    return Err(Error::new(ErrorKind::InvalidData, "Invalid magic bytes"))
}

let block_size = read_u32_le(cur)? as usize;
let payload_start = cur.pos; // Start of block payload (transactions)
Ok((block_size, payload_start))
}

pub fn next_block_header(cur:&mut Cursor)-> Result<Option<Blockheader>,Error>{
    let (size, payload_start) = read_block_framing(cur)?;
    if payload_start + size > cur.buf.len(){
        return Ok(None);
    }
    let header = parse_header(cur)?;
    // Move cursor to the end of the block payload
    cur.pos = payload_start + size;
Ok(Some(header))
}



pub fn count_blocks(cur: &mut Cursor) -> Result<u32, Error> {
    let mut offset = 0;
    let magic_bytes: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];
    let mut blocks = 0;

    while offset + 8 <= cur.buf.len() {
        if &cur.buf[offset..offset + 4] != magic_bytes {
            return Err(Error::new(ErrorKind::InvalidData, "Invalid magic bytes"));
        }
        // skip magic bytes
        offset += 4;
        if offset + 4 > cur.buf.len() {
            break;
        }
        let block_size = u32::from_le_bytes([
            cur.buf[offset],
            cur.buf[offset + 1],
            cur.buf[offset + 2],
            cur.buf[offset + 3],
        ]) as usize;
        offset += 4;

        if offset+ block_size > cur.buf.len(){
            break;
        }
        offset += block_size;
        blocks += 1
    }
    Ok(blocks)
}
