fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    let bytes: [u8; 4] = data[offset..offset + 4].try_into().unwrap();

    u32::from_le_bytes(bytes)
}
pub fn match_block(content: &[u8]) {
    let mut offset = 0usize;

    while offset + 4 <= content.len() {
        if !match_magic_bytes(content, offset) {
            println!("Magic bytes not matched!");
            break;
        }

        let size = read_u32_le(content, offset + 4) as usize;
        let block_size = read_u32_le(content, offset+size) as usize;
        if offset + 8 + block_size > content.len() {
            break;
        }
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
struct Blockheader {
    version: u32,
    prev_block: [u8; 32],
    merkle_root: [u8; 32],
    time: u32,
    bits: u32, // target at the time of block mined
    nonce: u32,
}

fn parse_header(header: &[u8])-> Blockheader {
 Blockheader {
     version : read_u32_le(header, 0),
     prev_block : read_32_bytes(header, 4),
     merkle_root : read_32_bytes(header, 36),
     time : read_u32_le(header, 68),
     bits : read_u32_le(header, 72),
     nonce : read_u32_le(header, 76 )
}
}
