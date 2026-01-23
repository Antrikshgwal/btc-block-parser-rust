pub fn read_le_bytes(content: &[u8]) {
    let mut offset = 0usize;

    while offset + 4 <= content.len() {
        if read_magic_bytes(content, offset) {
            println!("Magic bytes not matched!");
            break;
        }

        let size = &content[offset + 4..offset + 8];
        let block_size = u32::from_le_bytes(size.try_into().unwrap()) as usize;
        if offset + 8 + block_size > content.len() {
            break;
        }
        offset += 8 + block_size;
    }
}

fn read_magic_bytes(content: &[u8], offset: usize) -> bool {
    let MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];
    let magic_array = &content[offset..offset + 4];
    if magic_array != MAGIC {
        return true;
    }
    false
}

fn parse_header(header: &[u8]){
  
}
