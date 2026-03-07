use std::io::{self, Read};

pub fn read_varint_base128<R: Read>(r: &mut R) -> io::Result<u64> {
    let mut value: u64 = 0;

    loop {
        let mut b = [0u8; 1];
        r.read_exact(&mut b)?;
        let byte = b[0];

        value = (value << 7) | (byte & 0x7F) as u64;

        if (byte & 0x80) == 0 {
            break;
        }

        value += 1;
    }

    Ok(value)
}
