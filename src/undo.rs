use std::io::{self, Read};
use crate::base128::read_varint_base128;

#[derive(Debug)]
pub struct Prevout {
    pub value_sats: u64,
    pub script_pubkey: Vec<u8>,
}

pub fn decompress_amount(x: u64) -> u64 {
    if x == 0 { return 0; }

    let mut x = x - 1;
    let mut e = x % 10;
    x /= 10;

    let mut n = if e < 9 {
        let d = (x % 9) + 1;
        x /= 9;
        x * 10 + d
    } else {
        x + 1
    };

    while e > 0 {
        n *= 10;
        e -= 1;
    }

    n
}

pub fn decompress_script<R: Read>(
    n_size: u64,
    r: &mut R,
) -> io::Result<Vec<u8>> {
    match n_size {
        0 => {
            let mut hash = [0u8; 20];
            r.read_exact(&mut hash)?;
            Ok([
                vec![0x76, 0xa9, 0x14],
                hash.to_vec(),
                vec![0x88, 0xac]
            ].concat())
        }
        1 => {
            let mut hash = [0u8; 20];
            r.read_exact(&mut hash)?;
            Ok([
                vec![0xa9, 0x14],
                hash.to_vec(),
                vec![0x87]
            ].concat())
        }
        2 | 3 => {
            let mut key = [0u8; 32];
            r.read_exact(&mut key)?;
            let prefix = if n_size == 2 { 0x02 } else { 0x03 };
            Ok([vec![33, prefix], key.to_vec(), vec![0xac]].concat())
        }
        4 | 5 => {
            // Bitcoin Core stores 32 bytes (x-coordinate); prefix is nSize-2 (0x02 or 0x03)
            let mut x = [0u8; 32];
            r.read_exact(&mut x)?;
            let prefix = (n_size - 2) as u8; // 2 or 3
            let mut compressed = [0u8; 33];
            compressed[0] = prefix;
            compressed[1..].copy_from_slice(&x);
            // Decompress to uncompressed pubkey using secp256k1
            let pubkey = bitcoin::secp256k1::PublicKey::from_slice(&compressed)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad uncompressed pubkey"))?;
            let uncompressed = pubkey.serialize_uncompressed(); // [u8; 65]
            let mut script = Vec::with_capacity(67);
            script.push(65);
            script.extend_from_slice(&uncompressed);
            script.push(0xac);
            Ok(script)
        }
        n if n >= 6 => {
            let len = (n - 6) as usize;
            let mut script = vec![0u8; len];
            r.read_exact(&mut script)?;
            Ok(script)
        }
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "bad nSize"))
    }
}

pub fn parse_txin_undo<R: Read>(r: &mut R) -> io::Result<Prevout> {
    let n_code = read_varint_base128(r)?;
    let height = n_code >> 1;

    if height > 0 {
        // Bitcoin Core writes a version dummy varint for legacy compat; read and discard it
        let _version_dummy = read_varint_base128(r)?;
    }

    let compressed_amount = read_varint_base128(r)?;
    let amount = decompress_amount(compressed_amount);

    let n_size = read_varint_base128(r)?;
    let script = decompress_script(n_size, r)?;

    Ok(Prevout {
        value_sats: amount,
        script_pubkey: script,
    })
}
