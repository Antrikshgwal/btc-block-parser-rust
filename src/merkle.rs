use sha2::{Sha256, Digest};

pub fn dsha256(data: &[u8]) -> [u8; 32] {
    let h1 = Sha256::digest(data);
    let h2 = Sha256::digest(&h1);
    h2.into()
}

pub fn compute_merkle(mut hashes: Vec<[u8; 32]>) -> [u8; 32] {
    while hashes.len() > 1 {
        if hashes.len() % 2 == 1 {
            let last = *hashes.last().unwrap();
            hashes.push(last);
        }

        let mut next = Vec::with_capacity(hashes.len() / 2);

        for pair in hashes.chunks(2) {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&pair[0]);
            buf[32..].copy_from_slice(&pair[1]);
            next.push(dsha256(&buf));
        }

        hashes = next;
    }

    hashes[0]
}
