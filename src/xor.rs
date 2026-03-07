use std::io::{self, Read};

pub struct XorReader<R> {
    inner: R,
    key: Box<[u8]>,
    key_len: usize,
    pos: usize, // total bytes read so far
    enabled: bool,
}

impl<R: Read> XorReader<R> {
    pub fn new(inner: R, key: Vec<u8>) -> Self {
        let enabled = key.iter().any(|&b| b != 0);

        Self {
            inner,
            key_len: key.len(),
            key: key.into_boxed_slice(),
            pos: 0,
            enabled,
        }
    }
}

impl<R: Read> Read for XorReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;

        if !self.enabled || n == 0 {
            return Ok(n);
        }

        let key = &self.key;
        let key_len = self.key_len;

        let mut key_index = self.pos % key_len;

        for b in &mut buf[..n] {
            *b ^= key[key_index];
            key_index += 1;
            if key_index == key_len {
                key_index = 0;
            }
        }

        self.pos += n;

        Ok(n)
    }
}
