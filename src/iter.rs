use crate::Blockheader;
 use std::error::Error;
use crate::cursor::Cursor;
use crate::next_block_header;

struct BlockIter<'a> {
    cur: Cursor<'a>,
}

impl BlockIter<'_> {
    fn next(&mut self) -> Option<Result<Blockheader, Box<dyn Error>>> {
        match next_block_header(&mut self.cur) {
            Ok(Some(header)) => Some(Ok(header)),
            Ok(None) => None, // No more blocks to read
            Err(e) => Some(Err(Box::new(e))), // Return the error encountered
        }
    }
}
