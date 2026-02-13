pub struct Cursor<'a> {
   pub buf: & 'a[u8], // Slice with lifetime same as the parent struct
   pub pos: usize // Current position in the buffer
}