# Ratchet - Blaxingly fast, Bitcoin block parser.

## ====== Structs ======

```rust
struct Cursor<'a> {
    buf: & 'a[u8], // Slice with lifetime same as the parent struct
    pos: usize // Current position in the buffer
}

struct BlockIter<'a> {
    cur: Cursor<'a>
}

```