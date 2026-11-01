# Chosen character-request API — pre-Rust oracle boundary

Extend the existing `node94-newline-writer-protocol` crate without changing its byte function or3023 byte fixtures.

```rust
pub trait CharacterRequests {
    fn write_bytes(&mut self, bytes: &[u8], flag: &core::cell::Cell<u8>) -> u8;
    fn write_character(&mut self, character: char, flag: &core::cell::Cell<u8>) -> u8;
}

pub fn write_indented_character<W: CharacterRequests + ?Sized>(
    character: char,
    flag: &core::cell::Cell<u8>,
    writer: &mut W,
) -> u8;
```

One chosen proxy state provides both operations. The caller binds it to the native entry-cached destination/table and the selected flag reference; the API does not recover a native receiver/vtable/struct ABI. Actual native current-method lookup is an external proxy bridge obligation, including method reconfiguration during the byte callback. The shared proxy may change its subsequent character behavior during that callback, and both callbacks may change the flag byte. Safe Rust references, role/frame separation and normal returns form a stronger domain than arbitrary raw aliases, unwinding or concurrency.

The Rust `char` parameter restricts input to valid scalar values. The native comparison is on the complete low32 argument; no upper64 RSI preservation is claimed. No UTF8 encoding or rendered-output behavior is implemented by this controller. All return values are the chosen proxy's low8 status; raw noncanonical statuses describe a conditional machine-proxy transfer, not original `fmt::Result` validity.

The byte request is exactly four spaces. A nonzero byte-callback result returns1 without a controller flag store or character request. Otherwise the controller stores the LF predicate into the fixed flag reference before the character request; the character method's return byte and later flag changes survive. NUL is still one character request. Inputs U+010A and U+1000A distinguish the complete character comparison from narrower8/16-bit comparisons. The independent oracle should freeze request order, flag values at each method entry, callback script effects and final status/state before any character Rust implementation is written.

No character Rust exists yet. Root owns the independent oracle freeze before implementation/build.
