# bad_sha1
Bad implementation of the deprecated SHA-1 hash function.

## Usage
```rust
use bad_sha1::hash;
use hex_literal::hex;
                                                          
assert_eq!(
    hash(b"The quick brown fox jumps over the lazy dog"),
    hex!("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"),
);
```
