# bad_sha1
Bad implementation of the deprecated SHA-1 hash function.  
Written as personal practice.

## Usage
```rust
assert_eq!(
    hash(b"The quick brown fox jumps over the lazy dog"),
    [
        0x2fd4e1c6u32,
        0x7a2d28fc,
        0xed849ee1,
        0xbb76e739,
        0x1b93eb12
    ]
);
```

