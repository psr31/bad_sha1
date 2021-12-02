const HASH_CONSTANTS: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

/// Hashes the given input using the SHA-1 (Secure Hash Algorithm 1)
/// cryptographic hash function, returning the 5 word digest.
///
/// # Arguments
///
/// *  `input` - Byte slice holding input message
///
/// # Examples
///
/// ```
/// use bad_sha1::hash;
/// use hex_literal::hex;
///
/// assert_eq!(
///     hash(b"The quick brown fox jumps over the lazy dog"),
///     hex!("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"),
/// );
/// ```
///
pub fn hash(input: &[u8]) -> [u8; 20] {
    let mut hash: [u32; 5] = HASH_CONSTANTS;

    let mut blocks = input.chunks_exact(64);

    for block in blocks.by_ref() {
        update_hash(&mut hash, block);
    }

    let remainder = blocks.remainder();
    let rem_len = remainder.len();

    let mut last_block = [0u8; 64];
    last_block[..rem_len].copy_from_slice(remainder);
    last_block[rem_len] = 0x80;

    if rem_len > 54 {
        update_hash(&mut hash, &last_block);
        last_block = [0u8; 64];
    }

    let bit_length = input.len() as u64 * 8;
    last_block[56..].copy_from_slice(&bit_length.to_be_bytes());
    update_hash(&mut hash, &last_block);

    let mut output = [0u8; 20];
    for word in 0..5 {
        output[word * 4] = (hash[word] >> 24) as u8;
        output[word * 4 + 1] = (hash[word] >> 16) as u8;
        output[word * 4 + 2] = (hash[word] >> 8) as u8;
        output[word * 4 + 3] = hash[word] as u8;
    }
    output
}

fn update_hash(hash: &mut [u32; 5], block: &[u8]) {
    let mut w = [0u32; 80];

    for t in 0..16 {
        w[t] = (block[t * 4] as u32) << 24;
        w[t] |= (block[t * 4 + 1] as u32) << 16;
        w[t] |= (block[t * 4 + 2] as u32) << 8;
        w[t] |= block[t * 4 + 3] as u32;
    }

    for t in 16..80 {
        w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
    }

    let mut a = hash[0];
    let mut b = hash[1];
    let mut c = hash[2];
    let mut d = hash[3];
    let mut e = hash[4];

    for &x in &w[0..20] {
        let temp = a
            .rotate_left(5)
            .wrapping_add((b & c) | (!b & d))
            .wrapping_add(e)
            .wrapping_add(x)
            .wrapping_add(0x5A827999);

        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }

    for &x in &w[20..40] {
        let temp = a
            .rotate_left(5)
            .wrapping_add(b ^ c ^ d)
            .wrapping_add(e)
            .wrapping_add(x)
            .wrapping_add(0x6ED9EBA1);

        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }

    for &x in &w[40..60] {
        let temp = a
            .rotate_left(5)
            .wrapping_add((b & c) | (b & d) | (c & d))
            .wrapping_add(e)
            .wrapping_add(x)
            .wrapping_add(0x8F1BBCDC);

        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }

    for &x in &w[60..80] {
        let temp = a
            .rotate_left(5)
            .wrapping_add(b ^ c ^ d)
            .wrapping_add(e)
            .wrapping_add(x)
            .wrapping_add(0xCA62C1D6);

        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }

    hash[0] = hash[0].wrapping_add(a);
    hash[1] = hash[1].wrapping_add(b);
    hash[2] = hash[2].wrapping_add(c);
    hash[3] = hash[3].wrapping_add(d);
    hash[4] = hash[4].wrapping_add(e);
}

#[cfg(test)]
mod tests {
    use crate::hash;
    use hex_literal::hex;

    #[test]
    fn test_hash1() {
        assert_eq!(
            hash(b"The quick brown fox jumps over the lazy dog"),
            hex!("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"),
        );
    }

    #[test]
    fn test_hash2() {
        assert_eq!(
            hash(b"The quick brown fox jumps over the lazy cog"),
            hex!("de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"),
        );
    }

    #[test]
    fn test_empty_string() {
        assert_eq!(hash(b""), hex!("da39a3ee5e6b4b0d3255bfef95601890afd80709"),);
    }

    #[test]
    fn test_padding() {
        assert_eq!(
            hash(b"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz========"),
            hex!("7822ad26c30799547bcb3d149ec98ea537eb5761"),
        );
    }
}
