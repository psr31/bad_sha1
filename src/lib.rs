
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
/// assert_eq!(
///     hash(b"The quick brown fox jumps over the lazy dog"),
///     [
///         0x2fd4e1c6,
///         0x7a2d28fc,
///         0xed849ee1,
///         0xbb76e739,
///         0x1b93eb12,
///     ]
/// );
/// ```
///
/// 
pub fn hash(input: &[u8]) -> [u32; 5] {
    let original_length = input.len() * 8;
    let mut temp;
    let mut a;
    let mut b;
    let mut c;
    let mut d;
    let mut e;
    let mut hash: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let mut seq = [0u32; 80];

    // Pad message
    let mut input = input.to_vec();
    input.push(0x80);
    let diff = input.len() % 64;
    if diff < 56 {
        input.extend(std::iter::repeat(0).take(56 - diff));
    } else {
        input.extend(std::iter::repeat(0).take(120 - diff));
    }
    input.extend_from_slice(&(original_length as u64).to_be_bytes());

    // Process message
    for block in input.chunks_exact(64) {
        for t in 0..16 {
            seq[t] = (block[t * 4] as u32) << 24;
            seq[t] |= (block[t * 4 + 1] as u32) << 16;
            seq[t] |= (block[t * 4 + 2] as u32) << 8;
            seq[t] |= block[t * 4 + 3] as u32;
        }

        for t in 16..80 {
            seq[t] = (seq[t - 3] ^ seq[t - 8] ^ seq[t - 14] ^ seq[t - 16]).rotate_left(1);
        }

        a = hash[0];
        b = hash[1];
        c = hash[2];
        d = hash[3];
        e = hash[4];

        for t in 0..20 {
            temp = a
                .rotate_left(5)
                .wrapping_add((b & c) | (!b & d))
                .wrapping_add(e)
                .wrapping_add(seq[t as usize])
                .wrapping_add(0x5A827999);

            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        for t in 20..40 {
            temp = a
                .rotate_left(5)
                .wrapping_add(b ^ c ^ d)
                .wrapping_add(e)
                .wrapping_add(seq[t as usize])
                .wrapping_add(0x6ED9EBA1);

            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        for t in 40..60 {
            temp = a
                .rotate_left(5)
                .wrapping_add((b & c) | (b & d) | (c & d))
                .wrapping_add(e)
                .wrapping_add(seq[t as usize])
                .wrapping_add(0x8F1BBCDC);

            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        for t in 60..80 {
            temp = a
                .rotate_left(5)
                .wrapping_add(b ^ c ^ d)
                .wrapping_add(e)
                .wrapping_add(seq[t as usize])
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

    hash
}

#[cfg(test)]
mod tests {
    use crate::hash;

    const TEST_TEXT: &[u8] = include_bytes!("../test.txt");

    #[test]
    fn test_hash1() {
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
    }

    #[test]
    fn test_hash2() {
        assert_eq!(
            hash(b"The quick brown fox jumps over the lazy cog"),
            [0xde9f2c7f, 0xd25e1b3a, 0xfad3e85a, 0x0bd17d9b, 0x100db4b3]
        );
    }

    #[test]
    fn test_empty_string() {
        assert_eq!(
            hash(b""),
            [0xda39a3ee, 0x5e6b4b0d, 0x3255bfef, 0x95601890, 0xafd80709]
        );
    }

    #[test]
    fn test_padding() {
        assert_eq!(
            hash(b"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz========"),
            [0x7822ad26, 0xc3079954, 0x7bcb3d14, 0x9ec98ea5, 0x37eb5761]
        );
    }

    #[test]
    fn test_file() {
        assert_eq!(
            hash(TEST_TEXT),
            [0x4e7d3ecd, 0xda407f4d, 0xd0e4173e, 0xee5a27cf, 0x05e00ca6]
        );
    }
}
