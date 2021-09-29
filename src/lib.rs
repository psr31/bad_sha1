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
    let original_length = input.len() * 8;
    let mut temp;
    let mut a;
    let mut b;
    let mut c;
    let mut d;
    let mut e;
    let mut hash: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let mut w = [0u32; 80];

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
            w[t] = (block[t * 4] as u32) << 24;
            w[t] |= (block[t * 4 + 1] as u32) << 16;
            w[t] |= (block[t * 4 + 2] as u32) << 8;
            w[t] |= block[t * 4 + 3] as u32;
        }

        for t in 16..80 {
            w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
        }

        a = hash[0];
        b = hash[1];
        c = hash[2];
        d = hash[3];
        e = hash[4];

        for t in 0..80 {
            let (logic, constant) = match t {
                t if t < 20 => ((b & c) | (!b & d), 0x5A827999),
                t if t < 40 => (b ^ c ^ d, 0x6ED9EBA1),
                t if t < 60 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                t if t < 80 => (b ^ c ^ d, 0xCA62C1D6),
                _ => unreachable!(),
            };

            temp = a
                .rotate_left(5)
                .wrapping_add(logic)
                .wrapping_add(e)
                .wrapping_add(w[t as usize])
                .wrapping_add(constant);

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

    let mut output = [0u8; 20];
    for word in 0..5 {
        output[word * 4] = (hash[word] >> 24) as u8;
        output[word * 4 + 1] = (hash[word] >> 16) as u8;
        output[word * 4 + 2] = (hash[word] >> 8) as u8;
        output[word * 4 + 3] = hash[word] as u8;
    }
    output
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
