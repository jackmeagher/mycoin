#![feature(repeat_generic_slice)]
extern crate sha1;
const DIGEST_LENGTH: usize = 20;
// First run, we're going to hash a vector of bytes into a 256-bit tuple (4 u64s)
//type DataBlock = [u8; DIGEST_LENGTH];
//type DataPad = [u8; DIGEST_LENGTH];
type DataPad = Vec<u8>;
type DataBlock = Vec<u8>;
type Digest = [u8; DIGEST_LENGTH];

fn hash(data: &[u8]) -> Digest {
    let mut m = sha1::Sha1::new();
    m.update(data);
    return m.digest().bytes();
}

fn format_bit(bit: bool) -> char {
    if bit {
        return '1';
    }
    return '0';
}

fn format_byte(byte: &u8) -> String {
    let mut s = String::new();
    for bit in byte_to_bits(byte).iter() {
        if (*bit) {
            s.push('1');
        } else {
            s.push('0');
        }
    }
    s
}

fn print_byte(byte: &u8) {
    println!("{}", format_byte(byte));
}

fn byte_to_bits(byte: &u8) -> [bool; 8] {
    [
        (byte & 0b10000000) != 0,
        (byte & 0b01000000) != 0,
        (byte & 0b00100000) != 0,
        (byte & 0b00010000) != 0,
        (byte & 0b00001000) != 0,
        (byte & 0b00000100) != 0,
        (byte & 0b00000010) != 0,
        (byte & 0b00000001) != 0
    ]
}

fn count_leading_zeros_in_block(bytes: &[u8]) -> u8 {
    let mut total_zeros: u8 = 0;
    for byte in bytes.iter() {
        let zeros = byte.leading_zeros() as u8;
        total_zeros += zeros;
        if zeros != 8 {
            return total_zeros;
        }
    }
    // In case it's all zeros!
    total_zeros
}

fn generate_initial_pad(length: usize) -> Option<DataPad> {
    Some([0u8].repeat(length))

}

fn next_pad(pad: Option<DataPad>) -> Option<DataPad> {
    match pad {
        Some(pad_) => next_pad_(pad_),
        None => None
    }
}

fn next_pad_(mut pad: DataPad) -> Option<DataPad> {
    let mut idx: usize = pad.len() - 1;
    while idx > 0 {
        if pad[idx] != 255 {
            pad[idx] += 1;
            return Some(pad);
        } else {
            pad[idx] = 0;
            idx -= 1;
        }
    }
    // Have to inspect the Most Significant Byte by hand to avoid underflowing usize
    if pad[0] != 255 {
        pad[0] += 1;
        return Some(pad);
    }
    return None;
}

// Returns (main sum, carry)
fn add_with_carry(x: u8, y: u8) -> (u8, bool) {
    let sum: u16 = (x as u16) + (y as u16);
    let least_significant_byte = sum as u8;
    return (least_significant_byte, sum >= (256u16));
}

fn xor_blocks(data: &mut DataBlock, pad: &DataPad) {
    debug_assert_eq!(data.len(), pad.len());
    for i in 0..data.len() {
        data[i] ^= pad[i];
    }
}


fn main() {
    let msg = "Hello, world!";
    println!("{}", msg);
    let h = hash(b"Hello, world!");
    println!("{}", format_bit(true));
    
    for byte in h.iter() {
        print_byte(byte);
    }
    println!("{}", 32 as u8);
    print_byte(&(32 as u8));
    print_byte(&(64 as u8));
    print_byte(&(65 as u8));
    print_byte(&(0b10101010 as u8));
}

#[cfg(test)]
mod tests {
    use super::*;

    mod invariants {
        use super::DIGEST_LENGTH;

        #[test]
        fn digest_is_less_than_256_bits() {
            // This is to make it okay to use u8 as the return type of count_leading_zeros
            assert!(DIGEST_LENGTH*8 < 256);
        }
    }

    mod format_byte {
        use super::format_byte;

        #[test]
        fn formats_powers_of_two_correctly() {
            assert_eq!(format_byte(&(1u8))  , "00000001");
            assert_eq!(format_byte(&(2u8))  , "00000010");
            assert_eq!(format_byte(&(4u8))  , "00000100");
            assert_eq!(format_byte(&(8u8))  , "00001000");
            assert_eq!(format_byte(&(16u8)) , "00010000");
            assert_eq!(format_byte(&(32u8)) , "00100000");
            assert_eq!(format_byte(&(64u8)) , "01000000");
            assert_eq!(format_byte(&(128u8)), "10000000");
        }
    }

    mod bit_arithmetic {
        use super::add_with_carry;

        #[test]
        fn basic_test() {
            assert_eq!(add_with_carry(128u8, 128u8), (0u8, true));
            //assert_eq!(add_with_carry(128 as u8, 127 as u8), (255 as u8, false));
            assert_eq!(add_with_carry(128u8, 129u8), (1u8, true));
        }

        #[test]
        fn one() {
            assert_eq!(add_with_carry(0u8, 0u8), (0u8, false));
        }

        #[test]
        fn two() {
            assert_eq!(add_with_carry(1u8, 0u8), (1u8, false));
        }

        #[test]
        fn three() {
            assert_eq!(add_with_carry(0u8, 1u8), (1u8, false));
        }

        #[test]
        fn four() {
            assert_eq!((128u8 as u16) + (128u8 as u16), 256u16);
            assert_eq!(add_with_carry(128u8, 128u8), (0u8, true));
        }

        #[test]
        fn five() {
            assert_eq!((255u8 as u16) + (1u8 as u16), 256u16);
            assert_eq!(add_with_carry(255u8, 1u8), (0u8, true));
        }

        #[test]
        fn six() {
            assert_eq!(add_with_carry(128u8, 127u8), (255u8, false));
        }
    }

    mod pad {
        use super::generate_initial_pad;
        use super::next_pad;
        use super::DIGEST_LENGTH;

        #[test]
        fn gives_correct_first_pad() {
            let mut v: Vec<u8> = Vec::new();
            assert_eq!(
                generate_initial_pad(0).unwrap(),
                v);
            assert_eq!(
                generate_initial_pad(1).unwrap(),
                vec![0u8]);
            assert_eq!(
                generate_initial_pad(2).unwrap(),
                vec![0u8, 0u8]);
            assert_eq!(
                generate_initial_pad(3).unwrap(),
                vec![0u8, 0u8, 0u8]);
        }

        #[test]
        fn gives_correct_short_second_pad() {
            let pad = next_pad(generate_initial_pad(1)).unwrap();

            assert_eq!(pad, vec![ 1u8 ]);

        }
        #[test]
        fn gives_correct_long_second_pad() {
            let pad = next_pad(generate_initial_pad(DIGEST_LENGTH)).unwrap();

            assert_eq!(pad,
                       vec![ 0u8, 0u8, 0u8, 0u8,
                         0u8, 0u8, 0u8, 0u8,
                         0u8, 0u8, 0u8, 0u8,
                         0u8, 0u8, 0u8, 0u8,
                         0u8, 0u8, 0u8, 1u8 ]);

        }

        #[test]
        fn rolls_over_correctly() {
            let test_val = next_pad(
                Some(vec![ 0u8, 0u8, 0u8, 0u8,
                  0u8, 0u8, 0u8, 0u8,
                  0u8, 0u8, 0u8, 0u8,
                  0u8, 0u8, 0u8, 0u8,
                  0u8, 0u8, 0u8, 255u8 ]));
            assert_eq!(test_val,
                Some(
                vec![ 0u8, 0u8, 0u8, 0u8,
                  0u8, 0u8, 0u8, 0u8,
                  0u8, 0u8, 0u8, 0u8,
                  0u8, 0u8, 0u8, 0u8,
                  0u8, 0u8, 1u8, 0u8 ]));
        }

        #[test]
        fn gives_correct_last_pad() {
            let test_val = next_pad(
                Some(vec![ 255u8, 255u8, 255u8, 255u8,
                  255u8, 255u8, 255u8, 255u8,
                  255u8, 255u8, 255u8, 255u8,
                  255u8, 255u8, 255u8, 255u8,
                  255u8, 255u8, 255u8, 254u8 ]));

            assert_eq!(test_val,
                Some(vec![ 255u8, 255u8, 255u8, 255u8,
                  255u8, 255u8, 255u8, 255u8,
                  255u8, 255u8, 255u8, 255u8,
                  255u8, 255u8, 255u8, 255u8,
                  255u8, 255u8, 255u8, 255u8 ]));
        }

        #[test]
        fn ends_correctly() {
            let test_val = next_pad(
                Some(vec![ 255u8, 255u8, 255u8, 255u8,
                  255u8, 255u8, 255u8, 255u8,
                  255u8, 255u8, 255u8, 255u8,
                  255u8, 255u8, 255u8, 255u8,
                  255u8, 255u8, 255u8, 255u8 ]));
            assert_eq!(test_val, None);
        }
    }

    mod hashing {
        use super::hash;

        #[test]
        fn known_hashes_are_good() {
            let h = hash(b"Hello World!");
            
            // The hex hash is 2ef7bde608ce5404e97d5f042f95f89f1c232871
            let known_result: [u8; 20] =
              [ 0x2e as u8,
                0xf7 as u8,
                0xbd as u8,
                0xe6 as u8,
                0x08 as u8,
                0xce as u8,
                0x54 as u8,
                0x04 as u8,
                0xe9 as u8,
                0x7d as u8,
                0x5f as u8,
                0x04 as u8,
                0x2f as u8,
                0x95 as u8,
                0xf8 as u8,
                0x9f as u8,
                0x1c as u8,
                0x23 as u8,
                0x28 as u8,
                0x71 as u8 ];
            assert_eq!(h, known_result);
        }
    }
}
