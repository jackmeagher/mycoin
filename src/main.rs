extern crate sha1;
const DIGEST_LENGTH: usize = 20;
// First run, we're going to hash a vector of bytes into a 256-bit tuple (4 u64s)
type DataBlock = [u8; DIGEST_LENGTH];

fn hash(data: &[u8]) -> DataBlock {
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

fn print_byte(byte: &u8) {
    println!("{}", format_byte(byte));
}

fn format_byte(byte: &u8) -> String {
    format!("{}{}{}{}{}{}{}{}",
             format_bit((byte & 0b10000000) != 0),
             format_bit((byte & 0b01000000) != 0),
             format_bit((byte & 0b00100000) != 0),
             format_bit((byte & 0b00010000) != 0),
             format_bit((byte & 0b00001000) != 0),
             format_bit((byte & 0b00000100) != 0),
             format_bit((byte & 0b00000010) != 0),
             format_bit((byte & 0b00000001) != 0))
}

fn count_zeroes_in_block(bytes: &DataBlock) -> u8 {
    let mut total_zeroes: u8 = 0;
    for byte in bytes.iter() {
        let zeroes = (byte.leading_zeros() as u8);
        total_zeroes += zeroes;
        if zeroes != 8 {
            return total_zeroes;
        }
    }
    // In case it's all zeroes!
    return total_zeroes;
}

fn generate_initial_pad() -> DataBlock {
    return [ 0 as u8, 0 as u8, 0 as u8, 0 as u8,
             0 as u8, 0 as u8, 0 as u8, 0 as u8,
             0 as u8, 0 as u8, 0 as u8, 0 as u8,
             0 as u8, 0 as u8, 0 as u8, 0 as u8,
             0 as u8, 0 as u8, 0 as u8, 0 as u8 ];

}

// Returns (main sum, carry)
fn add_with_carry(x: u8, y: u8) -> (u8, bool) {
    let sum: u16 = (x as u16) + (y as u16);
    let least_significant_byte = sum as u8;
    return (least_significant_byte, sum >= (256u16));
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
            // This is to make it okay to use u8 as the return type of count_leading_zeroes
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
