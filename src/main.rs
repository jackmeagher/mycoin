#![feature(repeat_generic_slice)]
extern crate sha1;
const DIGEST_LENGTH: usize = 20;
const MAX_BLOCK_SIZE: usize = 1024;
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
    /*
    let mut s = String::with_capacity(8);
    for bit in byte_to_bits(byte).iter() {
        if *bit {
            s.push('1');
        } else {
            s.push('0');
        }
    }
    */
    format!("{:x?}{:x?}", ((byte >> 4) << 4) / 16u8, byte % 16)
}

fn format_bytes(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 8);
    /*
    for byte in bytes {
        for bit in byte_to_bits(byte).iter() {
            if *bit {
                s.push('1');
            } else {
                s.push('0');
            }
        }
    }
    */
    for byte in bytes {
        s.push_str(&format_byte(byte));
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

fn count_leading_zeros_in_block(bytes: &[u8]) -> usize {
    let mut total_zeros: usize = 0;
    for byte in bytes.iter() {
        let zeros = byte.leading_zeros();
        total_zeros += (zeros as usize);
        if zeros != 8 {
            return total_zeros;
        }
    }
    // In case it's all zeros!
    total_zeros
}

fn generate_initial_pad_(length: usize) -> DataPad {
    [0u8].repeat(length)
}

fn generate_initial_pad(length: usize) -> Option<DataPad> {
    Some( [0u8].repeat(length) )
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

fn next_pad_assume_valid(mut pad: DataPad) -> DataPad {
    let mut idx: usize = pad.len() - 1;
    while idx > 0 {
        if pad[idx] != 255 {
            pad[idx] += 1;
            return pad;
        } else {
            pad[idx] = 0;
            idx -= 1;
        }
    }
    // Have to inspect the Most Significant Byte by hand to avoid underflowing usize
    if pad[0] != 255 {
        pad[0] += 1;
        return pad;
    }
    panic!()
}

// Returns (main sum, carry)
fn add_with_carry(x: u8, y: u8) -> (u8, bool) {
    let sum: u16 = (x as u16) + (y as u16);
    let least_significant_byte = sum as u8;
    return (least_significant_byte, sum >= (256u16));
}

// I THINK that xoring and adding the nonces are ultimately the same
fn xor_blocks(data: &DataBlock, pad: &DataPad) -> DataBlock {
    debug_assert_eq!(data.len(), pad.len());

    let mut xored: Vec<u8> = [ 0u8 ].repeat(data.len());

    for i in 0..data.len() {
        xored[i] = data[i] ^ pad[i];
    }

    xored
}

fn add_blocks(data: &DataBlock, pad: &DataPad) -> DataBlock {
    debug_assert_eq!(data.len(), pad.len());

    let length: usize = data.len();
    let mut sum: Vec<u8> = [ 0u8 ].repeat(length);

    let mut i = length - 1;
    let mut carry = false;
    loop {
        if !carry {
            let (partial_sum, partial_carry) = add_with_carry(data[i], pad[i]);
            sum[i] = partial_sum;
            carry = partial_carry;
        } else {
            let temp_sum: u16 = (data[i] as u16) + (pad[i] as u16) + 1u16;
            sum[i] = temp_sum as u8;
            carry = temp_sum >= 256u16;
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
    sum
}

fn find_nonce_for_difficulty(data_: &DataBlock, difficulty: usize) -> DataPad {
    assert!(data_.len() * 8 <= MAX_BLOCK_SIZE);
    let mut data: DataBlock = Vec::with_capacity(MAX_BLOCK_SIZE / 8);
    let padding = (MAX_BLOCK_SIZE / 8) - data_.len();

    for _i in 0..padding {
        data.push( 0u8 );
    }

    for byte in data_ {
        data.push( *byte );
    }

    let mut nonce = generate_initial_pad_(MAX_BLOCK_SIZE / 8);

    assert!(nonce.len() == data.len());

    loop {
        let sum = add_blocks(&data, &nonce);
        let digest = hash(&sum[..]);
        let zeros = count_leading_zeros_in_block(&digest);
        if zeros >= difficulty {
            println!("Found nonce! difficulty={}", difficulty);
            println!("Data  : {}", format_bytes(&data[..]));
            println!("Nonce : {}", format_bytes(&nonce[..]));
            println!("Sum   : {}", format_bytes(&sum[..]));
            println!("Digest: {}\n", format_bytes(&digest));
            break
        }
        nonce = next_pad_assume_valid(nonce);
    }

    nonce
}


fn main() {
    let nonce = find_nonce_for_difficulty(&[123u8].repeat(MAX_BLOCK_SIZE/8), 23);
}

#[cfg(test)]
mod tests {
    use super::*;

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
        use super::count_leading_zeros_in_block;

        #[test]
        fn counts_zeros_correctly() {
            assert_eq!(0, count_leading_zeros_in_block(&[ 255u8 ]));
            assert_eq!(1, count_leading_zeros_in_block(&[ 0b01111111u8 ]));
            assert_eq!(2, count_leading_zeros_in_block(&[ 0b00111111u8 ]));
            
            assert_eq!(8, count_leading_zeros_in_block(&[ 0u8, 255u8 ]));
            assert_eq!(9, count_leading_zeros_in_block(&[ 0u8, 0b01111111u8 ]));
            assert_eq!(10, count_leading_zeros_in_block(&[ 0u8, 0b00111111u8 ]));

            assert_eq!(160, count_leading_zeros_in_block(&[
                                                         0u8, 0u8, 0u8, 0u8,
                                                         0u8, 0u8, 0u8, 0u8,
                                                         0u8, 0u8, 0u8, 0u8,
                                                         0u8, 0u8, 0u8, 0u8,
                                                         0u8, 0u8, 0u8, 0u8 ]));
        }

        #[test]
        fn gives_correct_first_pad() {
            let v: Vec<u8> = Vec::new();
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

        use super::xor_blocks;
        use super::add_blocks;

        #[test]
        fn xor_simple_blocks() {
            let result1 = xor_blocks(
                &vec![ 0u8, 255u8 ],
                &vec![ 255u8, 0u8 ]
            );
            assert_eq!(result1, vec![ 255u8, 255u8 ]);

            let result2 = xor_blocks(
                &vec![ 255u8, 255u8 ],
                &vec![ 255u8, 255u8 ]
            );
            assert_eq!(result2, vec![ 0u8, 0u8 ]);

            let result3 = xor_blocks(
                &vec![ 0b10101010u8, 0b10101010u8 ],
                &vec![ 0b01010101u8, 0b11110000u8 ]
            );
            assert_eq!(result3, vec![ 255u8, 0b01011010u8 ]);
        }

        #[test]
        fn add_simple_blocks() {
            let result1 = add_blocks(
                &vec![ 0u8, 128u8 ],
                &vec![ 0u8, 128u8 ]
            );
            assert_eq!(result1, vec![ 1u8, 0u8 ]);

            let result2 = add_blocks(
                &vec![ 1u8, 128u8 ],
                &vec![ 0u8, 128u8 ]
            );
            assert_eq!(result2, vec![ 2u8, 0u8 ]);

            let result3 = add_blocks(
                &vec![ 0u8, 128u8 ],
                &vec![ 1u8, 128u8 ]
            );
            assert_eq!(result3, vec![ 2u8, 0u8 ]);

            let result4 = add_blocks(
                &vec![ 0u8, 127u8 ],
                &vec![ 0u8, 128u8 ]
            );
            assert_eq!(result4, vec![ 0u8, 255u8 ]);

            let result5 = add_blocks(
                &vec![ 0u8, 129u8 ],
                &vec![ 0u8, 128u8 ]
            );
            assert_eq!(result5, vec![ 1u8, 1u8 ]);
        }

        #[test]
        fn add_blocks_discards_total_carry(){
            let result1 = add_blocks(
                &vec![ 255u8, 255u8 ],
                &vec![ 1u8  , 0u8   ]
            );
            assert_eq!(result1, vec![ 0u8, 255u8 ])
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
