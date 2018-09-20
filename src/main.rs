extern crate sha1;
const DIGEST_LENGTH: usize = 20;
// First run, we're going to hash a vector of bytes into a 256-bit tuple (4 u64s)
fn hash(_: &[u8]) -> [u8; DIGEST_LENGTH] {
    let mut m = sha1::Sha1::new();
    m.update(b"Hello World!");
    return m.digest().bytes();
}

fn format_bit(bit: bool) -> char {
    if bit {
        return '1';
    }
    return '0';
}

fn print_byte(byte: &u8) {
    println!("{}",
             format_byte(byte));
    /*
             format_bit((byte & 0b10000000) != 0),
             format_bit((byte & 0b01000000) != 0),
             format_bit((byte & 0b00100000) != 0),
             format_bit((byte & 0b00010000) != 0),
             format_bit((byte & 0b00001000) != 0),
             format_bit((byte & 0b00000100) != 0),
             format_bit((byte & 0b00000010) != 0),
             format_bit((byte & 0b00000001) != 0));
             */
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

    mod format_byte {
        use super::format_byte;

        #[test]
        fn formats_powers_of_two_correctly() {
            assert_eq!(format_byte(&(1 as u8))  , "00000001");
            assert_eq!(format_byte(&(2 as u8))  , "00000010");
            assert_eq!(format_byte(&(4 as u8))  , "00000100");
            assert_eq!(format_byte(&(8 as u8))  , "00001000");
            assert_eq!(format_byte(&(16 as u8)) , "00010000");
            assert_eq!(format_byte(&(32 as u8)) , "00100000");
            assert_eq!(format_byte(&(64 as u8)) , "01000000");
            assert_eq!(format_byte(&(128 as u8)), "10000000");
        }
    }
}
