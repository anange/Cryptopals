pub fn hex_to_b64(hex: &str) -> String {
    if hex.len() % 2 != 0 {
        panic!("Hex string should have even digits");
    }
    let bytes = hex_to_bytes(hex);
    let mut b64_conv = B64Converter::new(bytes);
    b64_conv.convert()
}

struct B64Converter {
    bytes: Vec<u8>,
    bit_index: usize,
    byte_index: usize,
}

impl B64Converter {
    pub fn new(bytes: Vec<u8>) -> B64Converter {
        let bit_index = 0;
        let byte_index = 0;
        B64Converter { bytes, bit_index, byte_index }
    }
    
    pub fn next(&mut self) -> Option<char> {
        let base64 = [
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
            'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
            'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
        ];
        if self.byte_index == self.bytes.len() {
            return None
        }
        let mut cur: u8;
        let remaining_bits = 8 - self.bit_index;
        cur = (self.bytes[self.byte_index] << self.bit_index) >> 2;
        if remaining_bits < 6 && self.byte_index != self.bytes.len() {
            cur += self.bytes[self.byte_index + 1] >> (10 - self.bit_index);
        }
        self.increase_bit_index();
        Some(base64[cur as usize])
    }

    fn increase_bit_index(&mut self) {
        self.bit_index += 6;
        if self.bit_index >= 8 {
            self.byte_index += 1;
            self.bit_index -= 8;
        }
    }

    pub fn convert(&mut self) -> String {
        let mut b64_chars: Vec<char> = Vec::new();
        let mut cur_char = self.next();
        while cur_char != None {
            b64_chars.push(cur_char.unwrap());
            cur_char = self.next();
        }
        match self.bit_index {
            4 => b64_chars.push('='),
            2 => {
                b64_chars.push('=');
                b64_chars.push('=');
            }
            _ => {}
        }
        b64_chars.into_iter().collect()
    }
}

pub fn fixed_xor(a: &str, b: &str) -> String {
    if a.len() != b.len() {
        panic!("Strings have no equal length");
    }
    let abytes = hex_to_bytes(a);
    let bbytes = hex_to_bytes(b);
    let mut cbytes: Vec<u8> = Vec::new();
    for i in 0..abytes.len() {
        cbytes.push(abytes[i] ^ bbytes[i]);
    }
    bytes_to_hex(cbytes)
}

pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut cur: u8 = 0u8;
    let mut bytes: Vec<u8> = Vec::new();

    let mut append = false;
    for c in hex.chars() {
       if append {
           cur += char_to_hex(c);
           bytes.push(cur);
       } else {
           cur = char_to_hex(c) << 4;
       }
       append = !append;
    }
    bytes
}

pub fn bytes_to_hex(bytes: Vec<u8>) -> String {
    let mut hex: Vec<char> = Vec::new();
    let mut cur: u8;

    for b in bytes {
        cur = b >> 4;
        hex.push(hex_to_char(cur));
        cur = b & 0b00001111u8;
        hex.push(hex_to_char(cur));
    }
    hex.into_iter().collect()
}

pub fn char_to_hex(c: char) -> u8 {
    if c >= '0' && c <= '9' {
        c as u8 - '0' as u8
    } else if c >= 'a' && c <= 'f' {
        10u8 + c as u8 - 'a' as u8
    } else {
        10u8 + c as u8 - 'A' as u8
    }
}

pub fn hex_to_char(c: u8) -> char {
    if c <= 9 {
        (c + '0' as u8) as char
    } else {
        (c - 10u8 + 'a' as u8) as char
    }
}

pub fn decode_byte_xor_cipher(hex: &str) -> (String, usize) {
    use std::str;
    let common_letters = ['e', 't', 'a', 'o', 'i', 'n', 's', 'h', 'r'];
    let bytes = hex_to_bytes(hex);
    let mut cur_score: usize;
    let mut max_score = 0;
    let mut best_match: Vec<u8> = Vec::new();
    for key in 0u8..255u8 {
        cur_score = 0;
        let xored = xor_with_byte(&bytes, key);
        for c in &xored {
            for letter in common_letters.iter() {
                if *letter == *c as char {
                    cur_score += 1;
                    break;
                }
            }
        }
        if max_score < cur_score {
            max_score = cur_score;
            best_match = xored;
        }
    }
    let decoded = str::from_utf8(&best_match);
    if decoded.is_err() {
        return (String::new(), 0)
    }
    (str::from_utf8(&best_match).unwrap().to_string(), max_score)
}

pub fn xor_with_byte(bytes: &Vec<u8>, key: u8) -> Vec<u8> {
    let mut xored_bytes: Vec<u8> = Vec::new();
    for byte in bytes {
        xored_bytes.push(byte ^ key);
    }
    xored_bytes
}
