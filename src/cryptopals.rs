const BASE64: [char; 64] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
    'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
];

pub fn decrypt_vigenere(bytes: &Vec<u8>) -> (String, String) {
    use std::str;
    let keysizes = get_possible_keysizes(&bytes);
    let mut key: String = String::new();
    let mut decrypted: String = String::new();
    for i in 0..5 {
        let keysize = keysizes[i].1;
        let mut slices = Vec::new();
        for c in bytes.chunks(keysize) {
            slices.push(c);
        }
        let mut same_byte_slices = Vec::new();
        for ind in 0..keysize {
            let mut cur_same_byte_slice = Vec::new();
            for s in &slices {
                if s.len() <= ind {
                    break
                }
                cur_same_byte_slice.push(s[ind]);
            }
            same_byte_slices.push(cur_same_byte_slice);
        }
        let mut key_bytes = Vec::new();
        for s in &same_byte_slices {
            let (_, _, key_byte) = decode_byte_xor_cipher(&bytes_to_hex(s.clone()));
            key_bytes.push(key_byte);
        }
        let bytes = hex_to_bytes(encrypt_repeating_xor(&bytes, &key_bytes).as_str());
        let mut decoded = str::from_utf8(&bytes);
        if decoded.is_err() {
            return (String::new(), String::new())
        }
        if is_valid(decoded.unwrap()) {
            decrypted = decoded.unwrap().to_string();
            key = str::from_utf8(&key_bytes).unwrap().to_string();
            break
        }
    }
    (decrypted, key)
}

pub fn get_possible_keysizes(bytes: &Vec<u8>) -> Vec<(f64, usize)> {
    use std::cmp;
    let mut keysizes: Vec<(f64, usize)> = Vec::new();
    for keysize in 2..41 {
        let blocks = cmp::min(3, bytes.len() / (2*keysize));
        let mut cur_dist = 0;
        for i in 0..blocks {
            let first: Vec<u8> = bytes[2*i*keysize..(2*i+1) * keysize].to_vec();
            let second: Vec<u8> = bytes[(2*i+1)*keysize..(2*i+2) * keysize].to_vec();
            cur_dist += hamming_distance(&first, &second);
        }
        let cur_dist = (cur_dist as f64) / (blocks * keysize) as f64;
        keysizes.push((cur_dist, keysize));
    }
    keysizes.sort_by(|a, b| a.partial_cmp(b).unwrap());
    keysizes
}


pub fn hex_to_b64(hex: &str) -> String {
    if hex.len() % 2 != 0 {
        panic!("Hex string should have even digits");
    }
    let bytes = hex_to_bytes(hex);
    let mut b64_conv = ToB64Converter::new(bytes);
    b64_conv.convert()
}

pub fn b64_to_bytes(b64_enc: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    let mut cur_byte: u8 = 0u8;
    let mut base64_index = 0;
    for ch in b64_enc.chars() {
        if ch == '=' {
            break
        } else if ch == '\n' {
            continue
        }
        let b64_value: u8 = BASE64.iter()
            .position(|&r| r == ch).expect(&ch.to_string()) as u8;
        match base64_index % 4 {
            0 => cur_byte = b64_value << 2,
            1 => {
                cur_byte += b64_value >> 4;
                bytes.push(cur_byte);
                cur_byte = b64_value << 4;
            },
            2 => {
                cur_byte += b64_value >> 2;
                bytes.push(cur_byte);
                cur_byte = b64_value << 6;
            },
            _ => bytes.push(cur_byte + b64_value)
        }
        base64_index += 1;
    }
    bytes
    //str::from_utf8(&bytes).unwrap().to_string()
}

struct ToB64Converter {
    bytes: Vec<u8>,
    bit_index: usize,
    byte_index: usize,
}

impl ToB64Converter {
    pub fn new(bytes: Vec<u8>) -> ToB64Converter {
        let bit_index = 0;
        let byte_index = 0;
        ToB64Converter { bytes, bit_index, byte_index }
    }

    pub fn next(&mut self) -> Option<char> {
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
        Some(BASE64[cur as usize])
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

pub fn decode_byte_xor_cipher(hex: &str) -> (String, i64, u8) {
    use std::str;
    let common_letters = [('e', 13), ('t', 9), ('a', 8), ('o', 8), ('i', 7),
                          ('n', 7), ('s', 6), ('h', 6), ('r', 6), ('d', 4),
                          ('l', 4), ('c', 3), ('u', 3), ('m', 2), ('w', 2),
                          ('f', 2), ('g', 2), ('y', 2), ('p', 2), ('b', 1),
                          ('v', 1), ('k', 1), ('&', -10), ('%', -10),
                          ('~', -20), ('(', -5), (')', -5), ('$', -20),
                          ('<', -20), ('>', -20), ('*', -20)];
    let bytes = hex_to_bytes(hex);
    let mut cur_score: i64;
    let mut max_score = 0;
    let mut decrypt_key: u8 = 0u8;
    let mut best_match: Vec<u8> = Vec::new();
    for key in 0u8..255u8 {
        cur_score = 0;
        let xored = xor_with_byte(&bytes, key);
        for c in &xored {
            for letter in common_letters.iter() {
                if letter.0 == *c as char {
                    cur_score += letter.1;
                    break;
                }
            }
        }
        if max_score < cur_score {
            max_score = cur_score;
            best_match = xored;
            decrypt_key = key;
        }
    }
    let decoded = str::from_utf8(&best_match);
    if decoded.is_err() {
        return (String::new(), 0, 0)
    }
    (str::from_utf8(&best_match).unwrap().to_string(), max_score, decrypt_key)
}

pub fn xor_with_byte(bytes: &Vec<u8>, key: u8) -> Vec<u8> {
    let mut xored_bytes: Vec<u8> = Vec::new();
    for byte in bytes {
        xored_bytes.push(byte ^ key);
    }
    xored_bytes
}

pub fn encrypt_repeating_xor(text_bytes: &[u8], key_bytes: &[u8]) -> String {
    let mut encrypted_bytes: Vec<u8> = Vec::new();
    let mut key_index = 0;
    for byte in text_bytes {
        encrypted_bytes.push(byte ^ key_bytes[key_index]);
        key_index = (key_index + 1) % key_bytes.len();
    }
    bytes_to_hex(encrypted_bytes)
}

pub fn hamming_distance(text1_bytes: &[u8], text2_bytes: &[u8]) -> usize {
    if text1_bytes.len() != text2_bytes.len() {
        panic!("Strings have to be of equal length");
    }
    let mut dist = 0;
    for i in 0..text1_bytes.len() {
        dist += byte_hamming_distance(text1_bytes[i], text2_bytes[i]);
    }
    dist
}

pub fn byte_hamming_distance(byte1: u8, byte2: u8) -> usize {
    let mut xored = byte1 ^ byte2;
    let mut dist = 0;
    while xored > 0 {
        if xored % 2 == 1 {
            dist += 1;
        }
        xored >>= 1;
    }
    dist
}

pub fn is_valid(text: &str) -> bool {
    let mut ascii_chars = 0;
    for c in text.chars() {
        if c.is_ascii() && (!c.is_ascii_control() || c == '\n') {
            ascii_chars += 1;
        }
    }
    let ascii_percentage = (ascii_chars as f64) / (text.len() as f64);
    ascii_percentage > 0.99
}

pub fn decrypt_aes_ecb(bytes: &[u8], key: &[u8]) -> String {
    use std::str;
    use openssl::symm::{decrypt, Cipher};

    let cipher = Cipher::aes_128_ecb();
    let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07";
    let decrypted = decrypt(cipher, key, Some(iv), bytes).unwrap();
    str::from_utf8(&decrypted).unwrap().to_string()
}
