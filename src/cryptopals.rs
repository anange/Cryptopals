extern crate rand;
const BASE64: [char; 64] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
    'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
];

pub fn bytes_to_string(bytes: &[u8]) -> String {
    use std::str;
    str::from_utf8(bytes).unwrap().to_string()
}

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
        let bytes = encrypt_repeating_xor(&bytes, &key_bytes);
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

pub fn encrypt_repeating_xor(text_bytes: &[u8], key_bytes: &[u8]) -> Vec<u8> {
    let mut encrypted_bytes: Vec<u8> = Vec::new();
    let mut key_index = 0;
    for byte in text_bytes {
        encrypted_bytes.push(byte ^ key_bytes[key_index]);
        key_index = (key_index + 1) % key_bytes.len();
    }
    encrypted_bytes
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

pub fn decrypt_aes_ecb(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let mut decrypted: Vec<u8> = Vec::new();
    for block in 0..(bytes.len() / 16) {
        let current_cipher = &bytes[block*16..((block+1) * 16)];
        let current_plain = decrypt_aes_ecb_block(current_cipher, key);
        decrypted.extend(current_plain);
    }
    remove_pkcs7_pad(&mut decrypted);
    decrypted
}

pub fn decrypt_aes_ecb_block(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    use openssl::symm::{Cipher, Mode, Crypter};
    let block_size = Cipher::aes_128_ecb().block_size();
    if bytes.len() != block_size || key.len() != block_size {
        panic!("Can only decrypt blocks");
    }

    let mut decrypter = Crypter::new(
    Cipher::aes_128_ecb(),
    Mode::Decrypt,
    key,
    None).unwrap();

    decrypter.pad(false);
    let mut plaintext = vec![0u8; 2 * block_size];
    decrypter.update(bytes, &mut plaintext)
        .expect("Error in decryption");
    plaintext.truncate(block_size);
    plaintext
}

pub fn encrypt_aes_ecb(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let mut encrypted: Vec<u8> = Vec::new();
    let mut padded_bytes = bytes.to_vec();
    pkcs7_pad(&mut padded_bytes, 16);
    for block in 0..(padded_bytes.len() / 16) {
        let current_plain = &padded_bytes[block*16..((block+1) * 16)];
        let current_cipher = encrypt_aes_ecb_block(current_plain, key);
        encrypted.extend(current_cipher);
    }
    encrypted
}

pub fn encrypt_aes_ecb_block(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    use openssl::symm::{Cipher, Mode, Crypter};
    let block_size = Cipher::aes_128_ecb().block_size();
    if bytes.len() != block_size || key.len() != block_size {
        panic!("Can only encrypt blocks");
    }

    let mut encrypter = Crypter::new(
    Cipher::aes_128_ecb(),
    Mode::Encrypt,
    key,
    None).unwrap();

    encrypter.pad(false);
    let mut encrypted = vec![0u8; 2 * block_size];
    encrypter.update(bytes, &mut encrypted)
        .expect("Error in encryption");
    encrypted.truncate(block_size);
    encrypted
}

pub fn is_ecb(bytes: &[u8]) -> bool {
    let key_types: [usize; 3] = [16, 24, 32];
    for key_length in key_types.iter() {
        let mut blocks_set = Vec::new();
        let blocks = bytes.len() / key_length;
        for i in 0..blocks {
            let current: Vec<u8> = bytes[i*key_length..(i+1)*key_length].to_vec();
            if blocks_set.contains(&current) {
                return true
            }
            blocks_set.push(current);
        }
    }
    false
}

pub fn pkcs7_pad(bytes: &mut Vec<u8>, desired_length_mult: usize) {
    let pad_length = desired_length_mult - (bytes.len() % desired_length_mult);
    if pad_length > 255 {
        panic!("PKCS#7 padding is well-defined until 255 bytes");
    }
    let mut padded_bytes = vec![pad_length as u8; pad_length];
    bytes.append(&mut padded_bytes);
}

pub fn remove_pkcs7_pad(bytes: &mut Vec<u8>) {
    let len = bytes.len();
    let drop = bytes[len - 1];
    if drop as usize > len {
        panic!("Invalid PKCS#7 padding");
    }
    let padding = bytes.split_off(len - drop as usize);
    for byte in padding {
        if byte != drop {
            panic!("Invalid PKCS#7 padding");
        }
    }
}

pub fn decrypt_aes_cbc(enc: &Vec<u8>, key: &Vec<u8>, iv: &Vec<u8>) -> Vec<u8> {
    let mut decrypted: Vec<u8> = Vec::new();
    for block in 0..(enc.len() / 16) {
        let current = &enc[block*16..((block+1) * 16)];
        let cur_decrypted = decrypt_aes_ecb_block(current, key);
        let cur_iv = if block == 0 {
            iv
        } else {
            &enc[(block-1)*16..block*16]
        };
        decrypted.extend(encrypt_repeating_xor(cur_iv, &cur_decrypted));
    }
    remove_pkcs7_pad(&mut decrypted);
    decrypted
}

pub fn encrypt_aes_cbc(plain: &Vec<u8>, key: &Vec<u8>, iv: &Vec<u8>) -> Vec<u8> {
    let mut padded = plain.to_vec();
    pkcs7_pad(&mut padded, 16);
    let mut encrypted: Vec<u8> = Vec::new();
    for block in 0..(padded.len() / 16) {
        let current = &padded[block*16..((block+1) * 16)];
        let xored = if block == 0 {
            encrypt_repeating_xor(current, iv)
        } else {
            encrypt_repeating_xor(current, &encrypted[(block-1)*16..block*16])
        };
        let cur_encrypted = encrypt_aes_ecb_block(&xored, key);
        encrypted.extend(&cur_encrypted);
    }
    encrypted
}

pub fn generate_key(length: usize) -> Vec<u8> {
    use self::rand::Rng;
    let mut rng = rand::thread_rng();
    let mut key: Vec<u8> = Vec::new();
    for _i in 0..length {
        key.push(rng.gen());
    }
    key
}

pub fn encryption_oracle(plaintext: &[u8]) -> Vec<u8> {
    use self::rand::Rng;
    let mut rng = rand::thread_rng();
    let key = generate_key(16);
    let iv = generate_key(16);
    let mut modified = generate_key(rng.gen_range(5, 11));
    modified.extend(plaintext);
    modified.extend(&generate_key(rng.gen_range(5, 11)));
    if rng.gen_range(0, 2) == 0 {
        encrypt_aes_cbc(&modified, &key, &iv)
    } else {
        encrypt_aes_ecb(&modified, &key)
    }
}

pub fn encrypt_ecb_same_key(unknown: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let key: Vec<u8> = vec!(3, 143, 12, 42, 98, 111, 210, 5,
                            60, 21, 180, 142, 10, 203, 250, 55);
    let mut appended: Vec<u8> = plaintext.to_vec();
    appended.extend(unknown);
    encrypt_aes_ecb(&appended, &key)
}

pub fn ecb_decryption(unknown: &[u8]) -> Vec<u8> {
    let mut decrypted = Vec::new();
    let block_size = find_blocksize(unknown);
    let plain = vec!(0u8; 2 * block_size);
    if !is_ecb(&encrypt_ecb_same_key(unknown, &plain)) {
        panic!("Not ecb");
    }
    let mut cur_byte = 0;
    let blocks = unknown.len() / block_size;
    for block_num in 0..blocks+1 {
        while cur_byte < (block_num+1) * block_size {
            let found_in_block = cur_byte % block_size;
            let mut what = Vec::new();
            if block_num > 0 {
                what = decrypted[(block_num-1)*block_size + 1 + found_in_block..].to_vec();
            }
            let mut test_str = vec!('A' as u8; block_size - found_in_block - 1);
            let actual_enc = encrypt_ecb_same_key(unknown, &test_str);
            test_str.extend(&decrypted[block_num*block_size
                            ..(block_num*block_size) + found_in_block]);
            let mut found = false;
            for ch in 0 as u8..255 as u8 {
                if block_num > 0 {
                    test_str.clear();
                    test_str.extend(&what);
                }
                test_str.push(ch as u8);
                let possible_enc = encrypt_ecb_same_key(unknown, &test_str);
                if possible_enc[..block_size]
                    .to_vec() ==
                    actual_enc[block_num*block_size..(block_num+1) * block_size]
                    .to_vec() {
                        decrypted.push(ch);
                        found = true;
                        break;
                }
                test_str.pop();
            }
            if !found {
                return decrypted
            }
            cur_byte += 1;
        }
    }
    decrypted
}

pub fn find_blocksize(unknown: &[u8]) -> usize {
    let mut test_plain = Vec::new();
    let mut previous = Vec::new();
    loop {
        test_plain.push(230u8);
        let encrypted = encrypt_ecb_same_key(unknown, &test_plain);
        let enc_bytes = encrypted[0..8].to_vec();
        if &previous == &enc_bytes {
            return test_plain.len() - 1
        }
        previous = encrypted[0..8].to_vec();
    }
}

pub fn kv_parse(encoded: &str) -> Vec<(&str, &str)> {
    let mut parsed = Vec::new();
    let kvs: Vec<&str> = encoded.split('&').collect();
    for kv in kvs {
        if kv == "" {
            continue
        }
        let pair: Vec<&str> = kv.split('=').collect();
        if pair.len() != 2 {
            panic!("Invalid kv encoding");
        }
        parsed.push((pair[0], pair[1]));
    }
    parsed
}
