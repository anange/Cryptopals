pub mod cryptopals;

#[cfg(test)]
mod tests {
    #[test]
    fn challenge1() {
        use cryptopals::hex_to_b64;
        let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let b64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        assert_eq!(b64, hex_to_b64(hex));
    }

    #[test]
    fn challenge2() {
        use cryptopals::fixed_xor;
        let a = "1c0111001f010100061a024b53535009181c";
        let b = "686974207468652062756c6c277320657965";
        let xored = "746865206b696420646f6e277420706c6179";
        assert_eq!(xored, fixed_xor(a, b));
    }

    #[test]
    fn challenge3() {
        use cryptopals::decode_byte_xor_cipher;
        let a = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        assert_eq!("Cooking MC's like a pound of bacon", decode_byte_xor_cipher(a).0);
    }

    #[test]
    fn challenge4() {
        use std::fs::File;
        use std::io::Read;
        use cryptopals::decode_byte_xor_cipher;
        let mut file = File::open("data/4.txt").unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).expect("Can't read file");

        let ciphers: Vec<&str> = contents.lines().collect();
        let mut max_score = 0;
        let mut correct = String::new();
        for line in &ciphers {
            let (decoded, score, _) = decode_byte_xor_cipher(line);
            if score > max_score {
                max_score = score;
                correct = decoded;
            }
        }
        assert_eq!("Now that the party is jumping\n", correct);
    }

    #[test]
    fn challenge5() {
        use cryptopals::encrypt_repeating_xor;
        let a = String::from("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal");
        let key = String::from("ICE");
        let encrypted = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        assert_eq!(encrypted, encrypt_repeating_xor(&a.into_bytes(), &key.into_bytes()));
    }

    #[test]
    fn test_hamming_distance() {
        use cryptopals::hamming_distance;
        let a = String::from("this is a test").into_bytes();
        let b = String::from("wokka wokka!!!").into_bytes();
        assert_eq!(37, hamming_distance(&a, &b));
    }

    #[test]
    fn test_base64_decode() {
        use cryptopals::b64_to_string;
        let enc1 = "YW55IGNhcm5hbCBwbGVhcw==";
        let dec1 = "any carnal pleas";
        assert_eq!(b64_to_string(enc1), dec1);
        let enc2 = "YW55IGNhcm5hbCBwbGVhc3U=";
        let dec2 = "any carnal pleasu";
        assert_eq!(b64_to_string(enc2), dec2);
        let enc3 = "YW55IGNhcm5hbCBwbGVhc3Vy";
        let dec3 = "any carnal pleasur";
        assert_eq!(b64_to_string(enc3), dec3);
    }

    #[test]
    fn challenge6_test() {
        use std::fs::File;
        use std::io::Read;
        let mut file = File::open("data/6-test.txt").unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).expect("Can't read file");

        use cryptopals::b64_to_string;
        use cryptopals::decrypt_vigenere;
        let encrypted = b64_to_string(&contents);
        let (_, key) = decrypt_vigenere(&encrypted);
        assert_eq!("KEY", key);
    }

    #[test]
    fn challenge6() {
        use std::fs::File;
        use std::io::Read;
        let mut file = File::open("data/6.txt").unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).expect("Can't read file");

        use cryptopals::b64_to_string;
        use cryptopals::decrypt_vigenere;
        let encrypted = b64_to_string(&contents);
        let (_, key) = decrypt_vigenere(&encrypted);
        assert_eq!("Terminator X: Bring the noise", key);
    }
}
