extern crate openssl;

pub mod cryptopals;
pub mod files;

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
        use files::read_from_file;
        let contents = read_from_file("data/4.txt");

        use cryptopals::decode_byte_xor_cipher;
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
        use cryptopals::hex_to_bytes;
        let a = String::from("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal");
        let key = String::from("ICE");
        let encrypted_hex = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        let encrypted = hex_to_bytes(encrypted_hex);
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
        use cryptopals::b64_to_bytes;
        let enc1 = "YW55IGNhcm5hbCBwbGVhcw==";
        let dec1 = "any carnal pleas";
        assert_eq!(b64_to_bytes(enc1), dec1.as_bytes());
        let enc2 = "YW55IGNhcm5hbCBwbGVhc3U=";
        let dec2 = "any carnal pleasu";
        assert_eq!(b64_to_bytes(enc2), dec2.as_bytes());
        let enc3 = "YW55IGNhcm5hbCBwbGVhc3Vy";
        let dec3 = "any carnal pleasur";
        assert_eq!(b64_to_bytes(enc3), dec3.as_bytes());
    }

    #[test]
    fn challenge6_test() {
        use files::read_from_file;
        let contents = read_from_file("data/6-test.txt");

        use cryptopals::b64_to_bytes;
        use cryptopals::decrypt_vigenere;
        let encrypted = b64_to_bytes(&contents);
        let (_, key) = decrypt_vigenere(&encrypted);
        assert_eq!("KEY", key);
    }

    #[test]
    fn challenge6() {
        use files::read_from_file;
        let contents = read_from_file("data/6.txt");

        use cryptopals::b64_to_bytes;
        use cryptopals::decrypt_vigenere;
        let encrypted = b64_to_bytes(&contents);
        let (_, key) = decrypt_vigenere(&encrypted);
        assert_eq!("Terminator X: Bring the noise", key);
    }

    #[test]
    fn challenge7() {
        use files::read_from_file;
        let contents = read_from_file("data/7.txt");
        let decrypted = read_from_file("data/7-decrypted.txt");

        use cryptopals::b64_to_bytes;
        use cryptopals::decrypt_aes_ecb;
        let encrypted = b64_to_bytes(&contents);
        let key = "YELLOW SUBMARINE".as_bytes();
        assert_eq!(decrypt_aes_ecb(&encrypted, &key), decrypted.into_bytes());
    }

    #[test]
    fn test_encrypt_decrypt_aes_ecb() {
        use cryptopals::decrypt_aes_ecb;
        use cryptopals::encrypt_aes_ecb;
        let text = "YELLOW SUBMARINE".as_bytes();
        let key = "KEYKEYKEYKEYKEYK".as_bytes();
        let encrypted = encrypt_aes_ecb(&text, &key);
        let decrypted = decrypt_aes_ecb(&encrypted, &key);
        assert_eq!(decrypted, "YELLOW SUBMARINE".as_bytes());
    }

    #[test]
    fn challenge8() {
        use files::read_from_file;
        let contents = read_from_file("data/8.txt");

        use cryptopals::hex_to_bytes;
        use cryptopals::is_ecb;
        let mut ecb_line = 0;
        for (index, line) in contents.lines().enumerate() {
            let bytes = hex_to_bytes(line);
            if is_ecb(&bytes) {
                ecb_line = index;
                break
            }
        }
        assert_eq!(ecb_line, 132);
    }

    #[test]
    fn challenge9() {
        use cryptopals::pkcs7_pad;
        let n = 20;
        let mut to_pad = "YELLOW SUBMARINE".as_bytes().to_vec();
        let after_pad = "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes();
        pkcs7_pad(&mut to_pad, n);
        assert_eq!(to_pad, after_pad);
    }

    #[test]
    fn test_remove_pkcs7_pad() {
        use cryptopals::remove_pkcs7_pad;
        let mut padded = vec!(3u8, 5u8, 2u8, 2u8);
        remove_pkcs7_pad(&mut padded);
        assert_eq!(padded, [3u8, 5u8]);
    }

    #[test]
    fn challenge10() {
        use files::read_from_file;
        let contents = read_from_file("data/10.txt");

        use cryptopals::{b64_to_bytes, decrypt_aes_cbc,
                         bytes_to_string, is_valid};
        let encrypted = b64_to_bytes(&contents);
        let key = "YELLOW SUBMARINE".as_bytes().to_vec();
        let iv = vec![0u8; 16];
        let decrypted = decrypt_aes_cbc(&encrypted, &key, &iv);
        assert!(is_valid(bytes_to_string(&decrypted).as_str()));
    }

    #[test]
    fn test_generate_key() {
        use cryptopals::generate_key;
        let key1 = generate_key(16);
        assert_eq!(key1.len(), 16);
        let key2 = generate_key(16);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_encrypt_decrypt_aes_cbc() {
        use cryptopals::{encrypt_aes_cbc, decrypt_aes_cbc};
        let text = "YELLOW SUBMARINES".as_bytes().to_vec();
        let key = "YELLOW SUBMARINE".as_bytes().to_vec();
        let iv = vec![0u8; 16];
        let encrypted = encrypt_aes_cbc(&text, &key, &iv);
        assert_eq!(text, decrypt_aes_cbc(&encrypted, &key, &iv));
    }

    #[test]
    fn challenge11() {
        use cryptopals::{encryption_oracle, is_ecb};
        let plaintext = vec!('A' as u8; 48);
        let enc = encryption_oracle(&plaintext);
        if is_ecb(&enc) {
            println!("ECB");
        } else {
            println!("CBC");
        }
    }

    #[test]
    fn challenge12() {
        use files::read_from_file;
        let contents = read_from_file("data/12.txt");

        use cryptopals::{b64_to_bytes, ecb_decryption, bytes_to_string};
        let unknown = b64_to_bytes(&contents);
        let decrypted = ecb_decryption(&unknown);
        println!("{}", bytes_to_string(&decrypted));
        assert!(decrypted.starts_with("Rollin' in my 5.0".as_bytes()));
    }

    #[test]
    fn test_kv_decode() {
        use cryptopals::kv_decode;
        let encoded = "foo=bar&baz=qux&zap=zazzle";
        let parsed = vec!(("foo".to_string(), "bar".to_string()),
                          ("baz".to_string(), "qux".to_string()),
                          ("zap".to_string(), "zazzle".to_string()));
        assert_eq!(kv_decode(encoded), parsed);
        let encoded = "email=foo@bar.com&uid=10&role=user";
        let parsed = vec!(("email".to_string(), "foo@bar.com".to_string()),
                          ("uid".to_string(), "10".to_string()),
                          ("role".to_string(), "user".to_string()));
        assert_eq!(kv_decode(encoded), parsed);
        let encoded = "email=foo@bar.com";
        let parsed = vec!(("email".to_string(), "foo@bar.com".to_string()));
        assert_eq!(kv_decode(encoded), parsed);
        let encoded = "";
        let parsed = vec!();
        assert_eq!(kv_decode(encoded), parsed);
    }

    #[test]
    fn test_kv_encode() {
        use cryptopals::kv_encode;
        let encoded = "foo=bar&baz=qux&zap=zazzle";
        let kvs = vec!(("foo", "bar"), ("baz", "qux"), ("zap", "zazzle"));
        assert_eq!(kv_encode(kvs), encoded);
        let encoded = "email=foo@bar.com&uid=10&role=user";
        let kvs = vec!(("email", "foo@bar.com"), ("uid", "10"), ("role", "user"));
        assert_eq!(kv_encode(kvs), encoded);
        let encoded = "email=foo@bar.com";
        let kvs = vec!(("email", "foo@bar.com"));
        assert_eq!(kv_encode(kvs), encoded);
        let encoded = "";
        let kvs = vec!();
        assert_eq!(kv_encode(kvs), encoded);
    }

    #[test]
    fn test_profile_for() {
        use cryptopals::{profile_for, kv_decode};
        let profile = profile_for("foo@bar.com");
        let kv_vec = kv_decode(&profile);
        assert_eq!(kv_vec[2].1, "user");
        let profile = profile_for("foo@bar.com&role=admin");
        let kv_vec = kv_decode(&profile);
        assert_eq!(kv_vec[2].1, "user");
    }

    #[test]
    fn test_profile_encrypt_decrypt() {
        use cryptopals::{get_encrypted_profile, decrypt_profile};
        let encrypted = get_encrypted_profile("foo@bar.com");
        let profile = decrypt_profile(&encrypted);
        assert_eq!(profile[0].1, "foo@bar.com");
        assert_eq!(profile[1].1, "48");
        assert_eq!(profile[2].1, "user");
    }
}
