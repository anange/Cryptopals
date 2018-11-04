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
            let (decoded, score) = decode_byte_xor_cipher(line);
            if score > max_score {
                max_score = score;
                correct = decoded;
            }
        }
        assert_eq!("Now that the party is jumping\n", correct);
    }
}
