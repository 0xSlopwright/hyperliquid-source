//! Independent input-only review client; no expected-file argument or reads.
//! Prepared for later explicitly authorized compilation against a retained rlib.
use node94_fse_weight_table::build_weight_table;
use std::fmt::Write;

fn image(text: &str) -> [u8; 260] {
    assert_eq!(text.len(), 520);
    let mut bytes = [0u8; 260];
    for i in 0..260 {
        bytes[i] = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap();
    }
    bytes
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(args.len(), 2, "only one stimulus file is accepted");
    let input = std::fs::read_to_string(&args[1]).unwrap();
    for (ordinal, line) in input.lines().filter(|line| !line.is_empty()).enumerate() {
        let pieces: Vec<&str> = line.split(' ').collect();
        assert_eq!(pieces.len(), 5);
        let id = pieces[0];
        assert!(!id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        let log: u8 = pieces[1].parse().unwrap();
        let maximum: u8 = pieces[2].parse().unwrap();
        let words: Vec<i16> = pieces[3].split(',').map(|s| s.parse().unwrap()).collect();
        assert_eq!(words.len(), 256);
        let initial = image(pieces[4]);

        // These words are outside the actual typed input array. If a future
        // client accidentally included them, the qualified domain would fail.
        let left_word = i16::MIN + (ordinal % 31) as i16;
        let right_word = i16::MAX - (ordinal % 31) as i16;
        let mut padded_words = [0i16; 258];
        padded_words[0] = left_word;
        padded_words[257] = right_word;
        padded_words[1..257].copy_from_slice(&words);
        let normalized: &[i16; 256] = (&padded_words[1..257]).try_into().unwrap();

        let before = 0xd3u8.wrapping_add(ordinal as u8);
        let after = 0x49u8.wrapping_sub(ordinal as u8);
        let mut padded_output = [0u8; 262];
        padded_output[0] = before;
        padded_output[261] = after;
        padded_output[1..261].copy_from_slice(&initial);
        let result = {
            let output: &mut [u8; 260] = (&mut padded_output[1..261]).try_into().unwrap();
            build_weight_table(log, maximum, normalized, output)
        };
        assert_eq!(padded_words[0], left_word);
        assert_eq!(padded_words[257], right_word);
        assert_eq!(padded_output[0], before);
        assert_eq!(padded_output[261], after);
        let (tag, length) = match result {
            Ok(length) => ("ok", length),
            Err(_) => {
                assert_eq!(&padded_output[1..261], &initial);
                ("unsupported", 0)
            }
        };
        let mut encoded = String::new();
        for byte in &padded_output[1..261] {
            write!(&mut encoded, "{byte:02x}").unwrap();
        }
        println!("{id} {tag} {length} {encoded}");
    }
}
