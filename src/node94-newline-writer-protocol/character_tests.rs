use node94_newline_writer_protocol::{CharacterRequests, write_indented_character};
mod character_driver;
use std::vec::Vec;

#[test]
fn independent_character_request_transcripts() {
    let inputs: Vec<_> = include_str!("character-inputs.txt").lines().collect();
    let expected: Vec<_> = include_str!("character-expected.txt").lines().collect();
    assert_eq!(inputs.len(), 320, "the independent pre-Rust input corpus must remain complete");
    assert_eq!(inputs.len(), expected.len());
    for (input, expected) in inputs.into_iter().zip(expected) {
        let actual = character_driver::transcript(input, |character, flag, writer| {
            write_indented_character(character, flag, writer)
        }).expect("valid independently frozen stimulus");
        assert_eq!(actual, expected, "stimulus {input}");
    }
}
