use node94_newline_writer_protocol::{write_indented_character, CharacterRequests};
use std::io::{self, BufRead};
mod character_driver;

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.expect("read input-only stimulus");
        match character_driver::transcript(&line, |character, flag, writer| {
            write_indented_character(character, flag, writer)
        }) {
            Ok(output) => println!("{output}"),
            Err(error) => { eprintln!("{error}"); std::process::exit(2); }
        }
    }
}
