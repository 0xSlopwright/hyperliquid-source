// Independently authored private client; ordinary API requests only.
use std::cell::Cell;
use std::io::{self, BufRead};
use node94_newline_writer_protocol::{CharacterRequests, write_indented_character};

struct Recorder {
    mode: usize,
    byte_response: u8,
    byte_edit: Option<u8>,
    mode_edit: Option<usize>,
    character_response: [u8; 2],
    character_edit: [Option<u8>; 2],
    observations: Vec<String>,
}
impl CharacterRequests for Recorder {
    fn write_bytes(&mut self, bytes: &[u8], flag: &Cell<u8>) -> u8 {
        let mut payload = String::new();
        for byte in bytes { payload.push_str(&format!("{byte:02x}")); }
        self.observations.push(format!("W:{payload}:{}:{}", flag.get(), self.mode));
        if let Some(edit) = self.byte_edit { flag.set(edit); }
        if let Some(edit) = self.mode_edit { self.mode = edit; }
        self.byte_response
    }
    fn write_character(&mut self, value: char, flag: &Cell<u8>) -> u8 {
        self.observations.push(format!("C:{:06x}:{}:{}", value as u32, flag.get(), self.mode));
        if let Some(edit) = self.character_edit[self.mode] { flag.set(edit); }
        self.character_response[self.mode]
    }
}
fn maybe_byte(text: &str) -> Option<u8> {
    if text == "-" { None } else { Some(text.parse().expect("stimulus byte")) }
}
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.expect("input stimulus");
        let fields: Vec<_> = line.split('|').collect();
        assert_eq!(fields.len(), 11, "stimulus-only fields");
        let scalar = u32::from_str_radix(fields[1], 16).expect("scalar number");
        let value = char::from_u32(scalar).expect("valid chosen char");
        let flag = Cell::new(fields[2].parse::<u8>().expect("initial flag"));
        let mode = fields[3].parse::<usize>().expect("initial mode");
        assert!(mode < 2);
        let mode_edit = if fields[6] == "-" { None } else {
            let edit = fields[6].parse::<usize>().expect("mode update");
            assert!(edit < 2); Some(edit)
        };
        let mut recorder = Recorder {
            mode, byte_response: fields[4].parse().expect("byte status"),
            byte_edit: maybe_byte(fields[5]), mode_edit,
            character_response: [fields[7].parse().expect("status0"), fields[9].parse().expect("status1")],
            character_edit: [maybe_byte(fields[8]), maybe_byte(fields[10])],
            observations: Vec::new(),
        };
        let status = write_indented_character(value, &flag, &mut recorder);
        println!("{}|{}|{}|{}|{}", fields[0], status, flag.get(), recorder.mode,
                 recorder.observations.join(","));
    }
}
