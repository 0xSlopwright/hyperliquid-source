//! Input-only scripted callback observations; production results come from the library.
use crate::CharacterRequests;
use std::cell::Cell;
use std::{format, string::String, vec::Vec};

pub struct Scripted {
    mode: usize,
    w_status: u8,
    w_flag: Option<u8>,
    w_mode: Option<usize>,
    c_status: [u8; 2],
    c_flag: [Option<u8>; 2],
    events: Vec<String>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|value| format!("{value:02x}")).collect()
}

impl CharacterRequests for Scripted {
    fn write_bytes(&mut self, bytes: &[u8], flag: &Cell<u8>) -> u8 {
        self.events.push(format!("W:{}:{}:{}", hex(bytes), flag.get(), self.mode));
        if let Some(value) = self.w_flag { flag.set(value); }
        if let Some(mode) = self.w_mode { self.mode = mode; }
        self.w_status
    }

    fn write_character(&mut self, character: char, flag: &Cell<u8>) -> u8 {
        self.events.push(format!("C:{:06x}:{}:{}", character as u32, flag.get(), self.mode));
        if let Some(value) = self.c_flag[self.mode] { flag.set(value); }
        self.c_status[self.mode]
    }
}

fn byte(text: &str) -> Result<u8, String> {
    text.parse().map_err(|_| format!("invalid byte: {text}"))
}

fn optional_byte(text: &str) -> Result<Option<u8>, String> {
    if text == "-" { Ok(None) } else { byte(text).map(Some) }
}

fn mode(text: &str) -> Result<usize, String> {
    match text { "0" => Ok(0), "1" => Ok(1), _ => Err("mode must be 0 or 1".into()) }
}

pub fn transcript<F>(input: &str, mut request: F) -> Result<String, String>
where
    F: FnMut(char, &Cell<u8>, &mut Scripted) -> u8,
{
    let fields: Vec<&str> = input.split('|').collect();
    if fields.len() != 11 { return Err("expected 11 input-only fields".into()); }
    let codepoint = u32::from_str_radix(fields[1], 16).map_err(|_| "invalid codepoint")?;
    let character = char::from_u32(codepoint).ok_or("outside chosen valid-char API")?;
    let flag = Cell::new(byte(fields[2])?);
    let mut writer = Scripted {
        mode: mode(fields[3])?,
        w_status: byte(fields[4])?,
        w_flag: optional_byte(fields[5])?,
        w_mode: if fields[6] == "-" { None } else { Some(mode(fields[6])?) },
        c_status: [byte(fields[7])?, byte(fields[9])?],
        c_flag: [optional_byte(fields[8])?, optional_byte(fields[10])?],
        events: Vec::new(),
    };
    let status = request(character, &flag, &mut writer);
    Ok(format!("{}|{}|{}|{}|{}", fields[0], status, flag.get(), writer.mode,
               writer.events.join(",")))
}
