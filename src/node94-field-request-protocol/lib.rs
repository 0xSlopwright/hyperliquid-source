#![no_std]
#![forbid(unsafe_code)]
//! A chosen safe higher-order field protocol, not an original formatter or ABI.

use core::cell::Cell;
use node94_newline_writer_protocol::write_indented_chunks;

/// Observed mode byte(F+18)&0x80 belongs to bit23 of the F+16 raw word.
pub const PRETTY_FLAG: u64 = 1 << 23;

/// Separate logical word projections. Values are opaque, never dereferenced.
pub struct WriterWords {
    pub destination: Cell<u64>,
    pub table: Cell<u64>,
    pub flags: Cell<u64>,
}

impl WriterWords {
    pub fn new(destination: u64, table: u64, flags: u64) -> Self {
        Self { destination: Cell::new(destination), table: Cell::new(table), flags: Cell::new(flags) }
    }
}

/// Chosen safe state, not the original S layout. All references remain valid.
pub struct FieldCells<'f> {
    pub formatter: Cell<&'f WriterWords>,
    pub error: Cell<u8>,
    pub present: Cell<u8>,
}

impl<'f> FieldCells<'f> {
    pub fn new(formatter: &'f WriterWords, error: u8, present: u8) -> Self {
        Self { formatter: Cell::new(formatter), error: Cell::new(error), present: Cell::new(present) }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContextKind { Flat, Pretty }

enum ContextSource<'a> {
    Flat(&'a WriterWords),
    Pretty { destination: u64, table: u64, flags: u64, newline: &'a Cell<u8> },
}

/// Real request capability supplied to G; pretty metadata stays private.
///
/// The supplied value callback chooses what to write and what byte to return.
/// There is no fabricated value formatter or hidden sticky inner error.
pub struct ValueContext<'a, W: ?Sized> {
    source: ContextSource<'a>,
    writer: &'a mut W,
}

impl<'a, W: ?Sized> ValueContext<'a, W>
where
    W: FnMut(u64, u64, &[u8], Option<&Cell<u8>>) -> u8,
{
    pub fn kind(&self) -> ContextKind {
        match self.source { ContextSource::Flat(_) => ContextKind::Flat, ContextSource::Pretty { .. } => ContextKind::Pretty }
    }

    pub fn writer_words(&self) -> (u64, u64) {
        match &self.source {
            ContextSource::Flat(words) => (words.destination.get(), words.table.get()),
            ContextSource::Pretty { destination, table, .. } => (*destination, *table),
        }
    }

    pub fn raw_flags_word(&self) -> u64 {
        match &self.source {
            ContextSource::Flat(words) => words.flags.get(),
            ContextSource::Pretty { flags, .. } => *flags,
        }
    }

    pub fn newline_flag(&self) -> Option<&Cell<u8>> {
        match &self.source { ContextSource::Flat(_) => None, ContextSource::Pretty { newline, .. } => Some(*newline) }
    }

    pub fn flat_writer(&self) -> Option<&WriterWords> {
        match &self.source { ContextSource::Flat(words) => Some(*words), ContextSource::Pretty { .. } => None }
    }

    /// Flat: request through current old-F words. Pretty: use the real adapter
    /// with captured words/shared N. Caller G may ignore any returned error.
    pub fn request(&mut self, bytes: &[u8]) -> u8 {
        match &self.source {
            ContextSource::Flat(words) => (self.writer)(words.destination.get(), words.table.get(), bytes, None),
            ContextSource::Pretty { destination, table, newline, .. } => {
                let writer = &mut *self.writer;
                write_indented_chunks(bytes, newline, &mut |piece, flag| {
                    writer(*destination, *table, piece, Some(flag))
                })
            }
        }
    }
}

fn finish<'s, 'f>(state: &'s FieldCells<'f>, status: u8) -> &'s FieldCells<'f> {
    // Abstract source update order only, not a generated physical store trace.
    state.error.set(status);
    state.present.set(1);
    state
}

/// Run only the qualified logical contract with real supplied W/G callbacks.
///
/// `None` is a chosen refusal for entry E=0/H outside0..1, not native behavior.
/// All references/name bytes remain valid and immutable; normal callbacks and
/// role/frame/local-metadata preservation are required for the native bridge.
/// W resolves current methods from passed D/V; G receives saved opaque words.
pub fn try_field_protocol<'s, 'f, W, G>(
    state: &'s FieldCells<'f>, name: &[u8], saved_data: u64, saved_descriptor: u64,
    writer: &mut W, value: &mut G,
) -> Option<&'s FieldCells<'f>>
where
    W: FnMut(u64, u64, &[u8], Option<&Cell<u8>>) -> u8 + ?Sized,
    G: for<'a> FnMut(u64, u64, &mut ValueContext<'a, W>) -> u8 + ?Sized,
{
    if state.error.get() != 0 {
        return Some(finish(state, 1));
    }
    let old = state.formatter.get();
    let pretty = old.flags.get() & PRETTY_FLAG != 0;
    let h = state.present.get();
    if h > 1 { return None; }

    if !pretty {
        let prefix: &[u8] = if h == 0 { b" { " } else { b", " };
        for bytes in [prefix, name, b": "] {
            // Empty name still makes this direct raw writer request.
            if writer(old.destination.get(), old.table.get(), bytes, None) != 0 {
                return Some(finish(state, 1));
            }
        }
        let mut context = ValueContext { source: ContextSource::Flat(old), writer: &mut *writer };
        let status = value(saved_data, saved_descriptor, &mut context);
        return Some(finish(state, status)); // Raw flat G AL, not normalization.
    }

    if h == 0 && writer(old.destination.get(), old.table.get(), b" {\n", None) != 0 {
        return Some(finish(state, 1));
    }
    let newline = Cell::new(1);
    // Actual post-opening samples, under the explicitly separated-role domain.
    let destination = old.destination.get();
    let table = old.table.get();
    let flags = old.flags.get();
    {
        let mut forward = |piece: &[u8], flag: &Cell<u8>| writer(destination, table, piece, Some(flag));
        for bytes in [name, b": "] {
            if write_indented_chunks(bytes, &newline, &mut forward) != 0 {
                return Some(finish(state, 1));
            }
        }
    }
    let status = {
        let mut context = ValueContext {
            source: ContextSource::Pretty { destination, table, flags, newline: &newline }, writer: &mut *writer,
        };
        value(saved_data, saved_descriptor, &mut context)
    };
    if status != 0 { return Some(finish(state, 1)); }
    // Private/preserved A/L specialization: known adapter, same N left by G.
    let suffix = write_indented_chunks(b",\n", &newline, &mut |piece, flag| {
        writer(destination, table, piece, Some(flag))
    });
    Some(finish(state, suffix))
}
