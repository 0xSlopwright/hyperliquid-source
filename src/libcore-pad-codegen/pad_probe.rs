use std::fmt;

struct Probe<'a>(&'a dyn fmt::Debug);

impl fmt::Debug for Probe<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = formatter.debug_struct("Probe");
        builder.field("value", self.0);
        builder.finish()
    }
}

#[no_mangle]
pub fn pad_probe(writer: &mut dyn fmt::Write, value: &dyn fmt::Debug) -> fmt::Result {
    writer.write_fmt(format_args!("{:#?}", Probe(value)))
}
