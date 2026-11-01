//! Ordinary external corpus test against the actual linked production library.
extern crate node94_field_request_protocol;
#[path = "test_driver.rs"]
mod test_driver;

#[test]
fn independent_certificate_transcripts() {
    let mut count = 0;
    for line in include_str!("target-transcripts.tsv").lines() {
        let (given, expected) = line.split_once('\t').expect("input and expected transcript");
        let actual = test_driver::transcript(given);
        assert_eq!(actual, expected, "stimulus {}", given.split('|').next().unwrap());
        count += 1;
    }
    assert_eq!(count, 925, "the independently generated corpus must be complete");
}
