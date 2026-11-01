//! External public-API tests from the 390-byte native parent witnesses.
//!
//! These run real supplied writer/value callbacks against the production rlib.
//! They neither execute native instructions nor implement an original formatter.
//! The native E/H/store/return order is a separate static witness; these tests
//! observe logical final state, callback timing, requests and reference identity.
extern crate node94_field_request_protocol;

use node94_field_request_protocol::{
    try_field_protocol, ContextKind, FieldCells, WriterWords, PRETTY_FLAG,
};
use std::cell::{Cell, RefCell};

#[derive(Clone, Debug, PartialEq, Eq)]
struct Request {
    destination: u64,
    table: u64,
    bytes: Vec<u8>,
    flag: Option<u8>,
}

fn request(destination: u64, table: u64, bytes: &[u8], flag: Option<&Cell<u8>>) -> Request {
    Request {
        destination,
        table,
        bytes: bytes.to_vec(),
        flag: flag.map(Cell::get),
    }
}

fn byte_requests(log: &RefCell<Vec<Request>>) -> Vec<Vec<u8>> {
    log.borrow().iter().map(|r| r.bytes.clone()).collect()
}

#[test]
fn prior_nonzero_error_normalizes_without_callbacks_or_h_domain_refusal() {
    for prior in [1, 2, 0x80, 0xff] {
        for present in [0, 1, 2, 0xff] {
            let formatter = WriterWords::new(10, 20, PRETTY_FLAG);
            let state = FieldCells::new(&formatter, prior, present);
            let mut writer = |_: u64, _: u64, _: &[u8], _: Option<&Cell<u8>>| -> u8 {
                panic!("prior error must not call writer")
            };
            let result = try_field_protocol(
                &state,
                b"unused",
                17,
                23,
                &mut writer,
                &mut |_, _, _| panic!("prior error must not call value"),
            );
            assert!(std::ptr::eq(result.expect("prior error is qualified"), &state));
            assert_eq!((state.error.get(), state.present.get()), (1, 1));
            assert!(std::ptr::eq(state.formatter.get(), &formatter));
        }
    }
    // Safe formatter references remain valid even here. No test claims to
    // admit native invalid/null pointer states just because they are unused.
}

#[test]
fn invalid_present_with_zero_error_is_only_a_chosen_api_refusal() {
    for present in [2, 0x80, 0xff] {
        let formatter = WriterWords::new(10, 20, 0);
        let state = FieldCells::new(&formatter, 0, present);
        let mut writer = |_: u64, _: u64, _: &[u8], _: Option<&Cell<u8>>| -> u8 {
            panic!("outside-domain request must not call writer")
        };
        let result = try_field_protocol(
            &state,
            b"unused",
            17,
            23,
            &mut writer,
            &mut |_, _, _| panic!("outside-domain request must not call value"),
        );
        assert!(result.is_none());
        assert_eq!((state.error.get(), state.present.get()), (0, present));
        assert!(std::ptr::eq(state.formatter.get(), &formatter));
    }
    // This None policy does not claim original behavior for noncanonical H.
}

#[test]
fn flat_early_writer_errors_normalize_every_nonzero_byte_and_short_circuit() {
    for stage in 0..3 {
        for response in [2, 0x80, 0xff] {
            let formatter = WriterWords::new(10, 20, 0);
            let state = FieldCells::new(&formatter, 0, 1);
            let log = RefCell::new(Vec::new());
            let index = Cell::new(0);
            let mut writer = |d, v, bytes: &[u8], flag: Option<&Cell<u8>>| {
                let n = index.get();
                index.set(n + 1);
                log.borrow_mut().push(request(d, v, bytes, flag));
                if n == stage { response } else { 0 }
            };
            let result = try_field_protocol(
                &state,
                b"field",
                17,
                23,
                &mut writer,
                &mut |_, _, _| panic!("value follows no failed writer"),
            );
            assert!(std::ptr::eq(result.unwrap(), &state));
            assert_eq!((state.error.get(), state.present.get()), (1, 1));
            let expected = [b", ".to_vec(), b"field".to_vec(), b": ".to_vec()];
            assert_eq!(byte_requests(&log), expected[..=stage]);
            assert!(log.borrow().iter().all(|r| r.flag.is_none()));
        }
    }
}

#[test]
fn flat_value_keeps_raw_al_and_really_uses_the_public_request_capability() {
    for response in [0, 2, 0x80, 0xff] {
        let formatter = WriterWords::new(10, 20, 0x42);
        let state = FieldCells::new(&formatter, 0, 0);
        let log = RefCell::new(Vec::new());
        let mut writer = |d, v, bytes: &[u8], flag: Option<&Cell<u8>>| {
            log.borrow_mut().push(request(d, v, bytes, flag));
            0
        };
        let result = try_field_protocol(
            &state,
            b"",
            17,
            23,
            &mut writer,
            &mut |data, descriptor, context| {
                assert_eq!((data, descriptor), (17, 23));
                assert_eq!(context.kind(), ContextKind::Flat);
                assert_eq!(context.writer_words(), (10, 20));
                assert_eq!(context.raw_flags_word(), 0x42);
                assert!(std::ptr::eq(context.flat_writer().unwrap(), &formatter));
                assert!(context.newline_flag().is_none());
                assert_eq!(context.request(b"supplied-value"), 0);
                response
            },
        );
        assert!(std::ptr::eq(result.unwrap(), &state));
        assert_eq!((state.error.get(), state.present.get()), (response, 1));
        assert_eq!(
            byte_requests(&log),
            vec![b" { ".to_vec(), vec![], b": ".to_vec(), b"supplied-value".to_vec()]
        );
        assert!(log.borrow().iter().all(|r| r.flag.is_none()));
    }
}

#[test]
fn flat_keeps_old_formatter_but_reloads_its_words_and_live_flags() {
    let old = WriterWords::new(10, 20, 0);
    let replacement = WriterWords::new(99, 199, 0x1234);
    let state = FieldCells::new(&old, 0, 0);
    let log = RefCell::new(Vec::new());
    let index = Cell::new(0);
    let mut writer = |d, v, bytes: &[u8], flag: Option<&Cell<u8>>| {
        let n = index.get();
        index.set(n + 1);
        log.borrow_mut().push(request(d, v, bytes, flag));
        if n == 0 {
            state.formatter.set(&replacement);
            state.error.set(0xff);
            state.present.set(0x80);
            old.destination.set(11);
            old.table.set(21);
            old.flags.set(PRETTY_FLAG | 0x44);
        } else if n == 1 {
            old.destination.set(12);
            old.table.set(22);
            old.flags.set(PRETTY_FLAG | 0x88);
        } else if n == 2 {
            old.destination.set(13);
            old.table.set(23);
            old.flags.set(PRETTY_FLAG | 0x99);
        }
        0
    };
    let result = try_field_protocol(
        &state,
        b"field",
        17,
        23,
        &mut writer,
        &mut |data, descriptor, context| {
            assert_eq!((data, descriptor), (17, 23));
            assert_eq!(context.kind(), ContextKind::Flat);
            assert!(std::ptr::eq(context.flat_writer().unwrap(), &old));
            assert_eq!(context.writer_words(), (13, 23));
            assert_eq!(context.raw_flags_word(), PRETTY_FLAG | 0x99);
            assert_eq!((state.error.get(), state.present.get()), (0xff, 0x80));
            assert_eq!(context.request(b"first"), 0);
            old.destination.set(14);
            old.table.set(24);
            old.flags.set(0x345);
            assert_eq!(context.writer_words(), (14, 24));
            assert_eq!(context.raw_flags_word(), 0x345);
            assert_eq!(context.request(b"second"), 0);
            2
        },
    );
    assert!(std::ptr::eq(result.unwrap(), &state));
    assert_eq!((state.error.get(), state.present.get()), (2, 1));
    assert!(std::ptr::eq(state.formatter.get(), &replacement));
    assert_eq!(
        log.borrow().iter().map(|r| (r.destination, r.table)).collect::<Vec<_>>(),
        vec![(10, 20), (11, 21), (12, 22), (13, 23), (14, 24)]
    );
    assert!(log.borrow().iter().all(|r| r.flag.is_none()));
}

#[test]
fn pretty_opening_samples_old_formatter_after_callback_without_resampling_mode() {
    // Native TEST BYTE PTR [F+0x12],0x80 binds this full-word bit literally.
    assert_eq!(PRETTY_FLAG, 1_u64 << 23);
    let old = WriterWords::new(10, 20, PRETTY_FLAG);
    let replacement = WriterWords::new(99, 199, PRETTY_FLAG | 0x1234);
    let state = FieldCells::new(&old, 0, 0);
    let log = RefCell::new(Vec::new());
    let index = Cell::new(0);
    let mut writer = |d, v, bytes: &[u8], flag: Option<&Cell<u8>>| {
        let n = index.get();
        index.set(n + 1);
        log.borrow_mut().push(request(d, v, bytes, flag));
        if n == 0 {
            assert_eq!(bytes, b" {\n");
            assert!(flag.is_none());
            old.destination.set(11);
            old.table.set(21);
            old.flags.set(0);
            state.formatter.set(&replacement);
            state.error.set(0x80);
            state.present.set(0xff);
        } else if n == 1 {
            old.destination.set(77);
            old.table.set(88);
            old.flags.set(PRETTY_FLAG | 0xff);
        }
        0
    };
    let result = try_field_protocol(
        &state,
        b"field",
        17,
        23,
        &mut writer,
        &mut |_, _, context| {
            assert_eq!(context.kind(), ContextKind::Pretty);
            assert_eq!(context.writer_words(), (11, 21));
            assert_eq!(context.raw_flags_word(), 0);
            assert!(context.flat_writer().is_none());
            assert_eq!(context.newline_flag().unwrap().get(), 0);
            assert_eq!((state.error.get(), state.present.get()), (0x80, 0xff));
            assert_eq!(context.request(b"value"), 0);
            0
        },
    );
    assert!(std::ptr::eq(result.unwrap(), &state));
    assert_eq!((state.error.get(), state.present.get()), (0, 1));
    assert!(std::ptr::eq(state.formatter.get(), &replacement));
    assert_eq!(
        byte_requests(&log),
        vec![b" {\n".to_vec(), b"    ".to_vec(), b"field".to_vec(), b": ".to_vec(),
             b"value".to_vec(), b",\n".to_vec()]
    );
    assert_eq!((log.borrow()[0].destination, log.borrow()[0].table), (10, 20));
    assert!(log.borrow()[1..].iter().all(|r| (r.destination, r.table) == (11, 21)));
}

#[test]
fn pretty_h1_empty_name_uses_one_shared_flag_and_keeps_copied_words() {
    let old = WriterWords::new(10, 20, PRETTY_FLAG | 0x42);
    let replacement = WriterWords::new(99, 199, 0);
    let state = FieldCells::new(&old, 0, 1);
    let log = RefCell::new(Vec::new());
    let index = Cell::new(0);
    let mut writer = |d, v, bytes: &[u8], flag: Option<&Cell<u8>>| {
        let n = index.get();
        index.set(n + 1);
        log.borrow_mut().push(request(d, v, bytes, flag));
        if n == 0 {
            old.destination.set(77);
            old.table.set(88);
            old.flags.set(0);
            state.formatter.set(&replacement);
        }
        0
    };
    let result = try_field_protocol(
        &state,
        b"",
        17,
        23,
        &mut writer,
        &mut |_, _, context| {
            assert_eq!(context.kind(), ContextKind::Pretty);
            assert_eq!(context.writer_words(), (10, 20));
            assert_eq!(context.raw_flags_word(), PRETTY_FLAG | 0x42);
            assert_eq!(context.newline_flag().unwrap().get(), 0);
            assert_eq!(context.request(b"v"), 0);
            0
        },
    );
    assert!(std::ptr::eq(result.unwrap(), &state));
    assert_eq!((state.error.get(), state.present.get()), (0, 1));
    assert_eq!(byte_requests(&log), vec![b"    ".to_vec(), b": ".to_vec(), b"v".to_vec(), b",\n".to_vec()]);
    assert!(log.borrow().iter().all(|r| (r.destination, r.table) == (10, 20)));
    assert_eq!(log.borrow().iter().map(|r| r.flag).collect::<Vec<_>>(),
               vec![Some(1), Some(0), Some(0), Some(1)]);
}

#[test]
fn pretty_opening_errors_normalize_and_do_not_call_value_or_adapter() {
    for response in [2, 0x80, 0xff] {
        let old = WriterWords::new(10, 20, PRETTY_FLAG);
        let state = FieldCells::new(&old, 0, 0);
        let log = RefCell::new(Vec::new());
        let mut writer = |d, v, bytes: &[u8], flag: Option<&Cell<u8>>| {
            log.borrow_mut().push(request(d, v, bytes, flag));
            old.flags.set(0);
            state.error.set(0);
            state.present.set(0xff);
            response
        };
        let result = try_field_protocol(
            &state,
            b"field",
            17,
            23,
            &mut writer,
            &mut |_, _, _| panic!("failed opening cannot call value"),
        );
        assert!(std::ptr::eq(result.unwrap(), &state));
        assert_eq!((state.error.get(), state.present.get()), (1, 1));
        assert_eq!(log.borrow().as_slice(), &[request(10, 20, b" {\n", None)]);
    }
}

#[test]
fn pretty_value_errors_normalize_after_real_requests_and_skip_suffix() {
    for response in [2, 0x80, 0xff] {
        let old = WriterWords::new(10, 20, PRETTY_FLAG);
        let state = FieldCells::new(&old, 0, 1);
        let log = RefCell::new(Vec::new());
        let mut writer = |d, v, bytes: &[u8], flag: Option<&Cell<u8>>| {
            log.borrow_mut().push(request(d, v, bytes, flag));
            0
        };
        let result = try_field_protocol(
            &state,
            b"n",
            17,
            23,
            &mut writer,
            &mut |_, _, context| {
                assert_eq!(context.request(b"value\n"), 0);
                assert_eq!(context.newline_flag().unwrap().get(), 1);
                state.error.set(0);
                state.present.set(0xff);
                response
            },
        );
        assert!(std::ptr::eq(result.unwrap(), &state));
        assert_eq!((state.error.get(), state.present.get()), (1, 1));
        assert_eq!(byte_requests(&log), vec![b"    ".to_vec(), b"n".to_vec(), b": ".to_vec(), b"value\n".to_vec()]);
    }
}

#[test]
fn supplied_value_can_ignore_an_inner_error_and_suffix_still_uses_its_flag() {
    let old = WriterWords::new(10, 20, PRETTY_FLAG);
    let state = FieldCells::new(&old, 0, 1);
    let log = RefCell::new(Vec::new());
    let mut writer = |d, v, bytes: &[u8], flag: Option<&Cell<u8>>| {
        log.borrow_mut().push(request(d, v, bytes, flag));
        if bytes == b"v\n" { 0x80 } else { 0 }
    };
    let result = try_field_protocol(
        &state,
        b"",
        17,
        23,
        &mut writer,
        &mut |_, _, context| {
            assert_eq!(context.request(b"v\n"), 1);
            assert_eq!(context.newline_flag().unwrap().get(), 1);
            state.error.set(0xff);
            state.present.set(0);
            0 // Deliberately ignore the real inner failure; no hidden accumulator.
        },
    );
    assert!(std::ptr::eq(result.unwrap(), &state));
    assert_eq!((state.error.get(), state.present.get()), (0, 1));
    assert_eq!(byte_requests(&log), vec![b"    ".to_vec(), b": ".to_vec(), b"v\n".to_vec(), b"    ".to_vec(), b",\n".to_vec()]);
    assert_eq!(log.borrow().iter().map(|r| r.flag).collect::<Vec<_>>(),
               vec![Some(1), Some(0), Some(1), Some(1), Some(1)]);
}

#[test]
fn pretty_callbacks_and_value_share_raw_newline_flag_across_requests() {
    let old = WriterWords::new(10, 20, PRETTY_FLAG);
    let state = FieldCells::new(&old, 0, 1);
    let log = RefCell::new(Vec::new());
    let index = Cell::new(0);
    let mut writer = |d, v, bytes: &[u8], flag: Option<&Cell<u8>>| {
        let n = index.get();
        index.set(n + 1);
        log.borrow_mut().push(request(d, v, bytes, flag));
        if n == 0 { flag.unwrap().set(0xff); }
        if n == 1 { flag.unwrap().set(0x80); }
        0
    };
    let result = try_field_protocol(
        &state,
        b"x",
        17,
        23,
        &mut writer,
        &mut |_, _, context| {
            assert_eq!(context.newline_flag().unwrap().get(), 0);
            context.newline_flag().unwrap().set(0xff);
            assert_eq!(context.request(b"v"), 0);
            context.newline_flag().unwrap().set(0);
            0
        },
    );
    assert!(std::ptr::eq(result.unwrap(), &state));
    assert_eq!((state.error.get(), state.present.get()), (0, 1));
    assert_eq!(byte_requests(&log), vec![b"    ".to_vec(), b"x".to_vec(), b"    ".to_vec(), b": ".to_vec(), b"    ".to_vec(), b"v".to_vec(), b",\n".to_vec()]);
    assert_eq!(log.borrow().iter().map(|r| r.flag).collect::<Vec<_>>(),
               vec![Some(1), Some(0), Some(0x80), Some(0), Some(0xff), Some(0), Some(1)]);
}

#[test]
fn suffix_payload_failure_is_captured_instead_of_returning_success_unconditionally() {
    for response in [2, 0x80, 0xff] {
        let old = WriterWords::new(10, 20, PRETTY_FLAG);
        let state = FieldCells::new(&old, 0, 1);
        let log = RefCell::new(Vec::new());
        let mut writer = |d, v, bytes: &[u8], flag: Option<&Cell<u8>>| {
            log.borrow_mut().push(request(d, v, bytes, flag));
            if bytes == b",\n" { response } else { 0 }
        };
        let result = try_field_protocol(
            &state,
            b"",
            17,
            23,
            &mut writer,
            &mut |_, _, context| {
                assert_eq!(context.request(b"v"), 0);
                0
            },
        );
        assert!(std::ptr::eq(result.unwrap(), &state));
        assert_eq!((state.error.get(), state.present.get()), (1, 1));
        assert_eq!(byte_requests(&log), vec![b"    ".to_vec(), b": ".to_vec(), b"v".to_vec(), b",\n".to_vec()]);
    }
}
