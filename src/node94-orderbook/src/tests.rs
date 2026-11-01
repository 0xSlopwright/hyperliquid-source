use crate::book::{PriceLevel, Slot};
use crate::*;

fn user(byte: u8) -> UserId {
    UserId::repeated(byte)
}

fn order(id: u64, side: Side, price: u64, quantity: u64) -> InsertOrder {
    InsertOrder {
        order_id: OrderId(id),
        user: user(id as u8),
        side,
        price,
        quantity,
        reduce_only: false,
    }
}

fn taker(id: u64, side: Side, price: u64, budget: u64) -> TakerOrder {
    TakerOrder {
        order_id: OrderId(id),
        user: user(id as u8),
        side,
        price,
        asset: 10_001,
        budget,
    }
}

#[test]
fn verified_layout_constants_are_retained_without_an_abi_claim() {
    assert_eq!(TargetSlotLayout::STRIDE, 0xf8);
    assert_eq!(TargetSlotLayout::QUANTITY, 0xc8);
    assert_eq!(TargetSlotLayout::ORDER_ID, 0xd8);
    assert_eq!(TargetSlotLayout::USER, 0xe0);
    assert_eq!(TargetSlotLayout::VACANT_DISCRIMINANT, 2);
    assert_eq!(TargetRelationLayout::PARENT_OPTION, 0x10);
    assert_eq!(TargetRelationLayout::PEER_OPTION, 0x20);
    assert_eq!(TargetRelationLayout::CHILDREN_VECTOR, 0x30);
    assert_eq!(TARGET_SHA256.len(), 64);
}

#[test]
fn bid_and_ask_levels_use_verified_best_price_ordering() {
    let mut book = Book::new();
    for (id, side, price) in [
        (1, Side::Bid, 99),
        (2, Side::Bid, 101),
        (3, Side::Bid, 100),
        (4, Side::Ask, 102),
        (5, Side::Ask, 100),
        (6, Side::Ask, 101),
    ] {
        book.insert(order(id, side, price, 1)).unwrap();
    }
    assert_eq!(book.best(Side::Bid).unwrap().unwrap().price, 101);
    assert_eq!(book.best(Side::Ask).unwrap().unwrap().price, 100);
    let snapshot = book.snapshot().unwrap();
    assert_eq!(
        snapshot
            .bids
            .iter()
            .map(|level| level.price)
            .collect::<Vec<_>>(),
        [101, 100, 99]
    );
    assert_eq!(
        snapshot
            .asks
            .iter()
            .map(|level| level.price)
            .collect::<Vec<_>>(),
        [100, 101, 102]
    );
    assert_eq!(
        snapshot
            .bids
            .iter()
            .map(|level| level.signed_key)
            .collect::<Vec<_>>(),
        [-101, -100, -99]
    );
}

#[test]
fn fifo_links_survive_head_middle_and_tail_cancellation() {
    let mut book = Book::new();
    let a = book.insert(order(1, Side::Bid, 100, 3)).unwrap();
    let b = book.insert(order(2, Side::Bid, 100, 5)).unwrap();
    let c = book.insert(order(3, Side::Bid, 100, 7)).unwrap();
    assert_eq!(book.snapshot().unwrap().bids[0].queue, [a, b, c]);

    book.cancel(b, CancelReason::Canceled).unwrap();
    assert_eq!(book.snapshot().unwrap().bids[0].queue, [a, c]);
    assert_eq!(
        (book.order(a).unwrap().next, book.order(c).unwrap().previous),
        (Some(c), Some(a))
    );
    book.cancel(a, CancelReason::Canceled).unwrap();
    assert_eq!(book.snapshot().unwrap().bids[0].queue, [c]);
    assert_eq!(book.order(c).unwrap().previous, None);
    book.cancel(c, CancelReason::Canceled).unwrap();
    assert!(book.snapshot().unwrap().bids.is_empty());
    assert_eq!((book.occupied_count(), book.aggregate_quantity()), (0, 0));
}

#[test]
fn free_list_is_lifo_and_reuse_has_no_old_queue_links() {
    let mut book = Book::new();
    let first = book.insert(order(1, Side::Ask, 100, 2)).unwrap();
    let second = book.insert(order(2, Side::Ask, 100, 3)).unwrap();
    book.cancel(first, CancelReason::Canceled).unwrap();
    book.cancel(second, CancelReason::Canceled).unwrap();
    let reuse_second = book.insert(order(3, Side::Bid, 110, 5)).unwrap();
    let reuse_first = book.insert(order(4, Side::Ask, 120, 7)).unwrap();
    assert_eq!((reuse_second, reuse_first), (second, first));
    assert_eq!(
        (
            book.order(reuse_second).unwrap().previous,
            book.order(reuse_second).unwrap().next
        ),
        (None, None)
    );
    assert_eq!(
        (
            book.order(reuse_first).unwrap().previous,
            book.order(reuse_first).unwrap().next
        ),
        (None, None)
    );
    book.check_consistency().unwrap();
}

#[test]
fn duplicate_order_behavior_is_explicitly_unsupported_and_atomic() {
    let mut book = Book::new();
    book.insert(order(7, Side::Bid, 100, 2)).unwrap();
    let before = book.snapshot().unwrap();
    assert_eq!(
        book.insert(order(7, Side::Ask, 101, 9)),
        Err(BookError::UnsupportedDuplicateOrder(OrderId(7)))
    );
    assert_eq!(book.snapshot().unwrap(), before);
}

#[test]
fn quantity_accounting_saturates_at_observed_boundaries() {
    let mut book = Book::new();
    book.aggregate_quantity = u64::MAX - 1;
    let slot = book.insert(order(1, Side::Bid, 1, 2)).unwrap();
    assert_eq!(book.aggregate_quantity(), u64::MAX);
    book.aggregate_quantity = 1;
    book.cancel(slot, CancelReason::Canceled).unwrap();
    assert_eq!(book.aggregate_quantity(), 0);
}

#[test]
fn partial_fill_updates_slot_and_global_quantity() {
    let mut book = Book::new();
    let maker = book.insert(order(1, Side::Ask, 100, 10)).unwrap();
    let outcome = book
        .match_best_once(taker(2, Side::Bid, 100, 4), MatchLimits::PERMISSIVE)
        .unwrap();
    let MatchOutcome::Fill {
        fill,
        maker_remaining,
        maker_removed,
        reported_budget,
        reason,
        ..
    } = outcome
    else {
        panic!("expected fill");
    };
    assert_eq!(
        (fill.maker_slot, fill.quantity, fill.notional),
        (maker, 4, 400)
    );
    assert_eq!(
        (maker_remaining, maker_removed, reported_budget, reason),
        (6, false, 4, MatchReason::CONTINUE)
    );
    assert_eq!(
        (
            book.order(maker).unwrap().quantity,
            book.aggregate_quantity()
        ),
        (6, 6)
    );
    book.check_consistency().unwrap();
}

#[test]
fn zero_budget_and_same_user_take_the_verified_early_exits() {
    let mut zero = Book::new();
    zero.insert(order(1, Side::Ask, 100, 10)).unwrap();
    assert_eq!(
        zero.match_best_once(taker(2, Side::Bid, 100, 0), MatchLimits::PERMISSIVE)
            .unwrap(),
        MatchOutcome::NoFill {
            status: MatchStatus::None,
            reported_budget: 0,
            reason: MatchReason::CONTINUE,
        }
    );

    let mut same = Book::new();
    let mut maker = order(1, Side::Ask, 100, 10);
    maker.user = user(9);
    same.insert(maker).unwrap();
    let mut incoming = taker(2, Side::Bid, 100, 5);
    incoming.user = user(9);
    assert_eq!(
        same.match_best_once(incoming, MatchLimits::PERMISSIVE)
            .unwrap(),
        MatchOutcome::NoFill {
            status: MatchStatus::None,
            reported_budget: 5,
            reason: MatchReason::SELF_CROSS,
        }
    );
    assert_eq!(same.aggregate_quantity(), 10);
}

#[test]
fn full_fill_removes_level_and_slot_can_be_reused() {
    let mut book = Book::new();
    let maker = book.insert(order(1, Side::Ask, 100, 4)).unwrap();
    let outcome = book
        .match_best_once(taker(2, Side::Bid, 100, 10), MatchLimits::PERMISSIVE)
        .unwrap();
    assert!(matches!(
        outcome,
        MatchOutcome::Fill {
            maker_remaining: 0,
            maker_removed: true,
            ..
        }
    ));
    assert!(book.best(Side::Ask).unwrap().is_none());
    let reused = book.insert(order(3, Side::Bid, 90, 1)).unwrap();
    assert_eq!(reused, maker);
    book.check_consistency().unwrap();
}

#[test]
fn match_exit_statuses_follow_the_target_cap_order() {
    let mut maker_zero = Book::new();
    maker_zero.insert(order(1, Side::Ask, 10, 10)).unwrap();
    let out = maker_zero
        .match_best_once(
            taker(2, Side::Bid, 10, 10),
            MatchLimits {
                maker_cap: 0,
                ..MatchLimits::PERMISSIVE
            },
        )
        .unwrap();
    assert_eq!(
        out,
        MatchOutcome::NoFill {
            status: MatchStatus::None,
            reported_budget: 10,
            reason: MatchReason::LIMIT_OR_MASK,
        }
    );

    let mut taker_zero = Book::new();
    taker_zero.insert(order(1, Side::Ask, 10, 10)).unwrap();
    let out = taker_zero
        .match_best_once(
            taker(2, Side::Bid, 10, 10),
            MatchLimits {
                taker_cap: 0,
                taker_other_cap: 9,
                ..MatchLimits::PERMISSIVE
            },
        )
        .unwrap();
    assert_eq!(
        out,
        MatchOutcome::NoFill {
            status: MatchStatus::InsufficientMargin,
            reported_budget: 0,
            reason: MatchReason::CONTINUE,
        }
    );
    assert_eq!(
        MatchStatus::InsufficientMargin.target_word(),
        0x8000_0000_0000_0003
    );
    assert_eq!(
        MatchStatus::MaxPosition.target_word(),
        0x8000_0000_0000_0004
    );
}

#[test]
fn taker_cap_can_produce_a_status_bearing_partial_fill() {
    let mut book = Book::new();
    book.insert(order(1, Side::Ask, 10, 10)).unwrap();
    let out = book
        .match_best_once(
            taker(2, Side::Bid, 10, 10),
            MatchLimits {
                taker_cap: 4,
                taker_other_cap: 3,
                ..MatchLimits::PERMISSIVE
            },
        )
        .unwrap();
    assert!(matches!(
        out,
        MatchOutcome::Fill {
            fill: Fill { quantity: 4, .. },
            status: MatchStatus::InsufficientMargin,
            reported_budget: 4,
            maker_remaining: 6,
            ..
        }
    ));
}

#[test]
fn fill_mask_bits_follow_taker_side_and_do_not_mutate_on_rejection() {
    for (side, mask) in [(Side::Bid, 0x001), (Side::Ask, 0x100)] {
        let mut book = Book::new();
        book.insert(order(1, side.opposite(), 10, 5)).unwrap();
        let before = book.snapshot().unwrap();
        let out = book
            .match_best_once(
                taker(2, side, 10, 5),
                MatchLimits {
                    fill_mask: TargetFillMask(mask),
                    ..MatchLimits::PERMISSIVE
                },
            )
            .unwrap();
        assert!(matches!(
            out,
            MatchOutcome::NoFill {
                reason: MatchReason::LIMIT_OR_MASK,
                ..
            }
        ));
        assert_eq!(book.snapshot().unwrap(), before);
    }
}

#[test]
fn notional_ceiling_is_inclusive_and_overflow_is_rejected_atomically() {
    let mut at_limit = Book::new();
    at_limit.insert(order(1, Side::Ask, 1, 1)).unwrap();
    assert!(matches!(
        at_limit.match_best_once(
            taker(2, Side::Bid, MAX_SUPPORTED_NOTIONAL, 1),
            MatchLimits::PERMISSIVE
        ),
        Ok(MatchOutcome::Fill { .. })
    ));

    let mut over = Book::new();
    over.insert(order(1, Side::Ask, 1, 2)).unwrap();
    let before = over.snapshot().unwrap();
    assert_eq!(
        over.match_best_once(
            taker(2, Side::Bid, MAX_SUPPORTED_NOTIONAL, 2),
            MatchLimits::PERMISSIVE
        ),
        Err(BookError::NotionalOutOfRange)
    );
    assert_eq!(over.snapshot().unwrap(), before);
}

#[test]
fn reduce_only_match_is_explicitly_unsupported_without_position_state() {
    let mut book = Book::new();
    let mut maker = order(1, Side::Ask, 10, 2);
    maker.reduce_only = true;
    book.insert(maker).unwrap();
    let before = book.snapshot().unwrap();
    assert_eq!(
        book.match_best_once(taker(2, Side::Bid, 10, 2), MatchLimits::PERMISSIVE),
        Err(BookError::UnsupportedReduceOnlyMatch(OrderId(1)))
    );
    assert_eq!(book.snapshot().unwrap(), before);
}

#[test]
fn user_cancel_collects_then_removes_in_ascending_order_id() {
    let mut book = Book::new();
    for id in [9, 2, 7] {
        let mut item = order(id, Side::Bid, 100 + id, 1);
        item.user = user(42);
        book.insert(item).unwrap();
    }
    book.insert(order(3, Side::Ask, 200, 1)).unwrap();
    let records = book
        .cancel_user(user(42), CancelReason::Liquidated)
        .unwrap();
    assert_eq!(
        records.iter().map(|row| row.order_id).collect::<Vec<_>>(),
        [OrderId(2), OrderId(7), OrderId(9)]
    );
    assert_eq!(book.occupied_count(), 1);
    book.check_consistency().unwrap();
}

#[test]
fn relations_attach_reciprocally_and_cascade_depth_first() {
    let mut book = Book::new();
    for id in 1..=5 {
        book.insert(order(id, Side::Bid, 100 + id, 1)).unwrap();
    }
    book.link_relations(
        OrderId(1),
        RelationRequest {
            peer: Some(OrderId(5)),
            children: vec![OrderId(2), OrderId(3), OrderId(999)],
            ..RelationRequest::default()
        },
    )
    .unwrap();
    book.link_relations(
        OrderId(2),
        RelationRequest {
            children: vec![OrderId(4)],
            ..RelationRequest::default()
        },
    )
    .unwrap();
    assert_eq!(book.order_by_id(OrderId(5)).unwrap().peer, Some(OrderId(1)));
    let records = book
        .cascade_cancel(OrderId(1), CancelReason::Canceled)
        .unwrap();
    assert_eq!(
        records.iter().map(|row| row.order_id).collect::<Vec<_>>(),
        [OrderId(4), OrderId(2), OrderId(3), OrderId(1)]
    );
    assert_eq!(book.order_by_id(OrderId(5)).unwrap().peer, None);
    book.check_consistency().unwrap();
}

#[test]
fn deterministic_snapshot_has_stable_level_and_slot_order() {
    let mut book = Book::new();
    book.insert(order(7, Side::Bid, 101, 4)).unwrap();
    book.insert(order(8, Side::Bid, 101, 6)).unwrap();
    book.insert(order(9, Side::Ask, 102, 5)).unwrap();
    let first = book.snapshot().unwrap().render();
    let second = book.snapshot().unwrap().render();
    assert_eq!(first, second);
    assert!(first.starts_with("occupied=3 aggregate=15 next_free=3\nbid key=-101 price=101"));
    assert!(first.contains("queue=[0, 1]"));
}

#[test]
fn long_deterministic_lifecycle_keeps_all_invariants() {
    let mut book = Book::new();
    let mut state = 94u64;
    let mut next_id = 1u64;
    let mut live = Vec::new();
    for step in 0..750 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        if live.is_empty() || state & 3 != 0 {
            let side = if state & 4 == 0 { Side::Bid } else { Side::Ask };
            let price = 1 + (state >> 8) % 17;
            let quantity = (state >> 24) % 100;
            let slot = book.insert(order(next_id, side, price, quantity)).unwrap();
            live.push((next_id, slot));
            next_id += 1;
        } else {
            let index = (state as usize) % live.len();
            let (_, slot) = live.swap_remove(index);
            book.cancel(slot, CancelReason::Canceled).unwrap();
        }
        book.check_consistency()
            .unwrap_or_else(|error| panic!("step {step}: {error}"));
        assert_eq!(book.occupied_count() as usize, live.len());
    }
}

#[test]
fn invalid_previous_neighbor_rejects_cancel_before_queue_writes() {
    let mut book = Book::new();
    let first = book.insert(order(1, Side::Bid, 100, 1)).unwrap();
    let second = book.insert(order(2, Side::Bid, 100, 1)).unwrap();
    book.slots[first.0 as usize] = Slot::Vacant {
        next_free: book.slots.len() as u64,
    };
    let before = book.bids.clone();
    assert_eq!(
        book.cancel(second, CancelReason::Canceled),
        Err(BookError::VacantSlot(first))
    );
    assert_eq!(book.bids, before);
    assert_eq!(book.occupied(second).unwrap().previous, Some(first));
}

#[test]
fn invariant_checker_detects_queue_cycle() {
    let mut book = Book::new();
    let first = book.insert(order(1, Side::Bid, 100, 1)).unwrap();
    let second = book.insert(order(2, Side::Bid, 100, 1)).unwrap();
    book.occupied_mut(second).unwrap().next = Some(first);
    assert_eq!(
        book.check_consistency(),
        Err(BookError::CorruptState("cycle in price queue"))
    );
}

#[test]
fn invariant_checker_detects_duplicate_reachability_and_unreachable_slots() {
    let mut duplicate = Book::new();
    let slot = duplicate.insert(order(1, Side::Bid, 100, 1)).unwrap();
    duplicate.asks.insert(
        101,
        PriceLevel {
            head: Some(slot),
            tail: Some(slot),
        },
    );
    assert!(matches!(
        duplicate.check_consistency(),
        Err(BookError::CorruptState(_))
    ));

    let mut unreachable = Book::new();
    unreachable.insert(order(1, Side::Bid, 100, 1)).unwrap();
    unreachable.bids.clear();
    assert_eq!(
        unreachable.check_consistency(),
        Err(BookError::CorruptState("occupied slot is unreachable"))
    );
}

#[test]
fn invariant_checker_detects_aggregate_and_free_list_corruption() {
    let mut aggregate = Book::new();
    aggregate.insert(order(1, Side::Bid, 100, 3)).unwrap();
    aggregate.aggregate_quantity = 2;
    assert_eq!(
        aggregate.check_consistency(),
        Err(BookError::CorruptState("aggregate quantity mismatch"))
    );

    let mut free = Book::new();
    let slot = free.insert(order(1, Side::Bid, 100, 1)).unwrap();
    free.cancel(slot, CancelReason::Canceled).unwrap();
    free.slots[slot.0 as usize] = Slot::Vacant { next_free: slot.0 };
    assert_eq!(
        free.check_consistency(),
        Err(BookError::CorruptState("cycle in free list"))
    );
}

#[test]
fn price_key_boundary_is_rejected_without_mutation() {
    let mut book = Book::new();
    book.insert(order(1, Side::Bid, i64::MAX as u64, 1))
        .unwrap();
    let before = book.snapshot().unwrap();
    assert_eq!(
        book.insert(order(2, Side::Ask, i64::MAX as u64 + 1, 1)),
        Err(BookError::PriceOutOfRange(i64::MAX as u64 + 1))
    );
    assert_eq!(book.snapshot().unwrap(), before);
}

#[test]
fn empty_book_has_no_best_order_or_stale_state() {
    let book = Book::new();
    assert_eq!(book.best(Side::Bid).unwrap(), None);
    assert_eq!(book.best(Side::Ask).unwrap(), None);
    assert_eq!(book.occupied_count(), 0);
    assert_eq!(book.aggregate_quantity(), 0);
    let snapshot = book.snapshot().unwrap();
    assert!(snapshot.bids.is_empty());
    assert!(snapshot.asks.is_empty());
    assert!(snapshot.slots.is_empty());
}

#[test]
fn zero_and_maximum_live_quantities_keep_saturating_accounting_consistent() {
    let mut book = Book::new();
    let zero = book.insert(order(1, Side::Ask, 100, 0)).unwrap();
    let maximum = book.insert(order(2, Side::Bid, 99, u64::MAX)).unwrap();
    assert_eq!(book.aggregate_quantity(), u64::MAX);
    book.check_consistency().unwrap();

    book.cancel(zero, CancelReason::Canceled).unwrap();
    assert_eq!(book.aggregate_quantity(), u64::MAX);
    book.cancel(maximum, CancelReason::Canceled).unwrap();
    assert_eq!(book.aggregate_quantity(), 0);
    book.check_consistency().unwrap();
}

#[test]
fn repeated_cancel_is_a_typed_safe_api_error() {
    let mut book = Book::new();
    let slot = book.insert(order(1, Side::Bid, 100, 1)).unwrap();
    let record = book.cancel(slot, CancelReason::Canceled).unwrap();
    assert_eq!(record.removed_quantity, 1);
    assert_eq!(
        book.cancel(slot, CancelReason::Canceled),
        Err(BookError::VacantSlot(slot))
    );
    book.check_consistency().unwrap();
}

#[test]
fn invariant_checker_rejects_an_empty_level_with_stale_presence() {
    let mut book = Book::new();
    book.bids.insert(-100, PriceLevel::default());
    assert_eq!(
        book.check_consistency(),
        Err(BookError::CorruptState("level has no head"))
    );
}
