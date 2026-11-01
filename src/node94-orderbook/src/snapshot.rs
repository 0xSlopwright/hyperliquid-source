use core::fmt::Write;
use std::collections::BTreeSet;

use crate::book::{Book, Slot};
use crate::types::{BookError, OrderId, Side, SlotId, UserId};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BookSnapshot {
    pub occupied_count: u64,
    pub aggregate_quantity: u64,
    pub next_free: u64,
    pub bids: Vec<LevelSnapshot>,
    pub asks: Vec<LevelSnapshot>,
    pub slots: Vec<SlotSnapshot>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LevelSnapshot {
    pub signed_key: i64,
    pub price: u64,
    pub head: SlotId,
    pub tail: SlotId,
    pub queue: Vec<SlotId>,
    pub quantity: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlotSnapshot {
    pub slot: SlotId,
    pub state: SlotStateSnapshot,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SlotStateSnapshot {
    Vacant {
        next_free: u64,
    },
    Occupied {
        order_id: OrderId,
        user: UserId,
        side: Side,
        price: u64,
        quantity: u64,
        previous: Option<SlotId>,
        next: Option<SlotId>,
        parent: Option<OrderId>,
        peer: Option<OrderId>,
        children: Vec<OrderId>,
    },
}

impl BookSnapshot {
    pub fn render(&self) -> String {
        let mut out = String::new();
        writeln!(
            out,
            "occupied={} aggregate={} next_free={}",
            self.occupied_count, self.aggregate_quantity, self.next_free
        )
        .expect("writing to String cannot fail");
        for (name, levels) in [("bid", &self.bids), ("ask", &self.asks)] {
            for level in levels {
                writeln!(
                    out,
                    "{name} key={} price={} head={} tail={} quantity={} queue={:?}",
                    level.signed_key,
                    level.price,
                    level.head.0,
                    level.tail.0,
                    level.quantity,
                    level.queue.iter().map(|slot| slot.0).collect::<Vec<_>>()
                )
                .expect("writing to String cannot fail");
            }
        }
        for slot in &self.slots {
            writeln!(out, "slot {} {:?}", slot.slot.0, slot.state)
                .expect("writing to String cannot fail");
        }
        out
    }
}

impl Book {
    pub fn check_consistency(&self) -> Result<(), BookError> {
        let mut reachable = BTreeSet::new();
        for side in [Side::Bid, Side::Ask] {
            let mut previous_key = None;
            for (key, level) in self.levels(side) {
                if previous_key.is_some_and(|old| old >= *key) {
                    return Err(BookError::CorruptState(
                        "price keys are not strictly ordered",
                    ));
                }
                previous_key = Some(*key);
                let head = level
                    .head
                    .ok_or(BookError::CorruptState("level has no head"))?;
                let tail = level
                    .tail
                    .ok_or(BookError::CorruptState("level has no tail"))?;
                let mut local = BTreeSet::new();
                let mut cursor = Some(head);
                let mut previous = None;
                while let Some(slot) = cursor {
                    if !local.insert(slot) {
                        return Err(BookError::CorruptState("cycle in price queue"));
                    }
                    if !reachable.insert(slot) {
                        return Err(BookError::CorruptState(
                            "live slot is reachable more than once",
                        ));
                    }
                    let order = self.occupied(slot)?;
                    if order.side != side || order.side.signed_price_key(order.price)? != *key {
                        return Err(BookError::CorruptState("slot is in the wrong price level"));
                    }
                    if order.previous != previous {
                        return Err(BookError::CorruptState("previous link mismatch"));
                    }
                    previous = Some(slot);
                    cursor = order.next;
                }
                if previous != Some(tail) {
                    return Err(BookError::CorruptState("tail is not the final queue entry"));
                }
            }
        }

        let mut free = BTreeSet::new();
        let mut cursor = self.next_free;
        while cursor != self.slots.len() as u64 {
            let slot = SlotId(cursor);
            if !free.insert(slot) {
                return Err(BookError::CorruptState("cycle in free list"));
            }
            let index = usize::try_from(cursor)
                .map_err(|_| BookError::CorruptState("free key does not fit usize"))?;
            cursor = match self.slots.get(index) {
                Some(Slot::Vacant { next_free }) => *next_free,
                Some(Slot::Occupied(_)) => {
                    return Err(BookError::CorruptState(
                        "free list reaches an occupied slot",
                    ));
                }
                None => return Err(BookError::CorruptState("free list leaves the slab")),
            };
        }

        let mut occupied = 0u64;
        let mut quantity = 0u64;
        let mut indexed = BTreeSet::new();
        for (index, slot) in self.slots.iter().enumerate() {
            let id = SlotId(index as u64);
            match slot {
                Slot::Occupied(order) => {
                    occupied = occupied.saturating_add(1);
                    quantity = quantity.saturating_add(order.quantity);
                    if !reachable.contains(&id) {
                        return Err(BookError::CorruptState("occupied slot is unreachable"));
                    }
                    if free.contains(&id) {
                        return Err(BookError::CorruptState("occupied slot is on free list"));
                    }
                    if self.order_index.get(&order.order_id) != Some(&id)
                        || !indexed.insert(order.order_id)
                    {
                        return Err(BookError::CorruptState("order index mismatch"));
                    }
                    if let Some(peer) = order.peer
                        && let Some(peer_slot) = self.order_index.get(&peer)
                        && self.occupied(*peer_slot)?.peer != Some(order.order_id)
                    {
                        return Err(BookError::CorruptState("peer relation is not reciprocal"));
                    }
                    for child in &order.children {
                        if let Some(child_slot) = self.order_index.get(child)
                            && self.occupied(*child_slot)?.parent != Some(order.order_id)
                        {
                            return Err(BookError::CorruptState(
                                "child relation lacks its back link",
                            ));
                        }
                    }
                }
                Slot::Vacant { .. } => {
                    if !free.contains(&id) {
                        return Err(BookError::CorruptState(
                            "vacant slot is absent from free list",
                        ));
                    }
                    if reachable.contains(&id) {
                        return Err(BookError::CorruptState("vacant slot is still in a queue"));
                    }
                }
            }
        }
        if occupied != self.occupied_count {
            return Err(BookError::CorruptState("occupied count mismatch"));
        }
        if quantity != self.aggregate_quantity {
            return Err(BookError::CorruptState("aggregate quantity mismatch"));
        }
        if indexed.len() != self.order_index.len() {
            return Err(BookError::CorruptState(
                "order index contains stale entries",
            ));
        }
        Ok(())
    }

    pub fn snapshot(&self) -> Result<BookSnapshot, BookError> {
        self.check_consistency()?;
        Ok(BookSnapshot {
            occupied_count: self.occupied_count,
            aggregate_quantity: self.aggregate_quantity,
            next_free: self.next_free,
            bids: self.snapshot_levels(Side::Bid)?,
            asks: self.snapshot_levels(Side::Ask)?,
            slots: self
                .slots
                .iter()
                .enumerate()
                .map(|(index, slot)| SlotSnapshot {
                    slot: SlotId(index as u64),
                    state: match slot {
                        Slot::Vacant { next_free } => SlotStateSnapshot::Vacant {
                            next_free: *next_free,
                        },
                        Slot::Occupied(order) => SlotStateSnapshot::Occupied {
                            order_id: order.order_id,
                            user: order.user,
                            side: order.side,
                            price: order.price,
                            quantity: order.quantity,
                            previous: order.previous,
                            next: order.next,
                            parent: order.parent,
                            peer: order.peer,
                            children: order.children.clone(),
                        },
                    },
                })
                .collect(),
        })
    }

    fn snapshot_levels(&self, side: Side) -> Result<Vec<LevelSnapshot>, BookError> {
        self.levels(side)
            .iter()
            .map(|(key, level)| {
                let head = level
                    .head
                    .ok_or(BookError::CorruptState("level has no head"))?;
                let tail = level
                    .tail
                    .ok_or(BookError::CorruptState("level has no tail"))?;
                let mut queue = Vec::new();
                let mut quantity = 0u64;
                let mut cursor = Some(head);
                while let Some(slot) = cursor {
                    let order = self.occupied(slot)?;
                    queue.push(slot);
                    quantity = quantity.saturating_add(order.quantity);
                    cursor = order.next;
                }
                Ok(LevelSnapshot {
                    signed_key: *key,
                    price: self.occupied(head)?.price,
                    head,
                    tail,
                    queue,
                    quantity,
                })
            })
            .collect()
    }
}
