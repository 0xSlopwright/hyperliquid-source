use std::collections::{BTreeMap, BTreeSet};

use crate::types::{
    BookError, CancelReason, CancelRecord, InsertOrder, OrderId, RelationRequest, Side, SlotId,
    UserId,
};

#[derive(Clone, Debug)]
pub(crate) struct OrderSlot {
    pub order_id: OrderId,
    pub user: UserId,
    pub side: Side,
    pub price: u64,
    pub quantity: u64,
    pub reduce_only: bool,
    pub previous: Option<SlotId>,
    pub next: Option<SlotId>,
    pub parent: Option<OrderId>,
    pub peer: Option<OrderId>,
    pub children: Vec<OrderId>,
}

#[derive(Clone, Debug)]
pub(crate) enum Slot {
    Occupied(OrderSlot),
    Vacant { next_free: u64 },
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PriceLevel {
    pub head: Option<SlotId>,
    pub tail: Option<SlotId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrderView {
    pub slot: SlotId,
    pub order_id: OrderId,
    pub user: UserId,
    pub side: Side,
    pub price: u64,
    pub quantity: u64,
    pub reduce_only: bool,
    pub previous: Option<SlotId>,
    pub next: Option<SlotId>,
    pub parent: Option<OrderId>,
    pub peer: Option<OrderId>,
    pub children: Vec<OrderId>,
}

#[derive(Clone, Debug)]
pub struct Book {
    pub(crate) slots: Vec<Slot>,
    pub(crate) next_free: u64,
    pub(crate) occupied_count: u64,
    pub(crate) aggregate_quantity: u64,
    pub(crate) bids: BTreeMap<i64, PriceLevel>,
    pub(crate) asks: BTreeMap<i64, PriceLevel>,
    pub(crate) order_index: BTreeMap<OrderId, SlotId>,
}

impl Default for Book {
    fn default() -> Self {
        Self::new()
    }
}

impl Book {
    pub const fn new() -> Self {
        Self {
            slots: Vec::new(),
            next_free: 0,
            occupied_count: 0,
            aggregate_quantity: 0,
            bids: BTreeMap::new(),
            asks: BTreeMap::new(),
            order_index: BTreeMap::new(),
        }
    }

    pub const fn occupied_count(&self) -> u64 {
        self.occupied_count
    }

    pub const fn aggregate_quantity(&self) -> u64 {
        self.aggregate_quantity
    }

    pub fn insert(&mut self, order: InsertOrder) -> Result<SlotId, BookError> {
        if self.order_index.contains_key(&order.order_id) {
            return Err(BookError::UnsupportedDuplicateOrder(order.order_id));
        }
        let key = order.side.signed_price_key(order.price)?;
        let old_tail = self
            .levels(order.side)
            .get(&key)
            .and_then(|level| level.tail);
        if let Some(tail) = old_tail {
            let tail_order = self.occupied(tail)?;
            if tail_order.side != order.side
                || tail_order.price != order.price
                || tail_order.next.is_some()
            {
                return Err(BookError::CorruptState("price-level tail is stale"));
            }
        }

        let slot = OrderSlot {
            order_id: order.order_id,
            user: order.user,
            side: order.side,
            price: order.price,
            quantity: order.quantity,
            reduce_only: order.reduce_only,
            previous: old_tail,
            next: None,
            parent: None,
            peer: None,
            children: Vec::new(),
        };
        let slot_id = self.allocate(slot)?;

        if let Some(tail) = old_tail {
            self.occupied_mut(tail)?.next = Some(slot_id);
        }
        let level = self.levels_mut(order.side).entry(key).or_default();
        if level.head.is_none() {
            level.head = Some(slot_id);
        }
        level.tail = Some(slot_id);
        self.aggregate_quantity = self.aggregate_quantity.saturating_add(order.quantity);
        self.order_index.insert(order.order_id, slot_id);
        Ok(slot_id)
    }

    pub fn order(&self, slot: SlotId) -> Result<OrderView, BookError> {
        let order = self.occupied(slot)?;
        Ok(Self::view(slot, order))
    }

    pub fn order_by_id(&self, order_id: OrderId) -> Result<OrderView, BookError> {
        let slot = self
            .order_index
            .get(&order_id)
            .copied()
            .ok_or(BookError::OrderNotFound(order_id))?;
        self.order(slot)
    }

    pub fn best(&self, side: Side) -> Result<Option<OrderView>, BookError> {
        let Some((_, level)) = self.levels(side).first_key_value() else {
            return Ok(None);
        };
        let head = level
            .head
            .ok_or(BookError::CorruptState("nonempty level has no head"))?;
        self.order(head).map(Some)
    }

    pub fn cancel(
        &mut self,
        slot: SlotId,
        reason: CancelReason,
    ) -> Result<CancelRecord, BookError> {
        let removed = self.remove_slot(slot)?;
        Ok(CancelRecord {
            slot,
            order_id: removed.order_id,
            reason,
            removed_quantity: removed.quantity,
        })
    }

    pub fn cancel_order(
        &mut self,
        order_id: OrderId,
        reason: CancelReason,
    ) -> Result<CancelRecord, BookError> {
        let slot = self
            .order_index
            .get(&order_id)
            .copied()
            .ok_or(BookError::OrderNotFound(order_id))?;
        self.cancel(slot, reason)
    }

    /// Collects the user's live order IDs first, sorts/deduplicates them, then
    /// removes that fixed list in ascending order, matching the verified path.
    pub fn cancel_user(
        &mut self,
        user: UserId,
        reason: CancelReason,
    ) -> Result<Vec<CancelRecord>, BookError> {
        let ids: BTreeSet<_> = self
            .slots
            .iter()
            .filter_map(|slot| match slot {
                Slot::Occupied(order) if order.user == user => Some(order.order_id),
                _ => None,
            })
            .collect();
        ids.into_iter()
            .map(|order_id| self.cancel_order(order_id, reason))
            .collect()
    }

    pub fn link_relations(
        &mut self,
        order_id: OrderId,
        request: RelationRequest,
    ) -> Result<(), BookError> {
        let slot = self.slot_for(order_id)?;
        let current = self.occupied(slot)?.clone();
        if request.parent.is_some() && current.parent.is_some() && request.parent != current.parent
        {
            return Err(BookError::UnsupportedRelationRewrite(order_id));
        }
        if request.peer.is_some() && current.peer.is_some() && request.peer != current.peer {
            return Err(BookError::UnsupportedRelationRewrite(order_id));
        }

        let parent = request
            .parent
            .filter(|id| self.order_index.contains_key(id))
            .or(current.parent);
        let peer = request
            .peer
            .filter(|id| self.order_index.contains_key(id))
            .or(current.peer);
        let mut children = Vec::new();
        for child in request.children {
            if child != order_id
                && self.order_index.contains_key(&child)
                && !current.children.contains(&child)
                && !children.contains(&child)
            {
                let existing_parent = self.occupied(self.slot_for(child)?)?.parent;
                if existing_parent.is_some() && existing_parent != Some(order_id) {
                    return Err(BookError::UnsupportedRelationRewrite(child));
                }
                children.push(child);
            }
        }
        if let Some(peer_id) = peer {
            let existing_peer = self.occupied(self.slot_for(peer_id)?)?.peer;
            if peer_id == order_id || (existing_peer.is_some() && existing_peer != Some(order_id)) {
                return Err(BookError::UnsupportedRelationRewrite(peer_id));
            }
        }

        if let Some(parent_id) = parent {
            let parent_slot = self.slot_for(parent_id)?;
            let parent_order = self.occupied_mut(parent_slot)?;
            if !parent_order.children.contains(&order_id) {
                parent_order.children.push(order_id);
            }
            self.occupied_mut(slot)?.parent = Some(parent_id);
        }
        if let Some(peer_id) = peer
            && current.peer != Some(peer_id)
        {
            let peer_slot = self.slot_for(peer_id)?;
            self.occupied_mut(peer_slot)?.peer = Some(order_id);
            self.occupied_mut(slot)?.peer = Some(peer_id);
        }
        for child_id in &children {
            let child_slot = self.slot_for(*child_id)?;
            self.occupied_mut(child_slot)?.parent = Some(order_id);
        }
        self.occupied_mut(slot)?.children.extend(children);
        Ok(())
    }

    /// Cancels children depth-first in stored order, then the root.
    pub fn cascade_cancel(
        &mut self,
        root: OrderId,
        reason: CancelReason,
    ) -> Result<Vec<CancelRecord>, BookError> {
        let mut visiting = BTreeSet::new();
        let mut visited = BTreeSet::new();
        let mut order = Vec::new();
        self.collect_postorder(root, &mut visiting, &mut visited, &mut order)?;
        let mut records = Vec::new();
        for order_id in order {
            if self.order_index.contains_key(&order_id) {
                records.push(self.cancel_order(order_id, reason)?);
            }
        }
        Ok(records)
    }

    fn collect_postorder(
        &self,
        order_id: OrderId,
        visiting: &mut BTreeSet<OrderId>,
        visited: &mut BTreeSet<OrderId>,
        output: &mut Vec<OrderId>,
    ) -> Result<(), BookError> {
        if visited.contains(&order_id) || !self.order_index.contains_key(&order_id) {
            return Ok(());
        }
        if !visiting.insert(order_id) {
            return Err(BookError::CorruptState("cycle in child relations"));
        }
        let children = self.occupied(self.slot_for(order_id)?)?.children.clone();
        for child in children {
            self.collect_postorder(child, visiting, visited, output)?;
        }
        visiting.remove(&order_id);
        visited.insert(order_id);
        output.push(order_id);
        Ok(())
    }

    pub(crate) fn remove_slot(&mut self, slot: SlotId) -> Result<OrderSlot, BookError> {
        let removed = self.occupied(slot)?.clone();
        let key = removed.side.signed_price_key(removed.price)?;
        let level = self
            .levels(removed.side)
            .get(&key)
            .copied()
            .ok_or(BookError::CorruptState(
                "slot points to a missing price level",
            ))?;

        match removed.previous {
            Some(previous) => {
                let order = self.occupied(previous)?;
                if order.next != Some(slot)
                    || order.side != removed.side
                    || order.price != removed.price
                {
                    return Err(BookError::CorruptState("invalid previous neighbor"));
                }
            }
            None if level.head != Some(slot) => {
                return Err(BookError::CorruptState(
                    "head does not reference first slot",
                ));
            }
            None => {}
        }
        match removed.next {
            Some(next) => {
                let order = self.occupied(next)?;
                if order.previous != Some(slot)
                    || order.side != removed.side
                    || order.price != removed.price
                {
                    return Err(BookError::CorruptState("invalid next neighbor"));
                }
            }
            None if level.tail != Some(slot) => {
                return Err(BookError::CorruptState("tail does not reference last slot"));
            }
            None => {}
        }

        if let Some(previous) = removed.previous {
            self.occupied_mut(previous)?.next = removed.next;
        }
        if let Some(next) = removed.next {
            self.occupied_mut(next)?.previous = removed.previous;
        }
        let level = self
            .levels_mut(removed.side)
            .get_mut(&key)
            .expect("preflight established the level");
        if removed.previous.is_none() {
            level.head = removed.next;
        }
        if removed.next.is_none() {
            level.tail = removed.previous;
        }
        if level.head.is_none() && level.tail.is_none() {
            self.levels_mut(removed.side).remove(&key);
        }

        self.clear_relations_before_remove(&removed)?;
        self.order_index.remove(&removed.order_id);
        self.aggregate_quantity = self.aggregate_quantity.saturating_sub(removed.quantity);
        self.free(slot)?;
        Ok(removed)
    }

    fn clear_relations_before_remove(&mut self, removed: &OrderSlot) -> Result<(), BookError> {
        for child_id in removed.children.clone() {
            if let Some(child_slot) = self.order_index.get(&child_id).copied() {
                self.occupied_mut(child_slot)?.parent = None;
            }
        }
        if let Some(peer_id) = removed.peer
            && let Some(peer_slot) = self.order_index.get(&peer_id).copied()
        {
            self.occupied_mut(peer_slot)?.peer = None;
        }
        Ok(())
    }

    fn allocate(&mut self, order: OrderSlot) -> Result<SlotId, BookError> {
        let key = self.next_free;
        if key == self.slots.len() as u64 {
            self.slots.push(Slot::Occupied(order));
            self.next_free = key
                .checked_add(1)
                .ok_or(BookError::CorruptState("slot key overflow"))?;
        } else {
            let index = usize::try_from(key)
                .map_err(|_| BookError::CorruptState("free key does not fit usize"))?;
            let next = match self.slots.get(index) {
                Some(Slot::Vacant { next_free }) => *next_free,
                Some(Slot::Occupied(_)) => {
                    return Err(BookError::CorruptState(
                        "free list points to an occupied slot",
                    ));
                }
                None => return Err(BookError::CorruptState("free list points outside the slab")),
            };
            self.slots[index] = Slot::Occupied(order);
            self.next_free = next;
        }
        self.occupied_count = self.occupied_count.saturating_add(1);
        Ok(SlotId(key))
    }

    fn free(&mut self, slot: SlotId) -> Result<(), BookError> {
        let index = self.slot_index(slot)?;
        if !matches!(self.slots[index], Slot::Occupied(_)) {
            return Err(BookError::VacantSlot(slot));
        }
        let old_head = self.next_free;
        self.slots[index] = Slot::Vacant {
            next_free: old_head,
        };
        self.next_free = slot.0;
        self.occupied_count = self.occupied_count.saturating_sub(1);
        Ok(())
    }

    pub(crate) fn occupied(&self, slot: SlotId) -> Result<&OrderSlot, BookError> {
        match self.slots.get(self.slot_index(slot)?) {
            Some(Slot::Occupied(order)) => Ok(order),
            Some(Slot::Vacant { .. }) => Err(BookError::VacantSlot(slot)),
            None => Err(BookError::SlotOutOfRange(slot)),
        }
    }

    pub(crate) fn occupied_mut(&mut self, slot: SlotId) -> Result<&mut OrderSlot, BookError> {
        let index = self.slot_index(slot)?;
        match self.slots.get_mut(index) {
            Some(Slot::Occupied(order)) => Ok(order),
            Some(Slot::Vacant { .. }) => Err(BookError::VacantSlot(slot)),
            None => Err(BookError::SlotOutOfRange(slot)),
        }
    }

    pub(crate) fn slot_for(&self, order_id: OrderId) -> Result<SlotId, BookError> {
        self.order_index
            .get(&order_id)
            .copied()
            .ok_or(BookError::OrderNotFound(order_id))
    }

    fn slot_index(&self, slot: SlotId) -> Result<usize, BookError> {
        let index = usize::try_from(slot.0).map_err(|_| BookError::SlotOutOfRange(slot))?;
        if index >= self.slots.len() {
            return Err(BookError::SlotOutOfRange(slot));
        }
        Ok(index)
    }

    pub(crate) fn levels(&self, side: Side) -> &BTreeMap<i64, PriceLevel> {
        match side {
            Side::Bid => &self.bids,
            Side::Ask => &self.asks,
        }
    }

    pub(crate) fn levels_mut(&mut self, side: Side) -> &mut BTreeMap<i64, PriceLevel> {
        match side {
            Side::Bid => &mut self.bids,
            Side::Ask => &mut self.asks,
        }
    }

    pub(crate) fn view(slot: SlotId, order: &OrderSlot) -> OrderView {
        OrderView {
            slot,
            order_id: order.order_id,
            user: order.user,
            side: order.side,
            price: order.price,
            quantity: order.quantity,
            reduce_only: order.reduce_only,
            previous: order.previous,
            next: order.next,
            parent: order.parent,
            peer: order.peer,
            children: order.children.clone(),
        }
    }
}
