use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use crate::arithmetic::{floor_sub, ledger_add_event, saturating_u64_add};
use crate::{Address, ArithmeticEvent, Computation, FeeError, PerpFeeOutput, SpotFeeOutput};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LedgerField {
    Volume,
    Unclaimed,
    Claimed,
    RewardedToReferrer,
    RewardedFees,
    TrialExtra,
    CollectedBuilderFees,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubtractionStage {
    GrossLessRebate,
    NetLessExtra,
}

/// The six-word per-token value serialized by node #94 as `V U C r F T`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TokenFeeState {
    pub volume: u64,
    pub unclaimed: u64,
    pub claimed: u64,
    pub rewarded_to_referrer: u64,
    pub rewarded_fees: u64,
    pub trial_extra: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LedgerCredit {
    pub tag: u64,
    pub amount: u64,
    pub address: Option<Address>,
}

impl LedgerCredit {
    pub const NONE: Self = Self {
        tag: 0,
        amount: 0,
        address: None,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FillFeeRecord {
    pub referrer: LedgerCredit,
    pub builder: LedgerCredit,
    pub gross: u64,
    pub rebate: u64,
    pub extra: u64,
}

impl FillFeeRecord {
    pub fn from_perp(output: &PerpFeeOutput) -> Result<Self, FeeError> {
        Ok(Self {
            referrer: scale_recipient(output.referrer, "referrer")?,
            builder: scale_recipient(output.builder, "builder")?,
            gross: scale_100(output.gross, "gross")?,
            rebate: scale_100(output.rebate, "rebate")?,
            extra: scale_100(output.extra, "extra")?,
        })
    }

    pub fn from_spot(output: &SpotFeeOutput) -> Self {
        Self {
            referrer: direct_recipient(output.referrer),
            builder: direct_recipient(output.builder),
            gross: output.gross,
            rebate: output.rebate,
            extra: output.extra,
        }
    }
}

fn scale_100(value: u64, field: &'static str) -> Result<u64, FeeError> {
    value
        .checked_mul(100)
        .ok_or(FeeError::LedgerScaleOverflow(field))
}

fn scale_recipient(
    recipient: Option<crate::FeeRecipient>,
    field: &'static str,
) -> Result<LedgerCredit, FeeError> {
    match recipient {
        Some(recipient) => Ok(LedgerCredit {
            tag: 1,
            amount: scale_100(recipient.amount, field)?,
            address: Some(recipient.address),
        }),
        None => Ok(LedgerCredit::NONE),
    }
}

fn direct_recipient(recipient: Option<crate::FeeRecipient>) -> LedgerCredit {
    match recipient {
        Some(recipient) => LedgerCredit {
            tag: 1,
            amount: recipient.amount,
            address: Some(recipient.address),
        },
        None => LedgerCredit::NONE,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LedgerRecordKind {
    OwnerBucket,
    TokenValue,
    BuilderBucket,
    BuilderTokenValue,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LedgerCreation {
    pub kind: LedgerRecordKind,
    pub owner: Address,
    pub token: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LedgerApplication {
    pub creations: Vec<LedgerCreation>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FeeLedger {
    values: BTreeMap<Address, BTreeMap<u64, TokenFeeState>>,
    collected_builder_fees: BTreeMap<Address, BTreeMap<u64, u64>>,
}

impl FeeLedger {
    /// Seeds or replaces an offline token value before applying a transition.
    pub fn insert_token_state(
        &mut self,
        owner: Address,
        token: u64,
        state: TokenFeeState,
    ) -> Option<TokenFeeState> {
        self.values.entry(owner).or_default().insert(token, state)
    }

    /// Seeds or replaces an offline collected-builder-fee value.
    pub fn insert_collected_builder_fee(
        &mut self,
        builder: Address,
        token: u64,
        amount: u64,
    ) -> Option<u64> {
        self.collected_builder_fees
            .entry(builder)
            .or_default()
            .insert(token, amount)
    }

    pub fn token_state(&self, owner: Address, token: u64) -> Option<&TokenFeeState> {
        self.values.get(&owner)?.get(&token)
    }

    pub fn collected_builder_fee(&self, builder: Address, token: u64) -> Option<u64> {
        self.collected_builder_fees
            .get(&builder)?
            .get(&token)
            .copied()
    }

    pub fn owner_bucket_count(&self) -> usize {
        self.values.len()
    }

    /// Applies a fill after resolving all required offline recipient addresses.
    /// Structurally unresolved input returns an error without changing state.
    pub fn apply(
        &mut self,
        payer: Address,
        token: u64,
        record: FillFeeRecord,
    ) -> Result<Computation<LedgerApplication>, FeeError> {
        // Missing addresses are an offline input error, not a target ledger
        // transition. Resolve both before any credit so a retry cannot apply
        // the payer or referrer part of the fill twice.
        let referrer = if record.referrer.tag as u32 == 1 {
            Some(
                record
                    .referrer
                    .address
                    .ok_or(FeeError::MissingLedgerRecipient("referrer"))?,
            )
        } else {
            None
        };
        let builder = if record.builder.tag as u8 != 0 && record.builder.amount != 0 {
            Some(
                record
                    .builder
                    .address
                    .ok_or(FeeError::MissingLedgerRecipient("builder"))?,
            )
        } else {
            None
        };
        let mut events = Vec::new();
        let mut application = LedgerApplication::default();

        self.ensure_value(payer, token, &mut application);
        self.add_value(
            payer,
            token,
            LedgerField::TrialExtra,
            record.extra,
            &mut events,
        );

        if let Some(address) = referrer {
            let after_rebate = floor_sub(
                record.gross,
                record.rebate,
                SubtractionStage::GrossLessRebate,
                &mut events,
            );
            let rewarded = floor_sub(
                after_rebate,
                record.extra,
                SubtractionStage::NetLessExtra,
                &mut events,
            );
            self.add_value(
                payer,
                token,
                LedgerField::RewardedFees,
                rewarded,
                &mut events,
            );
            self.add_value(
                payer,
                token,
                LedgerField::RewardedToReferrer,
                record.referrer.amount,
                &mut events,
            );
            self.ensure_value(address, token, &mut application);
            self.add_value(
                address,
                token,
                LedgerField::Unclaimed,
                record.referrer.amount,
                &mut events,
            );
        }

        if let Some(address) = builder {
            self.ensure_value(address, token, &mut application);
            self.add_value(
                address,
                token,
                LedgerField::Unclaimed,
                record.builder.amount,
                &mut events,
            );
            self.add_builder_fee(
                address,
                token,
                record.builder.amount,
                &mut application,
                &mut events,
            );
        }

        Ok(Computation::new(application, events))
    }

    fn ensure_value(&mut self, owner: Address, token: u64, application: &mut LedgerApplication) {
        let is_new_owner = !self.values.contains_key(&owner);
        let bucket = self.values.entry(owner).or_default();
        if is_new_owner {
            application.creations.push(LedgerCreation {
                kind: LedgerRecordKind::OwnerBucket,
                owner,
                token,
            });
        }
        if let Entry::Vacant(entry) = bucket.entry(token) {
            entry.insert(TokenFeeState::default());
            application.creations.push(LedgerCreation {
                kind: LedgerRecordKind::TokenValue,
                owner,
                token,
            });
        }
    }

    fn add_value(
        &mut self,
        owner: Address,
        token: u64,
        field: LedgerField,
        amount: u64,
        events: &mut Vec<ArithmeticEvent>,
    ) {
        let state = self
            .values
            .get_mut(&owner)
            .and_then(|bucket| bucket.get_mut(&token))
            .expect("ensure_value precedes every update");
        let slot = match field {
            LedgerField::Volume => &mut state.volume,
            LedgerField::Unclaimed => &mut state.unclaimed,
            LedgerField::Claimed => &mut state.claimed,
            LedgerField::RewardedToReferrer => &mut state.rewarded_to_referrer,
            LedgerField::RewardedFees => &mut state.rewarded_fees,
            LedgerField::TrialExtra => &mut state.trial_extra,
            LedgerField::CollectedBuilderFees => unreachable!("separate builder map"),
        };
        *slot = saturating_u64_add(*slot, amount, ledger_add_event(owner, token, field), events);
    }

    fn add_builder_fee(
        &mut self,
        owner: Address,
        token: u64,
        amount: u64,
        application: &mut LedgerApplication,
        events: &mut Vec<ArithmeticEvent>,
    ) {
        let is_new_owner = !self.collected_builder_fees.contains_key(&owner);
        let bucket = self.collected_builder_fees.entry(owner).or_default();
        if is_new_owner {
            application.creations.push(LedgerCreation {
                kind: LedgerRecordKind::BuilderBucket,
                owner,
                token,
            });
        }
        let is_new_token = !bucket.contains_key(&token);
        let value = bucket.entry(token).or_default();
        if is_new_token {
            application.creations.push(LedgerCreation {
                kind: LedgerRecordKind::BuilderTokenValue,
                owner,
                token,
            });
        }
        *value = saturating_u64_add(
            *value,
            amount,
            ledger_add_event(owner, token, LedgerField::CollectedBuilderFees),
            events,
        );
    }
}
