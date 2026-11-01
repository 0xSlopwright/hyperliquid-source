use std::collections::BTreeMap;

use crate::arithmetic::{
    DISCOUNT_VOLUME_LIMIT, REFERRER_VOLUME_LIMIT, saturating_i64_sub, saturating_u64_add,
    target_i64, target_max, target_min,
};
use crate::types::Profiles;
use crate::{
    Address, ArithmeticEvent, BuilderFee, Computation, FeeError, FeeProfile, FeeRates,
    FeeRecipient, FeeSchedule, LiquidityRole, PerpFeeOutput, PerpFill, SpotFeeOutput, SpotFill,
};

#[derive(Clone, Copy)]
struct ResolvedRow {
    current: FeeRates,
    previous: Option<FeeRates>,
    previous_tag: u32,
    anchor: f64,
}

#[derive(Clone, Copy)]
struct PerpLeg {
    deployer: f64,
    protocol: f64,
}

#[derive(Clone, Copy)]
struct PerpLegInput {
    payer: Address,
    role: LiquidityRole,
    rate: f64,
    deployer_scale: f64,
    asset_scale: f64,
    trial: bool,
}

impl PerpLeg {
    fn total(self) -> f64 {
        self.deployer + self.protocol
    }
}

#[derive(Clone, Debug)]
pub struct FeeEngine {
    schedule: FeeSchedule,
    profiles: Profiles,
}

impl FeeEngine {
    pub fn new(schedule: FeeSchedule) -> Result<Self, FeeError> {
        schedule.validate()?;
        Ok(Self {
            schedule,
            profiles: BTreeMap::new(),
        })
    }

    pub fn schedule(&self) -> &FeeSchedule {
        &self.schedule
    }

    pub fn profile(&self, owner: Address) -> Option<&FeeProfile> {
        self.profiles.get(&owner)
    }

    pub fn insert_profile(&mut self, owner: Address, profile: FeeProfile) -> Option<FeeProfile> {
        self.profiles.insert(owner, profile)
    }

    pub fn remove_profile(&mut self, owner: Address) -> Option<FeeProfile> {
        self.profiles.remove(&owner)
    }

    pub fn compute_perp(&self, fill: PerpFill) -> Result<Computation<PerpFeeOutput>, FeeError> {
        if fill.notional < 0 {
            return Err(FeeError::NegativeNotional);
        }

        let mut events = Vec::new();
        let resolved = self.resolve_row(fill.payer)?;
        let current_rate = resolved.current.perp.select(fill.role);
        let deployer_scale = if fill.deployer_deleted {
            0.0
        } else {
            fill.deployer_scale
        };

        let current = self.perp_leg(
            PerpLegInput {
                payer: fill.payer,
                role: fill.role,
                rate: current_rate,
                deployer_scale,
                asset_scale: fill.asset_scale.factor(),
                trial: fill.trial,
            },
            &mut events,
        );

        let previous = if resolved.previous_tag != 0 {
            let rates = resolved
                .previous
                .ok_or(FeeError::MissingPreviousRates { owner: fill.payer })?;
            Some(self.perp_leg(
                PerpLegInput {
                    payer: fill.payer,
                    role: fill.role,
                    rate: rates.perp.select(fill.role),
                    deployer_scale,
                    asset_scale: fill.asset_scale.factor(),
                    trial: fill.trial,
                },
                &mut events,
            ))
        } else {
            None
        };

        let notional = fill.notional as f64;
        let current_total = current.total();
        let fee = target_i64(current_total * notional);
        let mut gross = if fee > 0 { fee as u64 } else { 0 };
        let extra = previous.map_or(0, |leg| {
            target_i64(target_max(leg.total() - current_total, 0.0) * notional).max(0) as u64
        });
        gross = gross.saturating_add(extra);

        let mut builder = None;
        if let Some(builder_fee) = fill.builder {
            let amount = self.builder_base(builder_fee, fill.notional);
            gross = saturating_u64_add(
                gross,
                amount,
                ArithmeticEvent::GrossWithBuilderSaturated,
                &mut events,
            );
            builder = Some(FeeRecipient {
                address: builder_fee.address,
                amount,
            });
        }

        let mut net = fee;
        let mut referrer = None;
        let mut split_done = fee <= 0;
        if !split_done
            && !fill.flagged
            && let Some(builder_fee) = fill.builder
        {
            let gain = self.tier_gain(fill.payer, builder_fee.address, fee, &mut events)?;
            if gain > 0 {
                let recipient = builder.as_mut().expect("builder initialized above");
                recipient.amount = recipient.amount.saturating_add(gain);
                net -= gain as i64;
                split_done = true;
            }
        }
        if !split_done
            && let Some(recipient) =
                self.referrer_credit(fill.payer, fee, fill.flagged, &mut events)?
        {
            net -= recipient.amount as i64;
            referrer = Some(recipient);
        }

        let deployer_share = if current_total != 0.0 {
            current.deployer / current_total
        } else {
            0.0
        };
        let deployer = target_i64(net as f64 * deployer_share);
        let protocol = saturating_i64_sub(net, deployer, &mut events);
        let output = PerpFeeOutput {
            referrer,
            builder,
            gross,
            rebate: if fee <= 0 { fee.unsigned_abs() } else { 0 },
            extra,
            deployer,
            protocol,
        };
        Ok(Computation::new(output, events))
    }

    pub fn compute_spot(&self, fill: SpotFill) -> Result<Computation<SpotFeeOutput>, FeeError> {
        if fill.notional < 0 {
            return Err(FeeError::NegativeNotional);
        }

        let mut events = Vec::new();
        let resolved = self.resolve_row(fill.payer)?;
        let current_rate = resolved.current.spot.select(fill.role);
        let previous_rate = if resolved.previous_tag != 0 {
            Some(
                resolved
                    .previous
                    .ok_or(FeeError::MissingPreviousRates { owner: fill.payer })?
                    .spot
                    .select(fill.role),
            )
        } else {
            None
        };

        let previous =
            previous_rate.map(|rate| self.spot_rate(fill.payer, fill, rate, true, &mut events));
        let active = if !fill.quote_leg {
            previous.unwrap_or_else(|| {
                self.spot_rate(fill.payer, fill, current_rate, false, &mut events)
            })
        } else {
            self.spot_rate(fill.payer, fill, current_rate, false, &mut events)
        };

        let notional = fill.notional as f64;
        let fee = target_i64(active * notional);
        let mut gross = if fee > 0 { fee as u64 } else { 0 };
        let rebate = if fee <= 0 { fee.unsigned_abs() } else { 0 };

        if !fill.quote_leg {
            return Ok(Computation::new(
                SpotFeeOutput {
                    referrer: None,
                    builder: None,
                    gross,
                    rebate,
                    extra: 0,
                },
                events,
            ));
        }

        let extra = previous.map_or(0, |old| {
            target_i64(target_max(old - active, 0.0) * notional).max(0) as u64
        });
        gross = gross.saturating_add(extra);

        let mut builder = None;
        if let Some(builder_fee) = fill.builder {
            let amount = self.builder_base(builder_fee, fill.notional);
            gross = saturating_u64_add(
                gross,
                amount,
                ArithmeticEvent::GrossWithBuilderSaturated,
                &mut events,
            );
            builder = Some(FeeRecipient {
                address: builder_fee.address,
                amount,
            });
        }

        let mut referrer = None;
        let mut split_done = fee <= 0;
        if !split_done
            && !fill.flagged
            && let Some(builder_fee) = fill.builder
        {
            let gain = self.tier_gain(fill.payer, builder_fee.address, fee, &mut events)?;
            if gain > 0 {
                let recipient = builder.as_mut().expect("builder initialized above");
                recipient.amount = recipient.amount.saturating_add(gain);
                split_done = true;
            }
        }
        if !split_done {
            referrer = self.referrer_credit(fill.payer, fee, fill.flagged, &mut events)?;
        }

        Ok(Computation::new(
            SpotFeeOutput {
                referrer,
                builder,
                gross,
                rebate,
                extra,
            },
            events,
        ))
    }

    fn resolve_row(&self, owner: Address) -> Result<ResolvedRow, FeeError> {
        if owner.is_fee_exempt() {
            return Ok(ResolvedRow {
                current: FeeRates::ZERO,
                previous: None,
                previous_tag: 0,
                anchor: 0.0,
            });
        }
        let Some(profile) = self.profiles.get(&owner) else {
            return Ok(ResolvedRow {
                current: self.schedule.default_rates,
                previous: None,
                previous_tag: 0,
                anchor: 0.0,
            });
        };
        if profile.row_tag & 0xff == 0 {
            return Ok(ResolvedRow {
                current: self.schedule.default_rates,
                previous: None,
                previous_tag: 0,
                anchor: 0.0,
            });
        }
        if profile.row.previous_tag != 0 && profile.row.previous.is_none() {
            return Err(FeeError::MissingPreviousRates { owner });
        }
        Ok(ResolvedRow {
            current: profile.row.current,
            previous: profile.row.previous,
            previous_tag: profile.row.previous_tag,
            anchor: profile.row.volume_anchor,
        })
    }

    fn perp_leg(&self, input: PerpLegInput, events: &mut Vec<ArithmeticEvent>) -> PerpLeg {
        let (mut deployer, mut protocol, multiplier) = if input.rate < 0.0 {
            let share = target_min(input.deployer_scale / (input.deployer_scale + 1.0), 0.5);
            let multiplier = if input.trial {
                match input.role {
                    LiquidityRole::Maker => self.schedule.multiplier_90,
                    LiquidityRole::Taker => self.schedule.multiplier_98,
                }
            } else {
                1.0
            };
            (share * input.rate, (1.0 - share) * input.rate, multiplier)
        } else {
            let multiplier = if input.trial && input.role == LiquidityRole::Maker {
                self.schedule.multiplier_90
            } else {
                1.0
            };
            (
                input.deployer_scale * input.rate,
                target_max(input.deployer_scale, 1.0) * input.rate,
                multiplier,
            )
        };
        protocol *= multiplier;
        protocol *= input.asset_scale;
        deployer *= input.asset_scale;
        if target_nonnegative(deployer) && target_nonnegative(protocol) {
            let discount = self.discount(input.payer, events);
            deployer *= 1.0 - discount;
            protocol *= 1.0 - discount;
        }
        PerpLeg { deployer, protocol }
    }

    fn spot_rate(
        &self,
        payer: Address,
        fill: SpotFill,
        rate: f64,
        previous: bool,
        events: &mut Vec<ArithmeticEvent>,
    ) -> f64 {
        let category = fill.category.0;
        let mut value = if category == 0 {
            rate
        } else if if previous {
            category == 1
        } else {
            category != 2
        } {
            rate / 5.0
        } else {
            target_max(rate, 0.0) * fill.category_weight
        };

        let positive_multiplier = if fill.aligned_quote && fill.role == LiquidityRole::Maker {
            self.schedule.multiplier_90
        } else {
            1.0
        };
        let negative_multiplier = if fill.aligned_quote && fill.role == LiquidityRole::Taker {
            self.schedule.multiplier_98
        } else {
            positive_multiplier
        };
        value *= if value < 0.0 {
            negative_multiplier
        } else {
            positive_multiplier
        };
        if value > 0.0 {
            value *= 1.0 - self.discount(payer, events);
        }
        value
    }

    fn builder_base(&self, builder: BuilderFee, notional: i64) -> u64 {
        target_i64(builder.rate_units as f64 / 100_000.0 * notional as f64).max(0) as u64
    }

    fn tier_gain(
        &self,
        payer: Address,
        beneficiary: Address,
        fee: i64,
        events: &mut Vec<ArithmeticEvent>,
    ) -> Result<u64, FeeError> {
        let top_anchor = self.resolve_row(beneficiary)?.anchor;
        let Some(top) = self.tier_step(top_anchor) else {
            return Ok(0);
        };
        if top == 0.0 {
            return Ok(0);
        }
        let (_, payer_anchor, weight) = self.window(payer, events);
        let low = self.tier_step(payer_anchor).unwrap_or(0.0);
        Ok(target_i64(fee as f64 * (weight * target_max(top - low, 0.0))).max(0) as u64)
    }

    fn referrer_credit(
        &self,
        payer: Address,
        fee: i64,
        flagged: bool,
        events: &mut Vec<ArithmeticEvent>,
    ) -> Result<Option<FeeRecipient>, FeeError> {
        if self.profiles.is_empty() {
            return Ok(None);
        }
        let Some(profile) = self.profiles.get(&payer) else {
            return Ok(None);
        };
        if profile.binding_flags & 1 == 0 {
            return Ok(None);
        }
        let address = profile
            .referrer
            .ok_or(FeeError::MissingReferrerAddress { owner: payer })?;
        let (sum, payer_anchor, weight) = self.window(payer, events);
        let share = if sum >= REFERRER_VOLUME_LIMIT {
            0.0
        } else if flagged {
            self.schedule.flagged_referrer_share
        } else {
            let top_anchor = self.resolve_row(address)?.anchor;
            let Some(top) = self.tier_step(top_anchor) else {
                return Ok(Some(FeeRecipient { address, amount: 0 }));
            };
            if top.partial_cmp(&0.0) != Some(std::cmp::Ordering::Greater) {
                0.0
            } else {
                let low = self.tier_step(payer_anchor).unwrap_or(0.0);
                target_max(weight * (top - low), 0.0)
            }
        };
        let amount = target_i64(fee as f64 * share).max(0) as u64;
        Ok(Some(FeeRecipient { address, amount }))
    }

    fn discount(&self, owner: Address, events: &mut Vec<ArithmeticEvent>) -> f64 {
        let Some(profile) = self.profiles.get(&owner) else {
            return 0.0;
        };
        if profile.binding_flags != 1 {
            return 0.0;
        }
        let sum = self.volume_sum(owner, profile, events);
        if sum < DISCOUNT_VOLUME_LIMIT {
            self.schedule.low_volume_discount
        } else {
            0.0
        }
    }

    fn window(&self, owner: Address, events: &mut Vec<ArithmeticEvent>) -> (u64, f64, f64) {
        let Some(profile) = self.profiles.get(&owner) else {
            return (0, 0.0, 1.0);
        };
        let sum = self.volume_sum(owner, profile, events);
        if profile.row_tag == 1 {
            (sum, profile.row.volume_anchor, profile.row.carried_weight)
        } else {
            (sum, 0.0, 1.0)
        }
    }

    fn volume_sum(
        &self,
        owner: Address,
        profile: &FeeProfile,
        events: &mut Vec<ArithmeticEvent>,
    ) -> u64 {
        let mut sum = 0_u64;
        for value in &profile.volume_words {
            sum = saturating_u64_add(
                sum,
                *value,
                ArithmeticEvent::WindowSumSaturated { owner },
                events,
            );
        }
        sum
    }

    fn tier_step(&self, anchor: f64) -> Option<f64> {
        let first = self.schedule.volume_tiers.first()?;
        if first.minimum_anchor > anchor {
            return None;
        }
        let mut share = first.share;
        for tier in &self.schedule.volume_tiers[1..] {
            if tier.minimum_anchor > anchor {
                break;
            }
            share = tier.share;
        }
        Some(share)
    }
}

fn target_nonnegative(value: f64) -> bool {
    value.partial_cmp(&0.0) != Some(std::cmp::Ordering::Less)
}
