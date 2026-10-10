//! Pure planning for reconciling refunds and disputes an aggregator connector
//! reports on a payment-sync response with what Hyperswitch already has on
//! file, for money movement the merchant performed directly on the
//! connector's own panel (see
//! `common_enums::connector_enums::Connector::syncs_refunds_and_disputes_on_payment_sync`
//! and `router_data::ConnectorReportedActivity`).
//!
//! Everything here is deliberately DB-free: it takes minimal, already-fetched
//! views of the existing state plus the reported activity, and returns the
//! actions the caller (the PSync post-update tracker, in `router`) should
//! apply. That keeps the reconciliation rules unit-testable without a
//! database and keeps the DB-touching code a thin, mechanical translation of
//! these actions into store calls.

use common_utils::types::MinorUnit;

use crate::router_data::{ConnectorReportedDispute, ConnectorReportedRefund};

/// Minimal, DB-agnostic view of an existing Hyperswitch refund on the payment
/// being synced — enough for [`plan_refund_reconciliation`] to reason about
/// without depending on the full Diesel `Refund` row.
#[derive(Debug, Clone)]
pub struct ExistingRefundView {
    pub refund_id: String,
    pub connector_refund_id: Option<String>,
    pub status: common_enums::enums::RefundStatus,
    pub amount: MinorUnit,
    pub created_at: time::PrimitiveDateTime,
}

/// What to do with one Hyperswitch refund, decided by
/// [`plan_refund_reconciliation`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefundReconciliationAction {
    /// An existing refund already carries this `connector_refund_id`: only its
    /// status needs to move to the terminal state the connector now reports.
    UpdateStatus {
        refund_id: String,
        status: common_enums::enums::RefundStatus,
    },
    /// An existing, still-unconfirmed refund (no `connector_refund_id` yet, same
    /// amount) is most likely the one the connector is now reporting — link the
    /// two instead of creating a duplicate. Covers e.g. a gateway timeout on a
    /// Hyperswitch-initiated refund that actually executed on the connector's
    /// side.
    Link {
        refund_id: String,
        connector_refund_id: String,
        status: common_enums::enums::RefundStatus,
    },
    /// Nothing in Hyperswitch accounts for this connector refund: create it
    /// with a deterministic id so concurrent syncs are idempotent (the DB's
    /// unique `(refund_id, merchant_id)` index turns a race into a duplicate
    /// insert the caller can safely ignore).
    Create {
        refund_id: String,
        connector_refund_id: String,
        amount: MinorUnit,
        status: common_enums::enums::RefundStatus,
    },
}

/// Non-terminal Hyperswitch refund statuses, i.e. ones a connector report may
/// still move forward.
///
/// `TransactionFailure` is terminal in this codebase, not non-terminal — see
/// `crates/router/src/core/refunds.rs`'s `terminal_status` list — despite the
/// name suggesting otherwise, so it is intentionally left out here.
fn is_non_terminal_refund_status(status: common_enums::enums::RefundStatus) -> bool {
    matches!(
        status,
        common_enums::enums::RefundStatus::Pending
            | common_enums::enums::RefundStatus::ManualReview
    )
}

fn is_terminal_reported_refund_status(status: common_enums::enums::RefundStatus) -> bool {
    matches!(
        status,
        common_enums::enums::RefundStatus::Success | common_enums::enums::RefundStatus::Failure
    )
}

/// Whether an existing, still-unconfirmed HS refund (no `connector_refund_id`
/// yet) is eligible to be linked to a reported refund with the same amount
/// (rule (b)).
///
/// Only "unknown outcome" statuses qualify: `Pending`/`ManualReview` (HS
/// never heard back at all) and `TransactionFailure` (the connector *call*
/// failed — a timeout, a network error — without HS ever getting a verdict
/// from the connector, which is exactly the "it actually executed anyway"
/// case this link is for). A refund the connector explicitly rejected
/// (`Failure`) or that HS already knows succeeded (`Success`) must never be
/// linked to a different connector refund id — those are conclusive
/// outcomes, not open questions.
fn is_link_candidate_status(status: common_enums::enums::RefundStatus) -> bool {
    matches!(
        status,
        common_enums::enums::RefundStatus::Pending
            | common_enums::enums::RefundStatus::ManualReview
            | common_enums::enums::RefundStatus::TransactionFailure
    )
}

/// The `refund_id` column is `VARCHAR(255)`
/// (`migrations/2022-09-29-084920_create_initial_tables/up.sql`), unique on
/// `(refund_id, merchant_id)`.
pub const REFUND_ID_COLUMN_MAX_LEN: usize = 255;

/// Deterministic refund id Hyperswitch assigns to a refund it discovers on
/// sync instead of one initiated through Hyperswitch: `ref_<connector>_<id>`,
/// falling back to a generated id when that would not fit the column.
pub fn deterministic_refund_id(connector_name: &str, connector_refund_id: &str) -> String {
    let candidate = format!("ref_{connector_name}_{connector_refund_id}");
    if candidate.len() <= REFUND_ID_COLUMN_MAX_LEN {
        candidate
    } else {
        common_utils::generate_id_with_default_len("ref")
    }
}

/// Plans the refund side of the reconciliation. See the action variants for
/// the exact rule each one implements.
///
/// A `connector_refund_id` reported more than once in the same call (the
/// connector should never do this, but the input is untrusted) is only
/// planned for once, using its first occurrence.
pub fn plan_refund_reconciliation(
    existing_refunds: &[ExistingRefundView],
    reported_refunds: &[ConnectorReportedRefund],
    connector_name: &str,
) -> Vec<RefundReconciliationAction> {
    plan_refund_reconciliation_for_payment(existing_refunds, reported_refunds, connector_name, None)
}

/// Whether an existing refund already took money out of the payment (or is about
/// to): the ones that count against the refundable total of a balance refund.
///
/// A `Pending` or `ManualReview` refund of Hyperswitch counts as taken on purpose: the
/// outcome is unknown, so reporting the balance as well could refund the same money
/// twice. The consequence is that such a refund BLOCKS the balance refund until it
/// resolves: while it is `Pending` the balance refund is a no-op, and it stays `Pending`
/// until its own refund sync (RSync) resolves it. If it ends in `Failure` it stops
/// counting and the next payment sync reports the balance again.
fn is_counted_against_balance(status: common_enums::enums::RefundStatus) -> bool {
    matches!(
        status,
        common_enums::enums::RefundStatus::Success
            | common_enums::enums::RefundStatus::Pending
            | common_enums::enums::RefundStatus::ManualReview
    )
}

/// Same as [`plan_refund_reconciliation`], additionally knowing the refundable
/// total of the payment, which reported refunds flagged
/// `amount_is_remaining_balance` need.
///
/// Such a refund (a connector that only says "voided / refunded in full") is
/// deduplicated by `connector_refund_id` like any other; otherwise its amount is
/// `payment_total` minus the refunds in Success, Pending or ManualReview (the
/// existing ones plus those this same plan creates). Nothing remaining means
/// Hyperswitch's own refunds already cover it: no action. Without a
/// `payment_total` a balance refund cannot be computed and is skipped.
///
/// The `amount` of a balance refund is ignored: it is always recomputed as above, so a
/// connector may leave it at any value (Payway sends the payment amount for reference).
/// A Pending/ManualReview refund of Hyperswitch counts against the balance (see
/// `is_counted_against_balance`), so it blocks the balance refund until it resolves.
///
/// A refund flagged `amount_is_cumulative_total` (a connector that reports how much of the
/// payment was refunded so far, e.g. Payway before the batch close) works the same way
/// with the reported `amount` as the total instead of `payment_total`: it is deduplicated
/// by `connector_refund_id` first, otherwise the amount recorded is the reported total
/// minus the refunds in Success, Pending or ManualReview (existing plus created by this
/// plan), nothing when they already cover it. The balance mode is the special case where
/// the cumulative total is the payment total. The connector must use a new
/// `connector_refund_id` for every new cumulative value so the next increase is recorded;
/// a Pending refund of Hyperswitch blocks the increase until it resolves, as above.
pub fn plan_refund_reconciliation_for_payment(
    existing_refunds: &[ExistingRefundView],
    reported_refunds: &[ConnectorReportedRefund],
    connector_name: &str,
    payment_total: Option<MinorUnit>,
) -> Vec<RefundReconciliationAction> {
    let mut actions = Vec::new();
    let mut planned_creates_total: i64 = 0;
    let mut consumed_link_candidates: std::collections::HashSet<&str> =
        std::collections::HashSet::new();
    let mut seen_connector_refund_ids: std::collections::HashSet<&str> =
        std::collections::HashSet::new();

    for reported in reported_refunds {
        if !seen_connector_refund_ids.insert(reported.connector_refund_id.as_str()) {
            continue;
        }

        // (a) an existing refund already carries this connector_refund_id.
        if let Some(existing) = existing_refunds.iter().find(|refund| {
            refund.connector_refund_id.as_deref() == Some(reported.connector_refund_id.as_str())
        }) {
            if is_non_terminal_refund_status(existing.status)
                && is_terminal_reported_refund_status(reported.status)
            {
                actions.push(RefundReconciliationAction::UpdateStatus {
                    refund_id: existing.refund_id.clone(),
                    status: reported.status,
                });
            }
            continue;
        }

        // The refunded total this report stands for, when it is not a plain refund: the
        // payment total for a balance refund, the reported amount for a cumulative one.
        let cumulative_total = if reported.amount_is_remaining_balance {
            let Some(payment_total) = payment_total else {
                continue;
            };
            Some(payment_total)
        } else if reported.amount_is_cumulative_total {
            Some(reported.amount)
        } else {
            None
        };
        let amount = match cumulative_total {
            Some(cumulative_total) => {
                let already_refunded: i64 = existing_refunds
                    .iter()
                    .filter(|refund| is_counted_against_balance(refund.status))
                    .map(|refund| refund.amount.get_amount_as_i64())
                    .sum();
                let remaining =
                    cumulative_total.get_amount_as_i64() - already_refunded - planned_creates_total;
                if remaining <= 0 {
                    continue;
                }
                MinorUnit::new(remaining)
            }
            None => reported.amount,
        };

        // (b) the oldest still-unconfirmed HS refund with the same amount, not
        // already claimed by an earlier reported refund in this same plan.
        let link_candidate = existing_refunds
            .iter()
            .filter(|refund| {
                refund.connector_refund_id.is_none()
                    && is_link_candidate_status(refund.status)
                    && refund.amount == amount
                    && !consumed_link_candidates.contains(refund.refund_id.as_str())
            })
            .min_by_key(|refund| refund.created_at);

        if let Some(existing) = link_candidate {
            consumed_link_candidates.insert(existing.refund_id.as_str());
            actions.push(RefundReconciliationAction::Link {
                refund_id: existing.refund_id.clone(),
                connector_refund_id: reported.connector_refund_id.clone(),
                status: reported.status,
            });
            continue;
        }

        // (c) nothing accounts for it: create it.
        planned_creates_total += amount.get_amount_as_i64();
        actions.push(RefundReconciliationAction::Create {
            refund_id: deterministic_refund_id(connector_name, &reported.connector_refund_id),
            connector_refund_id: reported.connector_refund_id.clone(),
            amount,
            status: reported.status,
        });
    }

    actions
}

/// Minimal, DB-agnostic view of an existing Hyperswitch dispute already
/// matched (by the caller) to a reported dispute's `connector_dispute_id`.
#[derive(Debug, Clone)]
pub struct ExistingDisputeView {
    pub stage: common_enums::enums::DisputeStage,
    pub status: common_enums::enums::DisputeStatus,
}

/// What to do with the dispute Hyperswitch may or may not already have for
/// this `connector_dispute_id`, decided by [`plan_dispute_reconciliation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisputeReconciliationAction {
    /// No dispute exists for this `connector_dispute_id` yet.
    Create,
    /// A non-terminal dispute exists and its status or stage changed.
    Update {
        status: common_enums::enums::DisputeStatus,
        stage: common_enums::enums::DisputeStage,
    },
    /// Either nothing changed, or the existing dispute is terminal — a
    /// terminal dispute is never modified by a payment sync.
    NoOp,
}

/// Terminal `DisputeStatus` values are never touched again by a payment sync.
/// `DisputeOpened` and `DisputeChallenged` are the only non-terminal states.
fn is_terminal_dispute_status(status: common_enums::enums::DisputeStatus) -> bool {
    !matches!(
        status,
        common_enums::enums::DisputeStatus::DisputeOpened
            | common_enums::enums::DisputeStatus::DisputeChallenged
    )
}

/// Plans the dispute side of the reconciliation. `existing` must already be
/// the Hyperswitch dispute matching `reported.connector_dispute_id`, if any
/// (the caller looks it up; this function stays DB-free).
pub fn plan_dispute_reconciliation(
    existing: Option<&ExistingDisputeView>,
    reported: &ConnectorReportedDispute,
) -> DisputeReconciliationAction {
    match existing {
        None => DisputeReconciliationAction::Create,
        Some(existing) if is_terminal_dispute_status(existing.status) => {
            DisputeReconciliationAction::NoOp
        }
        // The merchant already submitted evidence (`DisputeChallenged`). MP's
        // payment object can only report the chargeback as still open
        // (`in_process` -> `DisputeOpened`) or resolved (`settled`/
        // `reimbursed`); it has no notion of "challenged". A reported
        // `DisputeOpened` here reflects a sync that simply predates HS's own
        // more advanced state — never regress `DisputeChallenged` back to
        // `DisputeOpened`. A resolution (Won/Lost) still applies below.
        Some(existing)
            if existing.status == common_enums::enums::DisputeStatus::DisputeChallenged
                && reported.status == common_enums::enums::DisputeStatus::DisputeOpened =>
        {
            DisputeReconciliationAction::NoOp
        }
        Some(existing)
            if existing.status != reported.status || existing.stage != reported.stage =>
        {
            DisputeReconciliationAction::Update {
                status: reported.status,
                stage: reported.stage,
            }
        }
        Some(_) => DisputeReconciliationAction::NoOp,
    }
}

#[cfg(test)]
mod tests {
    use common_enums::enums::{DisputeStage, DisputeStatus, RefundStatus};

    use super::*;

    /// Builds a `PrimitiveDateTime` for day `day` of January 2026, without
    /// needing the `time` crate's `macros` feature (not enabled for this
    /// crate) just for test fixtures.
    fn dt(day: u8) -> time::PrimitiveDateTime {
        time::PrimitiveDateTime::new(
            time::Date::from_calendar_date(2026, time::Month::January, day)
                .expect("valid test date"),
            time::Time::MIDNIGHT,
        )
    }

    fn reported_refund(
        connector_refund_id: &str,
        amount: i64,
        status: RefundStatus,
    ) -> ConnectorReportedRefund {
        ConnectorReportedRefund {
            connector_refund_id: connector_refund_id.to_string(),
            amount: MinorUnit::new(amount),
            status,
            amount_is_remaining_balance: false,
            amount_is_cumulative_total: false,
        }
    }

    fn cumulative_refund(connector_refund_id: &str, total: i64) -> ConnectorReportedRefund {
        ConnectorReportedRefund {
            amount_is_cumulative_total: true,
            ..reported_refund(connector_refund_id, total, RefundStatus::Success)
        }
    }

    fn balance_refund(connector_refund_id: &str, status: RefundStatus) -> ConnectorReportedRefund {
        ConnectorReportedRefund {
            // Ignored for a balance refund; deliberately wrong to prove it.
            amount: MinorUnit::new(1),
            amount_is_remaining_balance: true,
            ..reported_refund(connector_refund_id, 1, status)
        }
    }

    fn existing_refund(
        refund_id: &str,
        connector_refund_id: Option<&str>,
        status: RefundStatus,
        amount: i64,
        created_at: time::PrimitiveDateTime,
    ) -> ExistingRefundView {
        ExistingRefundView {
            refund_id: refund_id.to_string(),
            connector_refund_id: connector_refund_id.map(str::to_string),
            status,
            amount: MinorUnit::new(amount),
            created_at,
        }
    }

    #[test]
    fn creates_refund_when_nothing_matches() {
        let reported = vec![reported_refund("cr_1", 1000, RefundStatus::Success)];
        let actions = plan_refund_reconciliation(&[], &reported, "mercadopago");
        assert_eq!(
            actions,
            vec![RefundReconciliationAction::Create {
                refund_id: "ref_mercadopago_cr_1".to_string(),
                connector_refund_id: "cr_1".to_string(),
                amount: MinorUnit::new(1000),
                status: RefundStatus::Success,
            }]
        );
    }

    #[test]
    fn updates_status_when_connector_refund_id_already_tracked_and_non_terminal() {
        let existing = vec![existing_refund(
            "ref_1",
            Some("cr_1"),
            RefundStatus::Pending,
            1000,
            dt(1),
        )];
        let reported = vec![reported_refund("cr_1", 1000, RefundStatus::Success)];
        let actions = plan_refund_reconciliation(&existing, &reported, "mercadopago");
        assert_eq!(
            actions,
            vec![RefundReconciliationAction::UpdateStatus {
                refund_id: "ref_1".to_string(),
                status: RefundStatus::Success,
            }]
        );
    }

    #[test]
    fn no_op_when_existing_refund_already_terminal() {
        let existing = vec![existing_refund(
            "ref_1",
            Some("cr_1"),
            RefundStatus::Success,
            1000,
            dt(1),
        )];
        let reported = vec![reported_refund("cr_1", 1000, RefundStatus::Success)];
        let actions = plan_refund_reconciliation(&existing, &reported, "mercadopago");
        assert!(actions.is_empty());
    }

    #[test]
    fn transaction_failure_is_treated_as_terminal_and_is_not_updated() {
        // Regression guard: TransactionFailure reads like a non-terminal name but
        // is terminal in this codebase (crates/router/src/core/refunds.rs).
        let existing = vec![existing_refund(
            "ref_1",
            Some("cr_1"),
            RefundStatus::TransactionFailure,
            1000,
            dt(1),
        )];
        let reported = vec![reported_refund("cr_1", 1000, RefundStatus::Success)];
        let actions = plan_refund_reconciliation(&existing, &reported, "mercadopago");
        assert!(actions.is_empty());
    }

    #[test]
    fn no_op_when_reported_status_is_not_terminal() {
        let existing = vec![existing_refund(
            "ref_1",
            Some("cr_1"),
            RefundStatus::Pending,
            1000,
            dt(1),
        )];
        let reported = vec![reported_refund("cr_1", 1000, RefundStatus::Pending)];
        let actions = plan_refund_reconciliation(&existing, &reported, "mercadopago");
        assert!(actions.is_empty());
    }

    #[test]
    fn links_oldest_unconfirmed_refund_with_same_amount() {
        let existing = vec![
            existing_refund("ref_newer", None, RefundStatus::Pending, 1000, dt(2)),
            existing_refund("ref_older", None, RefundStatus::Pending, 1000, dt(1)),
        ];
        let reported = vec![reported_refund("cr_1", 1000, RefundStatus::Success)];
        let actions = plan_refund_reconciliation(&existing, &reported, "mercadopago");
        assert_eq!(
            actions,
            vec![RefundReconciliationAction::Link {
                refund_id: "ref_older".to_string(),
                connector_refund_id: "cr_1".to_string(),
                status: RefundStatus::Success,
            }]
        );
    }

    #[test]
    fn two_unconfirmed_refunds_same_amount_link_to_different_reports() {
        let existing = vec![
            existing_refund("ref_older", None, RefundStatus::Pending, 1000, dt(1)),
            existing_refund("ref_newer", None, RefundStatus::Pending, 1000, dt(2)),
        ];
        let reported = vec![
            reported_refund("cr_1", 1000, RefundStatus::Success),
            reported_refund("cr_2", 1000, RefundStatus::Success),
        ];
        let actions = plan_refund_reconciliation(&existing, &reported, "mercadopago");
        assert_eq!(
            actions,
            vec![
                RefundReconciliationAction::Link {
                    refund_id: "ref_older".to_string(),
                    connector_refund_id: "cr_1".to_string(),
                    status: RefundStatus::Success,
                },
                RefundReconciliationAction::Link {
                    refund_id: "ref_newer".to_string(),
                    connector_refund_id: "cr_2".to_string(),
                    status: RefundStatus::Success,
                },
            ]
        );
    }

    #[test]
    fn does_not_link_a_refund_with_a_different_amount() {
        let existing = vec![existing_refund(
            "ref_1",
            None,
            RefundStatus::Pending,
            500,
            dt(1),
        )];
        let reported = vec![reported_refund("cr_1", 1000, RefundStatus::Success)];
        let actions = plan_refund_reconciliation(&existing, &reported, "mercadopago");
        assert_eq!(
            actions,
            vec![RefundReconciliationAction::Create {
                refund_id: "ref_mercadopago_cr_1".to_string(),
                connector_refund_id: "cr_1".to_string(),
                amount: MinorUnit::new(1000),
                status: RefundStatus::Success,
            }]
        );
    }

    #[test]
    fn does_not_link_a_refund_the_connector_explicitly_rejected() {
        // Failure is a conclusive outcome, not an "unknown" one: a Failure
        // refund must never be linked to a different connector refund id —
        // the reported one is a genuinely different refund and must be
        // created instead.
        let existing = vec![existing_refund(
            "ref_1",
            None,
            RefundStatus::Failure,
            1000,
            dt(1),
        )];
        let reported = vec![reported_refund("cr_1", 1000, RefundStatus::Success)];
        let actions = plan_refund_reconciliation(&existing, &reported, "mercadopago");
        assert_eq!(
            actions,
            vec![RefundReconciliationAction::Create {
                refund_id: "ref_mercadopago_cr_1".to_string(),
                connector_refund_id: "cr_1".to_string(),
                amount: MinorUnit::new(1000),
                status: RefundStatus::Success,
            }]
        );
    }

    #[test]
    fn links_a_refund_whose_connector_call_failed_without_a_verdict() {
        // TransactionFailure means the connector *call* failed (timeout,
        // network error) without HS ever getting a verdict — exactly the
        // "it actually executed on the connector's side anyway" case the
        // link rule exists for.
        let existing = vec![existing_refund(
            "ref_1",
            None,
            RefundStatus::TransactionFailure,
            1000,
            dt(1),
        )];
        let reported = vec![reported_refund("cr_1", 1000, RefundStatus::Success)];
        let actions = plan_refund_reconciliation(&existing, &reported, "mercadopago");
        assert_eq!(
            actions,
            vec![RefundReconciliationAction::Link {
                refund_id: "ref_1".to_string(),
                connector_refund_id: "cr_1".to_string(),
                status: RefundStatus::Success,
            }]
        );
    }

    #[test]
    fn duplicate_reported_connector_refund_ids_are_planned_once() {
        let reported = vec![
            reported_refund("cr_1", 1000, RefundStatus::Success),
            reported_refund("cr_1", 1000, RefundStatus::Success),
        ];
        let actions = plan_refund_reconciliation(&[], &reported, "mercadopago");
        assert_eq!(actions.len(), 1);
    }

    #[test]
    fn deterministic_id_falls_back_to_generated_when_too_long() {
        let long_id = "x".repeat(300);
        let id = deterministic_refund_id("mercadopago", &long_id);
        assert!(id.len() <= REFUND_ID_COLUMN_MAX_LEN);
        assert!(!id.contains(&long_id));
    }

    fn reported_dispute(status: DisputeStatus, stage: DisputeStage) -> ConnectorReportedDispute {
        ConnectorReportedDispute {
            connector_dispute_id: "168355689156".to_string(),
            stage,
            status,
            connector_status: "charged_back".to_string(),
            amount: MinorUnit::new(1000),
            currency: common_enums::enums::Currency::ARS,
            reason: None,
        }
    }

    #[test]
    fn creates_dispute_when_missing() {
        let reported = reported_dispute(DisputeStatus::DisputeOpened, DisputeStage::Dispute);
        let action = plan_dispute_reconciliation(None, &reported);
        assert_eq!(action, DisputeReconciliationAction::Create);
    }

    #[test]
    fn updates_dispute_when_non_terminal_and_status_changed() {
        let existing = ExistingDisputeView {
            stage: DisputeStage::Dispute,
            status: DisputeStatus::DisputeOpened,
        };
        let reported = reported_dispute(DisputeStatus::DisputeLost, DisputeStage::Dispute);
        let action = plan_dispute_reconciliation(Some(&existing), &reported);
        assert_eq!(
            action,
            DisputeReconciliationAction::Update {
                status: DisputeStatus::DisputeLost,
                stage: DisputeStage::Dispute,
            }
        );
    }

    #[test]
    fn no_op_when_terminal_dispute_is_never_touched() {
        let existing = ExistingDisputeView {
            stage: DisputeStage::Dispute,
            status: DisputeStatus::DisputeLost,
        };
        let reported = reported_dispute(DisputeStatus::DisputeWon, DisputeStage::Dispute);
        let action = plan_dispute_reconciliation(Some(&existing), &reported);
        assert_eq!(action, DisputeReconciliationAction::NoOp);
    }

    #[test]
    fn no_op_when_nothing_changed() {
        let existing = ExistingDisputeView {
            stage: DisputeStage::Dispute,
            status: DisputeStatus::DisputeOpened,
        };
        let reported = reported_dispute(DisputeStatus::DisputeOpened, DisputeStage::Dispute);
        let action = plan_dispute_reconciliation(Some(&existing), &reported);
        assert_eq!(action, DisputeReconciliationAction::NoOp);
    }

    #[test]
    fn never_regresses_challenged_dispute_back_to_opened() {
        // The merchant already submitted evidence; MP's payment object has
        // no "challenged" concept and would otherwise report this as still
        // open — that must not undo the merchant's own progress.
        let existing = ExistingDisputeView {
            stage: DisputeStage::Dispute,
            status: DisputeStatus::DisputeChallenged,
        };
        let reported = reported_dispute(DisputeStatus::DisputeOpened, DisputeStage::Dispute);
        let action = plan_dispute_reconciliation(Some(&existing), &reported);
        assert_eq!(action, DisputeReconciliationAction::NoOp);
    }

    #[test]
    fn challenged_dispute_still_resolves_to_won_or_lost() {
        let existing = ExistingDisputeView {
            stage: DisputeStage::Dispute,
            status: DisputeStatus::DisputeChallenged,
        };
        let reported = reported_dispute(DisputeStatus::DisputeWon, DisputeStage::Dispute);
        let action = plan_dispute_reconciliation(Some(&existing), &reported);
        assert_eq!(
            action,
            DisputeReconciliationAction::Update {
                status: DisputeStatus::DisputeWon,
                stage: DisputeStage::Dispute,
            }
        );

        let reported = reported_dispute(DisputeStatus::DisputeLost, DisputeStage::Dispute);
        let action = plan_dispute_reconciliation(Some(&existing), &reported);
        assert_eq!(
            action,
            DisputeReconciliationAction::Update {
                status: DisputeStatus::DisputeLost,
                stage: DisputeStage::Dispute,
            }
        );
    }

    fn plan_balance(
        existing: &[ExistingRefundView],
        total: i64,
    ) -> Vec<RefundReconciliationAction> {
        plan_refund_reconciliation_for_payment(
            existing,
            &[balance_refund("annulment_77", RefundStatus::Success)],
            "payway",
            Some(MinorUnit::new(total)),
        )
    }

    fn balance_create(amount: i64) -> RefundReconciliationAction {
        RefundReconciliationAction::Create {
            refund_id: "ref_payway_annulment_77".to_string(),
            connector_refund_id: "annulment_77".to_string(),
            amount: MinorUnit::new(amount),
            status: RefundStatus::Success,
        }
    }

    #[test]
    fn balance_refund_without_existing_refunds_creates_the_full_amount() {
        assert_eq!(plan_balance(&[], 10_000), vec![balance_create(10_000)]);
    }

    #[test]
    fn balance_refund_is_a_no_op_when_a_succeeded_total_refund_exists() {
        let existing = vec![existing_refund(
            "ref_1",
            Some("5"),
            RefundStatus::Success,
            10_000,
            dt(1),
        )];
        assert!(plan_balance(&existing, 10_000).is_empty());
    }

    #[test]
    fn balance_refund_creates_only_what_is_left_after_a_partial_refund() {
        let existing = vec![existing_refund(
            "ref_1",
            Some("5"),
            RefundStatus::Success,
            3_000,
            dt(1),
        )];
        assert_eq!(plan_balance(&existing, 10_000), vec![balance_create(7_000)]);
    }

    #[test]
    fn balance_refund_is_a_no_op_when_a_pending_refund_covers_the_total() {
        let existing = vec![existing_refund(
            "ref_1",
            None,
            RefundStatus::Pending,
            10_000,
            dt(1),
        )];
        assert!(plan_balance(&existing, 10_000).is_empty());
        let manual_review = vec![existing_refund(
            "ref_2",
            None,
            RefundStatus::ManualReview,
            10_000,
            dt(1),
        )];
        assert!(plan_balance(&manual_review, 10_000).is_empty());
    }

    #[test]
    fn balance_refund_ignores_failed_refunds() {
        let existing = vec![
            existing_refund("ref_1", Some("5"), RefundStatus::Failure, 10_000, dt(1)),
            existing_refund("ref_2", Some("6"), RefundStatus::Failure, 4_000, dt(2)),
        ];
        assert_eq!(
            plan_balance(&existing, 10_000),
            vec![balance_create(10_000)]
        );
    }

    #[test]
    fn balance_refund_already_created_is_deduplicated_by_connector_refund_id() {
        let existing = vec![existing_refund(
            "ref_payway_annulment_77",
            Some("annulment_77"),
            RefundStatus::Success,
            7_000,
            dt(1),
        )];
        // The created refund counts against the total, and the id match comes first.
        assert!(plan_balance(&existing, 10_000).is_empty());

        let pending = vec![existing_refund(
            "ref_payway_annulment_77",
            Some("annulment_77"),
            RefundStatus::Pending,
            7_000,
            dt(1),
        )];
        assert_eq!(
            plan_balance(&pending, 10_000),
            vec![RefundReconciliationAction::UpdateStatus {
                refund_id: "ref_payway_annulment_77".to_string(),
                status: RefundStatus::Success,
            }]
        );
    }

    #[test]
    fn balance_refund_links_an_unconfirmed_refund_with_the_computed_amount() {
        let existing = vec![
            existing_refund("ref_1", Some("5"), RefundStatus::Success, 3_000, dt(1)),
            existing_refund(
                "ref_2",
                None,
                RefundStatus::TransactionFailure,
                7_000,
                dt(2),
            ),
        ];
        assert_eq!(
            plan_balance(&existing, 10_000),
            vec![RefundReconciliationAction::Link {
                refund_id: "ref_2".to_string(),
                connector_refund_id: "annulment_77".to_string(),
                status: RefundStatus::Success,
            }]
        );
    }

    #[test]
    fn balance_refund_without_a_payment_total_is_skipped() {
        let actions = plan_refund_reconciliation_for_payment(
            &[],
            &[balance_refund("annulment_77", RefundStatus::Success)],
            "payway",
            None,
        );
        assert!(actions.is_empty());
    }

    #[test]
    fn explicit_amount_refunds_ignore_the_payment_total() {
        let reported = vec![reported_refund("cr_1", 1000, RefundStatus::Success)];
        assert_eq!(
            plan_refund_reconciliation_for_payment(
                &[],
                &reported,
                "mercadopago",
                Some(MinorUnit::new(5)),
            ),
            plan_refund_reconciliation(&[], &reported, "mercadopago")
        );
    }

    fn plan_cumulative(
        existing: &[ExistingRefundView],
        id: &str,
        total: i64,
    ) -> Vec<RefundReconciliationAction> {
        plan_refund_reconciliation_for_payment(
            existing,
            &[cumulative_refund(id, total)],
            "payway",
            Some(MinorUnit::new(10_000)),
        )
    }

    fn cumulative_create(id: &str, amount: i64) -> RefundReconciliationAction {
        RefundReconciliationAction::Create {
            refund_id: format!("ref_payway_{id}"),
            connector_refund_id: id.to_string(),
            amount: MinorUnit::new(amount),
            status: RefundStatus::Success,
        }
    }

    #[test]
    fn cumulative_total_without_refunds_creates_the_whole_total() {
        assert_eq!(
            plan_cumulative(&[], "partial_77_3000", 3_000),
            vec![cumulative_create("partial_77_3000", 3_000)]
        );
    }

    #[test]
    fn cumulative_total_is_a_no_op_when_an_own_refund_already_covers_it() {
        let existing = vec![existing_refund(
            "ref_1",
            Some("5"),
            RefundStatus::Success,
            3_000,
            dt(1),
        )];
        assert!(plan_cumulative(&existing, "partial_77_3000", 3_000).is_empty());
    }

    #[test]
    fn cumulative_total_records_only_the_increase_over_a_previous_report() {
        let existing = vec![existing_refund(
            "ref_payway_partial_77_3000",
            Some("partial_77_3000"),
            RefundStatus::Success,
            3_000,
            dt(1),
        )];
        assert_eq!(
            plan_cumulative(&existing, "partial_77_5000", 5_000),
            vec![cumulative_create("partial_77_5000", 2_000)]
        );
        // The earlier value is deduplicated by its connector refund id.
        assert!(plan_cumulative(&existing, "partial_77_3000", 3_000).is_empty());
    }

    #[test]
    fn cumulative_total_is_blocked_by_a_pending_own_refund() {
        let existing = vec![existing_refund(
            "ref_1",
            None,
            RefundStatus::Pending,
            3_000,
            dt(1),
        )];
        assert!(plan_cumulative(&existing, "partial_77_3000", 3_000).is_empty());
    }

    #[test]
    fn cumulative_total_ignores_failed_refunds_and_does_not_need_a_payment_total() {
        let existing = vec![existing_refund(
            "ref_1",
            Some("5"),
            RefundStatus::Failure,
            3_000,
            dt(1),
        )];
        let actions = plan_refund_reconciliation_for_payment(
            &existing,
            &[cumulative_refund("partial_77_3000", 3_000)],
            "payway",
            None,
        );
        assert_eq!(actions, vec![cumulative_create("partial_77_3000", 3_000)]);
    }

    #[test]
    fn cumulative_total_subtracts_an_own_smaller_refund() {
        let existing = vec![existing_refund(
            "ref_1",
            Some("5"),
            RefundStatus::Success,
            1_000,
            dt(1),
        )];
        assert_eq!(
            plan_cumulative(&existing, "partial_77_3000", 3_000),
            vec![cumulative_create("partial_77_3000", 2_000)]
        );
    }
}
