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
    let mut actions = Vec::new();
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

        // (b) the oldest still-unconfirmed HS refund with the same amount, not
        // already claimed by an earlier reported refund in this same plan.
        let link_candidate = existing_refunds
            .iter()
            .filter(|refund| {
                refund.connector_refund_id.is_none()
                    && is_link_candidate_status(refund.status)
                    && refund.amount == reported.amount
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
        actions.push(RefundReconciliationAction::Create {
            refund_id: deterministic_refund_id(connector_name, &reported.connector_refund_id),
            connector_refund_id: reported.connector_refund_id.clone(),
            amount: reported.amount,
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
}
