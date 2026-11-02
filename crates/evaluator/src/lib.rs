//! Independent reference evaluator (architecture §4.5, layer 1).
//!
//! Evaluates a [`ValidatedSpec`] as a pure predicate over a candidate invocation. This
//! crate is the executable specification for codegen and MUST NOT depend on the codegen
//! crate or the template pack — that independence is what makes differential testing
//! meaningful, and `scripts/check-dep-rules.sh` enforces it structurally.
//!
//! Check order mirrors the generated-code contract (§4.4): signer predicate first
//! (including strict signer-set), then context/function/tuple scoping, then stateful
//! invariants. Missing state denies; nothing defaults open.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use ozpb_domain::LedgerSeq;
use ozpb_policy_spec::{
    signer_set_hash, AddressRef, Constraint, PolicyRef, PredicateKind, SignerSpec, StateSpec,
    ValidatedSpec,
};
use serde::{Deserialize, Serialize};
use stellar_xdr::{Limits, ScAddress, ScVal, WriteXdr};

pub mod spending_limit;

/// A candidate invocation, as the smart account's `__check_auth` would observe it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invocation {
    /// Target contract (C-address strkey).
    pub contract: String,
    pub fn_name: String,
    pub args: Vec<ArgValue>,
}

/// Argument values in the simplified evaluation model.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ArgValue {
    Address(String),
    I128(#[serde(with = "ozpb_domain::wide_int")] i128),
    /// Any other value: canonical ScVal XDR, base64.
    ScvalXdr(String),
}

/// Evaluation context: everything the account/policy would see at enforcement time.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalContext {
    /// The smart account address — resolves the spec's `SELF` marker at runtime (§4.4).
    pub smart_account: String,
    pub current_ledger: LedgerSeq,
    /// Signers that actually authenticated for this authorization.
    pub authenticated_signers: Vec<SignerSpec>,
    /// The rule's live signer set as stored on-chain (strict-mode comparison input).
    pub rule_live_signers: Vec<SignerSpec>,
    /// Calls consumed so far in this installation; `None` models missing/unavailable state.
    pub call_count_so_far: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Permit,
    Deny(DenyReason),
    Indeterminate(IndeterminateReason),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum IndeterminateReason {
    #[error("one or more reviewed policies are outside the Phase 1 reference model")]
    ReviewedPoliciesUnmodeled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    #[error("no rule covers this contract (default-deny)")]
    NoMatchingRule,
    #[error("rule expired (valid_until passed)")]
    RuleExpired,
    #[error("zero authenticated signers")]
    ZeroSigners,
    #[error("signer predicate unsatisfied")]
    PredicateUnsatisfied,
    #[error("strict mode: live rule signer set diverged from the granted set")]
    SignerSetDiverged,
    #[error("function not allowed on this contract")]
    FunctionNotAllowed,
    #[error("no allowed-call tuple matched the arguments")]
    NoTupleMatched,
    #[error("call count for this installation exhausted")]
    CallCountExceeded,
    #[error("required policy state missing or unavailable (missing state denies)")]
    MissingState,
}

/// Evaluate the spec as a pure predicate. Multiple rules may cover the same contract:
/// the invocation is permitted iff at least one rule permits it; otherwise the first
/// (deterministic) denial is returned.
pub fn evaluate(spec: &ValidatedSpec, ctx: &EvalContext, inv: &Invocation) -> Verdict {
    let mut first_denial: Option<DenyReason> = None;
    let mut unmodeled_permit = false;
    let mut any_rule = false;

    for rule in &spec.spec().rules {
        if rule.context.contract != inv.contract {
            continue;
        }
        any_rule = true;
        match evaluate_rule_inner(rule, ctx, inv) {
            Ok(()) => {
                if rule
                    .policies
                    .iter()
                    .any(|policy| matches!(policy, PolicyRef::Reviewed { .. }))
                {
                    // Reviewed policies are composed conjunctively with the generated scope
                    // policy. Scope denial is therefore conclusive, but scope permission is not:
                    // the upstream policy may still deny for state this evaluator does not model.
                    unmodeled_permit = true;
                } else {
                    return Verdict::Permit;
                }
            }
            Err(reason) => {
                if first_denial.is_none() {
                    first_denial = Some(reason);
                }
            }
        }
    }

    if unmodeled_permit {
        return Verdict::Indeterminate(IndeterminateReason::ReviewedPoliciesUnmodeled);
    }
    match (any_rule, first_denial) {
        (false, _) => Verdict::Deny(DenyReason::NoMatchingRule),
        (true, Some(reason)) => Verdict::Deny(reason),
        // Unreachable: a matching rule either permits or yields a reason.
        (true, None) => Verdict::Deny(DenyReason::NoMatchingRule),
    }
}

/// Evaluate exactly the generated scope/count policy of one rule. Reviewed policies are
/// deliberately excluded. The differential harness uses this entry point because it compares
/// against that generated contract, not against upstream contracts it did not execute.
pub fn evaluate_generated_rule(
    rule: &ozpb_policy_spec::RuleSpec,
    ctx: &EvalContext,
    inv: &Invocation,
) -> Verdict {
    if rule.context.contract != inv.contract {
        return Verdict::Deny(DenyReason::NoMatchingRule);
    }
    match evaluate_rule_inner(rule, ctx, inv) {
        Ok(()) => Verdict::Permit,
        Err(reason) => Verdict::Deny(reason),
    }
}

fn evaluate_rule_inner(
    rule: &ozpb_policy_spec::RuleSpec,
    ctx: &EvalContext,
    inv: &Invocation,
) -> Result<(), DenyReason> {
    // 0a. Rule lifetime.
    if let Some(vu) = &rule.valid_until {
        if ctx.current_ledger.0 > vu.ledger.0 {
            return Err(DenyReason::RuleExpired);
        }
    }

    // 0b. SIGNER PREDICATE — always first (§4.4). An unchecked signer list would let
    // anyone authorize with zero signatures, because the account defers signer
    // validation to policies whenever a rule has policies attached.
    if ctx.authenticated_signers.is_empty() {
        return Err(DenyReason::ZeroSigners);
    }
    let auth = &rule.authorization;
    match &auth.kind {
        PredicateKind::AnyOf => {
            let matched = count_matched(&ctx.authenticated_signers, &auth.signers);
            if matched < 1 {
                return Err(DenyReason::PredicateUnsatisfied);
            }
        }
        PredicateKind::AllOf => {
            let matched = count_matched(&ctx.authenticated_signers, &auth.signers);
            if matched < auth.signers.len() {
                return Err(DenyReason::PredicateUnsatisfied);
            }
        }
        PredicateKind::Threshold { n } => {
            let matched = count_matched(&ctx.authenticated_signers, &auth.signers);
            if (matched as u32) < *n {
                return Err(DenyReason::PredicateUnsatisfied);
            }
        }
        PredicateKind::AnyOfCurrentRuleSigners => {
            let matched = count_matched(&ctx.authenticated_signers, &ctx.rule_live_signers);
            if matched < 1 {
                return Err(DenyReason::PredicateUnsatisfied);
            }
        }
    }

    // 0c. Strict signer-set semantics (Decision D1): the live rule signer set must equal
    // the granted set, so later add_signer calls cannot silently broaden the grant.
    // Comparing the two `Result`s directly would fail open: two `Err`s are equal, so a signer
    // set that cannot be encoded would match every other one that cannot. Divergence is the
    // honest verdict when the sets cannot be shown to be the same — including when one of them
    // cannot be encoded at all.
    if auth.strict_signer_set {
        let diverged = match (
            signer_set_hash(&ctx.rule_live_signers),
            signer_set_hash(&auth.signers),
        ) {
            (Ok(live), Ok(granted)) => live != granted,
            _ => true,
        };
        if diverged {
            return Err(DenyReason::SignerSetDiverged);
        }
    }

    // The smart-account layer rejects signatures from identities outside the selected
    // rule before invoking any policy. Keep this after policy-specific signer checks so
    // the reference evaluator retains the generated policy's stable denial precedence.
    if ctx.authenticated_signers.iter().any(|signer| {
        !ctx.rule_live_signers
            .iter()
            .any(|live| same_signer_identity(signer, live))
    }) {
        return Err(DenyReason::PredicateUnsatisfied);
    }

    // 1+2. Function allowlist and complete-tuple matching (exact arg count).
    let fn_known = rule.allowed_calls.iter().any(|c| c.fn_name == inv.fn_name);
    if !fn_known {
        return Err(DenyReason::FunctionNotAllowed);
    }
    let tuple_ok = rule
        .allowed_calls
        .iter()
        .filter(|c| c.fn_name == inv.fn_name)
        .any(|call| tuple_matches(call, ctx, inv));
    if !tuple_ok {
        return Err(DenyReason::NoTupleMatched);
    }

    // 3. Stateful invariants: missing state denies; the cap never resets within an
    //    installation.
    for st in &rule.state {
        match st {
            StateSpec::CallCountPerInstallation { max_calls } => match ctx.call_count_so_far {
                None => return Err(DenyReason::MissingState),
                Some(count) if count >= *max_calls => return Err(DenyReason::CallCountExceeded),
                Some(_) => {}
            },
        }
    }

    Ok(())
}

fn count_matched(authenticated: &[SignerSpec], expected: &[SignerSpec]) -> usize {
    // Set-intersection semantics over the identity the account actually stores. In particular,
    // `verifier_code_hash` is not part of `Signer::External`; comparing the full off-chain enum
    // would incorrectly make authorization depend on a field the host never sees.
    let mut seen: Vec<&SignerSpec> = Vec::new();
    let mut matched = 0usize;
    for s in authenticated {
        if expected
            .iter()
            .any(|candidate| same_signer_identity(s, candidate))
            && !seen
                .iter()
                .any(|candidate| same_signer_identity(s, candidate))
        {
            seen.push(s);
            matched += 1;
        }
    }
    matched
}

fn same_signer_identity(left: &SignerSpec, right: &SignerSpec) -> bool {
    match (left, right) {
        (
            SignerSpec::Delegated {
                address: left_address,
            },
            SignerSpec::Delegated {
                address: right_address,
            },
        ) => left_address == right_address,
        (
            SignerSpec::External {
                verifier: left_verifier,
                key_hex: left_key,
                ..
            },
            SignerSpec::External {
                verifier: right_verifier,
                key_hex: right_key,
                ..
            },
        ) => {
            left_verifier == right_verifier
                && hex::decode(left_key)
                    .ok()
                    .zip(hex::decode(right_key).ok())
                    .is_some_and(|(left, right)| left == right)
        }
        _ => false,
    }
}

fn tuple_matches(
    call: &ozpb_policy_spec::AllowedCall,
    ctx: &EvalContext,
    inv: &Invocation,
) -> bool {
    // Exact argument count: complete tuples only.
    if call.args.len() != inv.args.len() {
        return false;
    }
    call.args.iter().all(|ac| {
        inv.args
            .get(ac.index as usize)
            .is_some_and(|value| constraint_satisfied(&ac.constraint, ctx, value))
    })
}

fn constraint_satisfied(c: &Constraint, ctx: &EvalContext, value: &ArgValue) -> bool {
    match (c, value) {
        (Constraint::EqAddress { value: expected }, ArgValue::Address(actual)) => match expected {
            AddressRef::SelfAccount(_) => *actual == ctx.smart_account,
            AddressRef::Address(a) => actual == a,
        },
        (Constraint::EqI128 { value: expected }, ArgValue::I128(actual)) => expected
            .parse::<i128>()
            .map(|e| e == *actual)
            .unwrap_or(false),
        (Constraint::LeI128 { max }, ArgValue::I128(actual)) => {
            max.parse::<i128>().map(|m| *actual <= m).unwrap_or(false)
        }
        (Constraint::GeI128 { min }, ArgValue::I128(actual)) => {
            min.parse::<i128>().map(|m| *actual >= m).unwrap_or(false)
        }
        (Constraint::EqScval { xdr_base64 }, actual) => exact_xdr_matches(xdr_base64, actual),
        // Explicit maximal widening: any value at this position satisfies (arity is
        // enforced by the caller before indexing).
        (Constraint::AnyValue, _) => true,
        // Type mismatch between constraint and value: never satisfied (fail closed).
        _ => false,
    }
}

/// Exact-XDR constraints apply to every argument type, including values which
/// callers supply in typed form. Use the protocol codec independently of codegen.
fn exact_xdr_matches(expected: &str, actual: &ArgValue) -> bool {
    let value = match actual {
        ArgValue::ScvalXdr(encoded) => return expected == encoded,
        ArgValue::I128(value) => ScVal::from(*value),
        ArgValue::Address(value) => match value.parse::<ScAddress>() {
            Ok(address @ (ScAddress::Account(_) | ScAddress::Contract(_))) => {
                ScVal::Address(address)
            }
            _ => return false,
        },
    };
    // These fixed-size protocol values need at most 44 bytes of XDR.
    value
        .to_xdr_base64(Limits { depth: 8, len: 128 })
        .is_ok_and(|encoded| encoded == expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ozpb_policy_spec::fixtures::{self, subscription_spec};

    const AMOUNT: i128 = 500_000_000;

    fn validate_generated_only(mut spec: ozpb_policy_spec::PolicySpec) -> ValidatedSpec {
        spec.rules[0]
            .policies
            .retain(|policy| matches!(policy, PolicyRef::Generated { .. }));
        spec.validate().unwrap()
    }

    fn validated() -> ValidatedSpec {
        validate_generated_only(subscription_spec())
    }

    fn delegate() -> SignerSpec {
        SignerSpec::Delegated {
            address: fixtures::DELEGATE.to_string(),
        }
    }

    fn stranger() -> SignerSpec {
        SignerSpec::Delegated {
            // A real, checksum-valid G-address distinct from the delegated signer. Validation
            // now rejects mnemonic lookalikes before evaluation.
            address: fixtures::MERCHANT.to_string(),
        }
    }

    fn base_ctx() -> EvalContext {
        EvalContext {
            smart_account: fixtures::ACCOUNT.to_string(),
            current_ledger: LedgerSeq(4_200_000),
            authenticated_signers: vec![delegate()],
            rule_live_signers: vec![delegate()],
            call_count_so_far: Some(0),
        }
    }

    fn original_invocation() -> Invocation {
        Invocation {
            contract: fixtures::TOKEN.to_string(),
            fn_name: "transfer".to_string(),
            args: vec![
                ArgValue::Address(fixtures::ACCOUNT.to_string()),
                ArgValue::Address(fixtures::MERCHANT.to_string()),
                ArgValue::I128(AMOUNT),
            ],
        }
    }

    #[test]
    fn original_recorded_invocation_permits() {
        let v = evaluate(&validated(), &base_ctx(), &original_invocation());
        assert_eq!(v, Verdict::Permit);
    }

    #[test]
    fn full_spec_never_false_permits_an_unmodeled_reviewed_policy() {
        let spec = subscription_spec().validate().unwrap();
        assert_eq!(
            evaluate(&spec, &base_ctx(), &original_invocation()),
            Verdict::Indeterminate(IndeterminateReason::ReviewedPoliciesUnmodeled)
        );

        let mut denied = original_invocation();
        denied.fn_name = "not_transfer".to_string();
        assert_eq!(
            evaluate(&spec, &base_ctx(), &denied),
            Verdict::Deny(DenyReason::FunctionNotAllowed),
            "the generated conjunct's denial remains conclusive"
        );
    }

    // --- generated-rule entry point (the differential harness drives this) ----------------
    //
    // The tests above go through `evaluate`, which walks every rule. `evaluate_rule` has its
    // own contract check, and nothing in this crate exercised it — so mutation testing found
    // that inverting that check changed no test outcome here. It is the entry point layer 1
    // and layer 2 both use, so it needs its own coverage rather than borrowing `evaluate`'s.

    fn only_rule() -> ozpb_policy_spec::RuleSpec {
        subscription_spec().rules.remove(0)
    }

    #[test]
    fn evaluate_rule_permits_its_own_contract_and_rejects_any_other() {
        let rule = only_rule();
        assert_eq!(
            evaluate_generated_rule(&rule, &base_ctx(), &original_invocation()),
            Verdict::Permit,
            "the recorded call against the rule's own target must permit"
        );

        let elsewhere = Invocation {
            contract: fixtures::MERCHANT.to_string(),
            ..original_invocation()
        };
        assert_eq!(
            evaluate_generated_rule(&rule, &base_ctx(), &elsewhere),
            Verdict::Deny(DenyReason::NoMatchingRule),
            "a rule must not evaluate a call aimed at a different contract"
        );
    }

    // --- signer predicates: isolating each `matched` comparison --------------------------
    //
    // Subtlety worth recording. A later check also returns `PredicateUnsatisfied`:
    //
    //     if authenticated_signers.iter().any(|s| !rule_live_signers.contains(s)) { … }
    //
    // So the obvious test — authenticate a stranger and expect `PredicateUnsatisfied` —
    // passes no matter which branch produced it, and mutation testing showed the predicate
    // comparison could be inverted with no test noticing. Each test below is built so only
    // the comparison under test can decide the outcome.

    #[test]
    fn any_of_denies_when_a_live_signer_is_not_a_granted_one() {
        // Every authenticated signer IS live (so the later check cannot fire) but none is in
        // the granted set, so `matched == 0` and only the any_of comparison can deny.
        let mut rule = only_rule();
        rule.authorization.strict_signer_set = false; // else the live/granted mismatch denies first
        let ctx = EvalContext {
            authenticated_signers: vec![stranger()],
            rule_live_signers: vec![stranger()],
            ..base_ctx()
        };
        assert_eq!(
            evaluate_generated_rule(&rule, &ctx, &original_invocation()),
            Verdict::Deny(DenyReason::PredicateUnsatisfied),
            "any_of must require a *granted* signer; being merely live is not enough"
        );
    }

    #[test]
    fn any_of_permits_when_more_than_one_granted_signer_matches() {
        // The other side of the same comparison: two matches must permit. Guards against a
        // bound that denies on "too many" rather than "too few".
        let mut rule = only_rule();
        rule.authorization.strict_signer_set = false;
        rule.authorization.signers = vec![delegate(), stranger()];
        let ctx = EvalContext {
            authenticated_signers: vec![delegate(), stranger()],
            rule_live_signers: vec![delegate(), stranger()],
            ..base_ctx()
        };
        assert_eq!(
            evaluate_generated_rule(&rule, &ctx, &original_invocation()),
            Verdict::Permit,
            "two granted signers satisfy any_of; only a too-few bound may deny"
        );
    }

    #[test]
    fn any_of_current_rule_signers_permits_two_live_signers_and_denies_none() {
        let mut rule = only_rule();
        rule.authorization.kind = PredicateKind::AnyOfCurrentRuleSigners;
        rule.authorization.strict_signer_set = false;

        // Two live signers authenticate: the comparison must treat that as enough.
        // (For this predicate `matched == 0` is unreachable without also tripping the later
        // live-set check, so the permitting side is what isolates the comparison.)
        let two_live = EvalContext {
            authenticated_signers: vec![delegate(), stranger()],
            rule_live_signers: vec![delegate(), stranger()],
            ..base_ctx()
        };
        assert_eq!(
            evaluate_generated_rule(&rule, &two_live, &original_invocation()),
            Verdict::Permit,
            "the dynamic predicate must permit when several live signers authorized"
        );

        // And it still denies with no signatures at all.
        let none = EvalContext {
            authenticated_signers: vec![],
            rule_live_signers: vec![delegate()],
            ..base_ctx()
        };
        assert_eq!(
            evaluate_generated_rule(&rule, &none, &original_invocation()),
            Verdict::Deny(DenyReason::ZeroSigners)
        );
    }

    #[test]
    fn external_signer_identity_ignores_the_off_chain_verifier_hash_claim() {
        let expected = SignerSpec::External {
            verifier: fixtures::TOKEN.to_string(),
            verifier_code_hash: ozpb_domain::sha256(b"expected-code"),
            key_hex: "aabb".to_string(),
        };
        let account_value = SignerSpec::External {
            verifier: fixtures::TOKEN.to_string(),
            verifier_code_hash: ozpb_domain::sha256(b"different-off-chain-claim"),
            key_hex: "AABB".to_string(),
        };
        let mut rule = only_rule();
        rule.authorization.signers = vec![expected];
        let context = EvalContext {
            authenticated_signers: vec![account_value.clone()],
            rule_live_signers: vec![account_value],
            ..base_ctx()
        };
        assert_eq!(
            evaluate_generated_rule(&rule, &context, &original_invocation()),
            Verdict::Permit,
            "the account stores verifier+key, not verifier Wasm hash; evaluator identity must match"
        );
    }

    #[test]
    fn external_signer_identity_requires_both_verifier_and_key() {
        let expected = SignerSpec::External {
            verifier: fixtures::TOKEN.to_string(),
            verifier_code_hash: ozpb_domain::sha256(b"expected-code"),
            key_hex: "aabb".to_string(),
        };
        let different_key = SignerSpec::External {
            verifier: fixtures::TOKEN.to_string(),
            verifier_code_hash: ozpb_domain::sha256(b"expected-code"),
            key_hex: "aacc".to_string(),
        };
        let different_verifier = SignerSpec::External {
            verifier: fixtures::ACCOUNT.to_string(),
            verifier_code_hash: ozpb_domain::sha256(b"expected-code"),
            key_hex: "aabb".to_string(),
        };

        assert!(!same_signer_identity(&expected, &different_key));
        assert!(!same_signer_identity(&expected, &different_verifier));
    }

    // --- signer predicate (checked FIRST) -------------------------------------------

    #[test]
    fn zero_signers_denies() {
        // THE zero-signer hole: the account defers signer validation to policies, so the
        // policy must deny an empty authenticated set before anything else.
        let mut ctx = base_ctx();
        ctx.authenticated_signers.clear();
        let v = evaluate(&validated(), &ctx, &original_invocation());
        assert_eq!(v, Verdict::Deny(DenyReason::ZeroSigners));
    }

    #[test]
    fn unrecognized_signer_denies() {
        let mut ctx = base_ctx();
        ctx.authenticated_signers = vec![stranger()];
        let v = evaluate(&validated(), &ctx, &original_invocation());
        assert_eq!(v, Verdict::Deny(DenyReason::PredicateUnsatisfied));
    }

    #[test]
    fn strict_mode_denies_when_live_signer_set_grows() {
        // Signer-mutation attack: an added rule signer must fail closed, not broaden.
        let mut ctx = base_ctx();
        ctx.rule_live_signers = vec![delegate(), stranger()];
        let v = evaluate(&validated(), &ctx, &original_invocation());
        assert_eq!(v, Verdict::Deny(DenyReason::SignerSetDiverged));
    }

    #[test]
    fn strict_mode_denies_when_live_signer_set_swapped() {
        let mut ctx = base_ctx();
        // The delegate still authenticates (it may sign anything), but the rule's stored
        // set was replaced — the grant no longer matches what was approved.
        ctx.rule_live_signers = vec![stranger()];
        let v = evaluate(&validated(), &ctx, &original_invocation());
        assert_eq!(v, Verdict::Deny(DenyReason::SignerSetDiverged));
    }

    #[test]
    fn duplicate_authenticated_signers_do_not_double_count() {
        let mut spec = subscription_spec();
        spec.rules[0].authorization.kind = PredicateKind::Threshold { n: 2 };
        spec.rules[0].authorization.signers.push(stranger());
        let v = validate_generated_only(spec);
        let mut ctx = base_ctx();
        ctx.rule_live_signers = vec![delegate(), stranger()];
        ctx.authenticated_signers = vec![delegate(), delegate()]; // same signer twice
        assert_eq!(
            evaluate(&v, &ctx, &original_invocation()),
            Verdict::Deny(DenyReason::PredicateUnsatisfied)
        );
        ctx.authenticated_signers = vec![delegate(), stranger()];
        assert_eq!(evaluate(&v, &ctx, &original_invocation()), Verdict::Permit);
    }

    #[test]
    fn all_of_requires_every_named_signer() {
        let mut spec = subscription_spec();
        spec.rules[0].authorization.kind = PredicateKind::AllOf;
        spec.rules[0].authorization.signers.push(stranger());
        let v = validate_generated_only(spec);
        let mut ctx = base_ctx();
        ctx.rule_live_signers = vec![delegate(), stranger()];
        // One of two present → deny.
        ctx.authenticated_signers = vec![delegate()];
        assert_eq!(
            evaluate(&v, &ctx, &original_invocation()),
            Verdict::Deny(DenyReason::PredicateUnsatisfied)
        );
        // ALL present → permit (guards the `matched < len` boundary, not `<=`).
        ctx.authenticated_signers = vec![delegate(), stranger()];
        assert_eq!(evaluate(&v, &ctx, &original_invocation()), Verdict::Permit);
    }

    /// Helper: swap the amount arg's constraint (+provenance) and return a validated spec.
    fn spec_with_amount_constraint(c: Constraint, prov: ozpb_domain::Provenance) -> ValidatedSpec {
        let mut spec = subscription_spec();
        spec.rules[0].allowed_calls[0].args[2].constraint = c;
        spec.rules[0].allowed_calls[0].args[2].provenance = prov;
        validate_generated_only(spec)
    }

    fn widened() -> ozpb_domain::Provenance {
        ozpb_domain::Provenance::UserWidened {
            intent: "test".to_string(),
            // High: the shared helper also labels AnyValue, which validation holds to a
            // high-blast-radius acknowledgement; bounds accept any radius.
            blast_radius: ozpb_domain::BlastRadius::High,
        }
    }

    #[test]
    fn ge_i128_lower_bound_permits_at_and_above_floor_denies_below() {
        let v = spec_with_amount_constraint(
            Constraint::GeI128 {
                min: AMOUNT.to_string(),
            },
            widened(),
        );
        for (amount, expect_permit) in [
            (AMOUNT - 1, false), // below floor
            (AMOUNT, true),      // at the floor (guards >= vs <)
            (AMOUNT * 2, true),  // above
        ] {
            let mut inv = original_invocation();
            inv.args[2] = ArgValue::I128(amount);
            let v_out = evaluate(&v, &base_ctx(), &inv);
            assert_eq!(
                matches!(v_out, Verdict::Permit),
                expect_permit,
                "GeI128 at {amount}"
            );
        }
    }

    #[test]
    fn eq_scval_permits_exact_match_denies_mismatch() {
        let v = spec_with_amount_constraint(
            Constraint::EqScval {
                xdr_base64: "AAAAAQ==".to_string(),
            },
            ozpb_domain::Provenance::ObservedExact,
        );
        // Exact scval → permit.
        let mut inv = original_invocation();
        inv.args[2] = ArgValue::ScvalXdr("AAAAAQ==".to_string());
        assert_eq!(evaluate(&v, &base_ctx(), &inv), Verdict::Permit);
        // Different scval → deny (guards the `==` equality).
        inv.args[2] = ArgValue::ScvalXdr("AAAAAg==".to_string());
        assert_eq!(
            evaluate(&v, &base_ctx(), &inv),
            Verdict::Deny(DenyReason::NoTupleMatched)
        );
        // Wrong type at the scval position → deny (fail closed).
        inv.args[2] = ArgValue::I128(1);
        assert_eq!(
            evaluate(&v, &base_ctx(), &inv),
            Verdict::Deny(DenyReason::NoTupleMatched)
        );
    }

    #[test]
    fn any_value_permits_arbitrary_values_but_arity_still_enforced() {
        let v = spec_with_amount_constraint(Constraint::AnyValue, widened());
        // Any value at the wildcard position is accepted.
        for val in [
            ArgValue::I128(1),
            ArgValue::I128(i128::MAX),
            ArgValue::Address(
                "GANYTHINGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            ),
        ] {
            let mut inv = original_invocation();
            inv.args[2] = val;
            assert_eq!(evaluate(&v, &base_ctx(), &inv), Verdict::Permit);
        }
        // Arity is still enforced: dropping the arg denies.
        let mut inv = original_invocation();
        inv.args.pop();
        assert_eq!(
            evaluate(&v, &base_ctx(), &inv),
            Verdict::Deny(DenyReason::NoTupleMatched)
        );
    }

    #[test]
    fn dynamic_predicate_uses_live_set_and_still_denies_zero_signers() {
        let mut spec = subscription_spec();
        spec.rules[0].authorization.kind = PredicateKind::AnyOfCurrentRuleSigners;
        spec.rules[0].authorization.strict_signer_set = false;
        spec.rules[0].authorization.signers.clear();
        let v = validate_generated_only(spec);

        // A signer in the live rule set passes, even though no identity is named.
        let mut ctx = base_ctx();
        ctx.rule_live_signers = vec![stranger()];
        ctx.authenticated_signers = vec![stranger()];
        assert_eq!(evaluate(&v, &ctx, &original_invocation()), Verdict::Permit);

        // Zero authenticated signers must still deny (v0.7 review requirement).
        ctx.authenticated_signers.clear();
        assert_eq!(
            evaluate(&v, &ctx, &original_invocation()),
            Verdict::Deny(DenyReason::ZeroSigners)
        );

        // A signer outside the live set denies.
        ctx.authenticated_signers = vec![delegate()];
        assert_eq!(
            evaluate(&v, &ctx, &original_invocation()),
            Verdict::Deny(DenyReason::PredicateUnsatisfied)
        );
    }

    // --- scope: contract / function / tuple ------------------------------------------

    #[test]
    fn different_contract_denies() {
        let mut inv = original_invocation();
        inv.contract = "COTHERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
        assert_eq!(
            evaluate(&validated(), &base_ctx(), &inv),
            Verdict::Deny(DenyReason::NoMatchingRule)
        );
    }

    #[test]
    fn different_function_denies() {
        let mut inv = original_invocation();
        inv.fn_name = "approve".to_string();
        assert_eq!(
            evaluate(&validated(), &base_ctx(), &inv),
            Verdict::Deny(DenyReason::FunctionNotAllowed)
        );
    }

    #[test]
    fn amount_mutations_deny_exactly() {
        for amount in [AMOUNT + 1, AMOUNT - 1, AMOUNT * 10, 0, i128::MAX] {
            let mut inv = original_invocation();
            inv.args[2] = ArgValue::I128(amount);
            assert_eq!(
                evaluate(&validated(), &base_ctx(), &inv),
                Verdict::Deny(DenyReason::NoTupleMatched),
                "amount {amount} must not match the exact constraint"
            );
        }
    }

    #[test]
    fn different_recipient_denies() {
        let mut inv = original_invocation();
        inv.args[1] = ArgValue::Address(
            "GATTACKERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        );
        assert_eq!(
            evaluate(&validated(), &base_ctx(), &inv),
            Verdict::Deny(DenyReason::NoTupleMatched)
        );
    }

    #[test]
    fn self_marker_resolves_to_the_context_account() {
        // from != SELF: deny.
        let mut inv = original_invocation();
        inv.args[0] = ArgValue::Address(fixtures::MERCHANT.to_string());
        assert_eq!(
            evaluate(&validated(), &base_ctx(), &inv),
            Verdict::Deny(DenyReason::NoTupleMatched)
        );
        // Same spec, different smart account: SELF follows the account (wasm is
        // account-independent).
        let mut ctx = base_ctx();
        ctx.smart_account = "CANOTHERACCOUNTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
        let mut inv = original_invocation();
        inv.args[0] = ArgValue::Address(ctx.smart_account.clone());
        assert_eq!(evaluate(&validated(), &ctx, &inv), Verdict::Permit);
    }

    #[test]
    fn extra_or_missing_args_deny() {
        let mut inv = original_invocation();
        inv.args.push(ArgValue::I128(1));
        assert_eq!(
            evaluate(&validated(), &base_ctx(), &inv),
            Verdict::Deny(DenyReason::NoTupleMatched)
        );
        let mut inv = original_invocation();
        inv.args.pop();
        assert_eq!(
            evaluate(&validated(), &base_ctx(), &inv),
            Verdict::Deny(DenyReason::NoTupleMatched)
        );
    }

    #[test]
    fn type_confusion_denies() {
        // An i128 where an address is expected must fail closed.
        let mut inv = original_invocation();
        inv.args[1] = ArgValue::I128(42);
        assert_eq!(
            evaluate(&validated(), &base_ctx(), &inv),
            Verdict::Deny(DenyReason::NoTupleMatched)
        );
    }

    // --- lifetime / state ---------------------------------------------------------------

    #[test]
    fn expired_rule_denies() {
        let mut ctx = base_ctx();
        ctx.current_ledger = LedgerSeq(4_223_457); // one past valid_until
        assert_eq!(
            evaluate(&validated(), &ctx, &original_invocation()),
            Verdict::Deny(DenyReason::RuleExpired)
        );
        ctx.current_ledger = LedgerSeq(4_223_456); // exactly at the boundary: still valid
        assert_eq!(
            evaluate(&validated(), &ctx, &original_invocation()),
            Verdict::Permit
        );
    }

    #[test]
    fn call_count_boundary() {
        let mut ctx = base_ctx();
        ctx.call_count_so_far = Some(11); // max is 12 -> one call left
        assert_eq!(
            evaluate(&validated(), &ctx, &original_invocation()),
            Verdict::Permit
        );
        ctx.call_count_so_far = Some(12); // exhausted
        assert_eq!(
            evaluate(&validated(), &ctx, &original_invocation()),
            Verdict::Deny(DenyReason::CallCountExceeded)
        );
    }

    #[test]
    fn missing_state_denies() {
        // §4.4: enforce never treats missing state as zero.
        let mut ctx = base_ctx();
        ctx.call_count_so_far = None;
        assert_eq!(
            evaluate(&validated(), &ctx, &original_invocation()),
            Verdict::Deny(DenyReason::MissingState)
        );
    }

    // --- widened constraints ---------------------------------------------------------

    #[test]
    fn user_widened_upper_bound_behaves_as_bound() {
        let mut spec = subscription_spec();
        spec.rules[0].allowed_calls[0].args[2].constraint = Constraint::LeI128 {
            max: "1000000000".to_string(),
        };
        spec.rules[0].allowed_calls[0].args[2].provenance = ozpb_domain::Provenance::UserWidened {
            intent: "cap at 100".to_string(),
            blast_radius: ozpb_domain::BlastRadius::Medium,
        };
        let v = validate_generated_only(spec);
        for (amount, expected) in [
            (1i128, Verdict::Permit),
            (1_000_000_000, Verdict::Permit),
            (1_000_000_001, Verdict::Deny(DenyReason::NoTupleMatched)),
        ] {
            let mut inv = original_invocation();
            inv.args[2] = ArgValue::I128(amount);
            assert_eq!(evaluate(&v, &base_ctx(), &inv), expected, "amount {amount}");
        }
    }

    proptest::proptest! {
        /// Property: no random invocation against the fixture spec is ever permitted
        /// without the delegate signer present (the predicate is checked first).
        #[test]
        fn nothing_permits_without_the_granted_signer(
            fn_name in "[a-z_]{1,12}",
            amount in proptest::prelude::any::<i128>(),
        ) {
            let mut ctx = base_ctx();
            ctx.authenticated_signers = vec![stranger()];
            let inv = Invocation {
                contract: fixtures::TOKEN.to_string(),
                fn_name,
                args: vec![
                    ArgValue::Address(fixtures::ACCOUNT.to_string()),
                    ArgValue::Address(fixtures::MERCHANT.to_string()),
                    ArgValue::I128(amount),
                ],
            };
            let v = evaluate(&validated(), &ctx, &inv);
            proptest::prop_assert_ne!(v, Verdict::Permit);
        }
    }
}
