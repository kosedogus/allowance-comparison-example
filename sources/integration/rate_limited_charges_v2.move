/// # Rate-limited bot charges — v2 integration
///
/// Same user-story as `rate_limited_charges_v1`: an AI agent gets a
/// monthly allowance with one charge per hour. v2 ships this as a
/// first-class library feature.
///
/// # Why this scenario favors v2
///
/// `spend_vault::Allowance` carries an `Option<RateLimiter>` field that
/// composes `openzeppelin_utils::rate_limiter`. The owner attaches a
/// limiter at `approve` / `mint_cap` time, or later via `set_allowance`.
/// The library calls `rate_limiter::try_consume` inside `spend`, aborts
/// `ERateLimited` on refusal, and emits a paired `RateLimitConsumed`
/// event for off-chain monitoring. No integrator-side bookkeeping
/// object, no parallel `last_charge_ms` field — the limiter lives next
/// to the allowance entry in the same row of the same table.
///
/// # Suspension idiom — v2-only
///
/// If the bot misbehaves, the owner calls
/// `set_allowance(cap_id, 0, ..., expected=...)`. The entry stays alive
/// (cap remains valid, the limiter is preserved), but every
/// `spend(&cap, > 0)` aborts `EAllowanceExceeded`. The owner can later
/// `set_allowance(cap_id, > 0, ..., expected = Some(0))` to resume —
/// limiter still in place, no need to reconstruct.
///
/// v1 has no suspension idiom. Re-granting overwrites the entire entry
/// (including the integrator-side policy reference in v1's analog of
/// this scenario); revoking removes it entirely.
module allowance_example::rate_limited_charges_v2;

use openzeppelin_allowance::spend_vault::{Self, Vault, SpenderCap};
use openzeppelin_utils::rate_limiter;
use sui::balance::Balance;
use sui::clock::Clock;

/// Owner-side onboarding. The owner calls this to mint a fresh cap
/// AND attach a one-per-cooldown rate limiter in the same call. The
/// resulting cap is `public_transfer`ed to the bot via `approve`.
///
/// The library does the rate-limit math; the integrator just chose the
/// strategy (Cooldown here — at most `capacity` charges before a
/// `cooldown_ms` wait) and the parameters.
public fun onboard_bot<U>(
    v: &mut Vault<U>,
    bot: address,
    monthly_budget: u64,
    expires_at_ms: u64,
    per_charge_max: u64,
    cooldown_ms: u64,
    clock: &Clock,
    ctx: &mut sui::tx_context::TxContext,
) {
    // Cooldown(capacity = per_charge_max, ...) — up to per_charge_max
    // units per `cooldown_ms` window. One typical charge drains the
    // limiter and arms the gate.
    let limiter = rate_limiter::new_cooldown(
        per_charge_max,
        cooldown_ms,
        per_charge_max,  // initial_available — fresh
        0,               // cooldown_end_ms (not armed)
        clock,
    );
    spend_vault::approve<U>(
        v,
        monthly_budget,
        expires_at_ms,
        option::some(limiter),
        bot,
        clock,
        ctx,
    );
}

/// Bot-side charge — the bot holds the cap and presents it directly.
/// The library does limiter check + remaining check + decrement +
/// limiter consume inside a single ordered abort precedence (see
/// `spend_vault::spend` doc). Returns `Balance<U>` for downstream PTB
/// composition.
public fun charge<U>(
    v: &mut Vault<U>,
    cap: &SpenderCap,
    amount: u64,
    clock: &Clock,
    ctx: &sui::tx_context::TxContext,
): Balance<U> {
    spend_vault::spend<U>(v, cap, amount, clock, ctx)
}

/// Owner-side: suspend the bot without losing the cap / limiter.
/// `expected = current` guards against a reduce-allowance race (the
/// read-modify-write between the owner's `allowance` read and this
/// call).
public fun suspend<U>(
    v: &mut Vault<U>,
    cap_id: ID,
    current_remaining: u64,
    expires_at_ms: u64,
    new_rate_limit: Option<openzeppelin_utils::rate_limiter::RateLimiter>,
    clock: &Clock,
    ctx: &sui::tx_context::TxContext,
) {
    spend_vault::set_allowance<U>(
        v,
        cap_id,
        0,  // SUSPENSION — entry stays alive, every spend > 0 aborts
        expires_at_ms,
        new_rate_limit,
        option::some(current_remaining),
        clock,
        ctx,
    );
}

/// Owner-side: resume the bot after suspension. Re-overwrites
/// `remaining` to the new desired cap; preserves the cap and (if
/// passed in) the limiter.
public fun resume<U>(
    v: &mut Vault<U>,
    cap_id: ID,
    new_amount: u64,
    expires_at_ms: u64,
    new_rate_limit: Option<openzeppelin_utils::rate_limiter::RateLimiter>,
    clock: &Clock,
    ctx: &sui::tx_context::TxContext,
) {
    spend_vault::set_allowance<U>(
        v,
        cap_id,
        new_amount,
        expires_at_ms,
        new_rate_limit,
        option::some(0),  // expected guard: assert we were really suspended (remaining == 0)
        clock,
        ctx,
    );
}
