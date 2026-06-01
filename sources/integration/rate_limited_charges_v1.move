/// # Rate-limited bot charges — v1 integration
///
/// User-story: an AI agent gets a monthly spending allowance but should
/// be capped at one charge per hour. The v1 library has no rate-limiter
/// integration — `coin_allowance::consume` checks expiry and remaining,
/// nothing else.
///
/// # Why this scenario is awkward in v1
///
/// The integrator must build a parallel rate-limiting layer. The most
/// common pattern: a shared `BotPolicy` object keyed by bot address that
/// records the last-charge timestamp. The integrator wraps `consume`
/// with a function that checks-and-updates the policy before delegating
/// to the library. Failure modes are integrator-defined, not
/// library-defined.
///
/// This module embeds a `last_charge_ms` field per bot. A full
/// implementation would compose `openzeppelin_utils::rate_limiter`,
/// which is what v2 does internally — closing the abstraction loop
/// shows exactly the cost v1 forces on integrators who want this
/// feature.
///
/// # Authority story
///
/// `consume` still authorizes the bot on `ctx.sender()`. The wrapper's
/// rate check happens BEFORE `consume`, and the wrapper does NOT carry
/// owner authority — only the bot can drain itself; the rate check
/// just refuses to make the call.
module allowance_example::rate_limited_charges_v1;

use openzeppelin_allowance::coin_allowance::{Self, Vault};
use sui::balance::Balance;
use sui::clock::Clock;

/// Integrator-defined error code for rate violation. NOT thrown by the
/// v1 library — purely an integrator concern.
const E_RATE_LIMITED: u64 = 100;

/// Parallel rate-tracking record, keyed by bot address. One per bot.
/// Lives in the integrator's package, NOT in the allowance library.
public struct BotPolicy has key {
    id: UID,
    bot: address,
    cooldown_ms: u64,
    last_charge_ms: u64,
}

/// Owner-side setup. Returns the policy ID so tests can read it back
/// from the shared input.
public fun new_policy(
    bot: address,
    cooldown_ms: u64,
    ctx: &mut sui::tx_context::TxContext,
): ID {
    let p = BotPolicy {
        id: object::new(ctx),
        bot,
        cooldown_ms,
        last_charge_ms: 0,
    };
    let id = object::id(&p);
    transfer::share_object(p);
    id
}

/// Wrapper around `consume` that enforces the per-bot cooldown. The bot
/// itself signs this PTB; `ctx.sender()` must equal `policy.bot` AND
/// must be the address granted on the underlying vault.
public fun charge<U>(
    v: &mut Vault<U>,
    policy: &mut BotPolicy,
    amount: u64,
    clock: &Clock,
    ctx: &mut sui::tx_context::TxContext,
): Balance<U> {
    let now = clock.timestamp_ms();
    // Cooldown check — integrator-defined; library does NOT enforce.
    assert!(
        ctx.sender() == policy.bot
            && now >= policy.last_charge_ms + policy.cooldown_ms,
        E_RATE_LIMITED,
    );
    policy.last_charge_ms = now;

    coin_allowance::consume<U>(v, amount, clock, ctx).destroy_some()
}
