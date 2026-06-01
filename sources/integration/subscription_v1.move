/// # Subscription with locked recipient — v1 integration
///
/// User-story: a SaaS owner deposits funds into a vault, allows a billing
/// agent to charge a fixed monthly fee, and pins the merchant treasury as
/// the destination so even a fully-compromised agent key cannot redirect
/// the funds anywhere else.
///
/// # Why this scenario favors v1
///
/// v1's `coin_allowance::grant` accepts an `Option<address>` recipient that
/// is sealed into the allowance entry at grant time. When the agent calls
/// `consume`, the library mints a `Coin<U>` of exactly `amount` and
/// `public_transfer`s it to the stored recipient — the agent never sees the
/// funds. This integration module therefore does NOT need to wrap the v1
/// library at all. The merchant integration is the four lines below:
/// `grant(..., Some(MERCHANT_TREASURY))` once at onboarding, then the
/// agent's `consume` call each cycle. The bound-path non-divertibility
/// guarantee is enforced by the library itself.
///
/// In contrast, `subscription_v2` must mint a `SpenderCap`, wrap it in a
/// `BoundedDelegation` object that pins the merchant address, and define
/// its own `charge` function that pulls a `Balance<U>` and forwards it via
/// `public_transfer`. v1 ships that guarantee; v2 hands it to the
/// integrator.
///
/// # Authority model (v1 — relevant subset)
///
/// - Owner authority = possession of `OwnerCap` whose `vault_id` matches.
/// - Spender authority = `ctx.sender()` equality against the address that
///   was granted. There is NO spender capability object — the agent is
///   authorized by its transaction signing key alone.
/// - Recipient binding: `Allowance.recipient: Option<address>`, set at
///   grant time, immutable until the next `grant`.
module allowance_example::subscription_v1;

use openzeppelin_allowance::coin_allowance::{Self, Vault, OwnerCap};
use sui::clock::Clock;
use sui::coin::Coin;

/// Owner-only thin entry point that bootstraps the merchant subscription.
/// Demonstrates the canonical v1 flow: grant with a sealed recipient.
///
/// The agent's address goes in as `spender`; the merchant's treasury goes
/// in as `recipient`. The library performs the recipient binding — no
/// integrator-side wrapper object exists.
public fun onboard_merchant<U>(
    v: &mut Vault<U>,
    cap: &OwnerCap,
    agent: address,
    merchant_treasury: address,
    monthly_fee: u64,
    cycles: u64,
    expires_at_ms: u64,
    clock: &Clock,
    ctx: &sui::tx_context::TxContext,
) {
    coin_allowance::grant<U>(
        v,
        cap,
        agent,
        monthly_fee * cycles,
        expires_at_ms,
        option::some(merchant_treasury),
        option::none(),
        clock,
        ctx,
    );
}

/// Cycle-time entry — called by the billing agent itself. `ctx.sender()`
/// is the agent's address; that is the spender-authority key in v1.
///
/// The library mints a `Coin<U>` of exactly `monthly_fee`, transfers it to
/// the sealed merchant address, and returns `None`. There is no
/// composable `Balance<U>` to handle.
public fun charge_cycle<U>(
    v: &mut Vault<U>,
    monthly_fee: u64,
    clock: &Clock,
    ctx: &mut sui::tx_context::TxContext,
) {
    let none_bal = coin_allowance::consume<U>(v, monthly_fee, clock, ctx);
    // Bound path: library already public_transferred the Coin to the
    // sealed merchant address. `Option<Balance<U>>` is `None`.
    none_bal.destroy_none();
}

/// Convenience to fund the vault out of the owner's coin in a single PTB
/// step. Identical to calling `coin_allowance::deposit` directly; included
/// only so the test reads as `subscription_v1::*` end-to-end.
public fun fund<U>(v: &mut Vault<U>, c: Coin<U>, ctx: &sui::tx_context::TxContext) {
    coin_allowance::deposit<U>(v, c, ctx);
}
