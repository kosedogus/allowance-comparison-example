/// # Subscription with locked recipient — v2 integration
///
/// Same user-story as `subscription_v1`: a SaaS owner pays a fixed monthly
/// fee to a merchant treasury via a billing agent; the agent must never
/// be able to divert the funds.
///
/// # Why v2 requires this integrator module
///
/// `spend_vault::spend` always returns `Balance<U>` — recipient binding is
/// NOT in the library. To preserve v1's non-divertibility guarantee under
/// v2 the integrator builds a `BoundedDelegation` wrapper that owns the
/// `SpenderCap` and pins the merchant address. The wrapper's `charge`
/// function is the only path the agent can use; the cap is otherwise
/// inaccessible.
///
/// This is the trade-off v2 makes by design: the safety property is
/// preserved end-to-end (sealed at wrap time) but pushed from library
/// code into the integrator's audited module — in exchange for the
/// library being fully composable for every other caller. The v1
/// library could not be composable AND ship recipient binding; v2
/// picks composability and asks the integrator for ~30 lines.
///
/// # Authority model (v2 — relevant subset)
///
/// - Owner authority = `ctx.sender() == vault.owner` (no `OwnerCap`).
/// - Spender authority = presentation of `&SpenderCap` whose `vault_id`
///   matches AND whose `cap_id` is in `vault.allowances`. Cap-gated, NOT
///   sender-gated: whoever holds the cap is authorized — including this
///   wrapper module, which is itself the cap-holder.
/// - Recipient binding: implemented HERE via `BoundedDelegation.recipient`.
///   The agent does not hold the cap directly; the agent triggers
///   `charge_cycle`, which calls `spend_vault::spend` and forwards the
///   returned `Balance<U>` to the sealed recipient.
module allowance_example::subscription_v2;

use openzeppelin_allowance::spend_vault::{Self, Vault, SpenderCap};
use sui::clock::Clock;
use sui::coin::{Self, Coin};

/// Integrator-owned wrapper that pins the merchant recipient at
/// construction. The embedded `SpenderCap` is the bearer authority — only
/// the wrapper's `charge_cycle` function can present it to
/// `spend_vault::spend`, so the agent's authorization to charge is gated
/// on calling THIS module, not on holding any spendable object directly.
///
/// `key + store` — the wrapper itself is transferable, so the owner can
/// hand it to the billing agent in the onboarding PTB and recover it later
/// if needed.
public struct BoundedDelegation has key, store {
    id: UID,
    cap: SpenderCap,
    recipient: address,
}

/// Owner-only — bootstraps the merchant subscription. `ctx.sender()` must
/// equal `vault.owner` (the library enforces this on `mint_cap`).
///
/// Step order in the same PTB:
///   1. `mint_cap` returns a fresh cap bound to the vault.
///   2. Wrap the cap inside `BoundedDelegation` with the merchant pinned.
///   3. `public_transfer` the wrapper to the agent.
///
/// The agent now holds a `BoundedDelegation` object but NOT the bare cap.
/// Any subsequent `charge_cycle` call by the agent feeds the wrapper's
/// internal cap into `spend_vault::spend` and routes the result to the
/// sealed recipient.
public fun onboard_merchant<U>(
    v: &mut Vault<U>,
    agent: address,
    merchant_treasury: address,
    monthly_fee: u64,
    cycles: u64,
    expires_at_ms: u64,
    clock: &Clock,
    ctx: &mut sui::tx_context::TxContext,
) {
    let cap = spend_vault::mint_cap<U>(
        v,
        monthly_fee * cycles,
        expires_at_ms,
        option::none(),  // no rate limit in this scenario; see rate_limited_charges_v2
        clock,
        ctx,
    );
    let bd = BoundedDelegation {
        id: object::new(ctx),
        cap,
        recipient: merchant_treasury,
    };
    transfer::public_transfer(bd, agent);
}

/// Cycle-time entry, called by the billing agent. The agent passes its
/// own `BoundedDelegation` (which it owns) and the shared vault.
///
/// `spend_vault::spend` returns `Balance<U>`; this module converts it to
/// a `Coin<U>` and `public_transfer`s to the sealed recipient — the
/// agent's transaction code never touches the balance. Even with a fully
/// compromised agent key, the funds cannot be redirected: the
/// `BoundedDelegation.recipient` field is private to this module and was
/// set immutably at `onboard_merchant` time.
public fun charge_cycle<U>(
    v: &mut Vault<U>,
    bd: &BoundedDelegation,
    monthly_fee: u64,
    clock: &Clock,
    ctx: &mut sui::tx_context::TxContext,
) {
    let bal = spend_vault::spend<U>(v, &bd.cap, monthly_fee, clock, ctx);
    transfer::public_transfer(coin::from_balance(bal, ctx), bd.recipient);
}

/// Convenience deposit — included so tests read as `subscription_v2::*`.
public fun fund<U>(v: &mut Vault<U>, c: Coin<U>, ctx: &sui::tx_context::TxContext) {
    spend_vault::deposit<U>(v, c, ctx);
}

/// Reader exposed for tests / off-chain monitoring.
public fun recipient(bd: &BoundedDelegation): address {
    bd.recipient
}
