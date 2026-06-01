/// # Yield aggregator with per-user delegation — v2 integration
///
/// Same user-story as `aggregator_v1`: a yield aggregator onboards
/// users, takes per-user delegations against their vaults, and rebalances
/// each user inside the aggregator's own functions.
///
/// # Why this scenario favors v2
///
/// v2's `SpenderCap` is `key + store` — a transferable, embeddable bearer
/// authority. The aggregator builds a protocol-owned table
/// `Table<address, UserRecord>` and stores ONE cap per user inside the
/// record. The aggregator's `rebalance_user` function borrows
/// `&record.cap` and calls `spend_vault::spend(v, &cap, ...)`. Because
/// authority is cap-presentation (not `ctx.sender()` equality), the
/// aggregator's keeper can rebalance many users in a single transaction
/// signed from the keeper's address — the keeper is none of the users
/// individually, but presents each user's cap to draw their funds.
///
/// # `cap_id` stability across `set_allowance`
///
/// v2's `set_allowance` mutates the entry in place — the cap_id and the
/// stored cap object are unchanged. The aggregator's `UserRecord.cap`
/// survives every owner-side reduce / suspend / re-fund. v1 has no
/// analog: the address-keyed entry is rewritten in place too, but there
/// is no embedded cap object whose stability matters. This is exactly
/// the v2-only composability win — wrappers and protocol tables embed
/// caps and survive parameter changes.
///
/// # Suspension idiom
///
/// `set_allowance(K, 0, ...)` overwrites `remaining` to 0 while keeping
/// the entry alive (and the cap valid). The aggregator's `UserRecord`
/// stays linked to a live cap; the next user rebalance aborts
/// `EAllowanceExceeded` instead of `ENoAllowance`. The owner can later
/// resume by calling `set_allowance(K, > 0, ...)`. v1 has no equivalent
/// — you either re-grant or revoke (which removes the entry entirely).
module allowance_example::aggregator_v2;

use openzeppelin_allowance::spend_vault::{Self, Vault, SpenderCap};
use sui::balance::Balance;
use sui::clock::Clock;
use sui::object_table::{Self, ObjectTable};

/// Per-user record stored inside the protocol-owned aggregator.
///
/// `key + store` so it can sit inside `ObjectTable<address, UserRecord>`
/// (object_table is the only Sui collection that accepts `has key`
/// items as values without re-wrapping). The cap is the embedded
/// `SpenderCap` — bearer authority for ONE user's vault. The aggregator
/// is the holder; the user no longer needs to touch the cap directly
/// once onboarded.
public struct UserRecord has key, store {
    id: UID,
    cap: SpenderCap,
    policy_strategy_id: u64,  // domain-specific policy data (placeholder)
}

/// Protocol-owned aggregator object — a shared object containing the
/// per-user records. One instance per aggregator deployment.
public struct Aggregator has key {
    id: UID,
    users: ObjectTable<address, UserRecord>,
}

/// Deploy + share the aggregator. Returns the aggregator's ID so the
/// caller (in tests) can read it back from shared input. Real
/// deployments would emit an event.
public fun deploy(ctx: &mut sui::tx_context::TxContext): ID {
    let agg = Aggregator {
        id: object::new(ctx),
        users: object_table::new<address, UserRecord>(ctx),
    };
    let agg_id = object::id(&agg);
    transfer::share_object(agg);
    agg_id
}

/// User-driven onboarding. The user (vault.owner) mints a cap against
/// their own vault, then hands the cap to the aggregator via this call.
/// The aggregator stores the cap inside a fresh `UserRecord`.
///
/// Note: `mint_cap` is gated on `ctx.sender() == vault.owner`, so this
/// flow naturally requires the user to sign their own onboarding tx.
/// After onboarding, the keeper can act on the user's vault without the
/// user signing anything further.
public fun onboard_user<U>(
    agg: &mut Aggregator,
    v: &mut Vault<U>,
    user: address,
    delegation_cap: u64,
    expires_at_ms: u64,
    policy_strategy_id: u64,
    clock: &Clock,
    ctx: &mut sui::tx_context::TxContext,
) {
    let cap = spend_vault::mint_cap<U>(
        v,
        delegation_cap,
        expires_at_ms,
        option::none(),  // no rate limit in this scenario
        clock,
        ctx,
    );
    let record = UserRecord {
        id: object::new(ctx),
        cap,
        policy_strategy_id,
    };
    agg.users.add(user, record);
}

/// Keeper-side rebalance — invoked by the aggregator's keeper address.
/// The cap is borrowed from the aggregator's table; the keeper does NOT
/// hold the cap directly. Authority comes from cap presentation, so
/// `ctx.sender()` (the keeper) is NOT the user; the spend still
/// succeeds.
public fun rebalance_user<U>(
    agg: &mut Aggregator,
    v: &mut Vault<U>,
    user: address,
    amount: u64,
    clock: &Clock,
    ctx: &mut sui::tx_context::TxContext,
): Balance<U> {
    let record = agg.users.borrow(user);
    spend_vault::spend<U>(v, &record.cap, amount, clock, ctx)
}

/// Reader for tests: extract the embedded cap_id so the test can
/// confirm `cap_id` survives across `set_allowance` calls.
public fun user_cap_id(agg: &Aggregator, user: address): ID {
    object::id(&agg.users.borrow(user).cap)
}

/// Reader for tests: does the aggregator track this user?
public fun has_user(agg: &Aggregator, user: address): bool {
    agg.users.contains(user)
}
