/// # Yield aggregator with per-user delegation — v1 integration
///
/// User-story: a yield aggregator
/// onboards a user, takes a per-user delegation to deploy that user's
/// funds across DeFi protocols, and rebalances each user independently
/// inside the aggregator's own functions.
///
/// # Why this scenario is awkward in v1
///
/// v1 keys allowances by spender ADDRESS (`Table<address, Allowance>`),
/// and `consume` authorizes on `ctx.sender()`. There is no spender-cap
/// object the aggregator can store per-user. The aggregator therefore has
/// two choices, neither clean:
///
/// 1. **Aggregator-as-spender (this module's approach).** The user grants
///    the aggregator's published address as spender. The aggregator's
///    on-chain functions (PTB-callable) draw funds from each user's
///    vault. Because `ctx.sender()` IS the aggregator's transaction
///    sender, this only works when the aggregator's flows are signed by
///    an off-chain key the aggregator controls (a keeper bot). The
///    aggregator does NOT compose cleanly with a contract-only flow —
///    the aggregator cannot, mid-PTB, "act as" multiple users from a
///    single keeper transaction unless the keeper is the spender for ALL
///    of them, conflating per-user authority into one global key.
///
/// 2. **User-as-spender.** Each user signs their own rebalance
///    transaction. Workable for occasional flows; defeats the
///    "aggregator does work on your behalf" value proposition.
///
/// The v2 sibling (`aggregator_v2.move`) takes the third path that v1
/// cannot offer: per-user `SpenderCap` objects embedded in a
/// protocol-owned `Table<address, UserRecord>`. The aggregator's
/// rebalance function borrows `&record.cap` for the user being
/// rebalanced; authority is cap-presentation, not sender equality, so
/// the keeper can rebalance many users in one PTB without being any of
/// them.
///
/// # What this module demonstrates
///
/// Path 1 (aggregator-as-spender). The aggregator publishes one
/// "service address" (`AGGREGATOR_SERVICE`). Users grant that address.
/// The aggregator's keeper signs PTBs from the service address and runs
/// the rebalances. Per-user accounting must be reconstructed off-chain
/// from `Consumed` events keyed on `(vault_id, spender)` — the on-chain
/// state is one entry per (vault, AGGREGATOR_SERVICE) pair.
module allowance_example::aggregator_v1;

use openzeppelin_allowance::coin_allowance::{Self, Vault, OwnerCap};
use sui::balance::Balance;
use sui::clock::Clock;

/// User onboards by granting the aggregator's service address. The user
/// must call this themselves — there is no path for the aggregator to do
/// the grant (the user must hold the `OwnerCap`). Each (vault, service)
/// pair lives as ONE address-keyed entry in the v1 ledger.
public fun onboard_user<U>(
    v: &mut Vault<U>,
    cap: &OwnerCap,
    aggregator_service: address,
    delegation_cap: u64,
    expires_at_ms: u64,
    clock: &Clock,
    ctx: &sui::tx_context::TxContext,
) {
    coin_allowance::grant<U>(
        v,
        cap,
        aggregator_service,
        delegation_cap,
        expires_at_ms,
        option::none(),  // unbound: aggregator wants the Balance to
                         // plumb mid-PTB into a downstream protocol
        option::none(),
        clock,
        ctx,
    );
}

/// Aggregator-side rebalance — `ctx.sender()` MUST be `aggregator_service`
/// (the address the user granted in `onboard_user`). Returns
/// `Balance<U>` so the aggregator's caller can plumb it into a
/// downstream DeFi call within the same PTB.
///
/// Per-user state lives only in the underlying Vault's address-keyed
/// table — the aggregator holds no on-chain per-user record (there is
/// no v1 spender object to embed). Per-user policy, fee accounting,
/// vault-ID mapping etc. must be maintained off-chain or in a parallel
/// integrator structure that this module does not provide.
public fun rebalance_user<U>(
    v: &mut Vault<U>,
    amount: u64,
    clock: &Clock,
    ctx: &mut sui::tx_context::TxContext,
): Balance<U> {
    // `ctx.sender()` is checked inside `consume`; it MUST equal the
    // address that was granted in `onboard_user`. The aggregator's
    // keeper signs this PTB from that address.
    coin_allowance::consume<U>(v, amount, clock, ctx).destroy_some()
}
