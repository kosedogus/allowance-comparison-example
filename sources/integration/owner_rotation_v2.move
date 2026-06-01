/// # Owner authority rotation — v2 integration
///
/// Same user-story as `owner_rotation_v1`: a treasury controlled by
/// multisig A must hand control to multisig B.
///
/// # Why this scenario is awkward in v2
///
/// v2 stores `owner: address` directly on the `Vault` and the field is
/// IMMUTABLE — there is no public function in `spend_vault` to change
/// it. This matches DeepBook V3's `BalanceManager` design. The only
/// rotation path is:
///
/// 1. `withdraw_all` — drain the pool to a `Coin<U>`.
/// 2. `destroy` — consume the Vault and drop its ledger.
/// 3. `new(initial_owner = successor)` — mint a fresh Vault.
/// 4. `deposit` — refund the pool from step 1.
/// 5. **Re-grant every cap manually.** Every cap from the old vault is
///    bound to the old `vault_id` and presents `EWrongVault` against
///    the new vault. The successor must call `approve` / `mint_cap` for
///    every spender; downstream wrappers (subscriptions, aggregators,
///    rate-limited bots) holding the OLD cap need to be swapped for the
///    new one, or torn down.
///
/// v2's recommended substitute for owner-rotation flexibility is to set
/// `initial_owner` to a multisig / governance / `delayed_transfer`-
/// wrapped address at construction. Rotation then lives at the
/// address-resolution layer (the multisig's own rotation flow). This
/// works for use cases where the rotation cadence is rare and the
/// multisig membership change is the rotation. It does NOT work for
/// "rotate the on-chain owner identity entirely" without remigration.
///
/// This module exposes the migration as one wrapper function. Real
/// integrators would extend it to iterate over an off-chain list of
/// caps and re-grant them on the new vault.
module allowance_example::owner_rotation_v2;

use openzeppelin_allowance::spend_vault::{Self, Vault};
use sui::clock::Clock;

/// Step 1 — called by the OLD owner. Drains the old vault, destroys it,
/// creates a new vault owned by `successor_owner`, deposits the
/// refunded balance into it, and shares it. The new vault's ID is
/// returned for off-chain bookkeeping.
///
/// IMPORTANT: the OLD owner CANNOT re-grant spenders on the new vault
/// — `approve` / `mint_cap` are gated on `ctx.sender() == v.owner`, and
/// `v.owner` is now `successor_owner`. The successor must complete
/// the re-grants themselves (`step2_regrant_spender` below). This is
/// the v2 authority discontinuity that v1's `OwnerCap` transfer
/// avoids.
///
/// EVERY cap of the old vault is now inert garbage in its holder's
/// wallet — `EWrongVault` on any subsequent `spend`.
public fun step1_migrate<U>(
    old_vault: Vault<U>,
    successor_owner: address,
    clock: &Clock,
    ctx: &mut sui::tx_context::TxContext,
): ID {
    // `clock` accepted for future expiry-related migration helpers;
    // currently unused but kept in the signature for parity with v1's
    // owner-side functions.
    let _ = clock;
    let refunded = spend_vault::destroy<U>(old_vault, ctx);
    let mut new_vault = spend_vault::new<U>(successor_owner, ctx);
    let new_id = object::id(&new_vault);
    spend_vault::deposit<U>(&mut new_vault, refunded, ctx);
    spend_vault::share(new_vault);
    new_id
}

/// Step 2 — called by the SUCCESSOR. Re-grants ONE spender on the new
/// vault. Real migrations iterate over many spenders. `expected: None`
/// because the new vault's allowance is by construction absent.
public fun step2_regrant_spender<U>(
    v: &mut Vault<U>,
    spender: address,
    amount: u64,
    expires_at_ms: u64,
    clock: &Clock,
    ctx: &mut sui::tx_context::TxContext,
) {
    spend_vault::approve<U>(
        v,
        amount,
        expires_at_ms,
        option::none(),
        spender,
        clock,
        ctx,
    );
}
