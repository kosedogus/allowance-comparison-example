/// # Owner provenance check — v1 integration
///
/// User-story: a downstream protocol (limit-order book, escrow,
/// marketplace listing) wants to refuse interactions unless the caller
/// is the rightful owner of the vault they are pointing at. The
/// integrator's `place_order` function should reject any caller who
/// does not own the named vault.
///
/// # Why this scenario is awkward in v1
///
/// v1's authority is "possession of `OwnerCap`". There is no
/// `vault.owner() -> address` reader because the answer is not stored
/// on the vault — it is "whoever currently owns the OwnerCap object
/// whose `cap_id` is bound to the vault". An on-chain consumer cannot
/// resolve a wallet address from `&Vault` alone.
///
/// The closest provable check the integrator can perform is to take
/// `&OwnerCap` as a parameter and assert that its object ID matches
/// `coin_allowance::cap_id(v)`. The caller, if they hold the cap, can
/// prove ownership at the call site by passing a borrow of it. The
/// cost: every integrator function that wants ownership-provenance
/// must include the cap in its signature, coupling the integrator's
/// public API to the allowance library's owner-authority object.
///
/// `&OwnerCap` is sufficient (no need to consume the cap by value), but
/// the user must hold it in their wallet and remember to plumb it into
/// the integrator call. PTB-side this means an extra input object.
module allowance_example::owner_check_v1;

use openzeppelin_allowance::coin_allowance::{Self, Vault, OwnerCap};

/// Integrator-defined error for "this OwnerCap is not bound to the
/// vault being acted on."
const E_WRONG_VAULT: u64 = 200;

/// Integrator function — accept a limit-order intent only if the
/// caller can present the OwnerCap bound to `v`. Returns an order ID
/// to keep the demo concrete.
public fun place_order<U>(
    v: &Vault<U>,
    cap: &OwnerCap,
    order_id: u64,
    _ctx: &sui::tx_context::TxContext,
): u64 {
    assert!(coin_allowance::cap_id(v) == object::id(cap), E_WRONG_VAULT);
    order_id
}
