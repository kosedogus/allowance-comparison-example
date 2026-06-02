/// # Owner provenance check — v1 integration
///
/// User-story: a downstream protocol (limit-order book, escrow,
/// marketplace listing) wants to refuse interactions unless the caller
/// is the rightful owner of the vault they are pointing at.
///
/// # The capability gap on v1
///
/// v1's authority is "possession of `OwnerCap`". The Vault struct has
/// no `owner` field, and the `OwnerCap` struct has no `owner_address`
/// field either — it carries only `id` and `vault_id`. The owner's
/// address lives entirely in Sui's runtime object-ownership layer
/// (whichever address currently holds the `OwnerCap` object), and
/// Sui Move has no primitive for reading "the current owner of object
/// X" from inside a function. **An on-chain consumer cannot derive
/// the owner's address from `&Vault` alone — full stop.** That
/// information is reachable only off-chain via Sui RPC.
///
/// # The closest available workaround
///
/// The integrator can require the caller to pass their `&OwnerCap`
/// in alongside the `&Vault`, and assert `cap.id == vault.cap_id`.
/// By Sui's object-input semantics, the cap must be an input the
/// transaction is authorized for — so in the common case (cap held
/// directly by an EOA), this proves "the transaction sender is the
/// owner."
///
/// What this workaround does NOT do:
///
/// - It does not expose the owner's address to the integrator's code.
///   You cannot write `if (vault.owner() == some_known_address) { ... }`
///   — there is no `vault.owner()`.
/// - It does not let the integrator verify ownership by an arbitrary
///   address. v1 cannot answer "is `0xALICE` the owner of this vault?"
///   on-chain.
/// - If the cap is wrapped inside a shared custody object (multisig,
///   DAO), the binding check still passes — but who "the owner" is
///   becomes a question the wrapper module answers, not the
///   allowance library.
///
/// In effect, v1 supports a narrower property than v2's
/// `spend_vault::owner(&v) -> address`. v2 exposes the owner address
/// itself; v1's cap-binding check is a proof-of-current-control proxy
/// that works only for the "is the caller the owner?" subcase.
///
/// `&OwnerCap` is sufficient (no need to consume the cap by value),
/// but the user must hold it in their wallet and remember to plumb
/// it into the integrator call. PTB-side this means an extra input
/// object.
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
