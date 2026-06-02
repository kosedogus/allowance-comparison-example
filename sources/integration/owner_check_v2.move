/// # Owner provenance check — v2 integration
///
/// Same user-story as `owner_check_v1`: a downstream protocol wants to
/// refuse `place_order` unless the caller owns the named vault.
///
/// # Why this scenario is direct in v2
///
/// v2 stores `owner: address` on the `Vault` itself and exposes
/// `spend_vault::owner(&v) -> address` as a total (never-aborts) read
/// that returns the address itself. The integrator's check is one
/// line:
///
/// ```move
/// assert!(spend_vault::owner(v) == ctx.sender(), E_NOT_OWNER);
/// ```
///
/// This is strictly more expressive than v1's cap-passing workaround.
/// In v1 the owner's address is not on the `Vault` and not on the
/// `OwnerCap` — it lives in Sui's runtime object-ownership layer, and
/// Sui Move has no primitive to read it. v1 can only verify "the
/// caller currently holds the cap" by having the caller pass `&cap`
/// in; it cannot expose the address to integrator code. v2 exposes
/// the address directly, so the integrator can compare it against
/// `ctx.sender()`, a stored value, a function argument, or any
/// arbitrary `address` — verifying ownership by a third-party address
/// is possible only here.
///
/// No cap is passed; no extra input object on the PTB; the
/// integrator's public API is decoupled from the allowance library's
/// authority objects. The same shape works for any read-only
/// consumer: limit books, escrow registries, vault marketplaces,
/// lending positions that key off "the vault's authoritative owner."
///
/// The trade is the one captured under Face A of Decision 3: v2's
/// owner address is immutable. The provenance check is rock-solid
/// because nothing can rotate underneath an in-flight integrator
/// state; the cost is that rotating ownership requires destroying
/// and re-creating the vault.
module allowance_example::owner_check_v2;

use openzeppelin_allowance::spend_vault::{Self, Vault};

/// Integrator-defined error for "the caller is not the vault owner."
const E_NOT_OWNER: u64 = 200;

/// Integrator function — accept a limit-order intent only if
/// `ctx.sender()` IS the vault's owner. No cap parameter required.
public fun place_order<U>(
    v: &Vault<U>,
    order_id: u64,
    ctx: &sui::tx_context::TxContext,
): u64 {
    assert!(spend_vault::owner(v) == ctx.sender(), E_NOT_OWNER);
    order_id
}
