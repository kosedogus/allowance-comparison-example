/// # Owner provenance check — v2 integration
///
/// Same user-story as `owner_check_v1`: a downstream protocol wants to
/// refuse `place_order` unless the caller owns the named vault.
///
/// # Why this scenario is direct in v2
///
/// v2 stores `owner: address` on the `Vault` itself and exposes
/// `spend_vault::owner(&v) -> address` as a total (never-aborts) read.
/// The integrator's check is one line:
///
/// ```move
/// assert!(spend_vault::owner(v) == ctx.sender(), E_NOT_OWNER);
/// ```
///
/// No cap is passed; no extra input object on the PTB; the integrator's
/// public API is decoupled from the allowance library's authority
/// objects. The same shape works for any read-only consumer: limit
/// books, escrow registries, vault marketplaces, lending positions
/// that key off "the vault's authoritative owner."
///
/// The trade is the one captured in Pattern 3: v2's owner address is
/// immutable. The provenance check is rock-solid because nothing can
/// rotate underneath an in-flight integrator state; the cost is that
/// rotating ownership requires destroying and re-creating the vault.
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
