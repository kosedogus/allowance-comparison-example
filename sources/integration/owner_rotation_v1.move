/// # Owner authority rotation — v1 integration
///
/// User-story: a treasury controlled by one
/// multisig needs to hand control to a successor multisig. All existing
/// delegations should survive the rotation; users should not need to
/// re-grant.
///
/// # Why this scenario favors v1
///
/// v1's `OwnerCap` is `key + store` — an owned object the current owner
/// can `public_transfer` to the successor. The successor immediately
/// holds the same authority over the same `Vault`; every existing
/// allowance entry (address-keyed) continues to work without touching
/// the ledger.
///
/// The cap is also composable: the OwnerCap can be wrapped behind
/// `openzeppelin_access::two_step_transfer` for a two-step handoff, or
/// behind `delayed_transfer` for a timelocked handoff, or held inside a
/// multisig / DAO custody object. Pure natural composition; the
/// allowance library is unaware of the wrapping.
///
/// This module exposes the rotation as one entry call so the v1↔v2 test
/// comparison reads cleanly; integrators can just call
/// `transfer::public_transfer(cap, new_owner)` directly without any
/// wrapper module.
module allowance_example::owner_rotation_v1;

use openzeppelin_allowance::coin_allowance::OwnerCap;

/// Hand the OwnerCap to a successor. Identical to writing
/// `transfer::public_transfer(cap, new_owner)` inline — wrapped only so
/// the test reads as `owner_rotation_v1::*`.
///
/// After this call, the new owner can immediately call `grant`,
/// `revoke`, `withdraw`, etc. against the same Vault. All existing
/// allowance entries are untouched.
public fun rotate(cap: OwnerCap, new_owner: address) {
    transfer::public_transfer(cap, new_owner);
}
