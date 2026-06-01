/// # Owner provenance check — v1 vs v2 comparison tests
///
/// Compares the two ways a downstream integrator (limit-order book,
/// escrow registry, marketplace listing) can verify "the caller owns
/// this vault" before accepting an intent.
///
/// # Actors
///
/// - `OWNER` — the legitimate vault owner.
/// - `MALLORY` — an attacker trying to act against `OWNER`'s vault.
///
/// # What each test demonstrates
///
/// 1. `happy_v1_owner_with_cap_can_place_order` — v1: owner holds the
///    OwnerCap and passes a borrow of it to the integrator; the
///    integrator's `cap_id == object::id(cap)` check passes.
/// 2. `failure_v1_wrong_cap_rejected` — v1: Mallory passes their own
///    (foreign) OwnerCap; the integrator's check aborts E_WRONG_VAULT.
/// 3. `happy_v2_owner_sender_passes_check` — v2: owner is the tx
///    sender; integrator reads `sv::owner(&v)` directly, no cap
///    parameter needed.
/// 4. `failure_v2_non_owner_sender_rejected` — v2: Mallory signs the
///    tx; `sv::owner(&v) != ctx.sender()` → aborts E_NOT_OWNER.
///
/// The first two show v1 can express the property but at the cost of
/// taking `&OwnerCap` in every integrator function signature; the
/// second two show v2 expresses it with one address comparison and no
/// extra input object.
#[test_only]
module allowance_example::owner_check_comparison_tests;

use allowance_example::owner_check_v1;
use allowance_example::owner_check_v2;
use openzeppelin_allowance::coin_allowance::{Self as ca, Vault as VaultV1, OwnerCap};
use openzeppelin_allowance::spend_vault::{Self as sv, Vault as VaultV2};
use sui::test_scenario as ts;
use sui::sui::SUI;

const OWNER: address = @0xA11CE;
const MALLORY: address = @0x6AD;

const ORDER_ID: u64 = 42;

// =====================================================================
// === v1 happy — owner presents the bound cap                       ===
// =====================================================================
#[test]
// Proves: v1 can express owner provenance — but only by including
// `&OwnerCap` in the integrator's function signature.
fun happy_v1_owner_with_cap_can_place_order() {
    let mut sc = ts::begin(OWNER);

    // Tx 1 — OWNER creates vault, keeps the cap.
    let (v, cap) = ca::new<SUI>(ts::ctx(&mut sc));
    let v_id = object::id(&v);
    ca::share(v);
    transfer::public_transfer(cap, OWNER);

    // Tx 2 — OWNER places an order, presenting the bound cap.
    ts::next_tx(&mut sc, OWNER);
    {
        let v = ts::take_shared_by_id<VaultV1<SUI>>(&sc, v_id);
        let cap = ts::take_from_address<OwnerCap>(&sc, OWNER);
        let id = owner_check_v1::place_order<SUI>(
            &v, &cap, ORDER_ID, ts::ctx(&mut sc),
        );
        assert!(id == ORDER_ID, 0);
        ts::return_to_address(OWNER, cap);
        ts::return_shared(v);
    };

    ts::end(sc);
}

// =====================================================================
// === v1 failure — wrong cap rejected                                ===
// =====================================================================
#[test]
// Proves: v1's provenance check is sound — Mallory's foreign cap is
// rejected by the integrator-side cap_id comparison.
#[expected_failure(abort_code = 200, location = allowance_example::owner_check_v1)]
fun failure_v1_wrong_cap_rejected() {
    let mut sc = ts::begin(OWNER);

    // Tx 1 — OWNER's vault.
    let (v_owner, cap_owner) = ca::new<SUI>(ts::ctx(&mut sc));
    let v_owner_id = object::id(&v_owner);
    ca::share(v_owner);
    transfer::public_transfer(cap_owner, OWNER);

    // Tx 2 — MALLORY's own (different) vault, so Mallory has SOMEthing
    // to pass.
    ts::next_tx(&mut sc, MALLORY);
    let (v_mal, cap_mal) = ca::new<SUI>(ts::ctx(&mut sc));
    ca::share(v_mal);

    // Tx 3 — MALLORY tries to place an order against OWNER's vault
    // using MALLORY's own cap. cap_id mismatch → E_WRONG_VAULT.
    ts::next_tx(&mut sc, MALLORY);
    {
        let v = ts::take_shared_by_id<VaultV1<SUI>>(&sc, v_owner_id);
        let _ = owner_check_v1::place_order<SUI>(
            &v, &cap_mal, ORDER_ID, ts::ctx(&mut sc),
        );
        ts::return_shared(v);
    };

    transfer::public_transfer(cap_mal, MALLORY);
    ts::end(sc);
}

// =====================================================================
// === v2 happy — owner is the tx sender                              ===
// =====================================================================
#[test]
// Proves: v2 expresses owner provenance with one address read; no cap
// parameter required. Integrator API surface stays decoupled from the
// allowance library's authority objects.
fun happy_v2_owner_sender_passes_check() {
    let mut sc = ts::begin(OWNER);

    // Tx 1 — OWNER creates a vault naming themselves.
    let v = sv::new<SUI>(OWNER, ts::ctx(&mut sc));
    let v_id = object::id(&v);
    sv::share(v);

    // Tx 2 — OWNER places an order. `ctx.sender() == sv::owner(&v)`.
    ts::next_tx(&mut sc, OWNER);
    {
        let v = ts::take_shared_by_id<VaultV2<SUI>>(&sc, v_id);
        let id = owner_check_v2::place_order<SUI>(&v, ORDER_ID, ts::ctx(&mut sc));
        assert!(id == ORDER_ID, 0);
        ts::return_shared(v);
    };

    ts::end(sc);
}

// =====================================================================
// === v2 failure — non-owner sender rejected                         ===
// =====================================================================
#[test]
// Proves: v2's provenance check rejects a non-owner sender — even
// though Mallory can READ the shared vault, they cannot pose as the
// owner because `sv::owner(&v)` is the stored, immutable address.
#[expected_failure(abort_code = 200, location = allowance_example::owner_check_v2)]
fun failure_v2_non_owner_sender_rejected() {
    let mut sc = ts::begin(OWNER);

    let v = sv::new<SUI>(OWNER, ts::ctx(&mut sc));
    let v_id = object::id(&v);
    sv::share(v);

    ts::next_tx(&mut sc, MALLORY);
    {
        let v = ts::take_shared_by_id<VaultV2<SUI>>(&sc, v_id);
        let _ = owner_check_v2::place_order<SUI>(&v, ORDER_ID, ts::ctx(&mut sc));
        ts::return_shared(v);
    };

    ts::end(sc);
}
