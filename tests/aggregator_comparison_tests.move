/// # Yield aggregator pattern — v1 vs v2 comparison tests
///
/// Compares `allowance_example::aggregator_v1` and
/// `allowance_example::aggregator_v2`. Same user-story (multiple users
/// onboard, an aggregator rebalances each), structurally different
/// integrator code: v1 forces a single aggregator-service address; v2
/// stores per-user caps in a protocol-owned table.
///
/// # Actors
///
/// - `USER1`, `USER2`: two independent vault owners onboarding.
/// - `AGGREGATOR_SERVICE`: the address the v1 aggregator publishes as the
///   spender. v1's keeper signs PTBs from this address.
/// - `KEEPER`: in v2, the off-chain keeper signing rebalance PTBs. The
///   keeper is NOT a spender; authority comes from the cap stored in
///   the aggregator object.
///
/// # What each test demonstrates
///
/// 1. `happy_v1_aggregator_as_spender` — v1: aggregator address is the
///    spender for both users; keeper signs each rebalance individually.
///    Works, but conflates aggregator identity with delegation authority.
/// 2. `happy_v2_protocol_owned_caps` — v2: per-user caps inside the
///    aggregator's table; keeper rebalances multiple users in a single
///    PTB without being any user's spender.
/// 3. `v2_cap_id_survives_set_allowance` — v2-only: the aggregator's
///    embedded `record.cap` survives owner-side `set_allowance` calls
///    (cap_id stable). The aggregator's table does not need any
///    repair / re-registration when the user adjusts their delegation.
/// 4. `failure_v1_keeper_cannot_rebalance_as_self` — v1: if the keeper
///    tries to rebalance from a non-granted address, `consume` aborts
///    `ENoAllowance`. v1 has no path for "rebalance on behalf of a
///    different user from a single keeper transaction."
#[test_only]
module allowance_example::aggregator_comparison_tests;

use allowance_example::aggregator_v1;
use allowance_example::aggregator_v2;
use openzeppelin_allowance::coin_allowance::{Self as ca, Vault as VaultV1};
use openzeppelin_allowance::spend_vault::{Self as sv, Vault as VaultV2};
use sui::balance::{Self, Balance};
use sui::clock;
use sui::coin;
use sui::sui::SUI;
use sui::test_scenario as ts;

const USER1: address = @0xA001;
const USER2: address = @0xA002;
const AGGREGATOR_SERVICE: address = @0xAA66;
const KEEPER: address = @0x1EE1;

const DELEGATION_CAP: u64 = 1_000_000;
const DEPOSIT: u64 = 5_000_000;
const REBALANCE_AMOUNT: u64 = 200_000;
const ONE_YEAR_MS: u64 = 365 * 24 * 60 * 60 * 1000;
const STRATEGY_FOO: u64 = 0xF00;

// =================================================================
// === Scenario 1 — v1 aggregator-as-spender (works but coupled) ===
// =================================================================
#[test]
// Proves: v1's only viable yield-aggregator pattern is to publish a
// single service address and have it be the spender for every user.
// Keeper signs each user's tx individually — one tx per (user, cycle).
fun happy_v1_aggregator_as_spender() {
    let mut sc = ts::begin(USER1);
    let clk = clock::create_for_testing(ts::ctx(&mut sc));

    // Tx 1 — USER1: create vault, deposit, grant aggregator service.
    let (mut v1, cap1) = ca::new<SUI>(ts::ctx(&mut sc));
    let f1 = coin::mint_for_testing<SUI>(DEPOSIT, ts::ctx(&mut sc));
    ca::deposit<SUI>(&mut v1, f1, ts::ctx(&mut sc));
    aggregator_v1::onboard_user<SUI>(
        &mut v1,
        &cap1,
        AGGREGATOR_SERVICE,
        DELEGATION_CAP,
        ONE_YEAR_MS,
        &clk,
        ts::ctx(&mut sc),
    );
    let v1_id = object::id(&v1);
    ca::share(v1);
    transfer::public_transfer(cap1, USER1);

    // Tx 2 — USER2: same, independent vault.
    ts::next_tx(&mut sc, USER2);
    let (mut v2, cap2) = ca::new<SUI>(ts::ctx(&mut sc));
    let f2 = coin::mint_for_testing<SUI>(DEPOSIT, ts::ctx(&mut sc));
    ca::deposit<SUI>(&mut v2, f2, ts::ctx(&mut sc));
    aggregator_v1::onboard_user<SUI>(
        &mut v2,
        &cap2,
        AGGREGATOR_SERVICE,
        DELEGATION_CAP,
        ONE_YEAR_MS,
        &clk,
        ts::ctx(&mut sc),
    );
    let v2_id = object::id(&v2);
    ca::share(v2);
    transfer::public_transfer(cap2, USER2);

    // Tx 3 — AGGREGATOR_SERVICE (keeper signs as the service address):
    // rebalance user 1.
    ts::next_tx(&mut sc, AGGREGATOR_SERVICE);
    {
        let mut v = ts::take_shared_by_id<VaultV1<SUI>>(&sc, v1_id);
        let bal = aggregator_v1::rebalance_user<SUI>(
            &mut v,
            REBALANCE_AMOUNT,
            &clk,
            ts::ctx(&mut sc),
        );
        assert!(balance::value(&bal) == REBALANCE_AMOUNT, 0);
        balance::destroy_for_testing(bal);
        ts::return_shared(v);
    };

    // Tx 4 — AGGREGATOR_SERVICE: rebalance user 2 (a SEPARATE tx in v1).
    ts::next_tx(&mut sc, AGGREGATOR_SERVICE);
    {
        let mut v = ts::take_shared_by_id<VaultV1<SUI>>(&sc, v2_id);
        let bal = aggregator_v1::rebalance_user<SUI>(
            &mut v,
            REBALANCE_AMOUNT,
            &clk,
            ts::ctx(&mut sc),
        );
        assert!(balance::value(&bal) == REBALANCE_AMOUNT, 1);
        balance::destroy_for_testing(bal);
        ts::return_shared(v);
    };

    clock::destroy_for_testing(clk);
    ts::end(sc);
}

// ===========================================================================
// === Scenario 2 — v2 protocol-owned caps; keeper rebalances many in 1 PTB ===
// ===========================================================================
#[test]
// Proves: v2's `key + store` SpenderCap embeds inside a protocol-owned
// table; keeper rebalances multiple users in ONE PTB without being any
// user's spender. The composition pattern v1 cannot express.
fun happy_v2_protocol_owned_caps() {
    let mut sc = ts::begin(KEEPER);
    let clk = clock::create_for_testing(ts::ctx(&mut sc));

    // Tx 1 — KEEPER: deploy aggregator (shared).
    let agg_id = aggregator_v2::deploy(ts::ctx(&mut sc));

    // Tx 2 — USER1: create vault, deposit, onboard with aggregator.
    ts::next_tx(&mut sc, USER1);
    let mut v1: VaultV2<SUI> = sv::new<SUI>(USER1, ts::ctx(&mut sc));
    let f1 = coin::mint_for_testing<SUI>(DEPOSIT, ts::ctx(&mut sc));
    sv::deposit<SUI>(&mut v1, f1, ts::ctx(&mut sc));
    let v1_id = object::id(&v1);
    {
        let mut agg = ts::take_shared_by_id<aggregator_v2::Aggregator>(&sc, agg_id);
        aggregator_v2::onboard_user<SUI>(
            &mut agg,
            &mut v1,
            USER1,
            DELEGATION_CAP,
            ONE_YEAR_MS,
            STRATEGY_FOO,
            &clk,
            ts::ctx(&mut sc),
        );
        ts::return_shared(agg);
    };
    sv::share(v1);

    // Tx 3 — USER2: same.
    ts::next_tx(&mut sc, USER2);
    let mut v2: VaultV2<SUI> = sv::new<SUI>(USER2, ts::ctx(&mut sc));
    let f2 = coin::mint_for_testing<SUI>(DEPOSIT, ts::ctx(&mut sc));
    sv::deposit<SUI>(&mut v2, f2, ts::ctx(&mut sc));
    let v2_id = object::id(&v2);
    {
        let mut agg = ts::take_shared_by_id<aggregator_v2::Aggregator>(&sc, agg_id);
        aggregator_v2::onboard_user<SUI>(
            &mut agg,
            &mut v2,
            USER2,
            DELEGATION_CAP,
            ONE_YEAR_MS,
            STRATEGY_FOO,
            &clk,
            ts::ctx(&mut sc),
        );
        ts::return_shared(agg);
    };
    sv::share(v2);

    // Tx 4 — KEEPER signs ONE tx that rebalances BOTH users.
    //         v1 cannot do this because v1's spender is `ctx.sender()`.
    ts::next_tx(&mut sc, KEEPER);
    {
        let mut agg = ts::take_shared_by_id<aggregator_v2::Aggregator>(&sc, agg_id);
        let mut vault1 = ts::take_shared_by_id<VaultV2<SUI>>(&sc, v1_id);
        let mut vault2 = ts::take_shared_by_id<VaultV2<SUI>>(&sc, v2_id);

        let bal1: Balance<SUI> = aggregator_v2::rebalance_user<SUI>(
            &mut agg,
            &mut vault1,
            USER1,
            REBALANCE_AMOUNT,
            &clk,
            ts::ctx(&mut sc),
        );
        let bal2: Balance<SUI> = aggregator_v2::rebalance_user<SUI>(
            &mut agg,
            &mut vault2,
            USER2,
            REBALANCE_AMOUNT,
            &clk,
            ts::ctx(&mut sc),
        );
        assert!(balance::value(&bal1) == REBALANCE_AMOUNT, 0);
        assert!(balance::value(&bal2) == REBALANCE_AMOUNT, 1);
        balance::destroy_for_testing(bal1);
        balance::destroy_for_testing(bal2);

        ts::return_shared(vault1);
        ts::return_shared(vault2);
        ts::return_shared(agg);
    };

    clock::destroy_for_testing(clk);
    ts::end(sc);
}

// =================================================================
// === Scenario 3 — v2-only: cap_id stable across set_allowance  ===
// =================================================================
#[test]
// Proves: v2-only — `cap_id` is stable across owner-side `set_allowance`.
// The aggregator's stored `record.cap` survives a reduce; no repair
// needed in the protocol-owned table. v1 has no embedded-cap concept
// for this to matter.
fun v2_cap_id_survives_set_allowance() {
    let mut sc = ts::begin(KEEPER);
    let clk = clock::create_for_testing(ts::ctx(&mut sc));

    let agg_id = aggregator_v2::deploy(ts::ctx(&mut sc));

    // Tx 2 — USER1 onboards.
    ts::next_tx(&mut sc, USER1);
    let mut v1: VaultV2<SUI> = sv::new<SUI>(USER1, ts::ctx(&mut sc));
    let f1 = coin::mint_for_testing<SUI>(DEPOSIT, ts::ctx(&mut sc));
    sv::deposit<SUI>(&mut v1, f1, ts::ctx(&mut sc));
    let v1_id = object::id(&v1);
    {
        let mut agg = ts::take_shared_by_id<aggregator_v2::Aggregator>(&sc, agg_id);
        aggregator_v2::onboard_user<SUI>(
            &mut agg,
            &mut v1,
            USER1,
            DELEGATION_CAP,
            ONE_YEAR_MS,
            STRATEGY_FOO,
            &clk,
            ts::ctx(&mut sc),
        );
        ts::return_shared(agg);
    };
    sv::share(v1);

    // Tx 3 — Capture the cap_id BEFORE the owner changes the entry's params.
    ts::next_tx(&mut sc, KEEPER);
    let cap_id_before = {
        let agg_ref = ts::take_shared_by_id<aggregator_v2::Aggregator>(&sc, agg_id);
        let id = aggregator_v2::user_cap_id(&agg_ref, USER1);
        ts::return_shared(agg_ref);
        id
    };

    // Tx 4 — USER1 (owner of vault) reduces the delegation in place.
    ts::next_tx(&mut sc, USER1);
    {
        let mut v = ts::take_shared_by_id<VaultV2<SUI>>(&sc, v1_id);
        let current = sv::allowance<SUI>(&v, cap_id_before);
        sv::set_allowance<SUI>(
            &mut v,
            cap_id_before,
            current / 2,                  // reduce by half
            ONE_YEAR_MS,
            option::none(),
            option::some(current),        // expected guard
            &clk,
            ts::ctx(&mut sc),
        );
        ts::return_shared(v);
    };

    // Tx 5 — Confirm the aggregator's stored cap_id is identical
    // and the entry is alive with the new amount.
    ts::next_tx(&mut sc, KEEPER);
    {
        let agg = ts::take_shared_by_id<aggregator_v2::Aggregator>(&sc, agg_id);
        let cap_id_after = aggregator_v2::user_cap_id(&agg, USER1);
        assert!(cap_id_before == cap_id_after, 0);
        let v = ts::take_shared_by_id<VaultV2<SUI>>(&sc, v1_id);
        assert!(sv::allowance<SUI>(&v, cap_id_after) == DELEGATION_CAP / 2, 1);
        assert!(sv::contains<SUI>(&v, cap_id_after), 2);
        ts::return_shared(v);
        ts::return_shared(agg);
    };

    clock::destroy_for_testing(clk);
    ts::end(sc);
}

// ==================================================================
// === Scenario 4 — v1 failure: keeper-from-wrong-address aborts  ===
// ==================================================================
#[test]
// Proves: v1's sender-keyed authority is the source of the aggregator
// limitation — a keeper signing from a non-granted address aborts
// `ENoAllowance`. To act on N users from one keeper key, v1 forces
// "keeper IS the spender for all N", which is the coupling v2 breaks.
#[expected_failure(
    abort_code = openzeppelin_allowance::coin_allowance::ENoAllowance,
)]
fun failure_v1_keeper_cannot_rebalance_as_self() {
    let mut sc = ts::begin(USER1);
    let clk = clock::create_for_testing(ts::ctx(&mut sc));

    // USER1: vault + deposit + grant AGGREGATOR_SERVICE.
    let (mut v1, cap1) = ca::new<SUI>(ts::ctx(&mut sc));
    let f1 = coin::mint_for_testing<SUI>(DEPOSIT, ts::ctx(&mut sc));
    ca::deposit<SUI>(&mut v1, f1, ts::ctx(&mut sc));
    aggregator_v1::onboard_user<SUI>(
        &mut v1,
        &cap1,
        AGGREGATOR_SERVICE,
        DELEGATION_CAP,
        ONE_YEAR_MS,
        &clk,
        ts::ctx(&mut sc),
    );
    let v1_id = object::id(&v1);
    ca::share(v1);
    transfer::public_transfer(cap1, USER1);

    // KEEPER (NOT AGGREGATOR_SERVICE) signs a rebalance — ctx.sender()
    // mismatch → ENoAllowance.
    ts::next_tx(&mut sc, KEEPER);
    {
        let mut v = ts::take_shared_by_id<VaultV1<SUI>>(&sc, v1_id);
        let bal = aggregator_v1::rebalance_user<SUI>(
            &mut v,
            REBALANCE_AMOUNT,
            &clk,
            ts::ctx(&mut sc),
        );
        balance::destroy_for_testing(bal);
        ts::return_shared(v);
    };

    clock::destroy_for_testing(clk);
    ts::end(sc);
}
