/// # Baseline equivalence — v1 vs v2 common case
///
/// These two tests are the BASELINE: the simplest possible delegation
/// (Alice gets X to spend, no recipient binding, no rate limit), run
/// against both libraries with NO integrator wrapper. They exist to
/// anchor the comparison: outside the special-purpose patterns
/// (bound recipient, protocol-owned caps, rate limiting, owner
/// rotation), the two libraries do the same thing with the same number
/// of effective calls. The naming/argument differences are the visible
/// delta:
///
/// | step              | v1                          | v2                                |
/// |-------------------|-----------------------------|-----------------------------------|
/// | mint              | `new` → `(Vault, OwnerCap)` | `new(initial_owner)` → `Vault`    |
/// | fund              | `deposit(v, c, ctx)`        | `deposit(v, c, ctx)`              |
/// | grant             | `grant(v, &cap, addr, ...)` | `approve(v, ..., addr, ...)`      |
/// | draw (spender)    | `consume(v, amount, ...)`   | `spend(v, &cap, amount, ...)`     |
/// | revoke            | `revoke(v, &cap, addr, ...)`| `revoke(v, cap_id, ctx)`          |
///
/// The spender-side cost asymmetry — v1 spender holds nothing
/// extra (`ctx.sender()` IS authority), v2 spender holds the
/// `SpenderCap` — IS the dividing axis for every comparison further
/// down the readme. This baseline is where it's smallest.
#[test_only]
module allowance_example::baseline_comparison_tests;

use openzeppelin_allowance::coin_allowance::{Self as ca, Vault as VaultV1};
use openzeppelin_allowance::spend_vault::{Self as sv, Vault as VaultV2, SpenderCap};
use sui::balance;
use sui::clock;
use sui::coin;
use sui::sui::SUI;
use sui::test_scenario as ts;

const OWNER: address = @0xA11CE;
const ALICE: address = @0xA11DE;

const GRANT_AMOUNT: u64 = 500_000;
const DRAW: u64 = 100_000;
const DEPOSIT: u64 = 2_000_000;
const ONE_YEAR_MS: u64 = 365 * 24 * 60 * 60 * 1000;

#[test]
// Proves: v1 baseline — owner grants, Alice consumes with no
// integrator wrapper. Sender-keyed authority; bimodal consume's
// unbound arm returns Some(Balance) the caller `.destroy_some()`s.
fun baseline_v1_unbound_delegation() {
    let mut sc = ts::begin(OWNER);
    let clk = clock::create_for_testing(ts::ctx(&mut sc));

    // Tx 1 — OWNER: new + fund + grant + share.
    let (mut v, cap) = ca::new<SUI>(ts::ctx(&mut sc));
    let funds = coin::mint_for_testing<SUI>(DEPOSIT, ts::ctx(&mut sc));
    ca::deposit<SUI>(&mut v, funds, ts::ctx(&mut sc));
    ca::grant<SUI>(
        &mut v,
        &cap,
        ALICE,
        GRANT_AMOUNT,
        ONE_YEAR_MS,
        option::none(),
        option::none(),
        &clk,
        ts::ctx(&mut sc),
    );
    let v_id = object::id(&v);
    ca::share(v);
    transfer::public_transfer(cap, OWNER);

    // Tx 2 — ALICE consumes. ctx.sender() is the authority; no cap
    // object handed to her.
    ts::next_tx(&mut sc, ALICE);
    {
        let mut v = ts::take_shared_by_id<VaultV1<SUI>>(&sc, v_id);
        let bal = ca::consume<SUI>(&mut v, DRAW, &clk, ts::ctx(&mut sc)).destroy_some();
        assert!(balance::value(&bal) == DRAW, 0);
        balance::destroy_for_testing(bal);
        // After: allowance(ALICE) is reduced from GRANT_AMOUNT to
        // GRANT_AMOUNT - DRAW; pool decreased by DRAW.
        assert!(ca::allowance<SUI>(&v, ALICE) == GRANT_AMOUNT - DRAW, 1);
        ts::return_shared(v);
    };

    clock::destroy_for_testing(clk);
    ts::end(sc);
}

#[test]
// Proves: v2 baseline — same end-state as v1 baseline but Alice holds
// a SpenderCap she presents to `spend`. Cap-gated authority; `spend`
// always returns Balance (no Option unwrap).
fun baseline_v2_unbound_delegation() {
    let mut sc = ts::begin(OWNER);
    let clk = clock::create_for_testing(ts::ctx(&mut sc));

    // Tx 1 — OWNER: new(OWNER) + fund + approve(ALICE) + share.
    let mut v = sv::new<SUI>(OWNER, ts::ctx(&mut sc));
    let funds = coin::mint_for_testing<SUI>(DEPOSIT, ts::ctx(&mut sc));
    sv::deposit<SUI>(&mut v, funds, ts::ctx(&mut sc));
    sv::approve<SUI>(
        &mut v,
        GRANT_AMOUNT,
        ONE_YEAR_MS,
        option::none(),
        ALICE,
        &clk,
        ts::ctx(&mut sc),
    );
    let v_id = object::id(&v);
    sv::share(v);

    // Tx 2 — ALICE picks up her cap and spends.
    ts::next_tx(&mut sc, ALICE);
    {
        let mut v = ts::take_shared_by_id<VaultV2<SUI>>(&sc, v_id);
        let cap = ts::take_from_address<SpenderCap>(&sc, ALICE);
        let bal = sv::spend<SUI>(&mut v, &cap, DRAW, &clk, ts::ctx(&mut sc));
        assert!(balance::value(&bal) == DRAW, 0);
        balance::destroy_for_testing(bal);
        assert!(sv::allowance<SUI>(&v, object::id(&cap)) == GRANT_AMOUNT - DRAW, 1);
        ts::return_to_address(ALICE, cap);
        ts::return_shared(v);
    };

    clock::destroy_for_testing(clk);
    ts::end(sc);
}
