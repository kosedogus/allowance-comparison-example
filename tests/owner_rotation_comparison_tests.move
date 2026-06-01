/// # Owner-rotation pattern — v1 vs v2 comparison tests
///
/// Compares `allowance_example::owner_rotation_v1` and
/// `allowance_example::owner_rotation_v2`. Same user-story (rotate
/// authority from multisig A to multisig B), profoundly different
/// flows.
///
/// # Actors
///
/// - `MULTISIG_A`: the current owner authority.
/// - `MULTISIG_B`: the successor.
/// - `SPENDER`: a pre-existing delegate. The point of the comparison is
///   what happens to this delegation when authority rotates.
///
/// # What each test demonstrates
///
/// 1. `happy_v1_owner_cap_transfer` — v1: one `public_transfer` call;
///    every existing allowance entry continues to work; successor can
///    immediately exercise full owner authority.
/// 2. `happy_v2_destroy_recreate` — v2: destroy old vault, create new
///    vault under successor, re-grant the spender. Existing caps are
///    invalidated (cap.vault_id refers to the destroyed vault).
/// 3. `failure_v2_old_cap_dead_after_migration` — v2: the spender's
///    cap from the old vault aborts `EWrongVault` when presented to
///    the new vault. Demonstrates the migration cost — every
///    downstream cap-holder must update.
#[test_only]
module allowance_example::owner_rotation_comparison_tests;

use allowance_example::owner_rotation_v1;
use allowance_example::owner_rotation_v2;
use openzeppelin_allowance::coin_allowance::{Self as ca, Vault as VaultV1, OwnerCap};
use openzeppelin_allowance::spend_vault::{Self as sv, Vault as VaultV2, SpenderCap};
use sui::balance;
use sui::clock;
use sui::coin::{Self, Coin};
use sui::sui::SUI;
use sui::test_scenario as ts;

const MULTISIG_A: address = @0x111A;
const MULTISIG_B: address = @0x222B;
const SPENDER: address = @0x5DDE;

const GRANT_AMOUNT: u64 = 500_000;
const DEPOSIT: u64 = 2_000_000;
const POST_ROTATION_SPEND: u64 = 100_000;
const ONE_YEAR_MS: u64 = 365 * 24 * 60 * 60 * 1000;

// ====================================================================
// === Scenario 1 — v1 happy path: transfer OwnerCap; delegation OK ===
// ====================================================================
#[test]
// Proves: v1 owner rotation = one `public_transfer(cap, NEW_OWNER)`.
// All existing allowance entries survive; new owner immediately exercises
// full authority. The downstream spender is unaware that rotation happened.
fun happy_v1_owner_cap_transfer() {
    let mut sc = ts::begin(MULTISIG_A);
    let clk = clock::create_for_testing(ts::ctx(&mut sc));

    // Tx 1 — MULTISIG_A: create vault, deposit, grant the SPENDER.
    let (mut v, cap) = ca::new<SUI>(ts::ctx(&mut sc));
    let funds = coin::mint_for_testing<SUI>(DEPOSIT, ts::ctx(&mut sc));
    ca::deposit<SUI>(&mut v, funds, ts::ctx(&mut sc));
    ca::grant<SUI>(
        &mut v,
        &cap,
        SPENDER,
        GRANT_AMOUNT,
        ONE_YEAR_MS,
        option::none(),
        option::none(),
        &clk,
        ts::ctx(&mut sc),
    );
    let v_id = object::id(&v);
    ca::share(v);
    transfer::public_transfer(cap, MULTISIG_A);

    // Tx 2 — MULTISIG_A: rotate authority to MULTISIG_B via one
    // `public_transfer`. No ledger touch; no successor signature
    // needed yet.
    ts::next_tx(&mut sc, MULTISIG_A);
    {
        let cap_taken = ts::take_from_address<OwnerCap>(&sc, MULTISIG_A);
        owner_rotation_v1::rotate(cap_taken, MULTISIG_B);
    };

    // Tx 3 — SPENDER continues to spend the SAME pre-existing
    // allowance — the rotation did not break the delegation.
    ts::next_tx(&mut sc, SPENDER);
    {
        let mut v = ts::take_shared_by_id<VaultV1<SUI>>(&sc, v_id);
        let bal_opt = ca::consume<SUI>(&mut v, POST_ROTATION_SPEND, &clk, ts::ctx(&mut sc));
        balance::destroy_for_testing(bal_opt.destroy_some());
        ts::return_shared(v);
    };

    // Tx 4 — MULTISIG_B (successor) exercises full owner authority:
    // withdraw some funds using the cap it now holds.
    ts::next_tx(&mut sc, MULTISIG_B);
    {
        let cap_b = ts::take_from_address<OwnerCap>(&sc, MULTISIG_B);
        let mut v = ts::take_shared_by_id<VaultV1<SUI>>(&sc, v_id);
        let drained: Coin<SUI> = ca::withdraw<SUI>(&mut v, &cap_b, 50_000, ts::ctx(&mut sc));
        assert!(coin::value(&drained) == 50_000, 0);
        transfer::public_transfer(drained, MULTISIG_B);
        ts::return_to_address(MULTISIG_B, cap_b);
        ts::return_shared(v);
    };

    clock::destroy_for_testing(clk);
    ts::end(sc);
}

// =================================================================
// === Scenario 2 — v2 happy path: destroy + recreate + re-grant ===
// =================================================================
#[test]
// Proves: v2 owner rotation requires destroy + recreate + re-grant across
// TWO transactions signed by different addresses (OLD owner destroys;
// NEW owner re-grants). The immutable owner is the trade-off cost.
fun happy_v2_destroy_recreate() {
    let mut sc = ts::begin(MULTISIG_A);
    let clk = clock::create_for_testing(ts::ctx(&mut sc));

    // Tx 1 — MULTISIG_A: create vault, deposit, approve SPENDER (cap
    // is transferred to SPENDER).
    let mut v_old = sv::new<SUI>(MULTISIG_A, ts::ctx(&mut sc));
    let funds = coin::mint_for_testing<SUI>(DEPOSIT, ts::ctx(&mut sc));
    sv::deposit<SUI>(&mut v_old, funds, ts::ctx(&mut sc));
    sv::approve<SUI>(
        &mut v_old,
        GRANT_AMOUNT,
        ONE_YEAR_MS,
        option::none(),
        SPENDER,
        &clk,
        ts::ctx(&mut sc),
    );
    let v_old_id = object::id(&v_old);
    sv::share(v_old);

    // Tx 2 — MULTISIG_A: step 1 — drain old, destroy, recreate under
    // MULTISIG_B, deposit funds, share new vault. MULTISIG_A's authority
    // ENDS here; the new vault is owned by MULTISIG_B.
    ts::next_tx(&mut sc, MULTISIG_A);
    let v_new_id = {
        let v_old_in = ts::take_shared_by_id<VaultV2<SUI>>(&sc, v_old_id);
        owner_rotation_v2::step1_migrate<SUI>(
            v_old_in,
            MULTISIG_B,
            &clk,
            ts::ctx(&mut sc),
        )
    };

    // Tx 3 — MULTISIG_B (the new owner) re-grants SPENDER. This
    // requires a separate transaction signed by MULTISIG_B — v2's
    // owner-side authority cannot be lent across the migration.
    ts::next_tx(&mut sc, MULTISIG_B);
    {
        let mut v_new = ts::take_shared_by_id<VaultV2<SUI>>(&sc, v_new_id);
        owner_rotation_v2::step2_regrant_spender<SUI>(
            &mut v_new,
            SPENDER,
            GRANT_AMOUNT,
            ONE_YEAR_MS,
            &clk,
            ts::ctx(&mut sc),
        );
        ts::return_shared(v_new);
    };

    // Tx 4 — SPENDER receives the NEW cap and uses it on the new vault.
    ts::next_tx(&mut sc, SPENDER);
    {
        let new_cap = ts::take_from_address<SpenderCap>(&sc, SPENDER);
        let mut v_new = ts::take_shared_by_id<VaultV2<SUI>>(&sc, v_new_id);
        let bal = sv::spend<SUI>(
            &mut v_new,
            &new_cap,
            POST_ROTATION_SPEND,
            &clk,
            ts::ctx(&mut sc),
        );
        balance::destroy_for_testing(bal);
        ts::return_to_address(SPENDER, new_cap);
        ts::return_shared(v_new);
    };

    clock::destroy_for_testing(clk);
    ts::end(sc);
}

// =====================================================================
// === Scenario 3 — v2 failure: OLD cap is dead post-migration       ===
// =====================================================================
#[test]
// Proves: v2 migration kills every previously-issued cap (`cap.vault_id`
// refers to the destroyed vault → `EWrongVault`). Every downstream
// cap-holder must update — the v1 OwnerCap-transfer flow has no such
// cascade.
#[expected_failure(
    abort_code = openzeppelin_allowance::spend_vault::EWrongVault,
)]
fun failure_v2_old_cap_dead_after_migration() {
    let mut sc = ts::begin(MULTISIG_A);
    let clk = clock::create_for_testing(ts::ctx(&mut sc));

    // Setup mirrors `happy_v2_destroy_recreate`.
    let mut v_old = sv::new<SUI>(MULTISIG_A, ts::ctx(&mut sc));
    let funds = coin::mint_for_testing<SUI>(DEPOSIT, ts::ctx(&mut sc));
    sv::deposit<SUI>(&mut v_old, funds, ts::ctx(&mut sc));
    sv::approve<SUI>(
        &mut v_old,
        GRANT_AMOUNT,
        ONE_YEAR_MS,
        option::none(),
        SPENDER,
        &clk,
        ts::ctx(&mut sc),
    );
    let v_old_id = object::id(&v_old);
    sv::share(v_old);

    // SPENDER receives the OLD cap. Save it for the re-use attempt.
    ts::next_tx(&mut sc, SPENDER);
    let old_cap = ts::take_from_address<SpenderCap>(&sc, SPENDER);

    // MULTISIG_A migrates (step 1) — destroys old, creates new under
    // MULTISIG_B, deposits funds, shares.
    ts::next_tx(&mut sc, MULTISIG_A);
    let v_new_id = {
        let v_old_in = ts::take_shared_by_id<VaultV2<SUI>>(&sc, v_old_id);
        owner_rotation_v2::step1_migrate<SUI>(
            v_old_in,
            MULTISIG_B,
            &clk,
            ts::ctx(&mut sc),
        )
    };

    // MULTISIG_B re-grants on the new vault (step 2) — required for
    // SPENDER to have any authority at all.
    ts::next_tx(&mut sc, MULTISIG_B);
    {
        let mut v_new = ts::take_shared_by_id<VaultV2<SUI>>(&sc, v_new_id);
        owner_rotation_v2::step2_regrant_spender<SUI>(
            &mut v_new,
            SPENDER,
            GRANT_AMOUNT,
            ONE_YEAR_MS,
            &clk,
            ts::ctx(&mut sc),
        );
        ts::return_shared(v_new);
    };

    // SPENDER attempts to spend on the NEW vault with the OLD cap.
    // EWrongVault: cap.vault_id refers to the destroyed vault.
    ts::next_tx(&mut sc, SPENDER);
    {
        let mut v_new = ts::take_shared_by_id<VaultV2<SUI>>(&sc, v_new_id);
        let bal = sv::spend<SUI>(
            &mut v_new,
            &old_cap,
            POST_ROTATION_SPEND,
            &clk,
            ts::ctx(&mut sc),
        );
        balance::destroy_for_testing(bal);
        ts::return_shared(v_new);
    };

    // Unreachable.
    transfer::public_transfer(old_cap, SPENDER);
    clock::destroy_for_testing(clk);
    ts::end(sc);
}
