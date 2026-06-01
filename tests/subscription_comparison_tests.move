/// # Subscription pattern — v1 vs v2 comparison tests
///
/// Compares `allowance_example::subscription_v1` and
/// `allowance_example::subscription_v2`. Same user-story, same actors,
/// same expected end-state — only the integrator-side code differs.
///
/// # Actors
///
/// - `OWNER`: vault owner (the SaaS subscriber paying for the service).
/// - `AGENT`: billing agent address; signs the charge transactions.
/// - `MERCHANT`: SaaS merchant treasury; receives every monthly fee.
///
/// # What each test demonstrates
///
/// 1. `happy_path_v1_bound_consume` — v1's library does the recipient
///    binding internally; the agent simply calls `consume` each cycle.
/// 2. `happy_path_v2_bounded_delegation` — same end state, but v2
///    requires an integrator-owned `BoundedDelegation` wrapper. Both
///    tests assert the merchant received exactly the fees.
/// 3. `failure_v1_agent_cannot_divert` — even if the agent passes a
///    different recipient on `consume`, the library ignores it: the
///    sealed recipient field of the entry is the only path. (v1's
///    `consume` signature does not accept a recipient parameter, so
///    "diversion" can only happen via the agent calling `withdraw` or
///    similar — which aborts `EWrongOwnerCap`. This test demonstrates
///    THAT path.)
/// 4. `failure_v2_agent_without_bd_cannot_charge` — v2 lock-in: the
///    library's `spend` requires `&SpenderCap`, which lives only inside
///    the `BoundedDelegation`. The agent CANNOT call `spend_vault::spend`
///    directly without the wrapper because the agent does not hold the
///    bare cap.
#[test_only]
module allowance_example::subscription_comparison_tests;

use allowance_example::subscription_v1;
use allowance_example::subscription_v2;
use openzeppelin_allowance::coin_allowance::{Self as ca, Vault as VaultV1};
use openzeppelin_allowance::spend_vault::{Self as sv, Vault as VaultV2};
use sui::clock;
use sui::coin::{Self, Coin};
use sui::sui::SUI;
use sui::test_scenario as ts;

const OWNER: address = @0xA11CE;
const AGENT: address = @0xBEEF;
const MERCHANT: address = @0xCAFE;
const ATTACKER: address = @0xBAD;

const MONTHLY_FEE: u64 = 100_000;
const CYCLES: u64 = 12;
const DEPOSIT: u64 = 2_000_000;
const ONE_YEAR_MS: u64 = 365 * 24 * 60 * 60 * 1000;

// ============================================================
// === Scenario 1 — v1 happy path: library handles recipient ===
// ============================================================
#[test]
// Proves: v1's library-level recipient binding. `grant(..., Some(MERCHANT))`
// + `consume` → coins land at MERCHANT without integrator wrapper code.
fun happy_path_v1_bound_consume() {
    let mut sc = ts::begin(OWNER);

    // Tx 1 — OWNER: bootstrap vault, deposit, grant agent with sealed merchant.
    let clk = clock::create_for_testing(ts::ctx(&mut sc));
    let (mut v, cap) = ca::new<SUI>(ts::ctx(&mut sc));
    let funds = coin::mint_for_testing<SUI>(DEPOSIT, ts::ctx(&mut sc));
    subscription_v1::fund<SUI>(&mut v, funds, ts::ctx(&mut sc));
    subscription_v1::onboard_merchant<SUI>(
        &mut v,
        &cap,
        AGENT,
        MERCHANT,
        MONTHLY_FEE,
        CYCLES,
        ONE_YEAR_MS,
        &clk,
        ts::ctx(&mut sc),
    );
    ca::share(v);
    transfer::public_transfer(cap, OWNER);

    // Tx 2 — AGENT: charge cycle 1.
    ts::next_tx(&mut sc, AGENT);
    {
        let mut v = ts::take_shared<VaultV1<SUI>>(&sc);
        subscription_v1::charge_cycle<SUI>(&mut v, MONTHLY_FEE, &clk, ts::ctx(&mut sc));
        ts::return_shared(v);
    };

    // Tx 3 — assert MERCHANT received exactly the fee, NOT the agent.
    ts::next_tx(&mut sc, MERCHANT);
    {
        let received = ts::take_from_address<Coin<SUI>>(&sc, MERCHANT);
        assert!(coin::value(&received) == MONTHLY_FEE, 0);
        ts::return_to_address(MERCHANT, received);
    };

    // No funds should be sitting in AGENT's address.
    assert!(!ts::has_most_recent_for_address<Coin<SUI>>(AGENT), 1);

    clock::destroy_for_testing(clk);
    ts::end(sc);
}

// ===================================================================
// === Scenario 2 — v2 happy path: BoundedDelegation wrapper required ===
// ===================================================================
#[test]
// Proves: v2 must reach the same recipient-pinned end-state through an
// integrator-owned wrapper (BoundedDelegation seals MERCHANT at wrap time).
// Same safety property, ~30 LoC more integrator code than v1.
fun happy_path_v2_bounded_delegation() {
    let mut sc = ts::begin(OWNER);

    // Tx 1 — OWNER: vault + fund + mint cap + wrap + transfer wrapper to AGENT.
    let clk = clock::create_for_testing(ts::ctx(&mut sc));
    let mut v = sv::new<SUI>(OWNER, ts::ctx(&mut sc));
    let funds = coin::mint_for_testing<SUI>(DEPOSIT, ts::ctx(&mut sc));
    subscription_v2::fund<SUI>(&mut v, funds, ts::ctx(&mut sc));
    subscription_v2::onboard_merchant<SUI>(
        &mut v,
        AGENT,
        MERCHANT,
        MONTHLY_FEE,
        CYCLES,
        ONE_YEAR_MS,
        &clk,
        ts::ctx(&mut sc),
    );
    sv::share(v);

    // Tx 2 — AGENT: charge cycle 1, using the BoundedDelegation it owns.
    ts::next_tx(&mut sc, AGENT);
    {
        let mut v = ts::take_shared<VaultV2<SUI>>(&sc);
        let bd = ts::take_from_address<subscription_v2::BoundedDelegation>(&sc, AGENT);
        assert!(subscription_v2::recipient(&bd) == MERCHANT, 0);
        subscription_v2::charge_cycle<SUI>(
            &mut v,
            &bd,
            MONTHLY_FEE,
            &clk,
            ts::ctx(&mut sc),
        );
        ts::return_to_address(AGENT, bd);
        ts::return_shared(v);
    };

    // Tx 3 — MERCHANT received the fee, AGENT did not.
    ts::next_tx(&mut sc, MERCHANT);
    {
        let received = ts::take_from_address<Coin<SUI>>(&sc, MERCHANT);
        assert!(coin::value(&received) == MONTHLY_FEE, 1);
        ts::return_to_address(MERCHANT, received);
    };
    assert!(!ts::has_most_recent_for_address<Coin<SUI>>(AGENT), 2);

    clock::destroy_for_testing(clk);
    ts::end(sc);
}

// ====================================================================
// === Scenario 3 — v1 failure: attacker with wrong cap cannot drain ===
// ====================================================================
// Demonstrates that the owner-side authority binding is itself the v1
// safety property protecting the merchant: even if an attacker controls
// a different OwnerCap, presenting it aborts EWrongOwnerCap (code 0).
#[test]
// Proves: v1 cap-vault binding (`EWrongOwnerCap`) is the owner-side
// safety perimeter — attacker holding a cap from a different vault
// cannot grant on the victim's vault.
#[expected_failure(
    abort_code = openzeppelin_allowance::coin_allowance::EWrongOwnerCap,
)]
fun failure_v1_wrong_cap_cannot_grant() {
    let mut sc = ts::begin(OWNER);
    let clk = clock::create_for_testing(ts::ctx(&mut sc));

    // OWNER creates vault A with its own cap; captures the ID so we
    // can reach it specifically later.
    let (v_a, cap_a) = ca::new<SUI>(ts::ctx(&mut sc));
    let v_a_id = object::id(&v_a);
    ca::share(v_a);
    transfer::public_transfer(cap_a, OWNER);

    // Attacker creates a *separate* vault B and obtains its cap.
    ts::next_tx(&mut sc, ATTACKER);
    let (v_b, cap_b) = ca::new<SUI>(ts::ctx(&mut sc));
    ca::share(v_b);

    // Attacker tries to use cap_b against vault A → EWrongOwnerCap.
    ts::next_tx(&mut sc, ATTACKER);
    let mut v_a_shared = ts::take_shared_by_id<VaultV1<SUI>>(&sc, v_a_id);
    subscription_v1::onboard_merchant<SUI>(
        &mut v_a_shared,
        &cap_b,                 // ← wrong cap; aborts here
        AGENT,
        ATTACKER,               // ← would be the diverted recipient
        MONTHLY_FEE,
        1,
        ONE_YEAR_MS,
        &clk,
        ts::ctx(&mut sc),
    );

    // Unreachable; the abort above ends the tx. Cleanup for completeness.
    ts::return_shared(v_a_shared);
    transfer::public_transfer(cap_b, ATTACKER);
    clock::destroy_for_testing(clk);
    ts::end(sc);
}

// =====================================================================
// === Scenario 4 — v2 failure: agent without cap cannot call spend  ===
// =====================================================================
// v2's `spend` requires `&SpenderCap`. The BoundedDelegation wrapper holds
// it; the AGENT only holds the WRAPPER. The agent cannot extract the cap
// (it's not a public field), and cannot mint a fresh one (mint_cap is
// owner-gated). The closest "diversion" attempt is the agent trying to
// `spend` against a different vault using a stolen / forged cap — which
// aborts EWrongVault (code 1).
#[test]
// Proves: v2 cap-vault binding (`EWrongVault`) — `cap.vault_id`
// immutable from mint protects against cross-vault confusion when
// store + transferable caps circulate.
#[expected_failure(
    abort_code = openzeppelin_allowance::spend_vault::EWrongVault,
)]
fun failure_v2_cross_vault_cap_cannot_spend() {
    let mut sc = ts::begin(OWNER);
    let clk = clock::create_for_testing(ts::ctx(&mut sc));

    // OWNER mints vault A and wraps a cap inside a BoundedDelegation
    // bound to vault A; gives the wrapper to AGENT.
    let mut v_a = sv::new<SUI>(OWNER, ts::ctx(&mut sc));
    let funds = coin::mint_for_testing<SUI>(DEPOSIT, ts::ctx(&mut sc));
    subscription_v2::fund<SUI>(&mut v_a, funds, ts::ctx(&mut sc));
    subscription_v2::onboard_merchant<SUI>(
        &mut v_a,
        AGENT,
        MERCHANT,
        MONTHLY_FEE,
        CYCLES,
        ONE_YEAR_MS,
        &clk,
        ts::ctx(&mut sc),
    );
    sv::share(v_a);

    // OWNER also creates vault B (unrelated to AGENT); capture its ID.
    ts::next_tx(&mut sc, OWNER);
    let v_b = sv::new<SUI>(OWNER, ts::ctx(&mut sc));
    let v_b_id = object::id(&v_b);
    sv::share(v_b);

    // AGENT tries to use its bd (bound to vault A) against vault B.
    ts::next_tx(&mut sc, AGENT);
    let mut v_b_shared = ts::take_shared_by_id<VaultV2<SUI>>(&sc, v_b_id);
    let bd = ts::take_from_address<subscription_v2::BoundedDelegation>(&sc, AGENT);
    subscription_v2::charge_cycle<SUI>(
        &mut v_b_shared,
        &bd,
        MONTHLY_FEE,
        &clk,
        ts::ctx(&mut sc),
    );
    // Unreachable.
    ts::return_to_address(AGENT, bd);
    ts::return_shared(v_b_shared);
    clock::destroy_for_testing(clk);
    ts::end(sc);
}

