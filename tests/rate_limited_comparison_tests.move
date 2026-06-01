/// # Rate-limited charges — v1 vs v2 comparison tests
///
/// Compares `allowance_example::rate_limited_charges_v1` and
/// `allowance_example::rate_limited_charges_v2`. Same user-story (an
/// agent gets a monthly budget with one charge per hour), substantially
/// different integration footprint: v1 needs a parallel
/// `BotPolicy` object with manual time tracking; v2 declares the
/// limiter at `approve` time and the library enforces it.
///
/// # Actors
///
/// - `OWNER`: the user who funds the vault and authorizes the agent.
/// - `AGENT`: the bot performing the periodic charges.
///
/// # What each test demonstrates
///
/// 1. `happy_v1_integrator_side_cooldown` — v1: separate BotPolicy
///    shared object; first charge succeeds, second within cooldown is
///    rejected by integrator code (E_RATE_LIMITED).
/// 2. `happy_v2_embedded_limiter` — v2: limiter attached at approve
///    time; first charge succeeds, second within cooldown aborts
///    `ERateLimited` from the library itself. No integrator-side
///    tracking object.
/// 3. `v2_suspend_and_resume_preserves_cap` — v2-only: owner suspends
///    the agent via `set_allowance(cap_id, 0, ..)`, the agent's next
///    charge aborts `EAllowanceExceeded`, then owner resumes via
///    `set_allowance(cap_id, > 0, ..)`. The cap object held by the
///    agent is the same across both events — wrappers and protocol
///    tables holding `&cap` survive the suspension cycle.
#[test_only]
module allowance_example::rate_limited_comparison_tests;

use allowance_example::rate_limited_charges_v1;
use allowance_example::rate_limited_charges_v2;
use openzeppelin_allowance::coin_allowance::{Self as ca, Vault as VaultV1};
use openzeppelin_allowance::spend_vault::{Self as sv, Vault as VaultV2, SpenderCap};
use sui::balance;
use sui::clock;
use sui::coin;
use sui::sui::SUI;
use sui::test_scenario as ts;

const OWNER: address = @0xA11CE;
const AGENT: address = @0xBEEF;

const MONTHLY_BUDGET: u64 = 1_000_000;
const CHARGE_AMOUNT: u64 = 50_000;
const DEPOSIT: u64 = 2_000_000;
const ONE_YEAR_MS: u64 = 365 * 24 * 60 * 60 * 1000;
const COOLDOWN_MS: u64 = 60 * 60 * 1000;       // 1 hour
const HALF_COOLDOWN_MS: u64 = 30 * 60 * 1000;  // 30 minutes — inside cooldown

// =================================================================
// === Scenario 1 — v1: integrator-side cooldown via BotPolicy   ===
// =================================================================
#[test]
// Proves: v1 has no library-level rate limiter. To get cooldown semantics
// the integrator authors a parallel `BotPolicy` shared object with manual
// `last_charge_ms` tracking; the refusal aborts with an integrator-defined
// error code (100), NOT a library-side ERateLimited.
#[expected_failure(abort_code = 100, location = allowance_example::rate_limited_charges_v1)]
fun happy_v1_integrator_side_cooldown() {
    let mut sc = ts::begin(OWNER);
    let mut clk = clock::create_for_testing(ts::ctx(&mut sc));
    // Move clock past zero so the BotPolicy's `last_charge_ms == 0`
    // initial condition is meaningful (now >= 0 + cooldown).
    clock::increment_for_testing(&mut clk, COOLDOWN_MS + 1);

    // Tx 1 — OWNER: vault, deposit, grant AGENT.
    let (mut v, cap) = ca::new<SUI>(ts::ctx(&mut sc));
    let funds = coin::mint_for_testing<SUI>(DEPOSIT, ts::ctx(&mut sc));
    ca::deposit<SUI>(&mut v, funds, ts::ctx(&mut sc));
    ca::grant<SUI>(
        &mut v,
        &cap,
        AGENT,
        MONTHLY_BUDGET,
        clock::timestamp_ms(&clk) + ONE_YEAR_MS,
        option::none(),
        option::none(),
        &clk,
        ts::ctx(&mut sc),
    );
    let v_id = object::id(&v);
    ca::share(v);
    transfer::public_transfer(cap, OWNER);

    // Tx 2 — OWNER: deploy the integrator-side BotPolicy.
    ts::next_tx(&mut sc, OWNER);
    let policy_id = rate_limited_charges_v1::new_policy(
        AGENT,
        COOLDOWN_MS,
        ts::ctx(&mut sc),
    );

    // Tx 3 — AGENT: first charge succeeds (now >= 0 + cooldown).
    ts::next_tx(&mut sc, AGENT);
    {
        let mut v = ts::take_shared_by_id<VaultV1<SUI>>(&sc, v_id);
        let mut policy = ts::take_shared_by_id<rate_limited_charges_v1::BotPolicy>(&sc, policy_id);
        let bal = rate_limited_charges_v1::charge<SUI>(
            &mut v,
            &mut policy,
            CHARGE_AMOUNT,
            &clk,
            ts::ctx(&mut sc),
        );
        balance::destroy_for_testing(bal);
        ts::return_shared(v);
        ts::return_shared(policy);
    };

    // Advance the clock by less than the cooldown.
    clock::increment_for_testing(&mut clk, HALF_COOLDOWN_MS);

    // Tx 4 — AGENT: second charge BEFORE cooldown elapses → aborts
    // E_RATE_LIMITED (the integrator's code, code 100).
    ts::next_tx(&mut sc, AGENT);
    {
        let mut v = ts::take_shared_by_id<VaultV1<SUI>>(&sc, v_id);
        let mut policy = ts::take_shared_by_id<rate_limited_charges_v1::BotPolicy>(&sc, policy_id);
        let bal = rate_limited_charges_v1::charge<SUI>(
            &mut v,
            &mut policy,
            CHARGE_AMOUNT,
            &clk,
            ts::ctx(&mut sc),
        );
        balance::destroy_for_testing(bal);
        ts::return_shared(v);
        ts::return_shared(policy);
    };

    // Unreachable; expected_failure handles cleanup.
    clock::destroy_for_testing(clk);
    ts::end(sc);
}

// =================================================================
// === Scenario 2 — v2: embedded RateLimiter; library enforces   ===
// =================================================================
#[test]
// Proves: v2 embeds `Option<RateLimiter>` per allowance entry; the library
// itself enforces — second charge inside the cooldown aborts library-side
// `ERateLimited` with NO integrator code path. Same property as v1's
// BotPolicy, zero integrator boilerplate.
#[expected_failure(abort_code = openzeppelin_allowance::spend_vault::ERateLimited)]
fun happy_v2_embedded_limiter() {
    let mut sc = ts::begin(OWNER);
    let mut clk = clock::create_for_testing(ts::ctx(&mut sc));
    // Advance the clock past 0 so the cooldown limiter's anchoring
    // computations are well-defined.
    clock::increment_for_testing(&mut clk, COOLDOWN_MS * 2);

    // Tx 1 — OWNER: vault, deposit, onboard AGENT with cooldown limiter.
    let mut v = sv::new<SUI>(OWNER, ts::ctx(&mut sc));
    let funds = coin::mint_for_testing<SUI>(DEPOSIT, ts::ctx(&mut sc));
    sv::deposit<SUI>(&mut v, funds, ts::ctx(&mut sc));
    rate_limited_charges_v2::onboard_bot<SUI>(
        &mut v,
        AGENT,
        MONTHLY_BUDGET,
        ONE_YEAR_MS,
        CHARGE_AMOUNT,   // per_charge_max — one charge drains the cooldown
        COOLDOWN_MS,
        &clk,
        ts::ctx(&mut sc),
    );
    let v_id = object::id(&v);
    sv::share(v);

    // Tx 2 — AGENT: first charge succeeds.
    ts::next_tx(&mut sc, AGENT);
    {
        let mut v = ts::take_shared_by_id<VaultV2<SUI>>(&sc, v_id);
        let cap = ts::take_from_address<SpenderCap>(&sc, AGENT);
        let bal = rate_limited_charges_v2::charge<SUI>(
            &mut v,
            &cap,
            CHARGE_AMOUNT,
            &clk,
            ts::ctx(&mut sc),
        );
        balance::destroy_for_testing(bal);
        ts::return_to_address(AGENT, cap);
        ts::return_shared(v);
    };

    // Tx 3 — AGENT: second charge IMMEDIATELY (no clock advance) →
    // ERateLimited from the library itself, no integrator code path.
    ts::next_tx(&mut sc, AGENT);
    {
        let mut v = ts::take_shared_by_id<VaultV2<SUI>>(&sc, v_id);
        let cap = ts::take_from_address<SpenderCap>(&sc, AGENT);
        let bal = rate_limited_charges_v2::charge<SUI>(
            &mut v,
            &cap,
            CHARGE_AMOUNT,
            &clk,
            ts::ctx(&mut sc),
        );
        balance::destroy_for_testing(bal);
        ts::return_to_address(AGENT, cap);
        ts::return_shared(v);
    };

    // Unreachable.
    clock::destroy_for_testing(clk);
    ts::end(sc);
}

// ==================================================================
// === Scenario 3 — v2-only: suspend + resume preserves the cap   ===
// ==================================================================
#[test]
// Proves: v2-only suspension idiom — `set_allowance(K, 0, ...)` freezes
// the agent without removing the entry; agent's SAME cap object resumes
// working after `set_allowance(K, > 0, ...)`. Wrappers and protocol tables
// holding `&cap` survive the freeze/resume cycle untouched.
fun v2_suspend_and_resume_preserves_cap() {
    let mut sc = ts::begin(OWNER);
    let mut clk = clock::create_for_testing(ts::ctx(&mut sc));
    clock::increment_for_testing(&mut clk, COOLDOWN_MS * 2);

    // Tx 1 — OWNER bootstraps. Capture the agent's cap_id by reading
    // the most recently created cap object in Tx 2.
    let mut v = sv::new<SUI>(OWNER, ts::ctx(&mut sc));
    let funds = coin::mint_for_testing<SUI>(DEPOSIT, ts::ctx(&mut sc));
    sv::deposit<SUI>(&mut v, funds, ts::ctx(&mut sc));
    rate_limited_charges_v2::onboard_bot<SUI>(
        &mut v,
        AGENT,
        MONTHLY_BUDGET,
        ONE_YEAR_MS,
        CHARGE_AMOUNT,   // per_charge_max — one charge drains the cooldown
        COOLDOWN_MS,
        &clk,
        ts::ctx(&mut sc),
    );
    let v_id = object::id(&v);
    sv::share(v);

    // Tx 2 — AGENT reads its cap_id; spends once.
    ts::next_tx(&mut sc, AGENT);
    let cap_id = {
        let mut v = ts::take_shared_by_id<VaultV2<SUI>>(&sc, v_id);
        let cap = ts::take_from_address<SpenderCap>(&sc, AGENT);
        let cap_id = object::id(&cap);
        let bal = rate_limited_charges_v2::charge<SUI>(
            &mut v,
            &cap,
            CHARGE_AMOUNT,
            &clk,
            ts::ctx(&mut sc),
        );
        balance::destroy_for_testing(bal);
        ts::return_to_address(AGENT, cap);
        ts::return_shared(v);
        cap_id
    };

    // Tx 3 — OWNER suspends the agent (set_allowance with new_amount = 0).
    ts::next_tx(&mut sc, OWNER);
    {
        let mut v = ts::take_shared_by_id<VaultV2<SUI>>(&sc, v_id);
        let cur = sv::allowance<SUI>(&v, cap_id);
        rate_limited_charges_v2::suspend<SUI>(
            &mut v,
            cap_id,
            cur,
            ONE_YEAR_MS,
            option::none(),     // also remove the limiter while suspended
            &clk,
            ts::ctx(&mut sc),
        );
        // Confirm the entry still exists (suspension, NOT revocation).
        assert!(sv::contains<SUI>(&v, cap_id), 0);
        assert!(sv::allowance<SUI>(&v, cap_id) == 0, 1);
        ts::return_shared(v);
    };

    // Tx 4 — OWNER resumes (set_allowance with new_amount > 0).
    ts::next_tx(&mut sc, OWNER);
    {
        let mut v = ts::take_shared_by_id<VaultV2<SUI>>(&sc, v_id);
        rate_limited_charges_v2::resume<SUI>(
            &mut v,
            cap_id,
            MONTHLY_BUDGET / 2,
            ONE_YEAR_MS,
            option::none(),
            &clk,
            ts::ctx(&mut sc),
        );
        assert!(sv::allowance<SUI>(&v, cap_id) == MONTHLY_BUDGET / 2, 2);
        ts::return_shared(v);
    };

    // Tx 5 — AGENT spends with the SAME cap object it was issued
    // originally. cap_id is unchanged across suspend / resume.
    ts::next_tx(&mut sc, AGENT);
    {
        let mut v = ts::take_shared_by_id<VaultV2<SUI>>(&sc, v_id);
        let cap = ts::take_from_address<SpenderCap>(&sc, AGENT);
        assert!(object::id(&cap) == cap_id, 3);
        let bal = rate_limited_charges_v2::charge<SUI>(
            &mut v,
            &cap,
            CHARGE_AMOUNT,
            &clk,
            ts::ctx(&mut sc),
        );
        balance::destroy_for_testing(bal);
        ts::return_to_address(AGENT, cap);
        ts::return_shared(v);
    };

    clock::destroy_for_testing(clk);
    ts::end(sc);
}

