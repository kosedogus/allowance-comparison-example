/// # v2 creator/owner decoupling — bystander handling tests
///
/// v2's `new<U>(initial_owner, ctx)` accepts an arbitrary
/// `initial_owner`; the creator and the named owner are decoupled by
/// default. This unlocks factory deploys and atomic create-fund-handoff
/// patterns, but it also means a bystander
/// address can find a Vault in their inventory that they didn't ask
/// for. This file demonstrates the worst-case attack — Mallory creates
/// + permissionlessly funds a Vault naming Alice as owner — and
/// confirms Alice's defense:
///
/// - Alice has full owner authority on the unsolicited Vault
///   (`ctx.sender() == v.owner == ALICE`).
/// - Alice can `destroy(vault, ctx)` to discard it unconditionally.
///   The leftover balance is returned as a `Coin<U>` Alice receives
///   (any spammer-deposited funds are recovered as a side-effect).
///
/// Net result: not a direct DoS, no funds-loss vector for Alice; the
/// only cost is UI clutter and a phishing-surface that the named owner
/// can clear at will.
///
/// v1 has no equivalent test because v1's `new` returns the OwnerCap
/// to `ctx.sender` — the creator IS the initial owner. The same
/// vector exists in v1 (creator + `public_transfer` of the cap) but
/// is a two-step rather than the default.
#[test_only]
module allowance_example::bystander_v2_tests;

use openzeppelin_allowance::spend_vault::{Self as sv, Vault as VaultV2};
use sui::clock;
use sui::coin::{Self, Coin};
use sui::sui::SUI;
use sui::test_scenario as ts;

const MALLORY: address = @0x6AD;
const ALICE: address = @0xA11CE;

const SPAMMER_DEPOSIT: u64 = 1_000_000;

#[test]
// Proves: v2 bystander-handling — Mallory creates a Vault naming Alice
// as owner and funds it permissionlessly; Alice's `destroy` discards
// the unsolicited Vault and pockets the spammer's deposit as a refund
// (Coin<SUI> Alice receives).
fun v2_bystander_creates_for_alice_alice_destroys() {
    let mut sc = ts::begin(MALLORY);
    let clk = clock::create_for_testing(ts::ctx(&mut sc));

    // Tx 1 — MALLORY mints a Vault naming Alice as owner. Mallory's
    // ctx.sender() is recorded as `creator`; `owner` is Alice. Vault
    // is shared in the same tx (key-only no-drop forces share-or-destroy).
    let mut v = sv::new<SUI>(ALICE, ts::ctx(&mut sc));
    let v_id = object::id(&v);
    assert!(sv::owner(&v) == ALICE, 0);

    // Tx 1 (cont.) — MALLORY permissionlessly deposits some funds. This
    // is allowed by the library design (deposit is permissionless,
    // confers no rights). Mallory is funding Alice's vault on Alice's
    // behalf with no further authority.
    let spammer_coin = coin::mint_for_testing<SUI>(SPAMMER_DEPOSIT, ts::ctx(&mut sc));
    sv::deposit<SUI>(&mut v, spammer_coin, ts::ctx(&mut sc));
    sv::share(v);

    // Tx 2 — ALICE discovers the unsolicited Vault (via VaultCreated
    // event indexing, or via her wallet showing the shared object's
    // owner == her address). She takes the Vault by value out of the
    // shared inventory and calls `destroy`. The library checks
    // `ctx.sender() == v.owner == ALICE` → passes. The leftover
    // balance (Mallory's deposit) is returned to Alice as a Coin.
    ts::next_tx(&mut sc, ALICE);
    {
        let v_in = ts::take_shared_by_id<VaultV2<SUI>>(&sc, v_id);
        let refund: Coin<SUI> = sv::destroy<SUI>(v_in, ts::ctx(&mut sc));
        assert!(coin::value(&refund) == SPAMMER_DEPOSIT, 1);
        // Alice transfers the recovered Coin to herself (or anywhere
        // else — it's hers).
        transfer::public_transfer(refund, ALICE);
    };

    // Tx 3 — Confirm Alice now holds the recovered Coin and the
    // unwanted Vault no longer exists on-chain (no shared object of
    // that ID).
    ts::next_tx(&mut sc, ALICE);
    {
        let received = ts::take_from_address<Coin<SUI>>(&sc, ALICE);
        assert!(coin::value(&received) == SPAMMER_DEPOSIT, 2);
        ts::return_to_address(ALICE, received);
    };

    clock::destroy_for_testing(clk);
    ts::end(sc);
}
