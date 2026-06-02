# Allowance v1 vs v2 — Integration Comparison

Side-by-side integration examples for `openzeppelin_allowance::coin_allowance`
(v1) and `openzeppelin_allowance::spend_vault` (v2). Each scenario is
implemented twice against the same user-story so the team can see, in real
compiling Move, where v1 is easier and where v2 is easier — and cherry-pick
accordingly.

The comparison subjects: recipient binding, spender identity, owner identity,
and rate limiting.

---

## What changed v1 → v2

Structural deltas at the library level. Each row is a factual delta — the
trade-off discussion is in the per-pattern sections below.

| Aspect | v1 (`coin_allowance`) | v2 (`spend_vault`) |
|---|---|---|
| **Module / function naming** | `coin_allowance` / `grant` / `consume` | `spend_vault` / `approve` / `spend` |
| **Owner API surface (grant-side)** | 2 functions — `grant` (overwrites; finite expiry), `grant_indefinite` (no expiry) | 3 functions — `approve` (mints + transfers cap to recipient in one call), `mint_cap` (returns cap by value for embedding), `set_allowance` (in-place update on existing entry) |
| **Owner identity** | `OwnerCap` (`key + store`) — possession-as-authority | Immutable `owner: address` set at `new`; sender-equality gate |
| **Spender identity** | Address-keyed `Table<address, Allowance>`; `consume` auths on `ctx.sender()` | `SpenderCap` (`key + store`) + `Table<ID, Allowance>`; `spend` auths on cap presentation |
| **`consume` / `spend` return** | `Option<Balance<U>>` — bimodal (`None` on bound path, `Some` on unbound) | `Balance<U>` always |
| **Recipient binding** | `Allowance.recipient: Option<address>`; bound `consume` does `public_transfer` internally | Not in the library; integrator authors a `BoundedDelegation` wrapper that pins the recipient |
| **Unlimited / no-expiry** | `grant_indefinite` is a separate function; `expires_at_ms: u64` finite-only | `u64::MAX` sentinels for `remaining` (unlimited, no decrement) and `expires_at_ms` (no expiry) on one API |
| **Rate limiting** | Not in the library | `Option<RateLimiter>` per allowance entry; library calls `try_consume` inside `spend` |
| **Update an existing entry** | `grant` overwrites (including recipient); cap-holder's reference is invalidated | `set_allowance(cap_id, ...)` mutates in place; `cap_id` stable across calls |
| **Suspension idiom** | Not supported (revoke removes the entry; re-grant rewrites) | `set_allowance(cap_id, 0, ...)` keeps the entry alive; `spend(&cap, > 0)` aborts `EAllowanceExceeded` |
| **Creator vs. owner of a fresh Vault** | Identical — `new` returns the OwnerCap to `ctx.sender()`; same address by default | Decoupled — `new(initial_owner, ctx)` accepts any address; creator and owner may differ |

**Note on `u64::MAX` sentinels.** v2 removes the "is `None` infinite or
absent?" ambiguity by using one convention (`u64::MAX` = unlimited /
no-expiry) instead of `Option<u64>`. The cost is an explicit
no-decrement branch inside `spend` for the sentinel — one extra audit
point in the hot path.

---

## At-a-glance — decisions the team picks

The body of this document is organized as **four decisions** the team
makes once. Each decision is illustrated by one or more scenarios from
the integration code. **Decision 3 bundles two faces** that pull in
opposite directions — picking that decision picks both face
consequences at once.

| Decision | Scenario | Easier in | Why |
|---|---|---|---|
| **D1 — Recipient binding** | Subscription (locked-recipient bot charges) | **v1** | v1's library does recipient binding internally (`recipient: Option<address>`). v2 needs the integrator to author a `BoundedDelegation` wrapper. |
| **D2 — Spender identity** | Yield aggregator (protocol-owned per-user delegations) | **v2** | v2's `SpenderCap` is `key + store`, embeddable in a `Table<address, UserRecord>`. v1's address-keyed spender conflates aggregator identity with delegation authority. |
| **D2 (sub-property)** | Suspension idiom (freeze without breaking embedded caps) | **v2-only** | `set_allowance(K, 0, ...)` keeps the entry alive and the cap stable. v1 has no equivalent — revoke removes the entry; re-grant has no embedded-cap stability story (address-keyed). |
| **D2 (sub-property)** | Cap-ID stability across `set_allowance` | **v2-only** | Owner-side parameter changes mutate the entry in place; the cap object held by downstream wrappers / protocol tables survives untouched. |
| **D3 — Owner identity** (Face A) | Owner rotation (multisig A → multisig B) | **v1** | v1's `OwnerCap` is a transferable object — one `public_transfer`. v2's owner address is immutable; rotation = destroy + recreate + re-grant every spender. |
| **D3 — Owner identity** (Face B) | Owner provenance check (integrator verifies "caller owns this vault") | **v2** | v2 exposes `sv::owner(&v) -> address` — the address itself is readable on-chain and compares to anything. v1 cannot read the owner address from `&Vault` at all (it lives in Sui's object-ownership layer, not on the vault); the cap-passing workaround proves only "caller is the owner," not "address X is." |
| **D4 — Rate limiting** | Rate-limited charges (one charge per hour) | **v2** | v2 ships `Option<RateLimiter>` per allowance — library enforces. v1 needs an integrator-side `BotPolicy` object with manual time tracking. |

**D3 is bundled.** Pick v1's transferable `OwnerCap` → accept the Face
B integrator-API cost. Pick v2's immutable `owner: address` → accept
the Face A rotation cost. There is no library shape that wins both
faces.

---

## Repository layout

```
allowance_example/
├── Move.toml
├── README.md                                this file
├── sources/
│   ├── library/                             VENDORED, unmodified
│   │   ├── coin_allowance.move              v1
│   │   ├── spend_vault.move                 v2
│   │   └── rate_limiter.move                openzeppelin_utils dep used by v2
│   └── integration/                         the comparison
│       ├── subscription_v1.move
│       ├── subscription_v2.move
│       ├── aggregator_v1.move
│       ├── aggregator_v2.move
│       ├── owner_rotation_v1.move
│       ├── owner_rotation_v2.move
│       ├── owner_check_v1.move
│       ├── owner_check_v2.move
│       ├── rate_limited_charges_v1.move
│       └── rate_limited_charges_v2.move
└── tests/
    ├── baseline_comparison_tests.move        Scenario A — equivalence of common case
    ├── subscription_comparison_tests.move
    ├── aggregator_comparison_tests.move
    ├── owner_rotation_comparison_tests.move
    ├── owner_check_comparison_tests.move     On-chain owner provenance check
    ├── rate_limited_comparison_tests.move
    └── bystander_v2_tests.move               v2-only — creator/owner decoupling, Alice destroys spam
```

`sources/library/rate_limiter.move` is vendored locally — a verbatim
copy of `openzeppelin_utils::rate_limiter` — so this example builds
standalone without resolving the sibling utils package. v2's library
references the type via `openzeppelin_utils::rate_limiter::RateLimiter`;
the vendored file lives under the matching address in `Move.toml`.

Every `#[test]` carries a one-line `// Proves: …` tag — grep for it
to skim the comparison axes without reading the design doc.

## Foundational properties — both versions

These semantics are true on v1 AND v2. Important context before reading
the per-pattern verdicts: this is **delegated draw against a pool the
owner controls**, not custody / escrow. A reviewer conflating it with
Sui Payment Kit (which actually escrows) will mis-evaluate the design.

- **Allowance ≠ guarantee (ceiling semantics).** `Sum(remaining)` across
  live spenders may exceed `vault.balance` — over-subscription is
  allowed by design. A `consume` / `spend` call with `remaining > 0`
  can still abort `EInsufficientVault` if the pool is short at draw
  time. This mirrors the ERC-20 `transferFrom` revert model.
- **Owner can always defund.** Both libraries' `withdraw` /
  `withdraw_all` consult only the owner gate and the pool balance —
  not the allowance ledger. The owner can drain the pool unilaterally,
  rendering outstanding allowances unfulfillable. No spender state can
  block this; it is intentional, not a bug.
- **Permissionless deposit.** Anyone may `deposit` into either vault.
  Deposited funds become owner-withdrawable property and spender-
  drawable within existing grants. Depositor obtains no rights.
  Convenience: third-party top-ups are trivial. Cost: a dust-spam
  vector — an attacker can flood the indexer event stream with 1-unit
  deposits. (v2's library rejects 0-value deposits; v1 silently
  accepts them.)
- **CAS guard on owner-side updates (opt-in, both versions).** Both
  libraries accept `expected: Option<u64>` on the owner-side update
  call (v1: `grant`, v2: `set_allowance`). With `Some(e)`, the call
  aborts `EUnexpectedAllowance` unless the current `remaining` equals
  `e`; with `None`, the update is unconditional. Same shape on both
  sides; same semantics. The team may want to discuss inverting the
  default (CAS-on by default) — that decision is orthogonal to the
  v1/v2 cherry-pick.
- **Reentrancy structurally absent.** Sui transfers execute no code at
  the destination — no fallback, no receive hook, no synchronous
  callback. `consume` / `spend` returning a `Balance<U>` or doing an
  internal `public_transfer` is reentrancy-safe by Sui's platform
  guarantee, not by a guard inside this library.
- **Broadest applicability driver.** The headline use case is **DAO /
  treasury delegating bounded spend to N keeper addresses against a
  shared pool**, where `Sum(remaining) > balance` is normal and the
  ceiling-semantics property is the safety story. Both libraries
  support this; the aggregator pattern (Decision 2) is the closest
  worked example.
- **Key-loss recovery shapes are asymmetric** (factual, both versions):
  - v1: if the `OwnerCap` is lost (transferred to a dead address,
    mistakenly destroyed), the vault's pool is permanently locked —
    no path to defund. Losing a spender's wallet key is recoverable:
    the owner can `revoke` and re-grant from a fresh address.
  - v2: if a `SpenderCap` is lost, the ledger entry remains but
    cannot be drawn; the owner can `revoke(cap_id)` and `mint_cap`
    a fresh one (the lost cap remains as inert garbage in nobody's
    wallet). If the v2 owner key is lost, the vault is equally
    stuck — but the authoritative address is queryable on-chain,
    supporting any off-chain recovery flow at the address-resolution
    layer.

---

## Decision 1 — Recipient binding (library-internal vs integrator wrapper)

**User-story.** A SaaS owner pays a fixed monthly fee to a merchant treasury
via a billing agent; the agent must never be able to divert the funds.

### v1 — library does the binding

```move
// Onboarding (one line, called by the OWNER, library does the rest):
ca::grant<USDC>(
    &mut v, &cap,
    AGENT,                          // spender (the agent's address)
    monthly_fee * cycles,
    expires_at_ms,
    option::some(MERCHANT),         // ← sealed recipient
    option::none(),                 // expected
    &clock, ctx,
);

// Each cycle (AGENT signs):
ca::consume<USDC>(&mut v, monthly_fee, &clock, ctx).destroy_none();
// Library mints Coin<USDC>, public_transfers to MERCHANT, returns None.
```

**Verdict:** v1 ships the recipient-pinning safety property end-to-end.
Zero integrator code. Approximately 4 lines.

**Cost of choosing v1 here:** `consume` returns `Option<Balance<U>>` —
bimodal. Every unbound caller writes `.destroy_some()`; every bound
caller writes `.destroy_none()`. Type-level papercut on every
integration. And the library does an internal `public_transfer` on the
bound path — the Sui ecosystem default is "return objects, let the
caller compose"; v1 deviates from that on this path.

### v2 — integrator authors a wrapper

```move
public struct BoundedDelegation has key, store {
    id: UID,
    cap: SpenderCap,
    recipient: address,             // sealed at wrap time, private field
}

public fun onboard_merchant<U>(... ) {
    let cap = sv::mint_cap<U>(v, monthly_fee * cycles, expires_at_ms, ...);
    let bd = BoundedDelegation { id: object::new(ctx), cap, recipient };
    transfer::public_transfer(bd, agent);
}

public fun charge_cycle<U>(v, bd: &BoundedDelegation, monthly_fee, clock, ctx) {
    let bal = sv::spend<U>(v, &bd.cap, monthly_fee, clock, ctx);
    transfer::public_transfer(coin::from_balance(bal, ctx), bd.recipient);
}
```

**Verdict:** safety property preserved (the wrapper seals the recipient at
construction); ~30 lines of integrator code; library is fully composable for
every other caller because `spend` always returns `Balance<U>`. The v2
design's deliberate trade: library composability over library convenience.

See [`subscription_v1.move`](sources/integration/subscription_v1.move),
[`subscription_v2.move`](sources/integration/subscription_v2.move), and
[`subscription_comparison_tests.move`](tests/subscription_comparison_tests.move).

---

## Decision 2 — Spender identity (address-keyed vs cap-keyed delegation)

**User-story.** A yield aggregator onboards N users, holds per-user
delegations, and rebalances each user's funds inside its own functions.

### v1 — aggregator-as-spender (workable but coupled)

```move
// USER1 grants the aggregator's service address:
ca::grant<USDC>(&mut v1, &cap1, AGGREGATOR_SERVICE, delegation_cap, ...);

// AGGREGATOR_SERVICE keeper signs a rebalance tx — ctx.sender() == service:
ca::consume<USDC>(&mut v, amount, &clock, ctx).destroy_some()
```

**Verdict:** works, but the aggregator MUST act through one published
address; that address IS the spender for every user. The keeper signs each
user's rebalance individually — **one transaction per user, per cycle**.
There is no path to rebalance multiple users in a single PTB from a
non-spender keeper key.

### v2 — protocol-owned cap table

```move
public struct UserRecord has key, store {
    id: UID,
    cap: SpenderCap,                // bearer authority, embedded
    policy_strategy_id: u64,
}
public struct Aggregator has key {
    id: UID,
    users: ObjectTable<address, UserRecord>,
}

// USER1 mints + hands over:
let cap = sv::mint_cap<USDC>(&mut v1, delegation_cap, ...);
agg.users.add(USER1, UserRecord { id: object::new(ctx), cap, policy_strategy_id });

// Keeper rebalances USER1 AND USER2 in ONE PTB, signed from the keeper key
// (which is NEITHER user — authority is cap-presentation, not sender):
let bal1 = aggregator_v2::rebalance_user<USDC>(&mut agg, &mut v1, USER1, amount, ...);
let bal2 = aggregator_v2::rebalance_user<USDC>(&mut agg, &mut v2, USER2, amount, ...);
```

> **Note — why v2 ships both `approve` and `mint_cap`.** `approve` is
> the one-call convenience path: it mints the cap and immediately
> `public_transfer`s it to the named recipient. Used in Patterns 1
> (subscription onboard via wrapper handed to the agent), 3 (rotation
> re-grant), and 5 (rate-limited onboarding). `mint_cap` returns the
> cap **by value** so the caller can embed it inside their own
> wrapper / table in the same PTB — used here in Decision 2, and in
> Decision 1's v2 wrapper. Without `mint_cap`, embedded composition
> would require an extra TTO ceremony per cap. Two functions cover
> the convenience / composability spectrum; both share `set_allowance`
> for in-place updates afterwards.
>
> One caveat about `approve`: it does an internal `public_transfer`
> of the freshly minted cap inside the library call. The general Sui
> guidance is "return objects, let the caller decide their disposition"
> — `approve` is the convenience exception, and the same critique that
> applies to v1's bound-path `consume` technically also applies to
> `approve`. If the team wants to avoid library-side `public_transfer`
> uniformly, ship `mint_cap` only and drop `approve`.
> `mint_cap` is the composable alternative; integrators worried about
> the pattern can use `mint_cap` everywhere and skip `approve`.

**Verdict:** v2's cap-as-object embeds naturally in a protocol-owned table;
the keeper rebalances arbitrarily many users in one PTB. **And** `cap_id` is
stable across `set_allowance`: the owner can reduce/suspend/refund without
invalidating the aggregator's stored cap (test
[`v2_cap_id_survives_set_allowance`](tests/aggregator_comparison_tests.move)
demonstrates this).

**Cost of choosing v2 here:**
- **Cap is bearer authority.** `SpenderCap` is `key + store` — freely
  `public_transfer`-able. Whoever holds the cap can spend; the
  owner-mental-model "I delegated to Alice" becomes "I minted cap K
  for Alice — but cap K may now be in Bob's wallet." Owner-side
  revocation is keyed on `cap_id`, not on a stable spender address.
- **Inert cap garbage post-revoke.** `revoke(cap_id)` removes the
  ledger entry; the cap object itself stays in its holder's wallet as
  inert garbage. The owner cannot destroy a cap they don't hold —
  structural on Sui (no on-chain wallet enumeration). Cap-holders
  must self-clean by `public_transfer`ing to `@0x0` or simply leaving
  the cap dormant.
- **Audit boundary extends into integrator code.** The
  `BoundedDelegation` / aggregator-table wrappers ARE the safety
  surface for the patterns they implement. The library is fully
  composable, but the recipient-pinning / per-user-isolation
  guarantees now live in unaudited integrator code unless the
  integrator vendors and audits these wrappers.
- **Indexer-side complexity** — see the "Off-chain indexer cost"
  section below.

See [`aggregator_v1.move`](sources/integration/aggregator_v1.move),
[`aggregator_v2.move`](sources/integration/aggregator_v2.move), and
[`aggregator_comparison_tests.move`](tests/aggregator_comparison_tests.move).

---

## Decision 3 — Owner identity (transferable cap vs immutable address)

This is one decision with **two faces** — owner rotation and on-chain
owner verification — that pull in opposite directions. The team picks
**both consequences together**: there is no "v1's rotation + v2's
verification" — picking the owner-identity model picks both faces of
its trade.

The two faces have separate integration code in this example
(`owner_rotation_*` and `owner_check_*`) precisely so each can be
inspected in isolation; the bundled trade-off summary at the end of
this section is the bottom line.

### Face A — Owner rotation

**User-story.** Treasury control needs to move from multisig A to
multisig B without remigrating any of the existing delegations.

#### v1 — OwnerCap is `key + store`, transferable

```move
// One call:
transfer::public_transfer(cap, MULTISIG_B);
// Existing allowance entries untouched; spenders unaffected;
// MULTISIG_B can immediately grant / revoke / withdraw on the same vault.
```

`OwnerCap` is also composable with `openzeppelin_access::two_step_transfer`
and `delayed_transfer` for two-step / timelocked handoffs — no coupling
built into the allowance library, pure natural composition. The full
shape is:

```move
// 1. Owner A wraps its OwnerCap behind two-step transfer.
let pending = openzeppelin_access::two_step_transfer::wrap(cap, NEW_OWNER, ctx);
// 2. Eventually NEW_OWNER calls accept_transfer to unwrap and own the cap.
let cap = openzeppelin_access::two_step_transfer::accept_transfer<OwnerCap>(pending, ctx);
```

The allowance library is unaware of the wrap; the spender side is
unaffected throughout. v2 has no equivalent shape because there is no
`OwnerCap` to wrap.

**Verdict:** ~1 line. Every existing delegation survives. The
delegate-spender side is completely unaware that rotation happened.

**Cost of choosing v1 here:**
- **Bare-cap mistransfer is one tx with no recovery.**
  `transfer::public_transfer(cap, WRONG_ADDR)` permanently moves owner
  authority. There is no library-level safety net; the only mitigation
  is to wrap the cap behind `openzeppelin_access::two_step_transfer`
  or `delayed_transfer` BEFORE handing it off. The "two-step wrap"
  example above is the recommended habit, not the default posture —
  a careless owner using bare `public_transfer` can lose the vault.
- **Cap loss = funds locked.** If the OwnerCap is sent to a dead
  address (or destroyed in a `coin::destroy_zero` style mistake), the
  vault's pool is permanently locked — no path to defund. v2's
  equivalent is "the named owner address must hold its key"; if that
  key is lost, the vault is equally stuck, but v2 at least makes the
  authoritative address visible on-chain for off-chain recovery flows.

#### v2 — destroy + recreate + re-grant (two transactions, two signers)

```move
// Tx 1 — MULTISIG_A signs:
let new_id = owner_rotation_v2::step1_migrate<USDC>(old_vault, MULTISIG_B, &clk, ctx);
// destroys old vault, mints new vault owned by MULTISIG_B, deposits refunded
// funds, shares new vault. MULTISIG_A's authority ends here.

// Tx 2 — MULTISIG_B signs (because approve is gated on v.owner):
owner_rotation_v2::step2_regrant_spender<USDC>(&mut v_new, SPENDER, amount, ...);
// Iterate over EVERY spender from the off-chain ledger.
```

The OLD `SpenderCap` objects in spenders' wallets are now inert garbage —
`spend(&old_cap, ...)` on the new vault aborts `EWrongVault` (test
[`failure_v2_old_cap_dead_after_migration`](tests/owner_rotation_comparison_tests.move)
confirms this). Every downstream cap-holder must update to the new cap.

**Verdict:** v2's "rotation by remigration" is the documented trade-off
of DeepBook V3-style immutable-owner. It works for governance-address
owners (where rotation lives in the multisig itself) and for greenfield
setups; it's painful when authority must actually move and the
delegation tree is wide.

**Quantified cost.** Re-granting N spenders = N + 3 transactions
(`destroy` + `new` + `deposit` + N × `approve`) — or one PTB up to
size limits. For N = 1–10 that's fine; for DAO-scale N = 100+ it is
infeasible in a single PTB and requires a multi-tx migration
campaign with off-chain coordination.

See [`owner_rotation_v1.move`](sources/integration/owner_rotation_v1.move),
[`owner_rotation_v2.move`](sources/integration/owner_rotation_v2.move), and
[`owner_rotation_comparison_tests.move`](tests/owner_rotation_comparison_tests.move).

### Face B — On-chain owner verification

**User-story.** A downstream protocol (limit-order book, escrow
registry, marketplace listing) wants to refuse interactions unless the
caller is the rightful owner of the vault they are pointing at.

#### v1 — the owner address cannot be read on-chain at all

`Vault` has no `owner` field; `OwnerCap` has no `owner_address` field
either (it carries only `id` and `vault_id`). The owner's address
lives in Sui's runtime object-ownership layer (whichever address
currently holds the `OwnerCap` object), and Move code has no
primitive to read "the current owner of object X." That information
is reachable only via off-chain RPC.

The closest workaround at the integration level is to have the
**caller pass their `&OwnerCap` as a function parameter** and verify
its binding:

```move
public fun place_order<U>(v: &Vault<U>, cap: &OwnerCap, ...) {
    assert!(coin_allowance::cap_id(v) == object::id(cap), E_WRONG_VAULT);
    // proceed
}
```

What this actually proves — and what it does NOT prove:

- ✅ Proves "the cap that authorizes this vault is in this PTB." By
  Sui's object-input semantics, the cap must be an input the
  transaction is authorized for — so for the common case where the
  owner holds the cap directly, this proves "the caller is the owner."
- ❌ Does **not** expose the owner's address to integrator code.
  v1 cannot answer "is `0xALICE` the owner of this vault?" for an
  arbitrary `0xALICE` on-chain — there is no path from `&Vault` to
  an address. Off-chain RPC can answer it; Move cannot.
- ❌ Does **not** generalize if the cap is wrapped in a shared
  custody object (multisig, DAO). The wrapper's own auth logic
  decides who can extract `&cap`; the binding check sees only "cap
  matches vault," not "caller is the human behind the wrapper."

**Cost of choosing v1 here:** the workaround only answers "is the
caller the owner?" in the simple case. Any integrator function that
needs to know **who** the owner is, or to verify ownership by a
specific address (without forcing that address to pass their cap
in), is not expressible against v1's `&Vault` alone. Beyond the
capability gap, every function that uses the workaround takes an
extra `&OwnerCap` parameter and forces every caller to plumb the
cap into the PTB.

#### v2 — integrator reads `vault.owner` directly

```move
public fun place_order<U>(v: &Vault<U>, ..., ctx: &TxContext) {
    assert!(spend_vault::owner(v) == ctx.sender(), E_NOT_OWNER);
    // proceed
}
```

`spend_vault::owner(&v)` returns the stored owner `address` as a
total, on-chain read. The integrator can compare it to `ctx.sender()`,
to a known constant, to a value stored in another object, or to an
arbitrary argument — the address is exposed, not just verifiable by
proxy. The property is sound because `v.owner` is immutable from
`new` (nothing can rotate underneath in-flight state).

This is **strictly more expressive** than v1's cap-passing workaround,
not a different ergonomic. v1 cannot expose the address at all; v2
exposes it directly. The Face A cost (rotation = destroy + recreate)
is the price paid for this expressiveness.

**Cost of choosing v2 here:** the on-chain check is rock-solid because
`vault.owner` cannot move. The flip side is Face A's pain — once the
integrator hard-codes "you must be the vault owner" against an
immutable address, the user has no way to rotate that address without
remigrating every delegation.

See [`owner_check_v1.move`](sources/integration/owner_check_v1.move),
[`owner_check_v2.move`](sources/integration/owner_check_v2.move), and
[`owner_check_comparison_tests.move`](tests/owner_check_comparison_tests.move).

### Bundled trade-off — the actual Decision 3

| | Face A (rotation) | Face B (on-chain verification) |
|---|---|---|
| **v1 — transferable `OwnerCap`** | ✅ One `public_transfer`, delegations untouched | ❌ The owner address is NOT readable from `&Vault` on-chain. The cap-passing workaround verifies only "caller is the owner" (and only when the cap is held directly), not "address X is the owner" |
| **v2 — immutable `owner: address`** | ❌ Destroy + recreate + re-grant N spenders | ✅ `sv::owner(&v) -> address` returns the address; integrator compares to anything (`ctx.sender()`, a stored value, a function argument) |

**The team is picking the row, not the cell.** Pick v1's transferable
cap → accept that the owner address is not exposed to Move code at all
(Face B capability gap). Pick v2's immutable address → accept that
rotation requires remigrating the delegation tree (Face A cost). There
is no library shape that wins both faces — "v1 owner + v2 owner-
queryability" is mechanically impossible because owner-as-cap and
owner-as-stored-address are mutually exclusive representations of the
same field.

---

## Decision 4 — Rate limiting (library-embedded vs integrator-built)

**User-story.** An agent gets a monthly budget but should be capped at one
charge per hour.

### v1 — integrator-side `BotPolicy`

```move
public struct BotPolicy has key {
    id: UID,
    bot: address,
    cooldown_ms: u64,
    last_charge_ms: u64,            // integrator tracks time manually
}

public fun charge<U>(v, policy: &mut BotPolicy, amount, clock, ctx): Balance<U> {
    let now = clock.timestamp_ms();
    assert!(
        ctx.sender() == policy.bot
            && now >= policy.last_charge_ms + policy.cooldown_ms,
        E_RATE_LIMITED,             // integrator-defined error code
    );
    policy.last_charge_ms = now;
    ca::consume<U>(v, amount, clock, ctx).destroy_some()
}
```

**Verdict:** works; ~25 lines of integrator code plus a separate shared
`BotPolicy` object that the bot must take/return on every charge. The
error code is integrator-side, not part of the allowance library's
documented abort precedence.

**Cost of choosing v1 here:** the rate-limiter logic is integrator-
audited code, not library-audited. Bugs in the parallel `BotPolicy`
(e.g. wrong cooldown arithmetic, missing sender check, drift between
the policy address and the granted spender) become integrator bugs.
Multiple integrators reinventing the same wheel multiplies the
audit surface.

### v2 — embedded `Option<RateLimiter>`

```move
// Onboarding:
let limiter = rate_limiter::new_cooldown(
    per_charge_max, cooldown_ms, per_charge_max, 0, &clock,
);
sv::approve<U>(v, monthly_budget, expires_at_ms, option::some(limiter),
               recipient, &clock, ctx);

// Charging (library enforces the limiter; ERateLimited is library-side):
sv::spend<U>(v, &cap, amount, &clock, ctx)
```

**Verdict:** zero integrator-side rate-limiting code. The library calls
`rate_limiter::try_consume` inside `spend`, aborts `ERateLimited` on
refusal (documented precedence step 6), and emits a paired
`RateLimitConsumed` event for off-chain monitoring. **And** the limiter is
preserved across `set_allowance` calls (or replaced atomically with the
allowance update).

**Cost of choosing v2 here:**
- **Hard dependency on `openzeppelin_utils::rate_limiter`.** Adopting
  v2 means coordinating upgrades with the utils package: a binary-
  incompatible change to the `RateLimiter` enum would invalidate
  existing on-chain Vaults that have a limiter attached (the
  serialized enum would fail to deserialize). The vendored copy in
  this example is the same shape; in production both packages must
  bump together.
- **Larger event surface.** v2 emits two rate-limiter event types
  v1 doesn't have (`RateLimitConfigured`, `RateLimitConsumed`).
  Indexers tracking rate-limiter state must subscribe to both.
- **Additional `spend` hot-path code.** The library's `spend` gains
  ~four lines of limiter check + consume; the limiter's own
  invariants apply transparently but expand the audit perimeter.
- **No in-place limiter reconfigure.** The `rate_limiter` primitive
  deliberately has no "reconfigure" — adjusting a limiter mid-grant
  means constructing a fresh `RateLimiter` and passing it through
  `set_allowance`. Slightly more PTB-side ceremony than a simple
  field write would be.

### Bonus — v2-only suspension idiom

```move
// Owner suspends without destroying the entry:
sv::set_allowance<U>(v, cap_id, 0, expires_at_ms, new_rate_limit,
                    option::some(current_remaining), &clock, ctx);
// AGENT's cap object stays valid; any spend(&cap, > 0) aborts EAllowanceExceeded.

// Owner resumes — same cap_id, same cap object held by every downstream wrapper:
sv::set_allowance<U>(v, cap_id, MONTHLY_BUDGET / 2, ..., option::some(0), ...);
```

v1 has no analog: revoke removes the entry; re-grant just rewrites the
address-keyed entry — both fine for v1's address-keyed model, but neither
preserves an *embedded cap object* (because v1 has no cap object to
embed).

See [`rate_limited_charges_v1.move`](sources/integration/rate_limited_charges_v1.move),
[`rate_limited_charges_v2.move`](sources/integration/rate_limited_charges_v2.move), and
[`rate_limited_comparison_tests.move`](tests/rate_limited_comparison_tests.move).

---

## Off-chain indexer / wallet cost (asymmetric)

Reading current state is structurally different on the two libraries
because the spender side is keyed differently. This matters for wallets
showing "what allowances do I have", indexers tracking spend volume by
spender, and dashboards reconciling "who currently controls this
delegation."

### Event surface

| | v1 (`coin_allowance`) | v2 (`spend_vault`) |
|---|---|---|
| Total event types | 6 — `VaultCreated`, `Deposited`, `Granted`, `Consumed`, `Revoked`, `Withdrawn`, `VaultDestroyed` | 9 — v1's set plus `AllowanceSet`, `RateLimitConfigured`, `RateLimitConsumed`; `Granted` → `Approved`, `Consumed` → `Spent` |
| v2-only event types | — | `AllowanceSet` (in-place update path), `RateLimitConfigured` (limiter attach), `RateLimitConsumed` (per-spend limiter draw) |

v2's larger surface is intentional — `AllowanceSet` separates in-place
updates from creates (`Approved`), and the two limiter events make
limiter behavior observable without polling state. The cost is that
every v2 indexer must handle 3 extra event types from day one.

### Spender / cap-holder lookup chain

| | v1 | v2 |
|---|---|---|
| Spender identity in events | `Granted.spender: address`, `Consumed.spender: address` | `Approved.cap_id: ID`, `Spent.cap_id: ID`, plus `Spent.caller: address` (tx signer, **not** necessarily cap-holder) |
| Hops from event to wallet | One — `event → address` | Two-to-three — `event → cap object → object-ownership-change events → current holder` |
| Cap-holder changes over time | N/A (address-as-identity is stable by definition) | Yes — cap is `key + store`, freely `public_transfer`-able; indexer must subscribe to ownership-change events to keep current-holder accurate |

In v1, `Granted { spender: 0xBOB }` immediately tells the indexer that
0xBOB has an allowance — the address IS the wallet. In v2,
`Approved { cap_id: ID(0xCAFE…) }` tells the indexer a cap was minted
but NOT who currently holds it; the indexer resolves `cap_id` to its
current owner via Sui RPC (`getObject` / `getOwnedObjects`) AND
watches ownership-change events so the wallet UI stays accurate when
the cap is later transferred.

`Spent.caller` on v2 is the transaction signer — which may be a
wrapper module's caller (e.g. the keeper in Decision 2's aggregator
scenario) and NOT the cap-holder. Reconstructing "did this spend come
from the original recipient or a downstream wrapper?" requires
correlating `Spent.cap_id` against the cap's current ownership at
spend time.

### Owner-side observability

| | v1 | v2 |
|---|---|---|
| Owner address from `&Vault` (on-chain) | No reader — owner = whoever currently holds the `OwnerCap` object | `sv::owner(&v) -> address`; immutable, total read |
| Owner address off-chain | `coin_allowance::cap_id(v)` → query current owner of that object via RPC | Read `VaultCreated.owner` once; never changes (immutable from `new`) |
| Wallet inventory signal | `OwnerCap` shows in the owner's owned-objects list — one-step UI for "vaults I own" | No per-vault inventory object on the owner side; wallets must scan `VaultCreated` events filtered by `owner == myAddress` |

v1 wins **owner-inventory UX** (the cap is the inventory item;
filtering owned objects by type is a one-step query against Sui RPC).
v2 wins **owner-identity stability** (one event, one address, no
follow-up RPC, no surprise rotation).

### Net

v1's pipeline is shorter and address-only on the spender side; v2's
adds at least one hop (cap_id → current holder) plus an ongoing
ownership-change subscription. v1 forces an extra hop on the
owner-discovery side (cap_id → current cap owner); v2 makes that a
single event field. Picking v2 means indexers and wallets plan for
the cap-resolution layer; picking v1 means they plan for the
owner-discovery RPC.

This is not a small thing — for any team that does NOT operate its
own indexer, v2's lookup chain becomes a third-party dependency on
whichever Sui indexer / wallet ships `cap_id`-aware queries first.

---

## v2-specific consideration — creator ≠ owner

v2's `new<U>(initial_owner, ctx)` accepts an arbitrary `initial_owner` —
the creator (`ctx.sender()`) and the named owner are decoupled by
default. This unlocks legitimate patterns (factory deploys, atomic
create-fund-handoff-to-end-user, DAO scripts standing up treasury
vaults), but it also means:

- **Anyone can mint a `Vault<U>` naming any address as `owner`** — the
  named owner receives a vault they didn't ask for. The creator pays
  the gas; the named owner has no on-chain consent step.
- **Not a direct DoS.** The named owner has no obligation to interact
  with the vault; the worst case is UI clutter (a vault shows up in
  their inventory) and a phishing-surface — an attacker might fund a
  spam-vault to impersonate a service and lure interactions.
- **The owner can always discard it.** `withdraw_all` + `destroy`
  (gated on `ctx.sender() == v.owner`) ends the vault unconditionally
  — and pockets any spammer-funded balance as a side-effect.
- **Indexers should default-filter on `creator == owner`** in the
  `VaultCreated` event. Vaults the user created themselves are
  user-intentional; third-party-created vaults belong behind an opt-in
  view. (Both fields are emitted; the library exposes both.)
- **Integrators accepting a user-supplied `&SpenderCap`** (Scenario C
  — yield aggregator) can optionally also validate
  `vault.creator == registering_user` if strict provenance matters.

v1 does not have this exact shape — `coin_allowance::new` returns the
`OwnerCap` to `ctx.sender()`, so the creator IS the initial owner.
Reaching the same end-state (vault owned by a different address)
requires the creator to explicitly `transfer::public_transfer(cap, …)`.
The vector still exists in v1 (anyone can create + immediately
transfer), but it's an extra step rather than the default.

The v2 design accepts this trade-off because the decoupling is required
for the factory / DAO / atomic-handoff patterns v2 unlocks. The
bystander-UX cost is documented in `spend_vault.move`'s `Vault` struct
doc; surfaced here so cherry-pick decisions weigh it.

See [`bystander_v2_tests.move`](tests/bystander_v2_tests.move) — Mallory
creates a Vault naming Alice as owner and permissionlessly deposits
some funds; Alice's `destroy(vault, ctx)` discards the unwanted Vault
and pockets Mallory's deposit as a refund.

## What this example does NOT cover

### Out of scope by design

- **Intra-Vault partitioning** (e.g. "$100 for swaps, $200 for refunds"
  in the same vault). Both versions reject this. The rejection lever:
  intra-Vault partitioning either requires spend-time
  recipient/witness enforcement (the bound-recipient mechanism v2
  deliberately removed, see Decision 1) or it is pure accounting
  metadata that **N-Vault provides better** — true capital partition
  + independent ownership + independent lifecycle, where intra-Vault
  sub-buckets would soft-slice a shared `vault.balance` and break the
  ceiling semantics (foundational property #1 above).
- **Object / NFT allowance.** Coin-only by design in both versions.
  Object allowance is a structurally different problem (per-object
  approvals, no fungibility) and would be a sibling library.
- **`openzeppelin_access::two_step_transfer` / `delayed_transfer`
  wrapping of `OwnerCap`** is sketched in Decision 3 Face A as the v1
  recommended-habit but not demonstrated end-to-end — wiring the
  vendored `access` package in would multiply the dependency surface
  for limited additional comparison value.
- **`openzeppelin_access::access_control` `Auth<Role>` as the library's
  own auth gate** is structurally foreclosed on both v1 and v2.
  `access_control` enforces two invariants:
  (1) `new<RootRole>` requires a genuine One-Time Witness, and the Sui
  VM produces exactly one OTW per type per package at the package's
  first publish — so at most one `AccessControl` registry exists per
  defining module, ever; (2) every role-typed entry point
  (`grant_role` / `revoke_role` / `renounce_role` / `set_role_admin` /
  `new_auth`) calls `assert_home_module`, which rejects any role type
  whose package + module don't match the root role's. Role identity is
  type-level (`TypeName`-keyed in the registry), not instance-level —
  there is no representation of "Role on Vault 0xABC specifically."
  Together this means the allowance library cannot define a role type
  consumers use against per-Vault registries, and consumers cannot
  define a per-Vault role inside their own registry either. `Auth<Role>`
  does compose at the integrator-wrapper layer (a consumer's own
  module can define `MyOperatorRole` against its own OTW-rooted
  registry and gate a function that internally calls `spend` /
  `consume`), but cannot be the allowance library's own auth gate.

