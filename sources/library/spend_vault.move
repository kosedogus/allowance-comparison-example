/// Cap-keyed fungible-coin allowance / approval primitive for Sui — v2
/// sibling of `coin_allowance`.
///
/// A `Vault<U>` is a shared escrow holding a `Balance<U>` plus a cap-ID-keyed
/// `Table` of per-cap `Allowance` entries. The Vault is owner-controlled via
/// `ctx.sender() == v.owner` (no `OwnerCap` — A2/D12 inversion vs v1). Each
/// `Allowance` entry is created by minting a `SpenderCap` whose `vault_id`
/// pins it to one Vault; whoever can present `&cap` to `spend` is authorized
/// to draw (CAP-GATED, not sender-gated — B6/D13 inversion vs v1's address
/// keying).
///
/// #### Core semantics
///
/// - **Ceiling, not guarantee.** `Sum(remaining)` across live caps may exceed
///   pool balance; a `spend` aborts `EInsufficientVault` if the pool is short
///   even with positive `remaining` (allowance ≠ guarantee).
/// - **Exact-amount-or-abort `spend`.** Successful `spend` delivers exactly
///   `amount` (never partial); decrements `remaining` by exactly `amount`
///   unless `remaining == u64::MAX` (the UNLIMITED sentinel — never
///   decremented). Always returns `Balance<U>` for maximal composability.
/// - **`u64::MAX` sentinels.** `remaining == u64::MAX` ⇒ unlimited grant;
///   `expires_at_ms == u64::MAX` ⇒ no expiry. The no-decrement / no-expire
///   branches are explicit; no `u64::MAX - amount` arithmetic ever occurs.
/// - **Cap-keyed delegation.** `SpenderCap` is `key + store`, transferable
///   and embeddable inside wrapper structs (BoundedDelegation) and protocol-
///   owned cap tables (Scenario C). `cap.vault_id` is immutable from mint;
///   `spend` asserts `EWrongVault` first to enforce the binding.
/// - **`cap_id` stable across `set_allowance`.** Owner-side parameter changes
///   (refill, reduce, suspend, attach/replace rate limiter) mutate the
///   entry IN PLACE — wrappers and protocol tables holding `&cap` survive
///   unbroken. This is the load-bearing property that justifies splitting
///   mint (`approve`/`mint_cap`) from update (`set_allowance`).
/// - **Suspension idiom.** `set_allowance(K, 0, …)` overwrites `remaining`
///   to 0 but leaves the entry alive. `spend(&cap, > 0)` aborts
///   `EAllowanceExceeded` (not `ENoAllowance`); owner can later
///   `set_allowance(K, > 0, …)` to resume. Use `revoke` to terminate.
/// - **Composed rate limiting.** `Option<RateLimiter>` per `Allowance` entry,
///   composing `openzeppelin_utils::rate_limiter`. This library does no
///   limiter math; it embeds the audited primitive the way it embeds
///   `Balance<U>`.
/// - **Optional CAS on `set_allowance`.** `expected: Option<u64>` aborts
///   `EUnexpectedAllowance` unless current raw `remaining == expected`.
///   Closes the reduce-allowance interleaving race when caller cares.
///   `None` is the unconditional ERC-20-equivalent overwrite path.
/// - **Owner can always defund.** `withdraw` / `withdraw_all` / `destroy`
///   consult only `ctx.sender == v.owner` and `v.balance` — never the
///   `allowances` Table. No live cap can lock owner funds.
///
/// #### Object model
///
/// - `Vault<U>` is `key`-only (no `store`, `drop`, or `copy`) — shared
///   object whose lifecycle (`new` → `share`/`destroy`) is controlled
///   solely by this module. `v.owner: address` is immutable from `new`;
///   rotation lives at the address level (multisig / governance /
///   `delayed_transfer`-wrapped owner).
/// - `SpenderCap` is `key + store` (no `copy`) — owned object, transferable,
///   embeddable. Each cap carries an immutable `vault_id: ID` set at mint.
/// - `Allowance` is a non-object `store + drop` value living inside
///   `Vault.allowances: Table<ID, Allowance>`. Not independently addressable.
///   `Table` is the SOLE storage for allowance state — no parallel
///   `VecSet<ID>` allowlist (single source of truth).
///
/// #### Authorization model
///
/// - Owner-gated functions (`approve`, `mint_cap`, `set_allowance`, `revoke`,
///   `withdraw`, `withdraw_all`, `destroy`) authorize on
///   `ctx.sender() == v.owner`. `ctx.sender()` on Sui is the transaction
///   signer, invariant across module/package call depth — no
///   `msg.sender == contract` notion. A package address can never be owner;
///   choose an EOA / multisig / governance address.
/// - `spend` is cap-gated: presence of `&SpenderCap` whose `vault_id`
///   matches AND whose `cap_id` is in `allowances` IS the authorization.
///   `ctx.sender()` is NOT checked. Whoever holds and can present the cap
///   may draw — including wrappers, keeper bots, and contract-custody
///   compositions.
///
/// #### Reentrancy
///
/// Structurally absent on Sui. `spend` returns `Balance<U>` and performs no
/// `public_transfer`; any caller-side downstream transfer executes NO code
/// at the destination (Sui transfers have no fallback / receive hook /
/// synchronous callback). No reentrancy guard exists, is needed, or is
/// possible.
///
/// #### Composability
///
/// - `new` returns the Vault by value so a single PTB can `new` → `deposit`
///   → `approve`/`mint_cap` → `share` atomically.
/// - `spend` returns `Balance<U>` (no imposed object) — plumb directly into
///   downstream protocol calls within the same PTB.
/// - Reads (`owner`, `allowance`, `spendable_now`, `expiry`, `contains`,
///   `balance_value`) take `&Vault`, never abort, reflect committed state at
///   call time. Treat as advisory pre-`spend` predicates; `spend` itself is
///   the only atomic check-and-draw.
///
/// #### Non-guarantees (read these)
///
/// - Solvency is NOT guaranteed (over-subscription). A live, non-exceeded
///   allowance can abort `EInsufficientVault`.
/// - Grants are NOT vested or time-locked. Owner may unilaterally
///   reduce / suspend / replace / revoke / defund at any time — with no
///   cap-holder consent.
/// - `deposit` is permissionless and confers no rights on the depositor;
///   deposited funds become owner-withdrawable and cap-spendable within
///   existing grants. Only fund a Vault whose owner you trust.
/// - `recipient` on `approve` is unvalidated. Choosing a sound address is
///   the owner's responsibility (D21).
/// - Cap objects outlive ledger entries. `revoke` removes the entry; the
///   cap object remains in its holder's wallet as inert garbage. The owner
///   cannot destroy a cap they don't hold.
module openzeppelin_allowance::spend_vault;

use openzeppelin_utils::rate_limiter::RateLimiter;
use sui::balance::{Self, Balance};
use sui::clock::Clock;
use sui::coin::{Self, Coin};
use sui::event;
use sui::table::{Self, Table};

// === Errors ===

/// Caller is not the Vault owner (`ctx.sender() != v.owner`). Owner gate per
/// INV-10.
#[error(code = 0)]
const EUnauthorized: vector<u8> = "Caller is not the Vault owner";

/// Presented `SpenderCap` is bound to a different `Vault`
/// (`cap.vault_id != object::id(v)`). Anti-confusion check per INV-8.
#[error(code = 1)]
const EWrongVault: vector<u8> = "Cap does not match this Vault";

/// Amount was zero on a value-moving entry point (`approve`, `mint_cap`,
/// `spend`, `withdraw`, `deposit`). Per INV-12. `set_allowance(K, 0, ...)`
/// is the suspension idiom (INV-27) and does NOT abort here.
#[error(code = 2)]
const EZeroAmount: vector<u8> = "Amount must be greater than zero";

/// Finite `expires_at_ms` was at or before `clock.timestamp_ms()`. Per
/// INV-13. The `u64::MAX` sentinel (INV-20) is accepted as "no expiry" and
/// never triggers this abort.
#[error(code = 3)]
const EExpiryInPast: vector<u8> = "Expiry must be in the future";

/// CAS guard failed on `set_allowance`: current raw allowance does not match
/// `expected`. Per INV-19. Absent cap_id is preempted by `ENoAllowance`
/// (INV-14).
#[error(code = 4)]
const EUnexpectedAllowance: vector<u8> = "Current allowance does not match expected";

/// No `Allowance` entry exists for the supplied `cap_id` (never granted,
/// owner-revoked, or wrong-Vault cap_id which is implicitly absent — INV-9).
/// Per INV-14 `spend` step 2 and `set_allowance` step 2. Distinct from
/// `EAllowanceExceeded`, which fires when the entry IS present but
/// `remaining == 0` (suspension — INV-27).
#[error(code = 5)]
const ENoAllowance: vector<u8> = "No allowance entry for this cap";

/// Entry exists with a finite expiry and
/// `clock.timestamp_ms() >= expires_at_ms`. Per INV-14 `spend` step 3 +
/// INV-36. The `u64::MAX` sentinel (INV-20) is "no expiry" and never
/// triggers this.
#[error(code = 6)]
const EAllowanceExpired: vector<u8> = "Allowance has expired";

/// Requested `amount` exceeds the entry's `remaining`. Per INV-14 `spend`
/// step 5. Also fires on a suspended entry (`set_allowance(K, 0, ...)`) for
/// any `amount > 0` — the documented suspension-vs-revoke discriminator
/// (INV-27).
#[error(code = 7)]
const EAllowanceExceeded: vector<u8> = "Amount exceeds remaining allowance";

/// The embedded rate limiter refused the request. Per INV-14 `spend` step 6
/// and INV-21. Re-asserted by `spend` via `rate_limiter::try_consume` so the
/// abort code is local (not `openzeppelin_utils::rate_limiter::ERateLimited`),
/// matching this module's precedence row.
#[error(code = 8)]
const ERateLimited: vector<u8> = "Rate limit exceeded";

/// `amount` exceeds `v.balance.value()`. Per INV-14 `spend` step 7 and
/// INV-15. The "allowance ≠ guarantee" path (INV-31): an in-cap, unexpired,
/// limiter-passing `spend` can still abort here if the pool is short.
#[error(code = 9)]
const EInsufficientVault: vector<u8> = "Vault balance insufficient";

// === Structs ===

/// Shared escrow + per-cap allowance ledger for coin type `U`.
///
/// `owner` is set ONCE at `new` from the `initial_owner` parameter and never
/// mutated by any public function (INV-11 / INV-39). Rotation, if needed,
/// lives at the address level: set `initial_owner` to a multisig /
/// governance / `delayed_transfer` address whose internal rotation flow is
/// outside this library (D24).
///
/// #### Creator vs. owner
///
/// `new<U>(initial_owner, ctx)` accepts an ARBITRARY `initial_owner` —
/// anyone may mint a Vault naming any address as owner (D21). The creator
/// (`ctx.sender()` at `new`, surfaced as `VaultCreated.creator`) and the
/// named `owner` are decoupled, which enables:
/// - DAO / multisig treasury deployment where a script creates Vaults for
///   the treasury address (the deployer keeps no residual authority);
/// - factory / deploy-and-handoff PTBs where a protocol creates a Vault for
///   an end-user inline;
/// - atomic create + fund + delegate in one PTB (Scenario E).
///
/// The asymmetry is observable and safe by construction:
/// - The creator obtains NO on-chain rights — only the named `owner` can
///   mint caps, set allowances, withdraw, or destroy (INV-10 / INV-32).
/// - `deposit` is permissionless (INV-34) but confers no rights on the
///   depositor; deposits become owner-withdrawable property.
/// - There is no on-chain owner→Vault registry to spoof: discovery is
///   off-chain via events. Wallets / indexers SHOULD default-filter Vaults
///   shown to a user on `creator == owner` (Vaults the user made
///   themselves) and surface third-party-created Vaults under an opt-in view.
/// - Integrators (Scenario C) that accept a user's `&SpenderCap` for spend
///   authorization may additionally validate
///   `vault.creator == registering_user` if strict provenance matters (the
///   library exposes both fields).
///
/// Worst case for an unsuspecting named owner of an unwanted Vault: UI
/// clutter plus a phishing surface no larger than any address-receivable
/// Sui object. The owner can `withdraw_all` + `destroy` at any time to
/// discard it (and pocket any spammer-funded balance — `deposit` is a gift
/// to the owner).
///
/// #### Authorization model
///
/// - Owner-gated functions (`approve`, `mint_cap`, `set_allowance`,
///   `revoke`, `withdraw`, `withdraw_all`, `destroy`) authorize on
///   `ctx.sender() == v.owner` (INV-10). There is NO `OwnerCap`
///   (A2 / D12 — major v1→v2 structural change).
/// - `spend` is CAP-GATED, not sender-gated (INV-18): whoever can present a
///   `&SpenderCap` whose `vault_id` matches and whose `cap_id` is in
///   `allowances` may draw, regardless of signing address.
///
/// #### Object shape
///
/// `key`-only by design (no `store`, no `copy`, no `drop`) — INV-1:
/// - Cannot be silently dropped: `new` must be followed by `share` or
///   `destroy` within the same transaction (the no-`drop` linearity forces
///   it).
/// - Cannot be wrapped, stored, or `public_transfer`'d by an external
///   module (no `store`).
/// - Its full lifecycle (`new` → `share`/`destroy`) is controlled solely
///   by this module.
///
/// `allowances: Table<ID, Allowance>` is the SOLE storage for allowance
/// state (INV-4 / D14). No parallel `VecSet<ID>` allowlist is maintained —
/// single source of truth, no drift risk, O(1) `Table::contains`.
public struct Vault<phantom U> has key {
    id: UID,
    owner: address,
    balance: Balance<U>,
    allowances: Table<ID, Allowance>,
}

/// Bearer authority for one allowance entry, bound to exactly one Vault.
///
/// `key + store` with no `copy` (INV-2):
/// - `store` is LOAD-BEARING: it enables `public_transfer`, embedding inside
///   wrapper objects (Scenario B — BoundedDelegation), and lodging inside
///   protocol-owned tables (Scenario C — Nenad's yield-aggregator pattern).
///   Without `store`, the central v2 composition benefit collapses.
/// - No `copy` means cap-holder authority cannot be duplicated by any path.
///
/// `vault_id` is set at mint (`approve` / `mint_cap`) to `object::id(v)` and
/// is IMMUTABLE for the cap's lifetime (INV-3 / INV-30) — there is no
/// setter, no mutating helper, and the field is private to this module. The
/// binding survives every transfer, wrap, or table embedding the cap
/// undergoes; it is the only safe way to permit `store` on a bearer cap
/// (the runtime `cap.vault_id == object::id(v)` check in `spend` —
/// INV-8 / `EWrongVault` — is the consumer of this immutability).
///
/// The cap carries NO phantom `U`: type pinning is achieved indirectly via
/// `vault_id` referring to one `Vault<U>` instance (INV-5).
public struct SpenderCap has key, store {
    id: UID,
    vault_id: ID,
}

/// Single ledger entry for one cap-ID, stored inside `Vault.allowances`.
///
/// `store + drop`, no `key`, no `copy` (INV-4):
/// - `store` so it can live in `Table<ID, Allowance>`.
/// - `drop` so overwrite, `table::remove`, and `table::drop` (at `destroy`)
///   dispose of it cleanly — including the embedded `Option<RateLimiter>`
///   (which is itself `store + drop`).
/// - No `key`: not an object, not independently addressable, reachable only
///   through Vault-mediated functions.
/// - No `copy`: single source of truth per cap_id.
///
/// `remaining`:
/// - `u64::MAX` is the UNLIMITED sentinel (INV-20 / INV-23): `spend` does
///   NOT decrement; the no-decrement branch is the only path. No
///   `u64::MAX - amount` arithmetic is ever performed.
/// - Any other value is the raw drawable cap; `spend` decrements by exactly
///   `amount` (INV-23).
/// - `0` is a SUSPENDED entry (INV-27): the cap_id stays in the Table; any
///   `spend(&cap, > 0)` aborts `EAllowanceExceeded` (not `ENoAllowance`),
///   downstream wrappers/protocol-tables holding `&cap` survive, and the
///   owner can `set_allowance(K, > 0, ...)` later to resume.
///
/// `expires_at_ms`:
/// - `u64::MAX` is the NO-EXPIRY sentinel (INV-20 / INV-13): grant-time
///   accept, spend-time never expires.
/// - Any finite value MUST be strictly `> now` at grant time (INV-13);
///   `spend` aborts `EAllowanceExpired` when `now >= expires_at_ms`.
///
/// `rate_limit`:
/// - `None` = no rate limit, zero-cost when unused.
/// - `Some(limiter)` embeds an audited
///   `openzeppelin_utils::rate_limiter::RateLimiter` (INV-21). This module
///   performs no limiter math — `spend` calls `rate_limiter::try_consume`,
///   the limiter's own invariants apply transparently.
///
/// `alive` is NOT a stored field — liveness is recomputed at every call
/// site from `(table::contains, expires_at_ms, clock.timestamp_ms())`. No
/// inconsistent-flag risk (INV-26).
public struct Allowance has store, drop {
    remaining: u64,
    expires_at_ms: u64,
    rate_limit: Option<RateLimiter>,
}

// === Events ===

/// Emitted by `new` when a Vault is minted.
///
/// `owner` is the Vault's authoritative gate-address (INV-10), set from the
/// `initial_owner` parameter and immutable thereafter (INV-11). `creator`
/// is `ctx.sender()` at `new` and MAY differ from `owner` (D21) — wallets
/// and indexers should default-filter on `creator == owner` to distinguish
/// user-intentional Vaults from third-party-created ones.
public struct VaultCreated<phantom U> has copy, drop {
    vault_id: ID,
    owner: address,
    creator: address,
}

/// Emitted by `deposit`. `depositor` is recorded for indexer attribution
/// only; the depositor receives NO on-chain rights (INV-34). Deposits are
/// permissionless — only fund a Vault whose owner you trust.
public struct Deposited<phantom U> has copy, drop {
    vault_id: ID,
    amount: u64,
    depositor: address,
}

/// Emitted by `approve` AND `mint_cap`. The two are distinguished by
/// `recipient`:
/// - `Some(r)` — `approve` was called; the cap was transferred to `r`.
/// - `None` — `mint_cap` was called; the cap was returned to the caller
///   for embedding inside a wrapper or protocol-owned table (Scenarios
///   B/C). Indexers reconstruct destination via Sui's standard object-
///   ownership-change event for the cap object.
///
/// `expires_at_ms == u64::MAX` denotes the no-expiry sentinel (INV-20).
/// `has_rate_limit: bool` is a lightweight presence flag; when `true`, a
/// `RateLimitConfigured` event is emitted alongside this one with the
/// limiter's variant + capacity (M1 mitigation per design-v2 D25). `by` is
/// `ctx.sender()` (the owner — may be a multisig address).
public struct Approved<phantom U> has copy, drop {
    vault_id: ID,
    cap_id: ID,
    recipient: Option<address>,
    amount: u64,
    expires_at_ms: u64,
    has_rate_limit: bool,
    by: address,
}

/// Emitted by `set_allowance`.
///
/// `new_amount == 0` signals the SUSPENSION idiom (INV-27 / D20) — the
/// cap_id stays alive, downstream wrappers/protocol-tables holding `&cap`
/// survive, and `spend(&cap, > 0)` aborts `EAllowanceExceeded` (not
/// `ENoAllowance`).
///
/// `cas_was_provided: bool` records `expected.is_some()` — the audit-trail
/// signal that lets compliance tooling spot "owner repeatedly overwrites
/// without CAS" patterns. `has_rate_limit: bool` is the presence flag; when
/// `true`, a `RateLimitConfigured` event is emitted alongside this one (the
/// `new_rate_limit` field unconditionally replaces the prior limiter, even
/// from `Some` to `None` — per OQ4 resolution).
public struct AllowanceSet<phantom U> has copy, drop {
    vault_id: ID,
    cap_id: ID,
    new_amount: u64,
    new_expires_at_ms: u64,
    has_rate_limit: bool,
    cas_was_provided: bool,
    by: address,
}

/// Emitted whenever a `RateLimiter` is ATTACHED to an `Allowance` entry —
/// alongside (the same tx as) `Approved` (via `approve`/`mint_cap`) or
/// `AllowanceSet` (via `set_allowance`).
///
/// `rate_limiter` itself emits no events (it's a pure library); this is
/// the only on-chain surface where limiter setup is observable. Indexers
/// tracking subscription / agent / cooldown patterns SHOULD index this
/// event to learn the limiter's variant + capacity at attach time.
/// Variant-specific details (refill_amount, window_ms, cooldown_ms,
/// anchor) are not in the event — fetch via
/// `openzeppelin_utils::rate_limiter` accessors keyed off `kind`:
/// - `kind == 0` (Bucket): `refill_amount`, `refill_interval_ms`,
///   `last_refill_ms`.
/// - `kind == 1` (FixedWindow): `window_ms`, `window_start_ms`.
/// - `kind == 2` (Cooldown): `cooldown_ms`, `cooldown_end_ms`.
///
/// NO event is emitted for limiter REMOVAL (i.e. `set_allowance` with
/// `new_rate_limit = None` when one was previously set) — the parent
/// `AllowanceSet { has_rate_limit: false, ... }` is the removal signal.
public struct RateLimitConfigured<phantom U> has copy, drop {
    vault_id: ID,
    cap_id: ID,
    kind: u8,
    capacity: u64,
    by: address,
}

/// Emitted on every successful `spend`. ONE EVENT PER SPEND.
///
/// `amount` is the value drawn THIS call; `remaining` is the entry's raw
/// `remaining` AFTER this call (so indexers reconstruct standing authority
/// without re-summing history). For the `u64::MAX` unlimited sentinel
/// (INV-20), `remaining` stays at `u64::MAX` post-call (no decrement).
///
/// `caller` is `ctx.sender()` — SEMANTICALLY DISTINCT from `by` elsewhere
/// because `spend` is cap-gated, not sender-gated (INV-18). The caller may
/// be the cap-holder directly OR a wrapper module's caller (e.g. a keeper
/// bot invoking a protocol's spend function in Scenario C). Off-chain
/// indexers reconstruct cap-holder identity by correlating `Approved`
/// recipients with subsequent `public_transfer` events of the cap object.
///
/// To learn whether THIS spend consumed rate-limited capacity, indexers
/// look for a `RateLimitConsumed` event in the SAME transaction. Absence
/// means the cap has no rate limiter attached; presence carries the
/// post-consume limiter `available`.
public struct Spent<phantom U> has copy, drop {
    vault_id: ID,
    cap_id: ID,
    amount: u64,
    remaining: u64,
    caller: address,
}

/// Emitted by `spend` ONLY when the cap's `Allowance.rate_limit.is_some()`
/// — i.e. when a limiter was actually consumed.
///
/// Paired with the `Spent` event from the same `spend` call (same tx).
/// When no `RateLimitConsumed` event accompanies a `Spent` event, the cap
/// has no limiter attached. `available_after` is
/// `openzeppelin_utils::rate_limiter::available(&limiter, clock)`
/// evaluated AFTER `try_consume` — the headroom left for the next call.
/// Subscription / agent / cooldown patterns read this without polling
/// state.
///
/// `consumed` is the same `amount` as `Spent.amount` for the matching call
/// — included redundantly so consumers of this event alone don't need to
/// join against `Spent`.
///
/// Note on failure: a `spend` that was REFUSED by the limiter aborts
/// `ERateLimited`, which rolls back all effects per Move/Sui semantics —
/// no `RateLimitConsumed` (or `Spent`) event is emitted. Indexers detect
/// rate-limited refusals via the abort code in transaction effects,
/// off-chain.
public struct RateLimitConsumed<phantom U> has copy, drop {
    vault_id: ID,
    cap_id: ID,
    consumed: u64,
    available_after: u64,
    caller: address,
}

/// Emitted by `revoke` on every non-aborting call, INCLUDING the idempotent
/// no-op path where the entry was already absent (INV-17). An aborted
/// `revoke` (non-owner caller) emits nothing per Move/Sui rollback
/// semantics. `by` is `ctx.sender()` (the owner).
public struct Revoked<phantom U> has copy, drop {
    vault_id: ID,
    cap_id: ID,
    by: address,
}

/// Emitted by both `withdraw` and `withdraw_all` (single event type — keeps
/// indexers from special-casing the drain path). `amount` is the actual
/// value transferred to the owner. `by` is `ctx.sender()` (the owner).
public struct Withdrawn<phantom U> has copy, drop {
    vault_id: ID,
    amount: u64,
    by: address,
}

/// Emitted by `destroy`. `refunded` is the leftover `Balance<U>` returned
/// as a `Coin<U>` (may be zero — `destroy` does not impose a non-empty
/// precondition on balance, unlike `withdraw_all`). After this event the
/// Vault no longer exists on-chain (INV-25); the corresponding
/// `SpenderCap` objects remain in holders' wallets as inert garbage
/// (INV-29).
public struct VaultDestroyed<phantom U> has copy, drop {
    vault_id: ID,
    refunded: u64,
    by: address,
}

// === Public Functions ===

// === Lifecycle ===

/// Create a new Vault for coin type `U` owned by `initial_owner`.
///
/// Returned **by value** so a single PTB can `new` → `deposit` →
/// `approve`/`mint_cap` → `share` atomically (INV-40). The Vault has `key`
/// only (no `drop`), so the transaction will fail unless every returned
/// Vault is consumed by either `share` or `destroy` in the same tx — there
/// is no path that silently loses a Vault (INV-1).
///
/// #### Parameters
/// - `initial_owner`: Address to be set as `v.owner`. Becomes the sole
///   address authorized to call owner-gated functions (INV-10). May be any
///   address — `ctx.sender()`, a multisig, a governance address, a
///   `delayed_transfer`-wrapped address, or arbitrary (D21). The library
///   does NOT validate this; choosing a sound `initial_owner` is the
///   caller's responsibility. Immutable post-`new` (INV-11 / INV-39).
/// - `ctx`: Transaction context. `ctx.sender()` is recorded as `creator`
///   in `VaultCreated` (informational only — see Vault doc).
///
/// #### Returns
/// - `Vault<U>` by value. Caller MUST `share` (most common) or `destroy`
///   in the same tx, else the tx aborts.
public fun new<U>(initial_owner: address, ctx: &mut TxContext): Vault<U> {
    let vault_uid = object::new(ctx);
    let vault_id = vault_uid.uid_to_inner();

    let vault = Vault<U> {
        id: vault_uid,
        owner: initial_owner,
        balance: balance::zero<U>(),
        allowances: table::new<ID, Allowance>(ctx),
    };

    event::emit(VaultCreated<U> {
        vault_id,
        owner: initial_owner,
        creator: ctx.sender(),
    });

    vault
}

/// Share the Vault. Defining-module-only entry point (`Vault<U>` omits
/// `store`, so external modules cannot call `transfer::public_share_object`
/// on it — INV-1).
///
/// Must be called within the same transaction that produced the Vault, OR
/// the Vault must be `destroy`'d — otherwise the tx fails (no `drop`
/// ability).
///
/// After `share`, the Vault is no longer addressable in this transaction
/// (Sui shared-object rule: a shared object becomes a valid shared input
/// only in *subsequent* transactions). All fund/grant/transfer steps for
/// the PTB must precede `share` (INV-40).
///
/// #### Parameters
/// - `v`: Vault to share. Consumed by value.
public fun share<U>(v: Vault<U>) {
    transfer::share_object(v);
}

// === Fund ===

/// Add coins to the shared pool. PERMISSIONLESS — anyone may deposit
/// (INV-34).
///
/// Depositing confers NO withdrawal, allowance, or governance rights on
/// the depositor. Deposited funds become owner-withdrawable (INV-32) and
/// cap-spendable within existing grants (INV-31). DOC WARNING: only fund a
/// Vault whose owner you trust — there is no path for the depositor to
/// reclaim deposited funds.
///
/// #### Parameters
/// - `v`: Vault to fund.
/// - `c`: Coin to deposit. Consumed by value; its value is added to the
///   pool.
/// - `ctx`: Transaction context. `ctx.sender()` is recorded as `depositor`
///   in the `Deposited` event for indexer attribution; the depositor
///   receives NO on-chain rights (INV-34).
///
/// #### Aborts
/// - `EZeroAmount` if `c.value() == 0`. Brings `deposit` in line with the
///   other amount-bearing inbound entries (`approve` / `mint_cap` /
///   `spend` / `withdraw`) and closes a permissionless event-litter /
///   spam vector. **Local deviation from design-v2 §Per-function abort
///   precedence** (which omits the check) and resolution of the OQ
///   flagged in invariants-v2 INV-12's "Deviation from v1 invariants"
///   block.
public fun deposit<U>(v: &mut Vault<U>, c: Coin<U>, ctx: &TxContext) {
    let amount = c.value();
    // Local deviation from design-v2: reject zero-value deposits to keep
    // `deposit` consistent with the rest of the value-moving inbound API
    // and close a permissionless event-litter vector. The assert is the
    // FIRST effective statement so a zero-value `Coin` aborts before any
    // state change and before `Deposited` is emitted (both rolled back
    // together per Move/Sui abort semantics).
    assert!(amount > 0, EZeroAmount);

    // INV-22 (value conservation): pool balance increases by exactly
    // `amount`. INV-42/INV-46 enforced structurally by `&mut Vault<U>`
    // (consensus-serialized per-Vault; no cross-Vault state touched).
    balance::join(&mut v.balance, coin::into_balance(c));

    event::emit(Deposited<U> {
        vault_id: object::id(v),
        amount,
        depositor: ctx.sender(),
    });
}

// === Grant ===

/// Owner-only. Mints a `SpenderCap` and transfers it to `recipient` in a
/// single call (Scenario A — the common-case "delegate to a known address"
/// path). `public fun` so wallets, CLIs, and PTB builders call it as a
/// single `moveCall` without PTB plumbing (the cap is transferred to
/// `recipient` inside the call rather than returned).
///
/// For embedded composition (Scenarios B/C — wrappers, protocol-owned cap
/// tables), use `mint_cap` instead — it returns the cap by value.
///
/// `approve` does NOT accept `expected: Option<u64>` (OQ1 resolution): a
/// fresh cap_id is by construction absent (raw allowance == 0), so CAS
/// would always either match (`None` / `Some(0)`) or always abort
/// (`Some(>0)`) — the parameter carries no information. Dropped for API
/// minimalism. Uniform with `mint_cap`.
///
/// #### Parameters
/// - `v`: Vault to mint against.
/// - `amount`: New cap's raw `remaining`. Must be `> 0` (INV-12).
///   `u64::MAX` is the UNLIMITED sentinel (INV-20) — `spend` never
///   decrements.
/// - `expires_at_ms`: Finite future timestamp, or `u64::MAX` for no expiry
///   (INV-13 / INV-20).
/// - `rate_limit`: `Some(RateLimiter)` to attach (composed from
///   `openzeppelin_utils::rate_limiter`, INV-21) or `None`.
/// - `recipient`: Address to receive the cap via `public_transfer`. NOT
///   validated — `@0x0` is the self-revoke shortcut; other unspendable
///   addresses behave equivalently (cap inert from mint). Owner's
///   responsibility (D21).
/// - `clock`: Shared system `Clock` for expiry validation.
/// - `ctx`: Transaction context. `ctx.sender()` must equal `v.owner`.
///
/// #### Aborts (INV-14 precedence)
/// 1. `EUnauthorized` — `ctx.sender() != v.owner` (INV-10).
/// 2. `EZeroAmount` — `amount == 0` (INV-12).
/// 3. `EExpiryInPast` — finite `expires_at_ms <= clock.timestamp_ms()`
///    (INV-13; `u64::MAX` always passes).
public fun approve<U>(
    v: &mut Vault<U>,
    amount: u64,
    expires_at_ms: u64,
    rate_limit: Option<RateLimiter>,
    recipient: address,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    // INV-14 precedence (inline; see also `mint_cap`).
    assert!(ctx.sender() == v.owner, EUnauthorized);              // INV-10
    assert!(amount > 0, EZeroAmount);                              // INV-12
    assert!(
        expires_at_ms == std::u64::max_value!()
            || expires_at_ms > clock.timestamp_ms(),
        EExpiryInPast,                                              // INV-13 + INV-20
    );

    let cap = mint_internal<U>(
        v,
        amount,
        expires_at_ms,
        rate_limit,
        option::some(recipient),
        ctx,
    );
    transfer::public_transfer(cap, recipient);
}

/// Owner-only. Mints a `SpenderCap` and RETURNS it by value for embedding
/// inside wrapper objects (Scenarios B/C). Caller decides cap destination
/// in the same PTB.
///
/// Cannot be `entry fun` (Move restriction: `entry` cannot return non-
/// droppable values; `SpenderCap` has no `drop`). Use `approve` for the
/// single-call wallet/CLI path.
///
/// #### Parameters / Returns / Aborts
/// Identical to `approve` minus the `recipient` parameter; returns the
/// freshly-minted `SpenderCap` by value (caller MUST consume — INV-2).
public fun mint_cap<U>(
    v: &mut Vault<U>,
    amount: u64,
    expires_at_ms: u64,
    rate_limit: Option<RateLimiter>,
    clock: &Clock,
    ctx: &mut TxContext,
): SpenderCap {
    // INV-14 precedence (inline; identical to `approve`'s).
    assert!(ctx.sender() == v.owner, EUnauthorized);              // INV-10
    assert!(amount > 0, EZeroAmount);                              // INV-12
    assert!(
        expires_at_ms == std::u64::max_value!()
            || expires_at_ms > clock.timestamp_ms(),
        EExpiryInPast,                                              // INV-13 + INV-20
    );

    mint_internal<U>(
        v,
        amount,
        expires_at_ms,
        rate_limit,
        option::none<address>(),
        ctx,
    )
}

// === Set Allowance ===

/// Owner-only. Modify an existing allowance entry IN PLACE — `cap_id` stays
/// stable (INV-28), downstream wrappers (BoundedDelegation, protocol-owned
/// cap tables) survive unbroken.
///
/// `cap_id` stability across `set_allowance` is THE central v2 property
/// that justifies introducing `set_allowance` as a distinct function from
/// `approve`/`mint_cap`. Without it, every owner-side parameter change
/// would invalidate the embedded cap, collapsing Scenarios B and C.
///
/// `new_amount == 0` is the SUSPENSION idiom (D20 / INV-27): the entry
/// stays alive, `spend(&cap, > 0)` aborts `EAllowanceExceeded` (not
/// `ENoAllowance`), and downstream embeddings survive. Owner can later
/// `set_allowance(K, > 0, ...)` to resume. Use `revoke` to terminate the
/// entry entirely.
///
/// `new_rate_limit` is overwritten UNCONDITIONALLY (OQ4 resolution): if
/// the prior entry had a limiter and you pass `None`, the limiter is
/// dropped (its `drop` ability handles cleanup). To preserve a limiter,
/// pass `Some(limiter)` — typically by reading state and reconstructing
/// via `openzeppelin_utils::rate_limiter` accessors.
///
/// `expected: Option<u64>` engages compare-and-set (CAS — INV-19):
/// - `None`: unconditional overwrite. Faster, races possible (see INV-43).
/// - `Some(e)`: aborts `EUnexpectedAllowance` unless the entry's current
///   `remaining` equals `e`. Closes the reduce-allowance interleaving
///   race: read `cur = allowance(v, K)`, then
///   `set_allowance(v, K, new, ..., expected = Some(cur), ...)` — the call
///   aborts if any `spend` was sequenced between the read and the set.
///
/// This function OVERWRITES, never increments (INV-24). All three of
/// `new_amount`, `new_expires_at_ms`, and `new_rate_limit` are replaced
/// atomically.
///
/// #### Parameters
/// - `v`: Vault to mutate.
/// - `cap_id`: ID of the cap whose entry is being modified. NOT a
///   `&SpenderCap` — anti-confusion is enforced implicitly via Table
///   lookup (INV-9): a cap_id from a different Vault is absent in this
///   Vault's Table, so the call aborts `ENoAllowance`.
/// - `new_amount`: New raw `remaining`. `0` = suspension; `u64::MAX` =
///   unlimited sentinel (INV-20).
/// - `new_expires_at_ms`: Finite future timestamp, or `u64::MAX` sentinel
///   for no expiry.
/// - `new_rate_limit`: New limiter (`Some`) or remove (`None`). The prior
///   limiter is unconditionally dropped.
/// - `expected`: CAS guard. `None` = unconditional; `Some(e)` = abort
///   unless current `remaining == e`.
/// - `clock`: Shared system `Clock` for expiry validation.
/// - `ctx`: Transaction context. `ctx.sender()` must equal `v.owner`.
///   Recorded as `AllowanceSet.by`.
///
/// #### Aborts (INV-14 precedence)
/// 1. `EUnauthorized` — `ctx.sender() != v.owner` (INV-10).
/// 2. `ENoAllowance` — `cap_id` not present in `v.allowances` (INV-9).
/// 3. `EExpiryInPast` — finite
///    `new_expires_at_ms <= clock.timestamp_ms()` (INV-13; `u64::MAX`
///    always passes).
/// 4. `EUnexpectedAllowance` — `expected = Some(e)` and current
///    `remaining != e` (INV-19).
public fun set_allowance<U>(
    v: &mut Vault<U>,
    cap_id: ID,
    new_amount: u64,
    new_expires_at_ms: u64,
    new_rate_limit: Option<RateLimiter>,
    expected: Option<u64>,
    clock: &Clock,
    ctx: &TxContext,
) {
    let vault_id = object::id(v);

    // INV-14 step 1: owner gate (INV-10).
    assert!(ctx.sender() == v.owner, EUnauthorized);

    // INV-14 step 2: ENoAllowance — INV-9 implicit Vault binding via
    // Table::contains. Preempts CAS (INV-19).
    assert!(v.allowances.contains(cap_id), ENoAllowance);

    // INV-14 step 3: EExpiryInPast (INV-13 + INV-20 sentinel handling).
    assert!(
        new_expires_at_ms == std::u64::max_value!()
            || new_expires_at_ms > clock.timestamp_ms(),
        EExpiryInPast,
    );

    // INV-14 step 4: EUnexpectedAllowance (CAS — INV-19). Reads `remaining`
    // via immutable borrow; the borrow releases before the `borrow_mut`
    // below (Move 2024 NLL handles this within the same block).
    let cas_was_provided = expected.is_some();
    if (cas_was_provided) {
        let current = v.allowances.borrow(cap_id).remaining;
        assert!(current == expected.destroy_some(), EUnexpectedAllowance);
    } else {
        // Consume the None to avoid an unused-Option warning. Option<u64>
        // has `drop` because u64 has `drop`, so this is a no-op.
        let _ = expected;
    };

    // INV-21 / RateLimitConfigured: emit BEFORE moving `new_rate_limit`
    // into the entry, so the helper can read variant + cap.
    let has_rate_limit = new_rate_limit.is_some();
    if (has_rate_limit) {
        emit_rate_limit_configured<U>(
            vault_id,
            cap_id,
            new_rate_limit.borrow(),
            ctx.sender(),
        );
    };

    // INV-24: overwrite (never increment). INV-27: `new_amount == 0`
    // leaves the entry alive (no table::remove). INV-28: in-place mutation
    // via borrow_mut preserves cap_id. OQ4: rate_limit replaced
    // unconditionally (the prior Option<RateLimiter>'s drop ability
    // handles cleanup).
    let entry = v.allowances.borrow_mut(cap_id);
    entry.remaining = new_amount;
    entry.expires_at_ms = new_expires_at_ms;
    entry.rate_limit = new_rate_limit;

    event::emit(AllowanceSet<U> {
        vault_id,
        cap_id,
        new_amount,
        new_expires_at_ms,
        has_rate_limit,
        cas_was_provided,
        by: ctx.sender(),
    });
}

// === Spend ===

/// Draw exactly `amount` against the supplied `&SpenderCap`. CAP-GATED,
/// NOT SENDER-GATED (INV-18 — the foundational v1 → v2 inversion).
///
/// EXACT-AMOUNT-OR-ABORT: a successful call delivers exactly `amount`,
/// never less, never a partial fill (INV-23). `spend` is the only atomic
/// check-and-draw — pre-`spend` reads (`allowance`, `spendable_now`) are
/// advisory (INV-44). Authorization is strictly cap-presentation +
/// allowlist membership:
///   `cap.vault_id == object::id(v)` (INV-8)
///   AND `object::id(cap) ∈ v.allowances` (INV-14 step 2)
/// `ctx.sender()` is NEVER checked for authorization here. Whoever can
/// present `&cap` to this function is authorized — including a wrapper
/// module's caller (Scenario C — keeper bot) and an address that received
/// the cap via `public_transfer` (Scenario A).
///
/// Returns `Balance<U>` (INV-6 / INV-7). No internal `public_transfer` —
/// caller plumbs the value into the next PTB step (downstream protocol
/// call, `coin::from_balance` + transfer, `balance::join` into another
/// pool, etc.). `Balance<U>` has no `drop`, so the value cannot be
/// silently discarded.
///
/// #### Reentrancy (INV-48)
/// Structurally impossible on Sui. `spend` performs no `public_transfer`,
/// no callback into untrusted code. A caller's downstream
/// `public_transfer(coin::from_balance(bal), addr)` executes NO code at
/// the destination — Sui transfers have no fallback / receive hook /
/// synchronous callback. No reentrancy guard exists, is needed, or is
/// possible.
///
/// #### Sentinel handling (INV-20)
/// - `remaining == u64::MAX` ⇒ UNLIMITED grant: `spend` does NOT
///   decrement `remaining`. The branch `if remaining != u64::MAX { ... }`
///   is the only mutation path; no `u64::MAX - amount` arithmetic is
///   ever performed.
/// - `expires_at_ms == u64::MAX` ⇒ NO EXPIRY: the expired-check branch
///   passes unconditionally.
///
/// #### Failure precedence (INV-14, deterministic single ordered abort)
/// Checked in this exact order; the FIRST holding condition is the one
/// that aborts. No later condition is observable when an earlier one
/// holds. On ANY abort, `v.balance` and every `v.allowances[k]` are
/// bit-identical to pre-call (INV-23 — no partial mutation).
///
/// 1. `EWrongVault` — `cap.vault_id != object::id(v)` (INV-8). Fires
///    BEFORE any Table access — anti-confusion has priority.
/// 2. `ENoAllowance` — `object::id(cap)` is not in `v.allowances`
///    (never granted, owner-revoked, or wrong-Vault cap_id implicitly —
///    INV-9). Distinct from `EAllowanceExceeded` against a suspended
///    entry (INV-27).
/// 3. `EAllowanceExpired` — finite expiry and `now >= expires_at_ms`
///    (INV-13 reciprocal; `u64::MAX` sentinel never expires).
/// 4. `EZeroAmount` — `amount == 0` (INV-12). Placed AFTER expired-check
///    by design — discriminability over cheapness (design §Notes 2).
/// 5. `EAllowanceExceeded` — `amount > remaining` (cap reached). Also
///    fires for suspended entries (`remaining == 0`) — the
///    suspension-vs-revoke discriminator (INV-27).
/// 6. `ERateLimited` — limiter present and refused (INV-21). Re-asserted
///    locally so the abort code matches this module's precedence row
///    (rather than `openzeppelin_utils::rate_limiter::ERateLimited`).
/// 7. `EInsufficientVault` — `amount > v.balance.value()` (pool short —
///    the "allowance ≠ guarantee" path, INV-31).
public fun spend<U>(
    v: &mut Vault<U>,
    cap: &SpenderCap,
    amount: u64,
    clock: &Clock,
    ctx: &TxContext,
): Balance<U> {
    let vault_id = object::id(v);
    let cap_id = object::id(cap);

    // ── Step 1: INV-8 EWrongVault. FIRST CHECK — before any Table access.
    assert!(cap.vault_id == vault_id, EWrongVault);

    // ── Step 2: INV-14 ENoAllowance.
    assert!(v.allowances.contains(cap_id), ENoAllowance);

    // Read-phase: copy out the scalar fields we need for steps 3–5. The
    // immutable borrow is released at the end of this block (Move 2024).
    let (remaining, expires_at_ms, has_rate_limit) = {
        let entry = v.allowances.borrow(cap_id);
        (entry.remaining, entry.expires_at_ms, entry.rate_limit.is_some())
    };

    // ── Step 3: INV-14 EAllowanceExpired (INV-26 alive predicate,
    //    computed). INV-20: u64::MAX sentinel always passes
    //    ("never expired").
    let now = clock.timestamp_ms();
    assert!(
        expires_at_ms == std::u64::max_value!() || now < expires_at_ms,
        EAllowanceExpired,
    );

    // ── Step 4: INV-14 EZeroAmount (INV-12).
    assert!(amount > 0, EZeroAmount);

    // ── Step 5: INV-14 EAllowanceExceeded. After this,
    //    `amount <= remaining` (for non-sentinel `remaining`); the
    //    sentinel u64::MAX trivially satisfies any u64 amount.
    assert!(amount <= remaining, EAllowanceExceeded);

    // ── Step 6: INV-14 ERateLimited (INV-21). Mutate the limiter via
    //    try_consume — atomic on the limiter (its own contract). We
    //    assert locally so the abort code is THIS module's ERateLimited
    //    rather than rate_limiter::ERateLimited (matches INV-14
    //    precedence row exactly).
    //
    //    If a later step (Step 7) aborts, Move's all-or-nothing tx
    //    semantics roll the try_consume state change back — INV-23 holds.
    let limiter_available_after = if (has_rate_limit) {
        let entry_mut = v.allowances.borrow_mut(cap_id);
        let limiter_mut = entry_mut.rate_limit.borrow_mut();
        assert!(
            openzeppelin_utils::rate_limiter::try_consume(limiter_mut, amount, clock),
            ERateLimited,
        );
        // `available` accepts `&RateLimiter`; Move coerces
        // `&mut RateLimiter` automatically. Captures the limiter's
        // post-consume headroom for the `RateLimitConsumed` event.
        option::some(openzeppelin_utils::rate_limiter::available(limiter_mut, clock))
    } else {
        option::none<u64>()
    };

    // ── Step 7: INV-14 EInsufficientVault (INV-15, INV-31).
    assert!(amount <= v.balance.value(), EInsufficientVault);

    // ── Commit: INV-23 exact decrement (with INV-20 sentinel
    //    no-decrement). INV-27 lazy semantics: even if
    //    `remaining_after == 0`, the entry stays in the Table (no
    //    table::remove). Future spend(&cap, > 0) aborts
    //    EAllowanceExceeded, not ENoAllowance.
    let remaining_after = if (remaining == std::u64::max_value!()) {
        std::u64::max_value!()
    } else {
        remaining - amount
    };
    v.allowances.borrow_mut(cap_id).remaining = remaining_after;

    // INV-22 / INV-15: exact split. Step 7 already proved
    // `amount <= balance`.
    let bal = balance::split(&mut v.balance, amount);

    // INV-18: emit Spent with `caller = ctx.sender()` (the sender, NOT a
    // gating value — semantic note in event doc).
    event::emit(Spent<U> {
        vault_id,
        cap_id,
        amount,
        remaining: remaining_after,
        caller: ctx.sender(),
    });

    // INV-21: paired RateLimitConsumed event ONLY when a limiter was
    // consumed. Carries the post-consume `available` for indexer
    // monitoring.
    if (has_rate_limit) {
        event::emit(RateLimitConsumed<U> {
            vault_id,
            cap_id,
            consumed: amount,
            available_after: limiter_available_after.destroy_some(),
            caller: ctx.sender(),
        });
    } else {
        // Consume the None to avoid unused warning. Option<u64> has drop.
        let _ = limiter_available_after;
    };

    bal
}

// === Revoke ===

/// Owner kill-switch: remove the `Allowance` entry for `cap_id` from this
/// Vault.
///
/// The ONLY failure mode is `EUnauthorized` (non-owner caller). Given an
/// owner caller, `revoke` ALWAYS succeeds — a present entry is removed,
/// an absent entry is an IDEMPOTENT NO-OP. In both non-aborting cases,
/// `Revoked` is emitted. On the `EUnauthorized` abort, Move/Sui rollback
/// semantics ensure NO event is emitted and NO state change occurs.
///
/// "Never aborts on allowance state" is load-bearing, not cosmetic
/// (INV-17). Revocation is the owner's emergency primitive. If `revoke`
/// could abort on raced/expired/inert state, an attacker could shape
/// state to make the owner's revoke fail — defeating the kill-switch.
/// The only permitted failure is the authorization precondition; never a
/// race.
///
/// #### Cap-object lifecycle (INV-29 — asymmetric)
///
/// `revoke` removes the LEDGER ENTRY only. The `SpenderCap` OBJECT itself
/// continues to exist in its holder's wallet (or wrapper) as inert
/// garbage. Subsequent `spend(&cap, ...)` against this cap aborts
/// `ENoAllowance`. The library cannot destroy a cap object the owner
/// does not hold — this is structural on Sui (no on-chain wallet
/// enumeration). Cap-holders may dispose of their inert caps by
/// `public_transfer`ing to `@0x0` or simply leaving them dormant.
///
/// #### `revoke` is the only owner-driven path that calls `table::remove`.
///
/// A `spend`-to-zero entry is left in place (INV-27 lazy semantics). The
/// resulting `ENoAllowance` (absent, post-revoke) vs `EAllowanceExceeded`
/// (present, `remaining == 0`, post-spend-to-zero OR post-suspension) is
/// the documented discriminator that lets wrappers / protocol tables tell
/// "owner cancelled" from "owner froze / spender drained."
///
/// #### Parameters
/// - `v`: Vault to mutate.
/// - `cap_id`: ID of the cap whose entry is being revoked. Absent cap_id
///   permitted (no-op, INV-17). Cross-Vault cap_id (foreign) is
///   implicitly absent in this Vault's Table — same no-op path (INV-9).
/// - `ctx`: Transaction context. `ctx.sender()` must equal `v.owner`.
///   Recorded as `Revoked.by`.
///
/// #### Aborts
/// - `EUnauthorized` if `ctx.sender() != v.owner` (INV-10).
public fun revoke<U>(v: &mut Vault<U>, cap_id: ID, ctx: &TxContext) {
    // INV-10: owner gate. ONLY failure mode.
    assert!(ctx.sender() == v.owner, EUnauthorized);

    // INV-17: present ⇒ remove; absent ⇒ no-op. Either way emit Revoked.
    // `table::remove` returns the removed Allowance value; we destructure
    // it to document the cleanup of the embedded rate_limit (everything
    // has `drop`, so falling out of scope works equivalently).
    if (v.allowances.contains(cap_id)) {
        let removed = v.allowances.remove(cap_id);
        let Allowance { remaining: _, expires_at_ms: _, rate_limit: _ } = removed;
    };

    // INV-17: emit Revoked on EVERY non-aborting call (present OR absent).
    // Indexers observe the event as confirmation regardless of prior
    // state.
    event::emit(Revoked<U> {
        vault_id: object::id(v),
        cap_id,
        by: ctx.sender(),
    });
}

// === Owner Exit ===

/// Owner-only. Withdraw exactly `amount` from the pool, returned as
/// `Coin<U>`.
///
/// Returns `Coin<U>` (not `Balance<U>`) per INV-7: owner exit goes to an
/// address (an object is the only thing transferable to an address). The
/// caller typically `public_transfer`s the returned Coin to wherever the
/// owner wants the funds.
///
/// **Owner can always defund** (INV-32): no consultation of
/// `v.allowances`, no consultation of any rate limiter — the only state
/// read is `v.balance.value()`. An outstanding allowance does NOT block
/// withdrawal; the withdrawal may leave a previously-valid `spend`
/// aborting with `EInsufficientVault` (INV-31 / INV-37 — allowance ≠
/// guarantee).
///
/// #### Parameters
/// - `v`: Vault to drain.
/// - `amount`: Exact value to extract. Must be `> 0` and
///   `<= v.balance.value()`.
/// - `ctx`: Transaction context. `ctx.sender()` must equal `v.owner`;
///   `&mut` is required because `coin::take` mints a fresh `Coin<U>`
///   object (needs a new UID).
///
/// #### Returns
/// - `Coin<U>` of exactly `amount`.
///
/// #### Aborts (INV-14 precedence)
/// 1. `EUnauthorized` — `ctx.sender() != v.owner` (INV-10).
/// 2. `EZeroAmount` — `amount == 0` (INV-12).
/// 3. `EInsufficientVault` — `amount > v.balance.value()` (INV-15).
public fun withdraw<U>(v: &mut Vault<U>, amount: u64, ctx: &mut TxContext): Coin<U> {
    assert!(ctx.sender() == v.owner, EUnauthorized);
    assert!(amount > 0, EZeroAmount);
    assert!(amount <= v.balance.value(), EInsufficientVault);

    // INV-22: pool decreases by exactly `amount`. coin::take is the safe
    // split-and-mint primitive (asserted above; no underflow possible).
    let coin = coin::take(&mut v.balance, amount, ctx);

    event::emit(Withdrawn<U> {
        vault_id: object::id(v),
        amount,
        by: ctx.sender(),
    });

    coin
}

/// Owner-only. Withdraw the ENTIRE pool balance, returned as `Coin<U>`.
///
/// Aborts `EInsufficientVault` on an empty pool — prevents `Coin<U>`
/// litter (a zero-value Coin that the owner would have to
/// `coin::destroy_zero`). To teardown an empty Vault, use `destroy`
/// (which IS permissive about zero balance; see its doc).
///
/// Same owner-defund property as `withdraw` (INV-32): no consultation of
/// `v.allowances`. Live allowances may abort `EInsufficientVault` on the
/// next `spend` after this call — intended (INV-31 / INV-37).
///
/// #### Parameters
/// - `v`: Vault to drain.
/// - `ctx`: Transaction context. `ctx.sender()` must equal `v.owner`.
///
/// #### Returns
/// - `Coin<U>` containing the full pre-call balance (`> 0`).
///
/// #### Aborts (INV-14 precedence)
/// 1. `EUnauthorized` — `ctx.sender() != v.owner` (INV-10).
/// 2. `EInsufficientVault` — `v.balance.value() == 0` (INV-15 — no zero
///    Coin litter; mirrors v1 behavior).
public fun withdraw_all<U>(v: &mut Vault<U>, ctx: &mut TxContext): Coin<U> {
    assert!(ctx.sender() == v.owner, EUnauthorized);

    let amount = v.balance.value();
    assert!(amount > 0, EInsufficientVault);

    let coin = coin::take(&mut v.balance, amount, ctx);

    event::emit(Withdrawn<U> {
        vault_id: object::id(v),
        amount,
        by: ctx.sender(),
    });

    coin
}

/// Owner-only. Consume the Vault by value, drop the allowance ledger,
/// delete the shared object, return the leftover balance as `Coin<U>`.
///
/// PERMISSIVE about empty balance — `destroy` returns `Coin<U>` even if
/// the leftover is zero (the caller does `coin::destroy_zero` as part of
/// cleanup). Asymmetric to `withdraw_all`'s strictness on purpose:
/// `destroy` is a teardown verb where zero-refund IS a normal flow step
/// (the Vault has already been drained to zero before destroy in the
/// common case).
///
/// **No pre-revoke required** for active allowances. `table::drop`
/// disposes of every `Allowance` entry — including embedded
/// `Option<RateLimiter>`s — cleanly. The corresponding `SpenderCap`
/// OBJECTS remain in holders' wallets as inert garbage (INV-29 asymmetric
/// — owner has no way to destroy caps they don't hold). Any subsequent
/// `spend(&cap, ...)` against those caps aborts `EWrongVault` (the Vault
/// no longer exists; the cap's `vault_id` mismatches every other Vault)
/// or `ENoAllowance` (if somehow presented to a Vault with the same
/// `vault_id` — structurally impossible since ID is unique).
///
/// Shared-object deletion via `object::delete(id)` is supported at the
/// pinned Sui CLI version (1.71.1 — invariants-v2 OQ8 resolved; existence
/// proof in
/// `openzeppelin_access::two_step_transfer::accept_transfer`).
///
/// #### Parameters
/// - `v`: Vault to destroy. Consumed BY VALUE.
/// - `ctx`: Transaction context. `ctx.sender()` must equal `v.owner`.
///
/// #### Returns
/// - `Coin<U>` of the leftover balance. May be zero.
///
/// #### Aborts (INV-14 precedence)
/// 1. `EUnauthorized` — `ctx.sender() != v.owner` (INV-10).
public fun destroy<U>(v: Vault<U>, ctx: &mut TxContext): Coin<U> {
    assert!(ctx.sender() == v.owner, EUnauthorized);

    // Capture vault_id BEFORE unpacking (UID is consumed by
    // `object::delete`).
    let vault_id = object::id(&v);

    // INV-25: by-value unpack of the Vault. `owner` (address) drops
    // trivially.
    let Vault { id, owner: _, balance, allowances } = v;

    // INV-25: drop the entire ledger. `Allowance has store + drop`, and
    // its embedded `Option<RateLimiter>` also drops cleanly —
    // table::drop unwinds all entries in one call. INV-29: cap OBJECTS
    // are not touched (library holds no references to live caps).
    table::drop(allowances);

    // INV-22: leftover Balance becomes the returned Coin's value (no `U`
    // created or destroyed). `coin::from_balance` consumes the Balance
    // and mints a fresh Coin (may be value 0).
    let refunded = balance.value();
    let coin = coin::from_balance(balance, ctx);

    event::emit(VaultDestroyed<U> {
        vault_id,
        refunded,
        by: ctx.sender(),
    });

    // INV-25: terminal — delete the shared object's UID. After this,
    // the `Vault<U>` no longer exists on-chain.
    object::delete(id);

    coin
}

// === Reads ===
//
// All reads are TOTAL — never abort, for any input, in any Vault state
// (INV-16). Use as advisory pre-`spend` predicates; `spend` itself is the
// only atomic check-and-draw (INV-44 — TOCTOU). Definitional identities
// pinned in INV-45.

/// Owner address. Set at `new(initial_owner, ...)` and immutable
/// thereafter (INV-11 / INV-39).
public fun owner<U>(v: &Vault<U>): address {
    v.owner
}

/// Raw `remaining` allowance for `cap_id`. `0` if absent (per INV-45 —
/// the ERC-20 `allowance()` semantic).
///
/// **Raw, NOT effective:** this value is the STORED `remaining` only —
/// it does NOT fold in expiry, pool balance, or rate-limiter availability.
/// Use `spendable_now` for the over-estimation-safe view that reflects
/// what `spend` will actually permit. Treat `allowance` as standing
/// authorization (the ceiling the owner has consented to); treat
/// `spendable_now` as drawability NOW. The divergence between them is
/// the precise distinction the v2 dual-read API exposes to mitigate the
/// ERC-20 over-estimation footgun.
///
/// The `u64::MAX` sentinel is returned as-is — denotes unlimited
/// authority (INV-20). Use `contains` if you need to disambiguate
/// "absent" from "present with `remaining == 0`" (suspended — INV-27).
public fun allowance<U>(v: &Vault<U>, cap_id: ID): u64 {
    if (v.allowances.contains(cap_id)) {
        v.allowances.borrow(cap_id).remaining
    } else {
        0
    }
}

/// Effective drawable amount for `cap_id` at `now = clock.timestamp_ms()`.
///
/// Per INV-45 definitional identity:
///
/// ```
/// spendable_now(K) =
///     0  if K absent  OR  finite expiry has passed
///     min(remaining, v.balance.value(), limiter.available) otherwise
/// ```
///
/// `limiter.available` is `openzeppelin_utils::rate_limiter::available(...)`
/// when a limiter is attached, or unbounded (no constraint from limiter
/// side) when absent.
///
/// **Always `<= allowance(v, cap_id)` and `<= balance_value(v)`**
/// (INV-45). Collapses to `0` the instant the grant is absent / expired /
/// limiter-exhausted — even while raw `allowance` may remain `> 0`. Use
/// this as the over-estimation-safe predicate before calling `spend`;
/// `spend(v, cap, spendable_now(v, cap_id, clock), ...)` is by
/// construction guaranteed to clear steps 1–5 of the precedence (the only
/// residual abort would be a between-call race per INV-44 / INV-42).
///
/// Never aborts.
public fun spendable_now<U>(v: &Vault<U>, cap_id: ID, clock: &Clock): u64 {
    if (!v.allowances.contains(cap_id)) {
        return 0
    };

    let entry = v.allowances.borrow(cap_id);
    let now = clock.timestamp_ms();

    // INV-26 alive predicate, computed.
    let alive =
        entry.expires_at_ms == std::u64::max_value!() || now < entry.expires_at_ms;
    if (!alive) {
        return 0
    };

    // Compose three bounds: raw remaining, pool balance, limiter
    // headroom (or u64::MAX if no limiter — neutral element for min).
    let limiter_bound = if (entry.rate_limit.is_some()) {
        openzeppelin_utils::rate_limiter::available(entry.rate_limit.borrow(), clock)
    } else {
        std::u64::max_value!()
    };

    let bal = v.balance.value();
    min3(entry.remaining, bal, limiter_bound)
}

/// Raw `expires_at_ms` for `cap_id`. `0` if absent.
///
/// Per INV-45: the `u64::MAX` sentinel is returned AS-IS (denotes "no
/// expiry"); `0` is the absent marker (no legitimate `expires_at_ms` can
/// be `0` because INV-13 enforces `> now` at grant time, and `now > 0`
/// for any non-genesis clock).
///
/// Use `contains` to disambiguate "absent" (`0`) from "no-expiry sentinel
/// stored" (`u64::MAX`) — the two are distinguishable: only an absent
/// cap_id returns `0` from this function.
public fun expiry<U>(v: &Vault<U>, cap_id: ID): u64 {
    if (v.allowances.contains(cap_id)) {
        v.allowances.borrow(cap_id).expires_at_ms
    } else {
        0
    }
}

/// `true` iff a ledger entry exists for `cap_id`. The PRECISE predicate
/// that disambiguates absent (`allowance == 0`, `expiry == 0`) from
/// legitimate sentinel-bearing entries (`allowance == u64::MAX` /
/// `expiry == u64::MAX`).
///
/// Critically: `contains == true` AND `allowance == 0` ⇒ the entry is
/// SUSPENDED (INV-27 — `set_allowance(K, 0, ...)` idiom or `spend`-
/// drained to zero). Wrappers / protocol tables read this to distinguish
/// "owner froze me, will resume" from "owner cancelled me, retire the
/// wrapper" — the central INV-27 / INV-29 use case.
public fun contains<U>(v: &Vault<U>, cap_id: ID): bool {
    v.allowances.contains(cap_id)
}

/// Pool balance — `v.balance.value()`. The shared pool that ALL live caps
/// draw from (INV-31 — Σ live `remaining` may exceed this; allowance ≠
/// guarantee).
public fun balance_value<U>(v: &Vault<U>): u64 {
    v.balance.value()
}

// === Private Helpers ===

/// Construct the cap + ledger entry and emit the events. Caller MUST
/// pre-assert the INV-14 precedence (`EUnauthorized` → `EZeroAmount` →
/// `EExpiryInPast`) BEFORE invoking — this helper performs no checks.
///
/// `recipient` is passed through to `Approved.recipient` verbatim:
/// - `approve` passes `Some(recipient_addr)` (even `Some(@0x0)`).
/// - `mint_cap` passes `None`.
/// No sentinel ambiguity.
fun mint_internal<U>(
    v: &mut Vault<U>,
    amount: u64,
    expires_at_ms: u64,
    rate_limit: Option<RateLimiter>,
    recipient: Option<address>,
    ctx: &mut TxContext,
): SpenderCap {
    let vault_id = object::id(v);
    let cap_uid = object::new(ctx);
    let cap_id = cap_uid.uid_to_inner();

    // INV-21: emit RateLimitConfigured BEFORE moving `rate_limit` into
    // the Allowance so the helper can read the limiter's variant +
    // capacity.
    let has_rate_limit = rate_limit.is_some();
    if (has_rate_limit) {
        emit_rate_limit_configured<U>(vault_id, cap_id, rate_limit.borrow(), ctx.sender());
    };

    // INV-3 / INV-30: cap.vault_id pinned at mint, immutable thereafter.
    let cap = SpenderCap { id: cap_uid, vault_id };

    // INV-4: fresh Allowance entry keyed by cap_id (fresh UID — never
    // collides with any existing entry per INV-42).
    let entry = Allowance { remaining: amount, expires_at_ms, rate_limit };
    v.allowances.add(cap_id, entry);

    event::emit(Approved<U> {
        vault_id,
        cap_id,
        recipient,
        amount,
        expires_at_ms,
        has_rate_limit,
        by: ctx.sender(),
    });

    cap
}

/// Emit `RateLimitConfigured` for a freshly attached `RateLimiter`.
/// Derives the `kind: u8` tag from the limiter's variant via the public
/// `is_bucket` / `is_fixed_window` / `is_cooldown` predicates exposed by
/// `openzeppelin_utils::rate_limiter`. Capacity is read via the
/// variant-agnostic `capacity()` accessor.
///
/// Encoding (pinned in `RateLimitConfigured` doc):
/// - `0` ⇒ Bucket
/// - `1` ⇒ FixedWindow
/// - `2` ⇒ Cooldown
///
/// Future variant additions in `openzeppelin_utils` would be a binary-
/// incompatible upgrade (per the limiter module's own upgrade-
/// compatibility note) and would require a coordinated change here as
/// well.
fun emit_rate_limit_configured<U>(
    vault_id: ID,
    cap_id: ID,
    limiter: &RateLimiter,
    by: address,
) {
    let kind = if (openzeppelin_utils::rate_limiter::is_bucket(limiter)) {
        0u8
    } else if (openzeppelin_utils::rate_limiter::is_fixed_window(limiter)) {
        1u8
    } else {
        // INV: rate_limiter exposes exactly three variants today; if a
        // future upgrade adds a fourth, this branch silently bins it as
        // Cooldown. The variant addition would already be a binary-
        // incompatible change requiring coordinated update (event doc
        // warning).
        2u8
    };
    let capacity = openzeppelin_utils::rate_limiter::capacity(limiter);

    event::emit(RateLimitConfigured<U> {
        vault_id,
        cap_id,
        kind,
        capacity,
        by,
    });
}

/// Three-way minimum over `u64`. Used by `spendable_now` to compose
/// remaining / pool / limiter bounds (INV-45). The `u64::MAX` sentinel
/// behaves as the neutral element naturally — `min3(u64::MAX, x, y)`
/// equals `min(x, y)`.
fun min3(a: u64, b: u64, c: u64): u64 {
    let ab = if (a <= b) { a } else { b };
    if (ab <= c) { ab } else { c }
}

// === Test-Only Helpers ===

/// Construct a `VaultCreated<U>` event value for test-side equality
/// assertions.
#[test_only]
public fun test_new_vault_created<U>(
    vault_id: ID,
    owner: address,
    creator: address,
): VaultCreated<U> {
    VaultCreated { vault_id, owner, creator }
}

/// Construct a `Deposited<U>` event value for test-side equality
/// assertions.
#[test_only]
public fun test_new_deposited<U>(
    vault_id: ID,
    amount: u64,
    depositor: address,
): Deposited<U> {
    Deposited { vault_id, amount, depositor }
}

/// Construct an `Approved<U>` event value for test-side equality
/// assertions.
#[test_only]
public fun test_new_approved<U>(
    vault_id: ID,
    cap_id: ID,
    recipient: Option<address>,
    amount: u64,
    expires_at_ms: u64,
    has_rate_limit: bool,
    by: address,
): Approved<U> {
    Approved {
        vault_id,
        cap_id,
        recipient,
        amount,
        expires_at_ms,
        has_rate_limit,
        by,
    }
}

/// Construct an `AllowanceSet<U>` event value for test-side equality
/// assertions.
#[test_only]
public fun test_new_allowance_set<U>(
    vault_id: ID,
    cap_id: ID,
    new_amount: u64,
    new_expires_at_ms: u64,
    has_rate_limit: bool,
    cas_was_provided: bool,
    by: address,
): AllowanceSet<U> {
    AllowanceSet {
        vault_id,
        cap_id,
        new_amount,
        new_expires_at_ms,
        has_rate_limit,
        cas_was_provided,
        by,
    }
}

/// Construct a `RateLimitConfigured<U>` event value for test-side
/// equality assertions.
#[test_only]
public fun test_new_rate_limit_configured<U>(
    vault_id: ID,
    cap_id: ID,
    kind: u8,
    capacity: u64,
    by: address,
): RateLimitConfigured<U> {
    RateLimitConfigured { vault_id, cap_id, kind, capacity, by }
}

/// Construct a `Spent<U>` event value for test-side equality assertions.
#[test_only]
public fun test_new_spent<U>(
    vault_id: ID,
    cap_id: ID,
    amount: u64,
    remaining: u64,
    caller: address,
): Spent<U> {
    Spent { vault_id, cap_id, amount, remaining, caller }
}

/// Construct a `RateLimitConsumed<U>` event value for test-side equality
/// assertions.
#[test_only]
public fun test_new_rate_limit_consumed<U>(
    vault_id: ID,
    cap_id: ID,
    consumed: u64,
    available_after: u64,
    caller: address,
): RateLimitConsumed<U> {
    RateLimitConsumed {
        vault_id,
        cap_id,
        consumed,
        available_after,
        caller,
    }
}

/// Construct a `Revoked<U>` event value for test-side equality
/// assertions.
#[test_only]
public fun test_new_revoked<U>(
    vault_id: ID,
    cap_id: ID,
    by: address,
): Revoked<U> {
    Revoked { vault_id, cap_id, by }
}

/// Construct a `Withdrawn<U>` event value for test-side equality
/// assertions.
#[test_only]
public fun test_new_withdrawn<U>(
    vault_id: ID,
    amount: u64,
    by: address,
): Withdrawn<U> {
    Withdrawn { vault_id, amount, by }
}

/// Construct a `VaultDestroyed<U>` event value for test-side equality
/// assertions.
#[test_only]
public fun test_new_vault_destroyed<U>(
    vault_id: ID,
    refunded: u64,
    by: address,
): VaultDestroyed<U> {
    VaultDestroyed { vault_id, refunded, by }
}
