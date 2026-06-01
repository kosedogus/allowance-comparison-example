/// Fungible coin allowance / approval primitive for Sui.
///
/// A `Vault<U>` is a shared escrow holding a `Balance<U>` plus an address-keyed ledger of
/// per-spender allowances. The Vault is owner-controlled through a vault-bound `OwnerCap`.
/// Spenders draw from the ledger via `consume`, which is EXACT-amount-or-abort and
/// authorized strictly by `ctx.sender()` (the standard ERC-20 `transferFrom` model, ported
/// to Sui's escrow constraint — see `#### Security Model`).
///
/// #### Core semantics
///
/// - **Ceiling, not guarantee.** `Sum(remaining)` across live spenders may exceed the pool
///   balance (over-subscription is sound). A `consume` may abort `EInsufficientVault` even
///   when the spender's `remaining` is positive.
/// - **Mandatory expiry.** `grant` requires a future `expires_at_ms`. The only path to
///   unbounded authority is the separate, loudly named `grant_indefinite`.
/// - **Optional recipient binding.** A grant with `recipient = some(R)` routes each
///   `consume` to `R` via `public_transfer` and returns `None` — the spender, even fully
///   compromised, can never divert bound funds. An unbound grant returns
///   `Some(Balance<U>)` for PTB-composable plumbing.
/// - **Optional compare-and-set (CAS) on (re-)grant.** `compare-and-set` is the
///   distributed-systems primitive "update only if the current value matches what I
///   read"; here, the caller passes `expected = some(e)` and the call aborts
///   `EUnexpectedAllowance` unless the current raw `allowance(spender) == e` (absent
///   counts as `0`). This closes the reduce-allowance interleaving race: an integrator
///   reads `cur = allowance(...)`, then calls `grant(..., expected = Some(cur), ...)`,
///   and the call aborts if any `consume` was sequenced between the read and the
///   grant. `expected = None` skips the check — the cheap, unconditional, ERC-20-
///   equivalent overwrite path. Throughout this module and the surrounding artifacts,
///   "CAS" always refers to this `expected`-based guard.
/// - **Owner can always defund.** `withdraw` / `withdraw_all` / `destroy` consult only the
///   cap binding and the pool — never the ledger. Allowances cannot lock owner funds.
///
/// #### Object model
///
/// - `Vault<U>` is `key`-only (no `store`, no `drop`, no `copy`) — shared object whose
///   lifecycle (`new` -> `share` / `destroy`) is controlled solely by this module.
/// - `OwnerCap` is `key + store` (no `copy`) — vault-bound owned authority. `store`
///   enables composition with the `openzeppelin_access` ownership-transfer wrappers
///   (`two_step_transfer::wrap`, `delayed_transfer::wrap`) with no security cost: the
///   `vault_id` binding (checked at runtime on every owner-gated call) is what makes
///   `store` safe.
/// - `Allowance` is a non-object `store + drop` value living inside
///   `Vault.allowances: Table<address, Allowance>`. Not independently addressable.
///
/// #### Security Model
///
/// - Owner authority == possession of the cap whose `vault_id` matches the Vault.
/// - Spender authority is address-keyed and non-transferable. There is no `SpenderCap`.
/// - `ctx.sender()` on Sui is the transaction signer, invariant across module/package
///   call depth (no `msg.sender == contract` notion). A package address can never be a
///   spender; granting to one yields a dead-on-arrival allowance.
/// - The bound-path `public_transfer` executes no destination code (Sui transfers do not
///   invoke a callback). `consume` cannot be reentered through the bound path.
///
/// #### Composability
///
/// - `new` returns the Vault by value so a single PTB can `new` -> `deposit` -> `grant*`
///   -> `share` -> `transfer(cap)` atomically.
/// - `consume` returns `Option<Balance<U>>` (no imposed object on the unbound path) so
///   the drawn value can be plumbed directly into a downstream call.
/// - Reads (`allowance`, `spendable`, `expiry`, `cap_id`) take `&Vault`, never abort,
///   and reflect committed state at call time. Treat them as advisory pre-`consume`
///   predicates; `consume` itself is the only atomic check-and-draw.
///
/// #### Non-guarantees (read these)
///
/// - Solvency is NOT guaranteed (over-subscription). A live, non-exceeded allowance can
///   abort `EInsufficientVault`.
/// - Grants are NOT vested or time-locked. The owner may unilaterally reduce, revoke,
///   shorten expiry, rebind recipient, or defund at any time — with no spender consent.
/// - `deposit` is permissionless and confers no rights on the depositor; deposited funds
///   become owner-withdrawable and spender-drawable within existing grants. Only fund a
///   Vault whose owner you trust.
/// - `recipient` is unvalidated. Binding to `@0x0` or any unspendable address strands the
///   funds on `consume` (transferred away, not credited back to the Vault). Choosing a
///   sound `recipient` is solely the owner's responsibility.
module openzeppelin_allowance::coin_allowance;

use sui::balance::{Self, Balance};
use sui::clock::Clock;
use sui::coin::{Self, Coin};
use sui::event;
use sui::table::{Self, Table};

// === Errors ===

/// Provided `OwnerCap` is not bound to the supplied `Vault`.
#[error(code = 0)]
const EWrongOwnerCap: vector<u8> = "OwnerCap does not match this Vault";
/// Amount or deposited coin value was zero on a value-moving entry point.
#[error(code = 1)]
const EZeroAmount: vector<u8> = "Amount must be greater than zero";
/// `expires_at_ms` was at or before the current clock timestamp in `grant`.
#[error(code = 2)]
const EExpiryInPast: vector<u8> = "Expiry must be in the future";
/// CAS guard failed: current raw allowance does not match `expected`.
#[error(code = 3)]
const EUnexpectedAllowance: vector<u8> = "Current allowance does not match expected";
/// `ctx.sender()` has no allowance entry in this Vault.
#[error(code = 4)]
const ENoAllowance: vector<u8> = "No allowance for sender";
/// Allowance entry exists but its expiry has passed.
#[error(code = 5)]
const EAllowanceExpired: vector<u8> = "Allowance has expired";
/// Requested amount exceeds the spender's `remaining`.
#[error(code = 6)]
const EAllowanceExceeded: vector<u8> = "Amount exceeds remaining allowance";
/// Requested amount exceeds the Vault's pooled `Balance<U>`.
#[error(code = 7)]
const EInsufficientVault: vector<u8> = "Vault balance insufficient";

// === Structs ===

/// Shared escrow + per-spender allowance ledger for coin type `U`.
///
/// One Vault per `(owner, U)` pair the owner chooses to set up. The Vault holds the
/// escrowed `Balance<U>` and an address-keyed `Table` of `Allowance` entries. Mutations
/// are gated by an `OwnerCap` whose `vault_id` matches this Vault, except for
/// `deposit` (permissionless) and `consume` (sender-authorized against a ledger entry).
///
/// `cap_id` records the singular `OwnerCap` object ID at `new` and is immutable.
/// Together with `OwnerCap.vault_id` it forms a closed two-way binding observable
/// on-chain; off-chain consumers resolve "who currently owns this Vault's authority"
/// by querying Sui RPC for the current owner of `cap_id`.
///
/// `key`-only by design (no `store`, `copy`, or `drop`). This makes the Vault a linear,
/// module-controlled object:
/// - It cannot be silently dropped — `new` must be followed by `share` or `destroy`
///   within the same transaction.
/// - It cannot be wrapped, stored, or `public_transfer`'d by an external module.
/// - Its full lifecycle (`new` -> `share`/`destroy`) is controlled by this module only.
///
/// (See INV-1 for the type-level guarantees this ability set enforces.)
public struct Vault<phantom U> has key {
    id: UID,
    cap_id: ID,
    balance: Balance<U>,
    allowances: Table<address, Allowance>,
}

/// Owner authority for exactly one `Vault<U>`.
///
/// `key + store` with no `copy`. `store` enables natural composition with the
/// `openzeppelin_access::two_step_transfer` / `delayed_transfer` wrappers and with
/// multisig / DAO custody objects — no security cost, because the runtime
/// `vault_id == object::id(vault)` check (asserted on every owner-gated call) is what
/// authorizes the cap against this specific Vault. The phantom type parameter is
/// intentionally absent: the cap-to-Vault binding is the `vault_id` field, not the
/// type system. (See INV-2 and INV-7.)
public struct OwnerCap has key, store {
    id: UID,
    vault_id: ID,
}

/// Single ledger entry for one spender of one Vault.
///
/// `store + drop`, no `key`, no `copy`:
/// - `store` so it can live in `Vault.allowances: Table<address, Allowance>`;
/// - `drop` so `remove` / overwrite / `table::drop` (at `destroy`) dispose of it cleanly;
/// - no `key` so the entry is reachable only through Vault-mediated functions, never
///   independently addressable;
/// - no `copy` so a single source of truth exists per (Vault, spender) pair.
///
/// `expires_at_ms = None` means `grant_indefinite` (the loud opt-out). `recipient =
/// Some(R)` binds the destination of every `consume` against this entry. `alive` is
/// NOT a stored field: liveness is recomputed from `(table::contains, expires_at_ms,
/// clock.timestamp_ms())` at every call site (no inconsistent-flag risk).
/// (See INV-3, INV-20, INV-21.)
public struct Allowance has store, drop {
    remaining: u64,
    expires_at_ms: Option<u64>,
    recipient: Option<address>,
}

// === Events ===

/// Emitted by `new` when a Vault and its bound `OwnerCap` are minted.
public struct VaultCreated<phantom U> has copy, drop {
    vault_id: ID,
    cap_id: ID,
    creator: address,
}

/// Emitted by `deposit`. `depositor` is recorded because deposits are permissionless;
/// the depositor MUST NOT be assumed to have any authority over the Vault (INV-25).
public struct Deposited<phantom U> has copy, drop {
    vault_id: ID,
    amount: u64,
    depositor: address,
}

/// Emitted by `grant` and `grant_indefinite`. `expires_at_ms == None` iff
/// `grant_indefinite`; `recipient == None` iff the grant is unbound. `by` is
/// `ctx.sender()` of the call — typically the cap holder (possibly a multisig
/// or wrapper module), NOT necessarily the granter of the cap.
public struct Granted<phantom U> has copy, drop {
    vault_id: ID,
    spender: address,
    amount: u64,
    expires_at_ms: Option<u64>,
    recipient: Option<address>,
    by: address,
}

/// Emitted on every successful `consume`. `amount` is the value drawn THIS call;
/// `remaining` is the spender's raw `remaining` AFTER this call (so an indexer can
/// reconstruct standing allowance without re-summing history). `recipient == Some(R)`
/// iff the grant was bound and funds were transferred to R; `None` iff the caller
/// received the `Balance<U>` directly.
public struct Consumed<phantom U> has copy, drop {
    vault_id: ID,
    spender: address,
    amount: u64,
    remaining: u64,
    recipient: Option<address>,
}

/// Emitted by `revoke` on every non-aborting call, INCLUDING the idempotent no-op
/// path where no entry existed (INV-14). An aborted `revoke` (mismatched cap) emits
/// nothing per Move/Sui rollback semantics. `by` is `ctx.sender()` of the call.
public struct Revoked<phantom U> has copy, drop {
    vault_id: ID,
    spender: address,
    by: address,
}

/// Emitted by both `withdraw` and `withdraw_all`. A single event type for both keeps
/// indexers from having to special-case the "drain" path. `amount` is the actual value
/// transferred to the cap holder.
public struct Withdrawn<phantom U> has copy, drop {
    vault_id: ID,
    amount: u64,
    by: address,
}

/// Emitted by `destroy`. `refunded` is the leftover `Balance<U>` returned as a
/// (possibly-zero) `Coin<U>`. After this event the Vault and its `OwnerCap` no longer
/// exist on-chain (INV-19).
public struct VaultDestroyed<phantom U> has copy, drop {
    vault_id: ID,
    refunded: u64,
    by: address,
}

// === Public Functions ===

// === Lifecycle ===

/// Create a new Vault for coin type `U` and its sole, vault-bound `OwnerCap`.
///
/// Returned **by value** so a single PTB can `new` -> `deposit` -> `grant*` ->
/// `share` -> `transfer(cap)` atomically (INV-28). The Vault has `key` only (no
/// `drop`), so the transaction will fail unless every returned Vault is consumed
/// by either `share` or `destroy` in the same tx — there is no path that silently
/// loses a Vault.
///
/// #### Parameters
/// - `ctx`: Transaction context. `ctx.sender()` is recorded as the `creator` in
///   `VaultCreated` (informational only — INV-25 / INV-26).
///
/// #### Returns
/// - `(Vault<U>, OwnerCap)` paired by `vault_id` (INV-7) and `cap_id`.
public fun new<U>(ctx: &mut TxContext): (Vault<U>, OwnerCap) {
    let vault_uid = object::new(ctx);
    let cap_uid = object::new(ctx);
    let vault_id = vault_uid.uid_to_inner();
    let cap_id = cap_uid.uid_to_inner();

    let vault = Vault<U> {
        id: vault_uid,
        cap_id,
        balance: balance::zero<U>(),
        allowances: table::new<address, Allowance>(ctx),
    };
    let cap = OwnerCap { id: cap_uid, vault_id };

    event::emit(VaultCreated<U> {
        vault_id,
        cap_id,
        creator: ctx.sender(),
    });

    (vault, cap)
}

/// Share the Vault. Defining-module-only entry point (`Vault<U>` omits `store`,
/// so external modules cannot call `transfer::public_share_object` on it). Must
/// be called within the same transaction that produced the Vault, OR the Vault
/// must be `destroy`'d — otherwise the tx fails (no `drop` ability, INV-1).
///
/// After `share`, the Vault is no longer addressable in this transaction (Sui
/// shared-object rule: a shared object becomes a valid shared input only in
/// *subsequent* transactions). All fund/grant/transfer steps for the PTB must
/// precede `share`.
///
/// #### Parameters
/// - `v`: Vault to share. Consumed by value.
public fun share<U>(v: Vault<U>) {
    transfer::share_object(v);
}

// === Fund ===

/// Add coins to the shared pool. PERMISSIONLESS — anyone may deposit (INV-25).
///
/// Depositing confers NO withdrawal, allowance, or governance rights on the
/// depositor. Deposited funds become owner-withdrawable (INV-23) and
/// spender-drawable within existing grants (INV-22). DOC WARNING: only fund a
/// Vault whose owner you trust.
///
/// Zero-value deposits are rejected with `EZeroAmount` to remove a permissionless
/// event-litter / spam vector (INV-8 — deliberate extension of the design's
/// EZeroAmount scope beyond grant/consume/withdraw). The assert is the FIRST
/// effective statement so a zero-value `Coin` aborts before any state change
/// and before the `Deposited` event (both rolled back together per Move/Sui
/// abort semantics).
///
/// #### Parameters
/// - `v`: Vault to fund.
/// - `c`: Coin to deposit. Consumed by value; its value is added to the pool.
/// - `ctx`: Transaction context. `ctx.sender()` is recorded as the `depositor`
///   in `Deposited` for indexer attribution; the depositor receives NO on-chain
///   rights (INV-25).
///
/// #### Aborts
/// - `EZeroAmount` if `c.value() == 0`.
public fun deposit<U>(v: &mut Vault<U>, c: Coin<U>, ctx: &TxContext) {
    let amount = c.value();
    // INV-8: reject zero-value deposits before any state change.
    assert!(amount > 0, EZeroAmount);

    // INV-15 (conservation): pool balance increases by exactly `amount`.
    // INV-30/INV-33 enforced structurally by `&mut Vault<U>` (consensus-
    // serialized per-Vault; no cross-Vault state touched).
    balance::join(&mut v.balance, coin::into_balance(c));

    event::emit(Deposited<U> {
        vault_id: object::id(v),
        amount,
        depositor: ctx.sender(),
    });
}

// === Grant ===

/// Grant or overwrite `spender`'s allowance with a finite expiry.
///
/// `recipient = Some(R)` binds every subsequent `consume` against this entry
/// to transfer to `R` via `public_transfer` (INV-24) — the spender, even
/// fully compromised, cannot divert bound funds. `recipient = None` leaves
/// the grant unbound: `consume` returns `Some(Balance<U>)` to the caller.
///
/// `expected = Some(e)` engages compare-and-set (CAS — see module-level doc for
/// the term): aborts `EUnexpectedAllowance` unless the current raw allowance
/// (`allowance(v, spender)`, absent = `0`) equals `e`. Source `e` from the
/// matching `allowance` read; this closes the reduce-allowance interleaving
/// race (INV-31). `expected = None` is the cheap, unconditional,
/// ERC-20-equivalent overwrite path.
///
/// This function OVERWRITES, never increments (INV-17). A re-grant replaces
/// `remaining`, `expires_at_ms`, AND `recipient` atomically — there is no
/// path that retains a stale prior `recipient` while only changing `amount`
/// (INV-36).
///
/// #### Parameters
/// - `v`: Vault to mutate.
/// - `cap`: Owner authority. Must be the cap bound to `v` (INV-7).
/// - `spender`: Address whose allowance is granted / overwritten. Authority
///   for `consume` is keyed strictly on `ctx.sender()` at consume time
///   (INV-26); a package/module address can never be a spender (INV-38).
/// - `amount`: New raw `remaining`. Must be `> 0`.
/// - `expires_at_ms`: Finite, strictly future expiry. Must be
///   `> clock.timestamp_ms()`.
/// - `recipient`: `Some(R)` binds the destination; `None` leaves unbound.
///   NOT validated — `@0x0` and unspendable addresses are accepted and will
///   strand funds on `consume` (INV-42). Owner's responsibility.
/// - `expected`: CAS guard. `Some(e)` aborts unless current raw `== e`.
/// - `clock`: Shared system clock.
/// - `ctx`: Transaction context. `ctx.sender()` is recorded as `Granted.by`
///   for indexer attribution; it MAY differ from the original cap minter
///   (multisig, wrapper).
///
/// #### Aborts
/// - `EWrongOwnerCap` if `cap` is not bound to `v`.
/// - `EZeroAmount` if `amount == 0`. Use `revoke` to remove a spender entry.
/// - `EExpiryInPast` if `expires_at_ms <= clock.timestamp_ms()`.
/// - `EUnexpectedAllowance` if `expected = Some(e)` and current raw `!= e`.
public fun grant<U>(
    v: &mut Vault<U>,
    cap: &OwnerCap,
    spender: address,
    amount: u64,
    expires_at_ms: u64,
    recipient: Option<address>,
    expected: Option<u64>,
    clock: &Clock,
    ctx: &TxContext,
) {
    // INV-7: cap-vault binding (authorization first).
    assert!(cap.vault_id == object::id(v), EWrongOwnerCap);
    // INV-8: non-zero amount.
    assert!(amount > 0, EZeroAmount);
    // INV-9: finite expiry must be strictly in the future.
    assert!(expires_at_ms > clock.timestamp_ms(), EExpiryInPast);
    // INV-10: CAS guard (absent counts as raw 0).
    assert_cas(v, spender, expected);

    apply_grant<U>(v, spender, amount, option::some(expires_at_ms), recipient, ctx);
}

/// Grant or overwrite `spender`'s allowance with NO expiry — the loud,
/// deliberate opt-out (design D3). Same overwrite, CAS, and recipient
/// semantics as `grant`; carries no `Clock` because there is nothing to
/// time-validate. `expires_at_ms` is stored as `None`.
///
/// Use this only when an indefinitely-running spender is intentional (e.g.
/// long-lived treasury keeper). Even an indefinite grant is fully revocable
/// (INV-14 / INV-39) and the owner can always defund (INV-23).
///
/// #### Parameters / Aborts
/// Identical to `grant` minus `expires_at_ms`, `clock`, and `EExpiryInPast`.
public fun grant_indefinite<U>(
    v: &mut Vault<U>,
    cap: &OwnerCap,
    spender: address,
    amount: u64,
    recipient: Option<address>,
    expected: Option<u64>,
    ctx: &TxContext,
) {
    // INV-7
    assert!(cap.vault_id == object::id(v), EWrongOwnerCap);
    // INV-8
    assert!(amount > 0, EZeroAmount);
    // INV-10
    assert_cas(v, spender, expected);

    apply_grant<U>(v, spender, amount, option::none<u64>(), recipient, ctx);
}

// === Spend ===

/// Draw exactly `amount` for `ctx.sender()` against their live allowance.
///
/// EXACT-AMOUNT-OR-ABORT: a successful call delivers exactly `amount`, never
/// less; there is no partial-fill mode (INV-16). `consume` is the only atomic
/// check-and-draw — pre-`consume` reads (`allowance`/`spendable`) are advisory
/// (INV-32). Authority is keyed strictly on `ctx.sender()` at call time
/// (INV-26 / INV-38): on Sui, `ctx.sender()` is the transaction signer,
/// invariant across module/package call depth — a package/module address can
/// never be a spender.
///
/// Return shape is bimodal and governed strictly by the stored
/// `recipient.is_some()` of the entry:
/// - `recipient = Some(R)`: this module mints a `Coin<U>` of exactly `amount`
///   and `public_transfer`s it to `R`, then returns `None`. The spender, even
///   fully compromised, CANNOT divert the funds (INV-24). `R` is fixed at
///   grant time (INV-36); `R == ctx.sender()` is permitted (INV-35) and
///   behaves identically to any other bound recipient.
/// - `recipient = None`: returns `Some(Balance<U>)`. `Balance<U>` has no
///   `drop` ability — the caller MUST plumb the value into a downstream call
///   or convert via `coin::from_balance` (INV-5).
///
/// #### Failure precedence (INV-11, deterministic single ordered abort)
/// Checked in this exact order; the FIRST holding condition is the one that
/// aborts. No later condition is observable when an earlier one holds:
/// 1. `ENoAllowance` — no entry for `ctx.sender()` (never-granted OR `revoke`'d
///    — entry removed). Distinct from `EAllowanceExceeded` against a
///    `consume`-to-zero inert row (INV-21).
/// 2. `EAllowanceExpired` — entry exists, finite `expires_at_ms`, and
///    `clock.timestamp_ms() >= expires_at_ms`. Indefinite grants
///    (`expires_at_ms = None`) skip this check.
/// 3. `EZeroAmount` — `amount == 0`.
/// 4. `EAllowanceExceeded` — `amount > remaining` (cap reached).
/// 5. `EInsufficientVault` — `amount > vault.balance` (pool short — the
///    documented "allowance ≠ guarantee" path, INV-22).
///
/// On ANY abort, `vault.balance` and every `remaining` are bit-identical to
/// pre-call (INV-16: no partial state mutation before any abort).
///
/// #### Reentrancy
/// `consume`'s bound branch performs `transfer::public_transfer` to an
/// address. In Sui, transferring an object to an address executes NO code at
/// the destination — no fallback, no receive hook, no synchronous callback.
/// The bound path therefore CANNOT be reentered; no reentrancy guard exists,
/// is needed, or is possible (INV-37, structural Sui platform guarantee).
///
/// #### Parameters
/// - `v`: Vault to draw from.
/// - `amount`: Exact value to extract. Subject to the precedence above.
/// - `clock`: Shared system clock; used only for the expiry check.
/// - `ctx`: Transaction context. `ctx.sender()` identifies the spender; `&mut`
///   is required because the bound path mints a `Coin<U>` (needs a fresh UID).
///
/// #### Returns
/// - `Some(Balance<U>)` on the unbound path (caller plumbs the value).
/// - `None` on the bound path (module already transferred a `Coin<U>` to `R`).
public fun consume<U>(
    v: &mut Vault<U>,
    amount: u64,
    clock: &Clock,
    ctx: &mut TxContext,
): Option<Balance<U>> {
    let sender = ctx.sender();

    // INV-11 step 1: ENoAllowance.
    assert!(v.allowances.contains(sender), ENoAllowance);

    // Read-phase: copy what we need out of the entry; the immutable borrow
    // releases at the end of this block so the later `borrow_mut` is legal
    // (Move 2024 borrow rules — no NLL across statements).
    let (expires_at_ms_opt, remaining, recipient) = {
        let entry = v.allowances.borrow(sender);
        (entry.expires_at_ms, entry.remaining, entry.recipient)
    };

    // INV-11 step 2: EAllowanceExpired (finite expiry only; strict `<`, so
    // `now == expires_at_ms` aborts — matches INV-9's grant-side `>` strictness).
    if (expires_at_ms_opt.is_some()) {
        assert!(
            clock.timestamp_ms() < *expires_at_ms_opt.borrow(),
            EAllowanceExpired,
        );
    };

    // INV-11 step 3: EZeroAmount. Strictly precedes any `balance::split` /
    // `coin::from_balance` so the bound-path Coin is provably > 0 (OQ4).
    assert!(amount > 0, EZeroAmount);

    // INV-11 step 4: EAllowanceExceeded. After this, `remaining - amount` is
    // provably safe (no native u64 underflow).
    assert!(amount <= remaining, EAllowanceExceeded);

    // INV-11 step 5: EInsufficientVault. After this, `balance::split` is safe.
    assert!(amount <= balance::value(&v.balance), EInsufficientVault);

    // INV-16: exact decrement (no partial fill, checked native u64 sub).
    // INV-21: zeroing `remaining` leaves the entry in the Table by design
    // (lazy inert semantics — `revoke` is the only owner-driven removal).
    let remaining_after = remaining - amount;
    v.allowances.borrow_mut(sender).remaining = remaining_after;

    // INV-15 / INV-16: exact split from the pool.
    let bal = balance::split(&mut v.balance, amount);

    // Emit BEFORE branching so the event reflects the canonical state change
    // regardless of how the caller disposes the returned Balance. The
    // `recipient` field on the event mirrors the stored binding.
    event::emit(Consumed<U> {
        vault_id: object::id(v),
        spender: sender,
        amount,
        remaining: remaining_after,
        recipient,
    });

    if (recipient.is_some()) {
        // Bound path (INV-24 / INV-36 / INV-37): mint Coin and transfer to
        // the STORED recipient. No caller parameter influences the destination.
        let r = recipient.destroy_some();
        transfer::public_transfer(coin::from_balance(bal, ctx), r);
        option::none<Balance<U>>()
    } else {
        // Unbound path (INV-5 / INV-6 / INV-29): return Balance for PTB
        // plumbing. Caller MUST handle (Balance has no drop).
        option::some(bal)
    }
}

// === Revoke ===

/// Owner kill-switch: remove `spender`'s allowance entry from this Vault.
///
/// The ONLY failure mode is `EWrongOwnerCap` (INV-14). Given a matching cap,
/// `revoke` ALWAYS succeeds — a present entry is removed, an absent entry is
/// an idempotent no-op. In BOTH non-aborting cases, `Revoked` is emitted.
/// On the cap-mismatch abort, Move/Sui rollback semantics ensure NO event is
/// emitted and NO state change occurs.
///
/// "Never aborts on allowance state" is load-bearing, not cosmetic: revocation
/// is the owner's emergency primitive. If `revoke` could abort on concurrent
/// allowance state (a raced or expired entry), an attacker could shape state
/// to make the owner's revoke fail — defeating the kill-switch. The only
/// permitted failure is the authorization precondition; never a race.
///
/// `revoke` is the ONLY owner-driven path that calls `table::remove`. A
/// `consume`-to-zero entry is left in place (INV-21, lazy inert semantics);
/// the resulting `ENoAllowance` (absent, post-revoke) vs `EAllowanceExceeded`
/// (present-zero, post-consume-to-zero) boundary in `consume` is intentional.
///
/// #### Parameters
/// - `v`: Vault to mutate.
/// - `cap`: Owner authority. Must be the cap bound to `v` (INV-7).
/// - `spender`: Spender to revoke. Absent entry is permitted (no-op).
/// - `ctx`: Transaction context. `ctx.sender()` is recorded as `Revoked.by`
///   (may be a multisig/wrapper executor, not necessarily a human owner).
///
/// #### Aborts
/// - `EWrongOwnerCap` if `cap` is not bound to `v`. On abort, NOTHING is
///   emitted and NO state changes (Move/Sui effect rollback).
public fun revoke<U>(
    v: &mut Vault<U>,
    cap: &OwnerCap,
    spender: address,
    ctx: &TxContext,
) {
    // INV-7 / INV-14: cap-vault binding is the ONLY abort path. Nothing later
    // emits or mutates until this passes.
    assert!(cap.vault_id == object::id(v), EWrongOwnerCap);

    // INV-14: present -> remove; absent -> no-op. Both paths proceed to emit.
    if (v.allowances.contains(spender)) {
        let _: Allowance = v.allowances.remove(spender);
    };

    // INV-14: emit on every non-aborting call. Sits AFTER the cap assert so a
    // mismatched-cap call emits nothing (rollback), but emits regardless of
    // whether an entry existed (present-removal AND absent no-op).
    event::emit(Revoked<U> {
        vault_id: object::id(v),
        spender,
        by: ctx.sender(),
    });
}

// === Owner exit ===

/// Withdraw exactly `amount` of `U` from the Vault's pool to a `Coin<U>` for
/// the cap holder.
///
/// Owner can ALWAYS defund — withdrawal consults only the cap binding (INV-7)
/// and the pool balance (INV-12); it does NOT consult the allowance ledger
/// (INV-23). A live allowance can become unfulfillable as a side effect: this
/// is intended (the ERC-20-equivalent "owner moves their own balance after
/// approve" behavior). The same-Vault consume/withdraw race is consensus-
/// serialized and deterministic — an owner `withdraw` sequenced before a
/// `consume` leaves the subsequent `consume` aborting `EInsufficientVault`
/// with `remaining > 0` (INV-22 / INV-30, defined behavior, not corruption).
///
/// #### Parameters
/// - `v`: Vault to draw from.
/// - `cap`: Owner authority. Must be the cap bound to `v`.
/// - `amount`: Exact value to withdraw. Must be `> 0` and `<= vault.balance`.
/// - `ctx`: Transaction context. `&mut` is required because this mints a
///   fresh `Coin<U>`. `ctx.sender()` is recorded as `Withdrawn.by`.
///
/// #### Returns
/// - `Coin<U>` of exactly `amount`. Owner-routed: caller transfers to the
///   chosen destination.
///
/// #### Aborts
/// - `EWrongOwnerCap` if `cap` is not bound to `v`.
/// - `EZeroAmount` if `amount == 0`. Use `withdraw_all` to fully drain.
/// - `EInsufficientVault` if `amount > vault.balance`.
public fun withdraw<U>(
    v: &mut Vault<U>,
    cap: &OwnerCap,
    amount: u64,
    ctx: &mut TxContext,
): Coin<U> {
    // INV-7
    assert!(cap.vault_id == object::id(v), EWrongOwnerCap);
    // INV-8
    assert!(amount > 0, EZeroAmount);
    // INV-12 (also note: INV-23 — withdrawal never consults the ledger).
    assert!(amount <= balance::value(&v.balance), EInsufficientVault);

    // INV-15 / INV-40: exact split (no skim), pool decreases by exactly `amount`.
    let coin = coin::from_balance(balance::split(&mut v.balance, amount), ctx);

    event::emit(Withdrawn<U> {
        vault_id: object::id(v),
        amount,
        by: ctx.sender(),
    });

    coin
}

/// Withdraw the ENTIRE pool balance as a `Coin<U>` for the cap holder.
///
/// Aborts `EInsufficientVault` on an empty pool — no zero-`Coin` litter
/// (INV-12). On success, leaves `vault.balance == 0`; the ledger is untouched
/// (allowances may persist with `remaining > 0` but every subsequent `consume`
/// will abort `EInsufficientVault` — see `withdraw` for the race semantics).
///
/// #### Parameters
/// Same as `withdraw` minus `amount`.
///
/// #### Returns
/// - `Coin<U>` of exactly the prior `vault.balance`.
///
/// #### Aborts
/// - `EWrongOwnerCap` if `cap` is not bound to `v`.
/// - `EInsufficientVault` if `vault.balance == 0`.
public fun withdraw_all<U>(
    v: &mut Vault<U>,
    cap: &OwnerCap,
    ctx: &mut TxContext,
): Coin<U> {
    // INV-7
    assert!(cap.vault_id == object::id(v), EWrongOwnerCap);

    // Read once; reused for the empty-pool guard AND the event amount.
    let amount = balance::value(&v.balance);
    // INV-12: empty-pool guard (no zero-`Coin` litter, no zero-`amount` event).
    assert!(amount > 0, EInsufficientVault);

    // INV-15 / INV-40: full drain — `balance::withdraw_all` extracts the
    // entire `Balance<U>`, leaving `v.balance` at zero.
    let coin = coin::from_balance(balance::withdraw_all(&mut v.balance), ctx);

    event::emit(Withdrawn<U> {
        vault_id: object::id(v),
        amount,
        by: ctx.sender(),
    });

    coin
}

// === Teardown ===

/// Consume the shared `Vault<U>` AND its bound `OwnerCap` together, refunding
/// any leftover pool balance as a (possibly-zero) `Coin<U>` to the caller.
///
/// Both objects are taken BY VALUE so authority cannot outlive the Vault
/// (INV-19): after a successful `destroy`, neither exists on-chain. The
/// function ALWAYS succeeds given a matching cap — against a non-empty
/// ledger (no pre-revoke required) AND against a zero-balance pool. Unlike
/// `withdraw_all`, `destroy` is the terminal owner exit and must not be
/// blockable — so a zero `refunded` returns a zero-value `Coin<U>` (the
/// caller can `coin::destroy_zero` it). This is the one place a zero `Coin`
/// is sound: it is the final settlement of a Vault that is going away.
///
/// The ledger is disposed wholesale via `table::drop` — sound because
/// `Allowance` has `drop` (INV-3). Inert and live entries are discarded
/// together; no `Revoked` events are emitted for them (revocation is per-
/// spender, `destroy` is Vault-level — observable as `VaultDestroyed`).
///
/// #### Sui toolchain note
/// Shared-object deletion is permitted on Sui 1.71.1 (resolved invariants
/// OQ2). The host repo's `two_step.move` shares `PendingOwnershipTransfer`
/// then deletes it by value via the same `id.delete()` pattern used here.
///
/// #### Parameters
/// - `v`: Vault to destroy. Consumed by value.
/// - `cap`: Owner authority. Consumed by value (so authority cannot outlive
///   the Vault). Must be the cap bound to `v`.
/// - `ctx`: Transaction context. `&mut` is required because this mints a
///   `Coin<U>`. `ctx.sender()` is recorded as `VaultDestroyed.by`.
///
/// #### Returns
/// - `Coin<U>` of exactly the prior `vault.balance` (possibly zero).
///
/// #### Aborts
/// - `EWrongOwnerCap` if `cap` is not bound to `v`. Both `v` and `cap`
///   survive (Move/Sui effect rollback).
public fun destroy<U>(
    v: Vault<U>,
    cap: OwnerCap,
    ctx: &mut TxContext,
): Coin<U> {
    // INV-7: cap-vault binding. Checked BEFORE destructuring so a mismatched
    // call rolls back with both by-value parameters intact.
    assert!(cap.vault_id == object::id(&v), EWrongOwnerCap);

    // Destructure both objects to consume them. `cap_id` and `vault_id` are
    // discarded — INV-7 already established they are consistent with the IDs
    // of `v` and `cap` respectively.
    let Vault { id: vault_uid, cap_id: _, balance, allowances } = v;
    let OwnerCap { id: cap_uid, vault_id: _ } = cap;

    // Capture event fields before consuming the underlying values.
    let vault_id = vault_uid.uid_to_inner();
    let refunded = balance::value(&balance);

    // INV-3 / INV-21: drop the ledger wholesale. `Allowance: drop` makes this
    // sound; `table::drop` releases the underlying dynamic-field storage in
    // one operation. Any inert / live entries are discarded together.
    allowances.drop();

    // INV-15 / INV-6 / INV-40: leftover Balance -> Coin<U>. Zero is sound
    // here (terminal exit; non-blockable). No skim.
    let coin = coin::from_balance(balance, ctx);

    event::emit(VaultDestroyed<U> {
        vault_id,
        refunded,
        by: ctx.sender(),
    });

    // INV-19 / OQ2: delete both UIDs. Shared-Vault deletion is supported on
    // Sui 1.71.1 (existence proof: two_step.move at the shared-then-deleted
    // PendingOwnershipTransfer pattern).
    vault_uid.delete();
    cap_uid.delete();

    coin
}

// === Reads ===

/// Raw `remaining` allowance for `spender` — the ERC-20 `allowance()`
/// semantic (standing authorization). Returns `0` for an absent / revoked
/// entry, and the raw `remaining` for a present entry — INDEPENDENT of
/// expiry and pool balance (INV-41). A present-and-expired entry still
/// returns its stored `remaining` here; use `spendable` for the
/// expiry-and-balance-respecting effective figure.
///
/// Never aborts, for any input, in any Vault state (INV-13).
///
/// Use as the source for the `expected` CAS argument of `grant` /
/// `grant_indefinite`: read `cur = allowance(v, s)`, then call
/// `grant(..., expected = Some(cur))` to close the reduce-allowance
/// interleaving race (INV-31).
///
/// #### Parameters
/// - `v`: Vault to query.
/// - `spender`: Spender address.
///
/// #### Returns
/// - `u64`: raw `remaining` (`0` if absent).
public fun allowance<U>(v: &Vault<U>, spender: address): u64 {
    current_raw(v, spender)
}

/// Effective drawable-now figure for `spender` in the current Vault state:
/// `alive(s) ? min(remaining, vault.balance) : 0` (INV-41). Returns `0` for
/// absent, revoked, expired, or inert spenders. Reflects BOTH expiry AND
/// the shared pool — diverges from `allowance` exactly when expiry has
/// elapsed (`spendable = 0 ∧ allowance > 0`) or the pool is short
/// (`spendable = balance < allowance`). This divergence IS the
/// over-estimation mitigation vs. ERC-20 shipping raw only.
///
/// **TOCTOU advisory (INV-32):** the return value reflects committed state
/// at call time. A competing tx may change state before a later `consume`
/// in the same PTB; `consume` itself is the only atomic check-and-draw.
/// Safe to use as a pre-`consume` gating predicate; NOT safe to treat as
/// a drawability guarantee.
///
/// Never aborts (INV-13).
///
/// #### Parameters
/// - `v`: Vault to query.
/// - `spender`: Spender address.
/// - `clock`: Shared system clock.
///
/// #### Returns
/// - `u64`: effective drawable (`0` if absent / expired / dead / inert).
public fun spendable<U>(v: &Vault<U>, spender: address, clock: &Clock): u64 {
    if (!v.allowances.contains(spender)) {
        return 0
    };
    let entry = v.allowances.borrow(spender);
    // INV-20 / INV-41: liveness = present ∧ (None ∨ now < expires_at_ms).
    // Short-circuit `&&` keeps the borrow safe on the indefinite path.
    if (
        entry.expires_at_ms.is_some()
            && clock.timestamp_ms() >= *entry.expires_at_ms.borrow()
    ) {
        return 0
    };
    let bal = balance::value(&v.balance);
    if (entry.remaining < bal) entry.remaining else bal
}

/// Finite expiry timestamp for `spender`, or `None`.
///
/// Returns `Some(expires_at_ms)` whenever an entry exists with a finite
/// expiry — even if that expiry has elapsed (so a UI can render "expired
/// at T"). Returns `None` for:
/// - absent / revoked spenders, OR
/// - present spenders granted via `grant_indefinite`
///   (`expires_at_ms = None`).
///
/// "No entry" and "indefinite" are intentionally collapsed in the return
/// shape — distinguish via `allowance(v, s) > 0` (indefinite has positive
/// raw allowance; absent has zero).
///
/// Never aborts (INV-13).
///
/// #### Parameters
/// - `v`: Vault to query.
/// - `spender`: Spender address.
///
/// #### Returns
/// - `Option<u64>`: `Some(expires_at_ms)` for present-and-finite, `None`
///   otherwise.
public fun expiry<U>(v: &Vault<U>, spender: address): Option<u64> {
    if (!v.allowances.contains(spender)) {
        return option::none()
    };
    v.allowances.borrow(spender).expires_at_ms
}

/// Returns the singular `OwnerCap` object ID that authorizes this Vault.
///
/// Set at `new`, never mutated (INV-2 cap singularity makes this a stable
/// authoritative pointer). Off-chain consumers query Sui RPC for the
/// current owner of this object to learn who currently holds owner
/// authority (which may be a wrapper, multisig, or DAO — see
/// `openzeppelin_access` for natural-composition wrappers). Added during
/// Stage 4 Code Draft for cap-binding observability; see 02-design.md's
/// Design Decisions Log entry (2026-05-20).
///
/// Never aborts (INV-13). Pure read of an immutable field.
///
/// #### Parameters
/// - `v`: Vault to query.
///
/// #### Returns
/// - `ID`: the bound `OwnerCap` object ID.
public fun cap_id<U>(v: &Vault<U>): ID {
    v.cap_id
}

// === Helpers (private) ===

/// CAS guard for `grant` / `grant_indefinite`. Aborts `EUnexpectedAllowance`
/// iff `expected = Some(e)` and the current raw allowance is not `e`. Absent
/// entries normalize to raw `0` (INV-10). `expected = None` is a no-op (the
/// unconditional overwrite path).
fun assert_cas<U>(v: &Vault<U>, spender: address, expected: Option<u64>) {
    if (expected.is_some()) {
        let e = expected.destroy_some();
        let current = current_raw(v, spender);
        assert!(current == e, EUnexpectedAllowance);
    };
    // `expected = None` path: `Option<u64>` drops at end of scope (has drop).
}

/// Raw `remaining` for `spender`; `0` if absent (INV-10 / INV-41 / INV-21).
/// Shared by the public `allowance` reader and the CAS guard's "current"
/// read so the two paths are guaranteed to compute the same value.
fun current_raw<U>(v: &Vault<U>, spender: address): u64 {
    if (v.allowances.contains(spender)) {
        v.allowances.borrow(spender).remaining
    } else {
        0
    }
}

/// Overwrite-not-increment apply (INV-17 / INV-36): replaces the spender's
/// entry with a FRESH `Allowance` constructed from THIS call's arguments —
/// `remaining`, `expires_at_ms`, AND `recipient` are all replaced atomically.
/// Emits `Granted`.
///
/// Caller MUST have already enforced: cap binding (INV-7), non-zero amount
/// (INV-8), future expiry (INV-9, `grant` only), and the CAS guard (INV-10).
fun apply_grant<U>(
    v: &mut Vault<U>,
    spender: address,
    amount: u64,
    expires_at_ms: Option<u64>,
    recipient: Option<address>,
    ctx: &TxContext,
) {
    if (v.allowances.contains(spender)) {
        // INV-36: full-record replacement; old entry dropped wholesale.
        let _: Allowance = v.allowances.remove(spender);
    };
    v.allowances.add(
        spender,
        Allowance { remaining: amount, expires_at_ms, recipient },
    );
    event::emit(Granted<U> {
        vault_id: object::id(v),
        spender,
        amount,
        expires_at_ms,
        recipient,
        by: ctx.sender(),
    });
}

// === Test-Only Helpers ===

/// Construct a `VaultCreated<U>` event value for test-side equality assertions.
#[test_only]
public fun test_new_vault_created<U>(
    vault_id: ID,
    cap_id: ID,
    creator: address,
): VaultCreated<U> {
    VaultCreated { vault_id, cap_id, creator }
}

/// Construct a `Deposited<U>` event value for test-side equality assertions.
#[test_only]
public fun test_new_deposited<U>(
    vault_id: ID,
    amount: u64,
    depositor: address,
): Deposited<U> {
    Deposited { vault_id, amount, depositor }
}

/// Construct a `Granted<U>` event value for test-side equality assertions.
#[test_only]
public fun test_new_granted<U>(
    vault_id: ID,
    spender: address,
    amount: u64,
    expires_at_ms: Option<u64>,
    recipient: Option<address>,
    by: address,
): Granted<U> {
    Granted { vault_id, spender, amount, expires_at_ms, recipient, by }
}

/// Construct a `Consumed<U>` event value for test-side equality assertions.
#[test_only]
public fun test_new_consumed<U>(
    vault_id: ID,
    spender: address,
    amount: u64,
    remaining: u64,
    recipient: Option<address>,
): Consumed<U> {
    Consumed { vault_id, spender, amount, remaining, recipient }
}

/// Construct a `Revoked<U>` event value for test-side equality assertions.
#[test_only]
public fun test_new_revoked<U>(
    vault_id: ID,
    spender: address,
    by: address,
): Revoked<U> {
    Revoked { vault_id, spender, by }
}

/// Construct a `Withdrawn<U>` event value for test-side equality assertions.
#[test_only]
public fun test_new_withdrawn<U>(
    vault_id: ID,
    amount: u64,
    by: address,
): Withdrawn<U> {
    Withdrawn { vault_id, amount, by }
}

/// Construct a `VaultDestroyed<U>` event value for test-side equality assertions.
#[test_only]
public fun test_new_vault_destroyed<U>(
    vault_id: ID,
    refunded: u64,
    by: address,
): VaultDestroyed<U> {
    VaultDestroyed { vault_id, refunded, by }
}
