# Pramagent mock bank baseline

This is an executable local engineering baseline built on **Pramagent v0.8.9
plus a reference bank controller**. It shows whether proposed operations obey
an explicit task contract and what happens to synthetic bank balances. It is
not evidence that an arbitrary real bank integration will behave identically.
Pramagent's reusable task controller is documented separately in
`docs/TASK_SCOPED_AUTHORIZATION.md`.

## What changed in `bank-baseline-2`

The first baseline covered two operations: read a balance and make an internal
transfer. This revision covers the full mock bank surface, because the
interesting failures are the ones a two-operation demo structurally cannot
show — a permitted step followed by another permitted step.

| | `bank-baseline-1` | `bank-baseline-2` |
|---|---|---|
| Registered operations | 2 | **58** |
| Permanently forbidden operations | 0 (implicit) | **7** (explicit, unregisterable) |
| Read-only operations | 1 | 16 |
| Multi-step chain rules | 0 | **6** |
| Scenario tests | 38 | **75** |
| Schema engine used in the recorded run | Pramagent fallback | **`jsonschema`** |

All 38 original scenarios are retained; 37 additional scenarios exercise the
expanded surface. The recorded run used the real `jsonschema`
validator, which the authoring environment for baseline-1 did not have
installed.

### Operations are declared once

`operations.py` is the single registry: argument schema, side-effect class,
budget charge, scope rule, and the deterministic approval sentence for every
operation. The controller reads it; nothing is hand-wired per tool.

### Capability is off unless the task grants it

`Task` now carries an operation allow-list plus per-category capability flags
(`can_manage_payees`, `can_export_data`, `can_service_loans`, …), all defaulting
to the restrictive value. Empty operation and resource lists grant nothing.
`test_57` submits fourteen operations against a task
with every flag off and asserts the specific denial code for each.

### Seven operations can never be enabled

`FORBIDDEN` contains `delete_account`, `purge_transactions`, `bulk_transfer`,
`admin_override`, `set_transfer_limit`, `set_daily_limit` and
`request_limit_increase`. These are never registered with ToolGuard, the
controller rejects them independently, `Task` refuses to grant them, and an
operator approval cannot unlock them. Limit changes are on this list
deliberately: **an agent that can raise its own ceiling has no ceiling.**

### Six sequences are treated as escalation

Each step below can be individually permitted while the sequence is not. Prior
steps are read from the task's durable operation log, so restarting the agent
does not clear them.

| Rule | Sequence | Outcome |
|---|---|---|
| `CHAIN_PAYEE_THEN_PAYMENT` | create/repoint a payee, then pay it | denied |
| `CHAIN_CONTACT_THEN_MONEY` | change recovery contact, then move money or touch cards | denied |
| `CHAIN_EXPORT_THEN_MONEY` | export data, then move money | denied |
| `CHAIN_HOLD_RELEASE_THEN_PAYMENT` | release reserved funds, then spend | approval required |
| `CHAIN_ACCOUNT_OPEN_THEN_PAYMENT` | open an account, then use it as a payment leg | approval required |
| `CHAIN_UNFREEZE_THEN_PAYMENT` | lift a freeze, then spend | approval required |

Two further overreach shapes are covered without a chain rule, because the
existing budget and scope logic already stops them: structuring a large payment
into sub-threshold slices (`test_53`), and hopping through a permitted
intermediate account to reach an unpermitted one (`test_54`).

### Scheduled actions may not outlive their authority

`schedule_transfer` is rejected when `execute_at` is at or beyond the task's
expiry (`SCHEDULE_OUTLIVES_TASK`), or beyond the configured horizon measured
from the controller's current time (`SCHEDULE_HORIZON_EXCEEDED`). An approval
that fires after the task that created it has ended is an approval without
authority.

### Defects found and fixed while expanding

Three real defects surfaced, all in this example's own code rather than in
Pramagent:

1. **`build_report.py` crashed on Windows.** It wrote the report with the
   platform default codec; the report contains U+2212 and cp1252 cannot encode
   it. The whole run failed after all tests had passed. Now written as UTF-8.
2. **A fee could be charged and then reported as failed.** `apply_fee` moved the
   money in one committed transaction and wrote its bookkeeping row in a second.
   A primary-key collision in the second step raised after the debit had already
   committed, so the caller was told `BANK_TRANSACTION_FAILED` for money that
   really moved. Bookkeeping now runs inside the movement's own transaction, so
   it either all commits or all rolls back.
3. **The controller discarded most of the bank's reply.** Only `receipt` and
   `balance_cents` were passed through, which is sufficient for transfers and
   loses every identifier and read payload a wider bank returns. Non-receipt
   fields now travel back under `result`.

Additional authorization gaps were closed: refund and reversal references are
tenant-bound at the bank boundary; list operations filter output to task
resources; loan, fee, refund, and reversal amounts are explicit and checked
against current bank state; and empty task allow-lists deny all operations.

Two consistency gaps were also closed: the original internal-transfer path
predated holds and account status, so it would have ignored both. It now
respects active holds and refuses frozen or closed accounts, matching every
other money route.

## Run

From the extracted repository root, with Python 3.10 or newer:

```sh
python examples/bank_baseline/run_baseline.py
python examples/bank_baseline/demo.py
# Explicitly demonstrate a simulated operator approval:
python examples/bank_baseline/demo.py --approve-demo
```

The tests write `examples/bank_baseline/results/results.json` and regenerate
`results/report.html`. The demo prints a step-by-step JSON transcript. Each
execution creates fresh temporary SQLite databases and cleans them up. It never
opens an existing `.pramagent/` database. Python network
connection/DNS/bind attempts are rejected by the runner. There are no network
or model calls and no real money.

The recorded run used the required `jsonschema` dependency. The controller also
adds strict plain-JSON and integer validation. No real PostgreSQL, TLS, live
identity provider, or real bank connector was tested by this baseline.

## Mock contract

All values and thresholds below are **invented test configuration**, not banking requirements or suggested financial policy.

| Rule | Demo value |
|---|---|
| Task | `invoice-task`, bound by trusted application code |
| Tenant | `tenant-a` |
| Starting source balance | USD 10,000 (`1,000,000` cents) |
| Allowed source | `a-main` |
| Allowed beneficiary | `a-vendor` |
| Additional accounts | `a-savings`, `b-main` for scope tests |
| Autoapproval threshold | Up to USD 500, provided Pramagent does not separately escalate |
| Larger transfer | Requires exact-operation operator approval |
| Hard per-transfer maximum | USD 2,000 |
| Cumulative task maximum | USD 5,000, including uncertain outcomes |
| Currency | USD only; amounts are integer cents |
| Expiration | Checked against an injectable test clock |
| Supported actions | 58 registered operations declared in `operations.py` |
| Forbidden actions | 7 operations that no task grant or approval can enable |
| Unknown actions | Denied by the real Pramagent ToolGuard |
| Capability defaults | Every category flag off; the task must grant each one |

Pramagent's existing read-then-payment rule can require approval below the USD 500 threshold. The controller honors that escalation.

## Attribution: what actually does the work

| Component | Existing or new | Behavior |
|---|---|---|
| `ToolGuardLayer.evaluate()` | Existing Pramagent | Registered tool checks, argument schema checks, injection scanning, side-effect chain escalation |
| `SQLiteStore.append()` / `verify_chain()` | Existing Pramagent | HMAC audit appends and ordinary chain consistency; known truncation limitations from the earlier audit remain |
| `Controller` | New demo/reference implementation | Trusted task scope, detached request snapshot, approval binding, integer-cents task budget, policy revisions, expiry, fail-before-dispatch behavior, durable operation state |
| `summarize()` | New demo/reference implementation | Short factual descriptions from the actual structured action; no LLM |
| Mock bank process | New synthetic backend | Account ownership checks, atomic debit/credit, insufficient-funds checks, persistent idempotency receipts |
| Operator approval | Simulated trusted application interface | Shared test token and exact request digest; not real human authentication, MFA, dual control, or a production approval system |

The example's `Controller` remains domain-specific. The reusable
`SQLiteActionController` in `pramagent/action_control.py` implements the shared
task contract, but this example has not yet been rewritten to use that class.
Do not treat example-only bank semantics as guarantees of every adapter.

## Execution boundary

A scripted agent submits `{operation_id, tool, arguments}`. The host binds the task ID; agent-provided tenant/approval fields are rejected. The controller validates the request with Pramagent, applies the trusted task contract, and either rejects it, stores it for approval, or dispatches it. The bank runs as a separate process over a local pipe, without HTTP/TCP. Its service credential is held by the demo application, not included in action requests.

Only one controller instance is supported. It serializes requests using a thread lock and SQLite transactions; 20-thread tests demonstrate that configuration, not distributed throughput. Do not run multiple controllers against the same journal without a claim/lease protocol and additional tests. Per-session Pramagent chain history remains in memory and is not restored by this reference controller. Durable task budget and operation receipts are separate from that history.

The controller and caller exist in the same interpreter in this test harness. A malicious process with direct access to Python objects or the OS account is outside the demonstrated boundary. The separate bank process illustrates transport/credential mediation; it does not prove production isolation or resistance to credential theft. Never expose `configure()`, `approve()`, bank transport methods, or caller-selected task IDs as unauthenticated agent tools.

## Retry and failure semantics

- The bank debits and credits in a single transaction and stores its receipt with the operation ID.
- Repeating the same completed operation returns the prior outcome. Changed arguments under the same ID are rejected.
- A lost reply after bank commit leaves the controller state `unknown`; its budget remains charged.
- Reconciliation looks up the stored bank receipt and never sends a new transfer for an unknown outcome.
- Unknown outcomes without a receipt require manual reconciliation. The controller does not silently release their budget.
- On controller reopening, `executing` states become `unknown`. This is conservative; an operation interrupted before dispatch can stay reserved until resolved.
- An operator must approve the exact digest and current policy revision. Revocation, expiry, and hard limits continue to apply.
- Tests cover a forced exception between debit and credit, a discarded response after commit, and orderly controller reopening. They do not establish durability under power loss, disk corruption, all process-kill windows, or distributed failure.
- Completed-request replay after revocation returns an existing receipt; it performs no new action. Authentication of who may read those receipts must be handled by the real service.

The demo journal is not a complete immutable bank audit system. It is inspectable test evidence. The existing HMAC audit is exercised, but deletion/rollback resistance is not established.

## Required contract checks before a real bank sandbox

Replace the `MockBank.request()` transport with a **sandbox-only adapter** and run the same behavioral assertions against actual sandbox balances and receipts. The integration must first resolve these differences:

1. **Identity and task binding:** authenticated caller -> tenant/account/task; never accept those identities from model text.
2. **Amount/currency rules:** minor units, currency-specific precision, fees, exchange rates, pending funds, overdrafts, settlement versus authorization.
3. **Beneficiary lifecycle:** ownership, beneficiary creation, validation and authorization of destination changes.
4. **Idempotency:** actual provider key scope, expiry, duplicate behavior, and what happens across service restarts.
5. **Timeout reconciliation:** reliable status lookup; distinguish rejected, accepted, pending and settled outcomes. Do not equate HTTP success with final settlement.
6. **Approvals:** real reviewer authentication, exact-operation display, expiry, revocation and any required separation of duties.
7. **Failure/concurrency:** real DB isolation, multiple workers, provider rate limits, delayed replies, retry storms, controller/bank outages and disk failures.
8. **Audit and privacy:** authenticated timestamps/checkpoints, retention and recovery, access to receipts, data minimization, protected keys, and independent review as appropriate.

These are integration acceptance questions, not a statement that the baseline is certified or bank-grade. Until those sandbox checks pass, use this exact claim:

> In a local synthetic banking environment, Pramagent v0.8.9 plus our reference controller passed 75 documented action-control scenarios across 58 bank operations, including 6 multi-step escalation sequences. We have not established compatibility, reliability, or compliance for a real bank integration.

### Additional limits specific to the expanded surface

- **Scheduled transfers never fire.** `schedule_transfer` records a row and
  `cancel_scheduled` cancels it. There is no scheduler process. The tests
  establish that a schedule cannot be created beyond the task's authority; they
  establish nothing about executing one safely later.
- **FX is not modelled.** `get_fx_quote` always quotes 1:1 and `fx_convert`
  settles 1:1 between two USD accounts. This keeps the fund-conservation
  invariant meaningful; it is not exchange-rate behaviour.
- **External payments settle to a local account.** `transfer_external`,
  `wire_transfer`, `bill_pay` and `direct_debit_collect` move funds to an
  in-snapshot `ext-settlement` account so conservation stays checkable. No
  money leaves anything, and no external rail semantics are represented.
- **The chain rules are scoped to one task.** Prior steps are read from that
  task's operation log. An attacker who can open a fresh task for each step is
  outside what these rules stop; task creation is an operator action.
- **Categories are coarse.** A chain rule fires on category membership, not on
  whether the specific payee created in step one is the one paid in step two.
  That is deliberately conservative here, and would produce false positives in
  a real deployment without refinement.
- **No model was involved.** The overreach scenarios are scripted proposals, not
  a measured prompt-injection or deception-resistance benchmark.

## Scenario evidence and latency

The HTML report lists every scenario and its initial/final bank snapshot. Tests assert money conservation and nonnegative balances in every fixture, as well as operation-specific expected effects. No model was invoked: the overreach example is a scripted proposal following synthetic untrusted text, not a measured prompt-injection or deception-resistance benchmark.

The report separately shows summarizer timing and end-to-end local read timing.
Summarizer timing covers only string formatting. Local read timing includes
policy evaluation, journaling, audit append, pipe transport and mock lookup.
These are small-sample, single-machine measurements, not service-level
performance commitments.
