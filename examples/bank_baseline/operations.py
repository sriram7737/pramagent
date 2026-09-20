"""Declarative registry of mock bank operations.

Every operation the controller will accept is described here exactly once:
its argument schema, its side-effect class, how it consumes task budget, the
scope rule that gates it, and the deterministic sentence shown to a human
approver. Nothing in this file calls a model.

Three properties matter for the demonstration:

* ``FORBIDDEN`` operations are never registered with ToolGuard and are also
  rejected by the controller. They cannot be enabled by task configuration and
  cannot be unlocked by an operator approval. Limit changes live here: an agent
  that can raise its own ceiling has no ceiling.
* ``CHAIN_RULES`` describe multi-step escalation. Each individual step can be
  permitted while the sequence is not.
* Summaries are rendered from validated arguments by this module, never by the
  caller and never by a model.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from pramagent.layers.tool_guard import SideEffect

IDENT = {'type': 'string', 'minLength': 1, 'maxLength': 80, 'pattern': '^[A-Za-z0-9_-]+$'}
TEXT = {'type': 'string', 'minLength': 1, 'maxLength': 200}
AMOUNT = {'type': 'integer', 'minimum': 1, 'maximum': 2**53 - 1}
COUNT = {'type': 'integer', 'minimum': 1, 'maximum': 100_000}
EPOCH = {'type': 'integer', 'minimum': 0, 'maximum': 2**53 - 1}
CURRENCY = {'type': 'string', 'enum': ['USD', 'EUR', 'GBP', 'JPY']}
ACCOUNT_KIND = {'type': 'string', 'enum': ['checking', 'savings']}


def usd(cents: int) -> str:
    whole, rest = divmod(int(cents), 100)
    return f'USD {whole:,}.{rest:02d}'


def obj(required: list[str], props: dict[str, Any]) -> dict[str, Any]:
    return {'type': 'object', 'required': required, 'properties': props, 'additionalProperties': False}


@dataclass(frozen=True)
class Operation:
    name: str
    schema: dict
    side_effect: SideEffect
    category: str
    route: str
    summary: Callable[[dict], str]
    scope: Callable[[Any, dict], str | None]
    charge: Callable[[dict], int] = lambda args: 0
    approval_always: bool = False


# --------------------------------------------------------------------------
# Scope helpers. Each returns an error code string, or None when permitted.
# --------------------------------------------------------------------------

def _enabled(task, name) -> str | None:
    return None if name in task.allowed_operations else 'OUTSIDE_TASK_SCOPE'


def readable(task) -> tuple[str, ...]:
    return task.readable_accounts


def scope_read_account(task, args):
    return None if args['account'] in readable(task) else 'OUTSIDE_TASK_SCOPE'


def scope_none(task, args):
    return None


def scope_transfer(task, args):
    # Preserves the original baseline's exact ordering and codes.
    if (set(args) != {'source', 'destination', 'amount_cents'}
            or type(args['amount_cents']) is not int
            or not 0 < args['amount_cents'] <= 2**53 - 1):
        return 'INVALID_AMOUNT_OR_FIELDS'
    if not task.can_transfer or args['source'] != task.source or args['destination'] not in task.destinations:
        return 'OUTSIDE_TASK_SCOPE'
    if args['amount_cents'] > task.max_transfer_cents:
        return 'TRANSFER_LIMIT'
    return None


def scope_source_only(task, args):
    if args.get('source') != task.source:
        return 'OUTSIDE_TASK_SCOPE'
    amount = args.get('amount_cents')
    if amount is not None and amount > task.max_transfer_cents:
        return 'TRANSFER_LIMIT'
    return None


def scope_external(task, args):
    """External rails may only pay a payee the task named up front."""
    if args['source'] != task.source or not task.can_transfer:
        return 'OUTSIDE_TASK_SCOPE'
    if args['payee_id'] not in task.allowed_payees:
        return 'PAYEE_NOT_IN_TASK'
    if args['amount_cents'] > task.max_transfer_cents:
        return 'TRANSFER_LIMIT'
    return None


def scope_payee_mgmt(task, args):
    if not task.can_manage_payees:
        return 'PAYEE_MANAGEMENT_NOT_PERMITTED'
    payee = args.get('payee_id')
    return None if payee is None or payee in task.allowed_payees else 'OUTSIDE_TASK_SCOPE'


def scope_card(task, args):
    if not task.can_manage_cards:
        return 'CARD_MANAGEMENT_NOT_PERMITTED'
    card = args.get('card_id')
    if card is not None and card not in task.allowed_cards:
        return 'OUTSIDE_TASK_SCOPE'
    return None


def scope_card_read(task, args):
    card = args.get('card_id')
    if card is not None and card not in task.allowed_cards:
        return 'OUTSIDE_TASK_SCOPE'
    return None


def scope_account_lifecycle(task, args):
    if not task.can_manage_accounts:
        return 'ACCOUNT_MANAGEMENT_NOT_PERMITTED'
    account = args.get('account')
    if account is not None and account not in readable(task):
        return 'OUTSIDE_TASK_SCOPE'
    return None


def scope_customer_write(task, args):
    return None if task.can_update_customer else 'CUSTOMER_UPDATE_NOT_PERMITTED'


def scope_export(task, args):
    if not task.can_export_data:
        return 'EXPORT_NOT_PERMITTED'
    if args.get('rows', 1) > task.max_export_rows:
        return 'EXPORT_ROW_LIMIT'
    account = args.get('account')
    if account is not None and account not in readable(task):
        return 'OUTSIDE_TASK_SCOPE'
    return None


def scope_share(task, args):
    if not task.can_export_data:
        return 'EXPORT_NOT_PERMITTED'
    if args['destination_email'] not in task.allowed_share_targets:
        return 'DESTINATION_NOT_IN_TASK'
    if args['account'] not in readable(task):
        return 'OUTSIDE_TASK_SCOPE'
    return None


def scope_schedule(task, args):
    err = scope_transfer(task, {k: args[k] for k in ('source', 'destination', 'amount_cents')})
    if err:
        return err
    if task.max_schedule_horizon <= 0:
        return 'SCHEDULING_NOT_PERMITTED'
    # A scheduled action must not be able to fire after the authority that
    # created it has expired.
    if args['execute_at'] >= task.expires_at:
        return 'SCHEDULE_OUTLIVES_TASK'
    return None


def scope_hold(task, args):
    if args['account'] not in readable(task):
        return 'OUTSIDE_TASK_SCOPE'
    return None if task.can_place_holds else 'HOLD_NOT_PERMITTED'


def scope_hold_release(task, args):
    if not task.can_place_holds:
        return 'HOLD_NOT_PERMITTED'
    return None if args['hold_id'] in task.allowed_holds else 'OUTSIDE_TASK_SCOPE'


def scope_loan(task, args):
    if not task.can_service_loans:
        return 'LOAN_SERVICING_NOT_PERMITTED'
    if args.get('source') is not None and args['source'] != task.source:
        return 'OUTSIDE_TASK_SCOPE'
    if args.get('account') is not None and args['account'] not in readable(task):
        return 'OUTSIDE_TASK_SCOPE'
    if args.get('loan_id') not in task.allowed_loans:
        return 'OUTSIDE_TASK_SCOPE'
    amount = args.get('amount_cents', args.get('expected_amount_cents'))
    if amount is not None and amount > task.max_transfer_cents:
        return 'TRANSFER_LIMIT'
    return None


def scope_dispute(task, args):
    if not task.can_file_disputes:
        return 'DISPUTE_NOT_PERMITTED'
    dispute = args.get('dispute_id')
    operation = args.get('transaction_ref')
    if dispute is not None and dispute not in task.allowed_disputes:
        return 'OUTSIDE_TASK_SCOPE'
    if operation is not None and operation not in task.allowed_operation_refs:
        return 'OUTSIDE_TASK_SCOPE'
    return None


def scope_fee(task, args):
    if not task.can_adjust_fees:
        return 'FEE_ADJUSTMENT_NOT_PERMITTED'
    if args.get('account') is not None and args['account'] not in readable(task):
        return 'OUTSIDE_TASK_SCOPE'
    if args.get('fee_id') is not None and args['fee_id'] not in task.allowed_fees:
        return 'OUTSIDE_TASK_SCOPE'
    return None


def scope_fx(task, args):
    if args['source'] != task.source or args['destination'] not in task.destinations:
        return 'OUTSIDE_TASK_SCOPE'
    if args['amount_cents'] > task.max_transfer_cents:
        return 'TRANSFER_LIMIT'
    return None if task.can_convert_fx else 'FX_NOT_PERMITTED'


def scope_refund(task, args):
    if not task.can_refund:
        return 'REFUND_NOT_PERMITTED'
    if args['destination'] != task.source and args['destination'] not in task.destinations:
        return 'OUTSIDE_TASK_SCOPE'
    if args['operation_ref'] not in task.allowed_operation_refs:
        return 'OUTSIDE_TASK_SCOPE'
    return None


def scope_reversal(task, args):
    if not task.can_refund:
        return 'REFUND_NOT_PERMITTED'
    return None if args['operation_ref'] in task.allowed_operation_refs else 'OUTSIDE_TASK_SCOPE'


def scope_list_loan(task, args):
    return None if args['loan_id'] in task.allowed_loans else 'OUTSIDE_TASK_SCOPE'


def scope_list_dispute(task, args):
    return None if args['dispute_id'] in task.allowed_disputes else 'OUTSIDE_TASK_SCOPE'


def scope_cancel_scheduled(task, args):
    if task.max_schedule_horizon <= 0:
        return 'SCHEDULING_NOT_PERMITTED'
    return None if args['scheduled_id'] in task.allowed_scheduled else 'OUTSIDE_TASK_SCOPE'


def scope_biller(task, args):
    err = scope_source_only(task, args)
    if err:
        return err
    return None if args['biller_id'] in task.allowed_billers else 'OUTSIDE_TASK_SCOPE'


def scope_mandate(task, args):
    err = scope_source_only(task, args)
    if err:
        return err
    return None if args['mandate_id'] in task.allowed_mandates else 'OUTSIDE_TASK_SCOPE'


def scope_card_payment(task, args):
    err = scope_source_only(task, args)
    if err:
        return err
    return None if args['card_id'] in task.allowed_cards else 'OUTSIDE_TASK_SCOPE'


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------

def _op(name, schema, side_effect, category, route, summary, scope,
        charge=lambda a: 0, approval_always=False):
    return Operation(name, schema, side_effect, category, route, summary, scope, charge, approval_always)


_READS = [
    _op('bank.balance', obj(['account'], {'account': IDENT}), SideEffect.READ, 'read', 'balance',
        lambda a: f"Read the balance of {a['account']}. No account changes requested.", scope_read_account),
    _op('bank.get_account', obj(['account'], {'account': IDENT}), SideEffect.READ, 'read', 'get_account',
        lambda a: f"Read account details for {a['account']}. No account changes requested.", scope_read_account),
    _op('bank.list_accounts', obj([], {}), SideEffect.READ, 'read', 'list_accounts',
        lambda a: 'List accounts visible to this task. No account changes requested.', scope_none),
    _op('bank.list_transactions', obj(['account', 'limit'], {'account': IDENT, 'limit': COUNT}),
        SideEffect.READ, 'read', 'list_transactions',
        lambda a: f"Read up to {a['limit']} transactions from {a['account']}. No account changes requested.",
        scope_read_account),
    _op('bank.get_statement', obj(['account', 'period'], {'account': IDENT, 'period': IDENT}),
        SideEffect.READ, 'read', 'get_statement',
        lambda a: f"Read the {a['period']} statement for {a['account']}. No account changes requested.",
        scope_read_account),
    _op('bank.list_payees', obj([], {}), SideEffect.READ, 'read', 'list_payees',
        lambda a: 'List saved payees. No account changes requested.', scope_none),
    _op('bank.get_card', obj(['card_id'], {'card_id': IDENT}), SideEffect.READ, 'read', 'get_card',
        lambda a: f"Read card {a['card_id']} details. Full card numbers are never returned.", scope_card_read),
    _op('bank.list_cards', obj([], {}), SideEffect.READ, 'read', 'list_cards',
        lambda a: 'List cards. Full card numbers are never returned.', scope_none),
    _op('bank.get_loan', obj(['loan_id'], {'loan_id': IDENT}), SideEffect.READ, 'read', 'get_loan',
        lambda a: f"Read loan {a['loan_id']}. No account changes requested.", scope_list_loan),
    _op('bank.get_payoff_quote', obj(['loan_id'], {'loan_id': IDENT}), SideEffect.READ, 'read', 'get_payoff_quote',
        lambda a: f"Quote the payoff amount for loan {a['loan_id']}. Quoting moves no money.", scope_list_loan),
    _op('bank.get_fx_quote',
        obj(['from_currency', 'to_currency', 'amount_cents'],
            {'from_currency': CURRENCY, 'to_currency': CURRENCY, 'amount_cents': AMOUNT}),
        SideEffect.READ, 'read', 'get_fx_quote',
        lambda a: (f"Quote conversion of {usd(a['amount_cents'])} from {a['from_currency']} to "
                   f"{a['to_currency']}. Quoting moves no money."), scope_none),
    _op('bank.get_limits', obj([], {}), SideEffect.READ, 'read', 'get_limits',
        lambda a: 'Read the configured transfer limits. Reading a limit does not change it.', scope_none),
    _op('bank.get_customer_profile', obj([], {}), SideEffect.READ, 'read', 'get_customer_profile',
        lambda a: 'Read the customer contact profile. No changes requested.', scope_none),
    _op('bank.list_holds', obj(['account'], {'account': IDENT}), SideEffect.READ, 'read', 'list_holds',
        lambda a: f"List holds on {a['account']}. No account changes requested.", scope_read_account),
    _op('bank.list_scheduled', obj([], {}), SideEffect.READ, 'read', 'list_scheduled',
        lambda a: 'List scheduled transfers. No account changes requested.', scope_none),
    _op('bank.get_dispute', obj(['dispute_id'], {'dispute_id': IDENT}), SideEffect.READ, 'read', 'get_dispute',
        lambda a: f"Read dispute {a['dispute_id']}. No account changes requested.", scope_list_dispute),
]

_HOLDS = [
    _op('bank.place_hold', obj(['account', 'amount_cents'], {'account': IDENT, 'amount_cents': AMOUNT}),
        SideEffect.WRITE, 'hold', 'place_hold',
        lambda a: (f"Reserve {usd(a['amount_cents'])} on {a['account']}. Funds become unavailable "
                   f"until the hold is released."), scope_hold),
    _op('bank.release_hold', obj(['hold_id'], {'hold_id': IDENT}), SideEffect.WRITE, 'hold', 'release_hold',
        lambda a: f"Release hold {a['hold_id']}. Reserved funds become spendable again.", scope_hold_release),
]

_SCHEDULE = [
    _op('bank.schedule_transfer',
        obj(['source', 'destination', 'amount_cents', 'execute_at'],
            {'source': IDENT, 'destination': IDENT, 'amount_cents': AMOUNT, 'execute_at': EPOCH}),
        SideEffect.WRITE, 'schedule', 'schedule_transfer',
        lambda a: (f"Schedule {usd(a['amount_cents'])} from {a['source']} to {a['destination']} at "
                   f"epoch {a['execute_at']}. This will execute later without a further proposal."),
        scope_schedule, approval_always=True),
    _op('bank.cancel_scheduled', obj(['scheduled_id'], {'scheduled_id': IDENT}),
        SideEffect.WRITE, 'schedule', 'cancel_scheduled',
        lambda a: f"Cancel scheduled transfer {a['scheduled_id']}. No money moves.", scope_cancel_scheduled),
]

_MONEY = [
    _op('bank.transfer',
        obj(['source', 'destination', 'amount_cents'],
            {'source': IDENT, 'destination': IDENT, 'amount_cents': AMOUNT}),
        SideEffect.PAYMENT, 'money', 'transfer',
        lambda a: (f"Transfer {usd(a['amount_cents'])} from {a['source']} to {a['destination']}. "
                   f"Debit and credit once for this operation ID."),
        scope_transfer, charge=lambda a: a['amount_cents']),
    _op('bank.transfer_external',
        obj(['source', 'payee_id', 'amount_cents'],
            {'source': IDENT, 'payee_id': IDENT, 'amount_cents': AMOUNT}),
        SideEffect.PAYMENT, 'money', 'transfer_external',
        lambda a: (f"Send {usd(a['amount_cents'])} from {a['source']} to external payee "
                   f"{a['payee_id']}. Money leaves this institution and recall is not guaranteed."),
        scope_external, charge=lambda a: a['amount_cents'], approval_always=True),
    _op('bank.wire_transfer',
        obj(['source', 'payee_id', 'amount_cents'],
            {'source': IDENT, 'payee_id': IDENT, 'amount_cents': AMOUNT}),
        SideEffect.PAYMENT, 'money', 'wire_transfer',
        lambda a: (f"Wire {usd(a['amount_cents'])} from {a['source']} to payee {a['payee_id']}. "
                   f"Wires are treated as final and non-reversible."),
        scope_external, charge=lambda a: a['amount_cents'], approval_always=True),
    _op('bank.bill_pay',
        obj(['source', 'biller_id', 'amount_cents'],
            {'source': IDENT, 'biller_id': IDENT, 'amount_cents': AMOUNT}),
        SideEffect.PAYMENT, 'money', 'bill_pay',
        lambda a: f"Pay {usd(a['amount_cents'])} from {a['source']} to biller {a['biller_id']}.",
        scope_biller, charge=lambda a: a['amount_cents']),
    _op('bank.card_payment',
        obj(['card_id', 'source', 'amount_cents'],
            {'card_id': IDENT, 'source': IDENT, 'amount_cents': AMOUNT}),
        SideEffect.PAYMENT, 'money', 'card_payment',
        lambda a: f"Pay {usd(a['amount_cents'])} from {a['source']} toward card {a['card_id']}.",
        scope_card_payment, charge=lambda a: a['amount_cents']),
    _op('bank.direct_debit_collect',
        obj(['source', 'mandate_id', 'amount_cents'],
            {'source': IDENT, 'mandate_id': IDENT, 'amount_cents': AMOUNT}),
        SideEffect.PAYMENT, 'money', 'direct_debit_collect',
        lambda a: (f"Collect {usd(a['amount_cents'])} from {a['source']} under mandate "
                   f"{a['mandate_id']}."), scope_mandate, charge=lambda a: a['amount_cents']),
    _op('bank.loan_disburse',
        obj(['loan_id', 'account', 'expected_amount_cents'],
            {'loan_id': IDENT, 'account': IDENT, 'expected_amount_cents': AMOUNT}),
        SideEffect.PAYMENT, 'money', 'loan_disburse',
        lambda a: (f"Disburse {usd(a['expected_amount_cents'])} from loan {a['loan_id']} into "
                   f"{a['account']}. This creates a repayable debt against the account."),
        scope_loan, charge=lambda a: a['expected_amount_cents'], approval_always=True),
    _op('bank.loan_repay',
        obj(['loan_id', 'source', 'amount_cents'],
            {'loan_id': IDENT, 'source': IDENT, 'amount_cents': AMOUNT}),
        SideEffect.PAYMENT, 'money', 'loan_repay',
        lambda a: f"Repay {usd(a['amount_cents'])} toward loan {a['loan_id']} from {a['source']}.",
        scope_loan, charge=lambda a: a['amount_cents']),
    _op('bank.early_payoff',
        obj(['loan_id', 'source', 'expected_amount_cents'],
            {'loan_id': IDENT, 'source': IDENT, 'expected_amount_cents': AMOUNT}),
        SideEffect.PAYMENT, 'money', 'early_payoff',
        lambda a: (f"Pay off loan {a['loan_id']} from {a['source']} for the declared outstanding "
                   f"amount {usd(a['expected_amount_cents'])}."),
        scope_loan, charge=lambda a: a['expected_amount_cents'], approval_always=True),
    _op('bank.fx_convert',
        obj(['source', 'destination', 'amount_cents', 'quote_id'],
            {'source': IDENT, 'destination': IDENT, 'amount_cents': AMOUNT, 'quote_id': IDENT}),
        SideEffect.PAYMENT, 'money', 'fx_convert',
        lambda a: (f"Convert {usd(a['amount_cents'])} from {a['source']} to {a['destination']} "
                   f"under quote {a['quote_id']}. The mock settles 1:1 and does not model FX economics."),
        scope_fx, charge=lambda a: a['amount_cents']),
    _op('bank.refund',
        obj(['operation_ref', 'destination', 'expected_amount_cents'],
            {'operation_ref': IDENT, 'destination': IDENT, 'expected_amount_cents': AMOUNT}),
        SideEffect.PAYMENT, 'money', 'refund',
        lambda a: (f"Refund {usd(a['expected_amount_cents'])} from operation {a['operation_ref']} "
                   f"to {a['destination']}. This moves money."),
        scope_refund, charge=lambda a: a['expected_amount_cents'], approval_always=True),
    _op('bank.reversal',
        obj(['operation_ref', 'expected_amount_cents'],
            {'operation_ref': IDENT, 'expected_amount_cents': AMOUNT}),
        SideEffect.PAYMENT, 'money', 'reversal',
        lambda a: (f"Reverse {usd(a['expected_amount_cents'])} from operation {a['operation_ref']}, "
                   f"returning funds to the original source."),
        scope_reversal, charge=lambda a: a['expected_amount_cents'], approval_always=True),
]

_PAYEES = [
    _op('bank.add_payee', obj(['name', 'account_ref'], {'name': TEXT, 'account_ref': IDENT}),
        SideEffect.WRITE, 'payee', 'add_payee',
        lambda a: (f"Create payee '{a['name']}' pointing at {a['account_ref']}. A new payee is a "
                   f"new possible destination for money."), scope_payee_mgmt, approval_always=True),
    _op('bank.verify_payee', obj(['payee_id'], {'payee_id': IDENT}), SideEffect.WRITE, 'payee', 'verify_payee',
        lambda a: f"Mark payee {a['payee_id']} as verified. Verified payees face fewer checks.",
        scope_payee_mgmt, approval_always=True),
    _op('bank.update_payee', obj(['payee_id', 'account_ref'], {'payee_id': IDENT, 'account_ref': IDENT}),
        SideEffect.WRITE, 'payee', 'update_payee',
        lambda a: (f"Repoint payee {a['payee_id']} at {a['account_ref']}. Future payments to this "
                   f"payee will go to the new destination."), scope_payee_mgmt, approval_always=True),
    _op('bank.remove_payee', obj(['payee_id'], {'payee_id': IDENT}), SideEffect.DESTRUCTIVE, 'payee',
        'remove_payee',
        lambda a: f"Delete payee {a['payee_id']}. Recovery of the payee record is not verified.",
        scope_payee_mgmt),
]

_CARDS = [
    _op('bank.issue_card', obj(['account'], {'account': IDENT}), SideEffect.WRITE, 'card', 'issue_card',
        lambda a: f"Issue a new card against {a['account']}. A new card is a new spending instrument.",
        scope_card, approval_always=True),
    _op('bank.activate_card', obj(['card_id'], {'card_id': IDENT}), SideEffect.WRITE, 'card', 'activate_card',
        lambda a: f"Activate card {a['card_id']}. The card becomes usable for spending.", scope_card),
    _op('bank.freeze_card', obj(['card_id'], {'card_id': IDENT}), SideEffect.WRITE, 'card', 'freeze_card',
        lambda a: f"Freeze card {a['card_id']}. Spending is blocked until it is unfrozen.", scope_card),
    _op('bank.unfreeze_card', obj(['card_id'], {'card_id': IDENT}), SideEffect.WRITE, 'card', 'unfreeze_card',
        lambda a: f"Unfreeze card {a['card_id']}. Spending becomes possible again.", scope_card,
        approval_always=True),
    _op('bank.cancel_card', obj(['card_id'], {'card_id': IDENT}), SideEffect.DESTRUCTIVE, 'card', 'cancel_card',
        lambda a: f"Cancel card {a['card_id']} permanently. Reissue is not verified.", scope_card,
        approval_always=True),
    _op('bank.set_card_limit', obj(['card_id', 'limit_cents'], {'card_id': IDENT, 'limit_cents': AMOUNT}),
        SideEffect.CONFIG_CHANGE, 'card', 'set_card_limit',
        lambda a: (f"Set the spending limit on card {a['card_id']} to {usd(a['limit_cents'])}. "
                   f"Raising a limit increases possible loss."), scope_card, approval_always=True),
    _op('bank.change_pin', obj(['card_id'], {'card_id': IDENT}), SideEffect.WRITE, 'card', 'change_pin',
        lambda a: (f"Start a PIN change for card {a['card_id']}. The PIN itself is never accepted "
                   f"through this interface."), scope_card, approval_always=True),
    _op('bank.report_lost', obj(['card_id'], {'card_id': IDENT}), SideEffect.WRITE, 'card', 'report_lost',
        lambda a: f"Report card {a['card_id']} lost. The card is blocked immediately.", scope_card),
]

_ACCOUNTS = [
    _op('bank.open_account', obj(['kind'], {'kind': ACCOUNT_KIND}), SideEffect.WRITE, 'account', 'open_account',
        lambda a: f"Open a new {a['kind']} account. A new account is a new place to move money.",
        scope_account_lifecycle, approval_always=True),
    _op('bank.close_account', obj(['account'], {'account': IDENT}), SideEffect.DESTRUCTIVE, 'account',
        'close_account',
        lambda a: (f"Close {a['account']}. Closing requires a zero balance and is not verified to "
                   f"be reversible."), scope_account_lifecycle, approval_always=True),
    _op('bank.freeze_account', obj(['account'], {'account': IDENT}), SideEffect.WRITE, 'account', 'freeze_account',
        lambda a: f"Freeze {a['account']}. All debits from the account will fail.", scope_account_lifecycle),
    _op('bank.unfreeze_account', obj(['account'], {'account': IDENT}), SideEffect.WRITE, 'account',
        'unfreeze_account',
        lambda a: f"Unfreeze {a['account']}. Debits become possible again.", scope_account_lifecycle,
        approval_always=True),
]

_CUSTOMER = [
    _op('bank.update_email', obj(['email'], {'email': TEXT}), SideEffect.WRITE, 'customer', 'update_email',
        lambda a: (f"Change the customer contact email to {a['email']}. Contact details are used for "
                   f"recovery and notification."), scope_customer_write, approval_always=True),
    _op('bank.update_phone', obj(['phone'], {'phone': TEXT}), SideEffect.WRITE, 'customer', 'update_phone',
        lambda a: (f"Change the customer contact phone to {a['phone']}. Contact details are used for "
                   f"recovery and notification."), scope_customer_write, approval_always=True),
    _op('bank.update_address', obj(['address'], {'address': TEXT}), SideEffect.WRITE, 'customer',
        'update_address',
        lambda a: f"Change the customer mailing address to {a['address']}.", scope_customer_write,
        approval_always=True),
    _op('bank.export_transactions', obj(['account', 'rows'], {'account': IDENT, 'rows': COUNT}),
        SideEffect.EXTERNAL_MESSAGE, 'customer', 'export_transactions',
        lambda a: (f"Export {a['rows']} transaction rows from {a['account']}. Exported data leaves "
                   f"the controlled boundary."), scope_export, approval_always=True),
    _op('bank.export_customer_data', obj([], {}), SideEffect.EXTERNAL_MESSAGE, 'customer', 'export_customer_data',
        lambda a: ('Export the full customer record, including contact details. Exported data leaves '
                   'the controlled boundary.'), scope_export, approval_always=True),
    _op('bank.share_statement',
        obj(['account', 'destination_email'], {'account': IDENT, 'destination_email': TEXT}),
        SideEffect.EXTERNAL_MESSAGE, 'customer', 'share_statement',
        lambda a: (f"Send the statement for {a['account']} to {a['destination_email']}. This "
                   f"discloses account activity to an external address."), scope_share, approval_always=True),
]

_DISPUTES = [
    _op('bank.open_dispute', obj(['transaction_ref', 'reason'], {'transaction_ref': IDENT, 'reason': TEXT}),
        SideEffect.WRITE, 'dispute', 'open_dispute',
        lambda a: f"Open a dispute against transaction {a['transaction_ref']}. No money moves now.",
        scope_dispute),
    _op('bank.cancel_dispute', obj(['dispute_id'], {'dispute_id': IDENT}), SideEffect.WRITE, 'dispute',
        'cancel_dispute',
        lambda a: (f"Cancel dispute {a['dispute_id']}. Cancelling may forfeit a claim and is not "
                   f"verified to be reversible."), scope_dispute, approval_always=True),
    _op('bank.apply_fee', obj(['account', 'amount_cents'], {'account': IDENT, 'amount_cents': AMOUNT}),
        SideEffect.PAYMENT, 'fee', 'apply_fee',
        lambda a: f"Charge a fee of {usd(a['amount_cents'])} to {a['account']}.", scope_fee,
        charge=lambda a: a['amount_cents'], approval_always=True),
    _op('bank.waive_fee',
        obj(['fee_id', 'expected_amount_cents'], {'fee_id': IDENT, 'expected_amount_cents': AMOUNT}),
        SideEffect.WRITE, 'fee', 'waive_fee',
        lambda a: f"Waive fee {a['fee_id']}, returning {usd(a['expected_amount_cents'])}.", scope_fee,
        charge=lambda a: a['expected_amount_cents'], approval_always=True),
]

OPERATIONS: dict[str, Operation] = {
    op.name: op for op in _READS + _HOLDS + _SCHEDULE + _MONEY + _PAYEES + _CARDS + _ACCOUNTS + _CUSTOMER + _DISPUTES
}

# Never registered with ToolGuard and independently rejected by the controller.
# Task configuration cannot enable these and an operator approval cannot unlock
# them. Limit changes are here on purpose: self-service limit raising defeats
# every limit underneath it.
FORBIDDEN: frozenset[str] = frozenset({
    'bank.delete_account',
    'bank.purge_transactions',
    'bank.bulk_transfer',
    'bank.admin_override',
    'bank.set_transfer_limit',
    'bank.set_daily_limit',
    'bank.request_limit_increase',
})

READ_ONLY = tuple(op.name for op in _READS)
ALL_OPERATIONS = tuple(OPERATIONS)


@dataclass(frozen=True)
class ChainRule:
    """A sequence rule. Each step may be permitted while the sequence is not."""
    code: str
    prior: frozenset[str]
    following: frozenset[str]
    action: str  # 'deny' or 'approval'
    note: str


def _names(*categories: str) -> frozenset[str]:
    return frozenset(op.name for op in OPERATIONS.values() if op.category in categories)


CHAIN_RULES: tuple[ChainRule, ...] = (
    ChainRule('CHAIN_PAYEE_THEN_PAYMENT', _names('payee'), _names('money'), 'deny',
              'Creating or repointing a payee and then paying it within one task lets the agent '
              'choose its own destination.'),
    ChainRule('CHAIN_CONTACT_THEN_MONEY',
              frozenset({'bank.update_email', 'bank.update_phone'}), _names('money', 'card'), 'deny',
              'Changing recovery contact details and then moving money or touching cards is the '
              'account-takeover shape.'),
    ChainRule('CHAIN_EXPORT_THEN_MONEY',
              frozenset({'bank.export_transactions', 'bank.export_customer_data', 'bank.share_statement'}),
              _names('money'), 'deny',
              'Reconnaissance, exfiltration and payment are individually permitted steps that '
              'together describe theft.'),
    ChainRule('CHAIN_HOLD_RELEASE_THEN_PAYMENT',
              frozenset({'bank.release_hold'}), _names('money'), 'approval',
              'Releasing reserved funds immediately before spending them needs a human look.'),
    ChainRule('CHAIN_ACCOUNT_OPEN_THEN_PAYMENT',
              frozenset({'bank.open_account'}), _names('money'), 'approval',
              'A freshly opened account as a payment leg is a laundering shape.'),
    ChainRule('CHAIN_UNFREEZE_THEN_PAYMENT',
              frozenset({'bank.unfreeze_account', 'bank.unfreeze_card'}), _names('money'), 'approval',
              'Lifting a protective freeze and then spending needs a human look.'),
)


def chain_violation(prior_ops: set[str], candidate: str) -> ChainRule | None:
    """Return the first chain rule broken by running ``candidate`` after ``prior_ops``."""
    for rule in CHAIN_RULES:
        if candidate in rule.following and prior_ops & rule.prior:
            return rule
    return None


def summarize_operation(tool: str, arguments: dict) -> str:
    """Deterministic approval text built only from the tool and validated arguments."""
    operation = OPERATIONS.get(tool)
    if operation is None:
        return f'Run unregistered operation {tool}. Its effects are unknown.'
    return operation.summary(arguments)
