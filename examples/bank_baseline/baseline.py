"""Offline mock bank and reference controller. Not a real banking integration."""
from __future__ import annotations
import hashlib, hmac, json, multiprocessing, os, secrets, sqlite3, threading, time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from pramagent.layers.tool_guard import ToolGuardLayer, ToolPolicy, SideEffect
from pramagent.types import Verdict
from pramagent.store import SQLiteStore
from operations import (OPERATIONS, FORBIDDEN, ALL_OPERATIONS, READ_ONLY,
                        chain_violation, readable, summarize_operation)

VERSION = 'bank-baseline-2'

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)

def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()

def no_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out: raise ValueError('duplicate property')
        out[key] = value
    return out

def snapshot(value):
    """Only plain JSON values; reject executable/custom objects and ambiguous types."""
    def check(x, depth=0):
        if depth > 15: raise ValueError('too deeply nested')
        if type(x) in (str, int, bool) or x is None: return
        if type(x) is list:
            for item in x: check(item, depth+1)
            return
        if type(x) is dict:
            for key, item in x.items():
                if type(key) is not str: raise ValueError('non-string property')
                check(item, depth+1)
            return
        raise ValueError('only plain integer-based JSON values accepted')
    if type(value) is str:
        if len(value.encode()) > 16000: raise ValueError('request too large')
        value = json.loads(value, object_pairs_hook=no_duplicates)
    check(value)
    encoded = canonical(value)
    if len(encoded.encode()) > 16000: raise ValueError('request too large')
    return json.loads(encoded)

@dataclass(frozen=True)
class Task:
    """Explicit, operator-authorised permission record for one unit of work.

    Every capability is off unless the task turns it on. The agent may propose a
    scope but never sets one: ``Controller.configure`` requires the operator
    token. Fields added beyond the original two-operation baseline default to
    the most restrictive value so existing task definitions keep their meaning.
    """
    task_id: str = 'invoice-task'
    tenant: str = 'tenant-a'
    source: str = 'a-main'
    destinations: tuple[str, ...] = ('a-vendor',)
    can_transfer: bool = False
    max_transfer_cents: int = 200_000
    total_cents: int = 500_000
    approval_above_cents: int = 50_000
    expires_at: int = 2_000_000_000
    revision: int = 1
    active: bool = True
    # Operation allow-list. Empty means no authority.
    allowed_operations: tuple[str, ...] = ()
    # Resource scopes are explicit. Empty means no matching resource.
    readable_accounts: tuple[str, ...] = ()
    allowed_payees: tuple[str, ...] = ()
    allowed_cards: tuple[str, ...] = ()
    allowed_loans: tuple[str, ...] = ()
    allowed_holds: tuple[str, ...] = ()
    allowed_scheduled: tuple[str, ...] = ()
    allowed_disputes: tuple[str, ...] = ()
    allowed_fees: tuple[str, ...] = ()
    allowed_billers: tuple[str, ...] = ()
    allowed_mandates: tuple[str, ...] = ()
    allowed_operation_refs: tuple[str, ...] = ()
    allowed_share_targets: tuple[str, ...] = ()
    can_manage_payees: bool = False
    can_manage_cards: bool = False
    can_manage_accounts: bool = False
    can_update_customer: bool = False
    can_export_data: bool = False
    max_export_rows: int = 0
    can_place_holds: bool = False
    can_service_loans: bool = False
    can_file_disputes: bool = False
    can_adjust_fees: bool = False
    can_convert_fx: bool = False
    can_refund: bool = False
    max_schedule_horizon: int = 0

    _INTS = ('max_transfer_cents','total_cents','approval_above_cents','expires_at','revision',
             'max_export_rows','max_schedule_horizon')
    _BOOLS = ('can_transfer','active','can_manage_payees','can_manage_cards','can_manage_accounts',
              'can_update_customer','can_export_data','can_place_holds','can_service_loans',
              'can_file_disputes','can_adjust_fees','can_convert_fx','can_refund')
    _TUPLES = ('destinations','allowed_operations','readable_accounts','allowed_payees',
               'allowed_cards','allowed_loans','allowed_holds','allowed_scheduled',
               'allowed_disputes','allowed_fees','allowed_billers','allowed_mandates',
               'allowed_operation_refs','allowed_share_targets')

    def __post_init__(self):
        for field in self._INTS:
            value = getattr(self, field)
            if type(value) is not int or value < 0 or value > 2**53-1: raise ValueError(field)
        for field in self._BOOLS:
            if type(getattr(self, field)) is not bool: raise ValueError('boolean required: '+field)
        for field in self._TUPLES:
            value = getattr(self, field)
            if type(value) is not tuple or not all(type(x) is str for x in value): raise ValueError(field+' tuple required')
        unknown = set(self.allowed_operations) - set(OPERATIONS)
        if unknown: raise ValueError('unknown operations: '+','.join(sorted(unknown)))
        # A task may never grant a forbidden operation, whatever the caller passes.
        if set(self.allowed_operations) & FORBIDDEN: raise ValueError('forbidden operation cannot be granted')

    def permits(self, tool: str) -> bool:
        return tool in self.allowed_operations


def summarize(request):
    """Deterministic approval text. Never produced by a model or by the caller."""
    return summarize_operation(request['tool'], request['arguments'])


BANK_OWNED = ('bank-treasury', 'bank-fees', 'ext-settlement')


def bank_worker(conn, path, service_key, initial_cents, fail_before_commit):
    """Bank server process. Pipe transport deliberately avoids all network calls.

    Bank-owned accounts (treasury, fees, external settlement) exist so that
    every operation is a movement between accounts inside the snapshot. That
    keeps "total synthetic funds are conserved" a meaningful invariant for
    fees, loans and external payments, not only for internal transfers.
    """
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.executescript('''
      PRAGMA journal_mode=WAL;
      CREATE TABLE IF NOT EXISTS accounts(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,balance INTEGER NOT NULL CHECK(balance>=0),status TEXT NOT NULL DEFAULT 'active',kind TEXT NOT NULL DEFAULT 'checking');
      CREATE TABLE IF NOT EXISTS transfers(operation_id TEXT PRIMARY KEY,digest TEXT NOT NULL,receipt TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS ledger(seq INTEGER PRIMARY KEY AUTOINCREMENT,tenant TEXT,account TEXT,delta INTEGER,kind TEXT,operation_id TEXT);
      CREATE TABLE IF NOT EXISTS payees(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,name TEXT NOT NULL,account_ref TEXT NOT NULL,verified INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS cards(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,account TEXT NOT NULL,status TEXT NOT NULL,limit_cents INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS holds(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,account TEXT NOT NULL,amount_cents INTEGER NOT NULL,status TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS scheduled(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,source TEXT,destination TEXT,amount_cents INTEGER,execute_at INTEGER,status TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS loans(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,account TEXT NOT NULL,outstanding_cents INTEGER NOT NULL,status TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS disputes(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,transaction_ref TEXT NOT NULL,status TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS fees(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,account TEXT NOT NULL,amount_cents INTEGER NOT NULL,status TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS customer(tenant TEXT PRIMARY KEY,email TEXT,phone TEXT,address TEXT);
      CREATE TABLE IF NOT EXISTS counters(name TEXT PRIMARY KEY,value INTEGER NOT NULL);
    ''')
    if db.execute('SELECT COUNT(*) FROM accounts').fetchone()[0] == 0:
        db.executemany('INSERT INTO accounts(id,tenant,balance) VALUES(?,?,?)',[
            ('a-main','tenant-a',initial_cents),('a-vendor','tenant-a',0),
            ('a-savings','tenant-a',0),('b-main','tenant-b',1_000_000),
            ('bank-treasury','bank',100_000_000),('bank-fees','bank',0),
            ('ext-settlement','bank',100_000_000)])
        db.execute("INSERT INTO payees VALUES('p-vendor','tenant-a','Known Vendor','a-vendor',1)")
        db.execute("INSERT INTO payees VALUES('p-other','tenant-a','Unverified Payee','a-savings',0)")
        db.execute("INSERT INTO cards VALUES('c-main','tenant-a','a-main','active',50_000)")
        db.execute("INSERT INTO cards VALUES('c-spare','tenant-a','a-main','frozen',10_000)")
        db.execute("INSERT INTO loans VALUES('l-1','tenant-a','a-main',300_000,'open')")
        db.execute("INSERT INTO disputes VALUES('d-1','tenant-a','tx-seed','open')")
        db.execute("INSERT INTO fees VALUES('f-1','tenant-a','a-main',500,'charged')")
        db.execute("INSERT INTO customer VALUES('tenant-a','owner@example.test','+10000000000','1 Test Street')")
        db.commit()

    def next_id(prefix):
        # The 'g' marker keeps generated identifiers from ever colliding with
        # seeded fixture rows such as 'f-1' or 'd-1'.
        row=db.execute('SELECT value FROM counters WHERE name=?',(prefix,)).fetchone()
        value=(row['value'] if row else 0)+1
        db.execute('INSERT OR REPLACE INTO counters VALUES(?,?)',(prefix,value))
        return f'{prefix}-g{value}'

    def account(aid):
        return db.execute('SELECT * FROM accounts WHERE id=?',(aid,)).fetchone()

    def owns(row, tenant):
        """Customer accounts must match the tenant; bank-owned legs are exempt."""
        return row is not None and (row['tenant']==tenant or row['tenant']=='bank')

    def held(aid):
        return db.execute("SELECT COALESCE(SUM(amount_cents),0) AS s FROM holds WHERE account=? AND status='active'",(aid,)).fetchone()['s']

    def permitted(body, name):
        """Trusted resource scope injected by the controller, never the agent."""
        scope=body.get('_scope')
        values=scope.get(name) if type(scope) is dict else None
        if type(values) is not list or not all(type(value) is str for value in values):
            return set()
        return set(values)

    def money(body, src, dst, amount, kind, after=None):
        """Idempotent movement between two accounts inside the snapshot.

        ``after`` runs inside the same transaction as the movement. Bookkeeping
        that happened outside it could fail once the debit had already
        committed, which would report a failure for money that really moved.
        """
        if type(amount) is not int or amount<=0 or amount>2**53-1: raise ValueError('invalid amount')
        material={'kind':kind,'tenant':body['tenant'],'source':src,'destination':dst,'amount_cents':amount}
        fingerprint=digest(material)
        db.execute('BEGIN IMMEDIATE')
        old=db.execute('SELECT digest,receipt FROM transfers WHERE operation_id=?',(body['operation_id'],)).fetchone()
        if old:
            db.rollback()
            return {'ok':True,'receipt':json.loads(old['receipt']),'replayed':True} if old['digest']==fingerprint else {'ok':False,'code':'BANK_IDEMPOTENCY_CONFLICT'}
        s,d=account(src),account(dst)
        if not owns(s,body['tenant']) or not owns(d,body['tenant']) or src==dst:
            db.rollback();return {'ok':False,'code':'BANK_ACCOUNT_SCOPE'}
        if s['status']!='active' or d['status']!='active':
            db.rollback();return {'ok':False,'code':'BANK_ACCOUNT_FROZEN'}
        if s['balance']-held(src)<amount:
            db.rollback();return {'ok':False,'code':'BANK_INSUFFICIENT_FUNDS'}
        db.execute('UPDATE accounts SET balance=balance-? WHERE id=?',(amount,src))
        db.execute('UPDATE accounts SET balance=balance+? WHERE id=?',(amount,dst))
        receipt={'operation_id':body['operation_id'],**material,'status':'completed'}
        db.execute('INSERT INTO transfers VALUES(?,?,?)',(body['operation_id'],fingerprint,canonical(receipt)))
        db.executemany('INSERT INTO ledger(tenant,account,delta,kind,operation_id) VALUES(?,?,?,?,?)',
                       [(body['tenant'],src,-amount,kind,body['operation_id']),
                        (body['tenant'],dst,amount,kind,body['operation_id'])])
        if after is not None: after()
        db.commit()
        return {'ok':True,'receipt':receipt,'replayed':False}

    def row_status(table, rid, tenant):
        query={
            'cards':'SELECT * FROM cards WHERE id=?',
            'holds':'SELECT * FROM holds WHERE id=?',
            'scheduled':'SELECT * FROM scheduled WHERE id=?',
            'loans':'SELECT * FROM loans WHERE id=?',
            'disputes':'SELECT * FROM disputes WHERE id=?',
            'fees':'SELECT * FROM fees WHERE id=?',
            'payees':'SELECT * FROM payees WHERE id=?',
        }.get(table)
        if query is None: raise ValueError('unsupported record table')
        row=db.execute(query,(rid,)).fetchone()
        if not row or row['tenant']!=tenant: return None
        return row

    def set_status(table, rid, tenant, status, allowed=None):
        row=row_status(table,rid,tenant)
        if not row: return {'ok':False,'code':'BANK_RECORD_SCOPE'}
        if allowed is not None and row['status'] not in allowed:
            return {'ok':False,'code':'BANK_INVALID_STATE'}
        query={
            'cards':'UPDATE cards SET status=? WHERE id=?',
            'holds':'UPDATE holds SET status=? WHERE id=?',
            'scheduled':'UPDATE scheduled SET status=? WHERE id=?',
            'loans':'UPDATE loans SET status=? WHERE id=?',
            'disputes':'UPDATE disputes SET status=? WHERE id=?',
            'fees':'UPDATE fees SET status=? WHERE id=?',
        }.get(table)
        if query is None:return {'ok':False,'code':'BANK_RECORD_SCOPE'}
        with db: db.execute(query,(status,rid))
        return {'ok':True,'id':rid,'status':status}

    conn.send({'ready':True})
    while True:
        message = conn.recv()
        if message.get('stop') and hmac.compare_digest(message.get('key',''),service_key): break
        try:
            if not hmac.compare_digest(str(message.get('key','')),service_key):
                conn.send({'ok':False,'code':'BANK_UNAUTHORIZED'});continue
            route = message['route']; body = message.get('body',{})
            if route == 'snapshot':
                response = {'ok':True,'accounts':dict(db.execute('SELECT id,balance FROM accounts')),
                            'transfers':db.execute('SELECT COUNT(*) FROM transfers').fetchone()[0]}
            elif route == 'lookup':
                row = db.execute('SELECT receipt FROM transfers WHERE operation_id=?',(body['operation_id'],)).fetchone()
                response = {'ok':True,'receipt':json.loads(row[0]) if row else None}
            elif route == 'balance':
                row = db.execute('SELECT tenant,balance FROM accounts WHERE id=?',(body['account'],)).fetchone()
                response = {'ok':True,'balance_cents':row[1]} if row and row[0]==body['tenant'] else {'ok':False,'code':'BANK_ACCOUNT_SCOPE'}
            elif route == 'transfer':
                amount=body['amount_cents']
                if type(amount) is not int or amount<=0 or amount>2**53-1: raise ValueError('invalid amount')
                material={key:body[key] for key in ['tenant','source','destination','amount_cents']}
                fingerprint=digest(material)
                db.execute('BEGIN IMMEDIATE')
                old=db.execute('SELECT digest,receipt FROM transfers WHERE operation_id=?',(body['operation_id'],)).fetchone()
                if old:
                    db.rollback()
                    response={'ok':True,'receipt':json.loads(old[1]),'replayed':True} if old[0]==fingerprint else {'ok':False,'code':'BANK_IDEMPOTENCY_CONFLICT'}
                else:
                    src=db.execute('SELECT tenant,balance,status FROM accounts WHERE id=?',(body['source'],)).fetchone()
                    dst=db.execute('SELECT tenant,balance,status FROM accounts WHERE id=?',(body['destination'],)).fetchone()
                    if not src or not dst or src['tenant']!=body['tenant'] or dst['tenant']!=body['tenant'] or body['source']==body['destination']:
                        db.rollback();response={'ok':False,'code':'BANK_ACCOUNT_SCOPE'}
                    elif src['status']!='active' or dst['status']!='active':
                        db.rollback();response={'ok':False,'code':'BANK_ACCOUNT_FROZEN'}
                    elif src['balance']-held(body['source'])<amount:
                        db.rollback();response={'ok':False,'code':'BANK_INSUFFICIENT_FUNDS'}
                    else:
                        db.execute('UPDATE accounts SET balance=balance-? WHERE id=?',(amount,body['source']))
                        if fail_before_commit:
                            fail_before_commit=False
                            raise RuntimeError('injected local failure after debit before credit')
                        db.execute('UPDATE accounts SET balance=balance+? WHERE id=?',(amount,body['destination']))
                        receipt={'operation_id':body['operation_id'],**material,'status':'completed'}
                        db.execute('INSERT INTO transfers VALUES(?,?,?)',(body['operation_id'],fingerprint,canonical(receipt)))
                        db.commit();response={'ok':True,'receipt':receipt,'replayed':False}
            # ---------------- reads ----------------
            elif route == 'get_account':
                row=account(body['account'])
                response={'ok':True,'account':{'id':row['id'],'balance_cents':row['balance'],'status':row['status'],'kind':row['kind']}} if owns(row,body['tenant']) and row['tenant']!='bank' else {'ok':False,'code':'BANK_ACCOUNT_SCOPE'}
            elif route == 'list_accounts':
                rows=db.execute('SELECT id,balance,status FROM accounts WHERE tenant=?',(body['tenant'],)).fetchall()
                allowed=permitted(body,'accounts')
                response={'ok':True,'accounts':[{'id':r['id'],'balance_cents':r['balance'],'status':r['status']} for r in rows if r['id'] in allowed]}
            elif route == 'list_transactions':
                row=account(body['account'])
                if not owns(row,body['tenant']) or row['tenant']=='bank': response={'ok':False,'code':'BANK_ACCOUNT_SCOPE'}
                else:
                    rows=db.execute('SELECT seq,delta,kind FROM ledger WHERE account=? ORDER BY seq DESC LIMIT ?',(body['account'],body['limit'])).fetchall()
                    response={'ok':True,'transactions':[dict(r) for r in rows]}
            elif route == 'get_statement':
                row=account(body['account'])
                if not owns(row,body['tenant']) or row['tenant']=='bank': response={'ok':False,'code':'BANK_ACCOUNT_SCOPE'}
                else:
                    total=db.execute('SELECT COALESCE(SUM(delta),0) AS s FROM ledger WHERE account=?',(body['account'],)).fetchone()['s']
                    response={'ok':True,'statement':{'account':body['account'],'period':body['period'],'net_cents':total,'closing_cents':row['balance']}}
            elif route == 'list_payees':
                rows=db.execute('SELECT id,name,account_ref,verified FROM payees WHERE tenant=?',(body['tenant'],)).fetchall()
                allowed=permitted(body,'payees')
                response={'ok':True,'payees':[dict(r) for r in rows if r['id'] in allowed]}
            elif route == 'get_card':
                row=row_status('cards',body['card_id'],body['tenant'])
                response={'ok':True,'card':{'id':row['id'],'account':row['account'],'status':row['status'],'limit_cents':row['limit_cents']}} if row else {'ok':False,'code':'BANK_RECORD_SCOPE'}
            elif route == 'list_cards':
                rows=db.execute('SELECT id,account,status,limit_cents FROM cards WHERE tenant=?',(body['tenant'],)).fetchall()
                allowed=permitted(body,'cards')
                response={'ok':True,'cards':[dict(r) for r in rows if r['id'] in allowed]}
            elif route == 'get_loan':
                row=row_status('loans',body['loan_id'],body['tenant'])
                response={'ok':True,'loan':{'id':row['id'],'outstanding_cents':row['outstanding_cents'],'status':row['status']}} if row else {'ok':False,'code':'BANK_RECORD_SCOPE'}
            elif route == 'get_payoff_quote':
                row=row_status('loans',body['loan_id'],body['tenant'])
                response={'ok':True,'payoff_cents':row['outstanding_cents']} if row else {'ok':False,'code':'BANK_RECORD_SCOPE'}
            elif route == 'get_fx_quote':
                # The mock quotes 1:1 on purpose; it does not model FX economics.
                response={'ok':True,'quote_id':next_id('q'),'rate':'1.0','amount_cents':body['amount_cents']}
                db.commit()
            elif route == 'get_limits':
                rows=db.execute('SELECT id,limit_cents FROM cards WHERE tenant=?',(body['tenant'],)).fetchall()
                allowed=permitted(body,'cards')
                response={'ok':True,'card_limits':[dict(r) for r in rows if r['id'] in allowed]}
            elif route == 'get_customer_profile':
                row=db.execute('SELECT * FROM customer WHERE tenant=?',(body['tenant'],)).fetchone()
                response={'ok':True,'profile':dict(row)} if row else {'ok':False,'code':'BANK_RECORD_SCOPE'}
            elif route == 'list_holds':
                rows=db.execute('SELECT id,amount_cents,status FROM holds WHERE account=? AND tenant=?',(body['account'],body['tenant'])).fetchall()
                response={'ok':True,'holds':[dict(r) for r in rows]}
            elif route == 'list_scheduled':
                rows=db.execute('SELECT id,source,destination,amount_cents,execute_at,status FROM scheduled WHERE tenant=?',(body['tenant'],)).fetchall()
                allowed=permitted(body,'scheduled')
                response={'ok':True,'scheduled':[dict(r) for r in rows if r['id'] in allowed]}
            elif route == 'get_dispute':
                row=row_status('disputes',body['dispute_id'],body['tenant'])
                response={'ok':True,'dispute':{'id':row['id'],'status':row['status']}} if row else {'ok':False,'code':'BANK_RECORD_SCOPE'}
            # ---------------- holds and scheduling ----------------
            elif route == 'place_hold':
                row=account(body['account'])
                if not owns(row,body['tenant']) or row['tenant']=='bank': response={'ok':False,'code':'BANK_ACCOUNT_SCOPE'}
                elif row['balance']-held(body['account'])<body['amount_cents']: response={'ok':False,'code':'BANK_INSUFFICIENT_FUNDS'}
                else:
                    hid=next_id('h')
                    with db: db.execute('INSERT INTO holds VALUES(?,?,?,?,?)',(hid,body['tenant'],body['account'],body['amount_cents'],'active'))
                    response={'ok':True,'hold_id':hid}
            elif route == 'release_hold':
                response=set_status('holds',body['hold_id'],body['tenant'],'released',allowed=('active',))
            elif route == 'schedule_transfer':
                sid=next_id('s')
                with db: db.execute('INSERT INTO scheduled VALUES(?,?,?,?,?,?,?)',(sid,body['tenant'],body['source'],body['destination'],body['amount_cents'],body['execute_at'],'pending'))
                response={'ok':True,'scheduled_id':sid}
            elif route == 'cancel_scheduled':
                response=set_status('scheduled',body['scheduled_id'],body['tenant'],'cancelled',allowed=('pending',))
            # ---------------- money movement ----------------
            elif route in ('transfer_external','wire_transfer','bill_pay','direct_debit_collect'):
                response=money(body,body['source'],'ext-settlement',body['amount_cents'],route)
            elif route == 'card_payment':
                response=money(body,body['source'],'bank-treasury',body['amount_cents'],route)
            elif route == 'loan_repay':
                loan=row_status('loans',body['loan_id'],body['tenant'])
                if not loan: response={'ok':False,'code':'BANK_RECORD_SCOPE'}
                else:
                    response=money(body,body['source'],'bank-treasury',body['amount_cents'],route,
                                   after=lambda: db.execute('UPDATE loans SET outstanding_cents=MAX(0,outstanding_cents-?) WHERE id=?',(body['amount_cents'],body['loan_id'])))
            elif route == 'early_payoff':
                loan=row_status('loans',body['loan_id'],body['tenant'])
                if not loan or loan['status']!='open': response={'ok':False,'code':'BANK_INVALID_STATE'}
                elif loan['outstanding_cents']!=body['expected_amount_cents']: response={'ok':False,'code':'BANK_AMOUNT_CHANGED'}
                else:
                    response=money(body,body['source'],'bank-treasury',loan['outstanding_cents'],route,
                                   after=lambda: db.execute("UPDATE loans SET outstanding_cents=0,status='closed' WHERE id=?",(body['loan_id'],)))
            elif route == 'loan_disburse':
                loan=row_status('loans',body['loan_id'],body['tenant'])
                if not loan or loan['status']!='open': response={'ok':False,'code':'BANK_INVALID_STATE'}
                elif loan['outstanding_cents']!=body['expected_amount_cents']: response={'ok':False,'code':'BANK_AMOUNT_CHANGED'}
                else: response=money(body,'bank-treasury',body['account'],loan['outstanding_cents'],route)
            elif route == 'fx_convert':
                response=money(body,body['source'],body['destination'],body['amount_cents'],route)
            elif route == 'refund':
                original=db.execute('SELECT receipt FROM transfers WHERE operation_id=?',(body['operation_ref'],)).fetchone()
                if not original: response={'ok':False,'code':'BANK_RECORD_SCOPE'}
                else:
                    prior=json.loads(original['receipt'])
                    if prior['tenant']!=body['tenant']: response={'ok':False,'code':'BANK_RECORD_SCOPE'}
                    elif prior['amount_cents']!=body['expected_amount_cents']: response={'ok':False,'code':'BANK_AMOUNT_CHANGED'}
                    else: response=money(body,'ext-settlement',body['destination'],prior['amount_cents'],route)
            elif route == 'reversal':
                original=db.execute('SELECT receipt FROM transfers WHERE operation_id=?',(body['operation_ref'],)).fetchone()
                if not original: response={'ok':False,'code':'BANK_RECORD_SCOPE'}
                else:
                    prior=json.loads(original['receipt'])
                    if prior['tenant']!=body['tenant']: response={'ok':False,'code':'BANK_RECORD_SCOPE'}
                    elif prior['amount_cents']!=body['expected_amount_cents']: response={'ok':False,'code':'BANK_AMOUNT_CHANGED'}
                    else: response=money(body,prior['destination'],prior['source'],prior['amount_cents'],route)
            elif route == 'apply_fee':
                response=money(body,body['account'],'bank-fees',body['amount_cents'],route,
                               after=lambda: db.execute('INSERT INTO fees VALUES(?,?,?,?,?)',(next_id('f'),body['tenant'],body['account'],body['amount_cents'],'charged')))
            elif route == 'waive_fee':
                fee=row_status('fees',body['fee_id'],body['tenant'])
                if not fee or fee['status']!='charged': response={'ok':False,'code':'BANK_INVALID_STATE'}
                elif fee['amount_cents']!=body['expected_amount_cents']: response={'ok':False,'code':'BANK_AMOUNT_CHANGED'}
                else:
                    response=money(body,'bank-fees',fee['account'],fee['amount_cents'],route,
                                   after=lambda: db.execute("UPDATE fees SET status='waived' WHERE id=?",(body['fee_id'],)))
            # ---------------- payees ----------------
            elif route == 'add_payee':
                pid=next_id('p')
                with db: db.execute('INSERT INTO payees VALUES(?,?,?,?,0)',(pid,body['tenant'],body['name'],body['account_ref']))
                response={'ok':True,'payee_id':pid,'verified':False}
            elif route == 'verify_payee':
                row=row_status('payees',body['payee_id'],body['tenant'])
                if not row: response={'ok':False,'code':'BANK_RECORD_SCOPE'}
                else:
                    with db: db.execute('UPDATE payees SET verified=1 WHERE id=?',(body['payee_id'],))
                    response={'ok':True,'payee_id':body['payee_id'],'verified':True}
            elif route == 'update_payee':
                row=row_status('payees',body['payee_id'],body['tenant'])
                if not row: response={'ok':False,'code':'BANK_RECORD_SCOPE'}
                else:
                    with db: db.execute('UPDATE payees SET account_ref=?,verified=0 WHERE id=?',(body['account_ref'],body['payee_id']))
                    response={'ok':True,'payee_id':body['payee_id'],'account_ref':body['account_ref']}
            elif route == 'remove_payee':
                row=row_status('payees',body['payee_id'],body['tenant'])
                if not row: response={'ok':False,'code':'BANK_RECORD_SCOPE'}
                else:
                    with db: db.execute('DELETE FROM payees WHERE id=?',(body['payee_id'],))
                    response={'ok':True,'payee_id':body['payee_id']}
            # ---------------- cards ----------------
            elif route == 'issue_card':
                row=account(body['account'])
                if not owns(row,body['tenant']) or row['tenant']=='bank': response={'ok':False,'code':'BANK_ACCOUNT_SCOPE'}
                else:
                    cid=next_id('c')
                    with db: db.execute('INSERT INTO cards VALUES(?,?,?,?,?)',(cid,body['tenant'],body['account'],'inactive',0))
                    response={'ok':True,'card_id':cid,'status':'inactive'}
            elif route == 'activate_card':
                response=set_status('cards',body['card_id'],body['tenant'],'active',allowed=('inactive','frozen'))
            elif route == 'freeze_card':
                response=set_status('cards',body['card_id'],body['tenant'],'frozen',allowed=('active',))
            elif route == 'unfreeze_card':
                response=set_status('cards',body['card_id'],body['tenant'],'active',allowed=('frozen',))
            elif route == 'cancel_card':
                response=set_status('cards',body['card_id'],body['tenant'],'cancelled',allowed=('active','frozen','inactive'))
            elif route == 'report_lost':
                response=set_status('cards',body['card_id'],body['tenant'],'blocked',allowed=('active','frozen','inactive'))
            elif route == 'set_card_limit':
                row=row_status('cards',body['card_id'],body['tenant'])
                if not row: response={'ok':False,'code':'BANK_RECORD_SCOPE'}
                else:
                    with db: db.execute('UPDATE cards SET limit_cents=? WHERE id=?',(body['limit_cents'],body['card_id']))
                    response={'ok':True,'card_id':body['card_id'],'limit_cents':body['limit_cents']}
            elif route == 'change_pin':
                # No PIN value is ever accepted through this interface.
                row=row_status('cards',body['card_id'],body['tenant'])
                response={'ok':True,'card_id':body['card_id'],'pin_change':'initiated'} if row else {'ok':False,'code':'BANK_RECORD_SCOPE'}
            # ---------------- account lifecycle ----------------
            elif route == 'open_account':
                aid=next_id('acct')
                with db: db.execute('INSERT INTO accounts(id,tenant,balance,status,kind) VALUES(?,?,0,?,?)',(aid,body['tenant'],'active',body['kind']))
                response={'ok':True,'account':aid,'kind':body['kind']}
            elif route == 'close_account':
                row=account(body['account'])
                if not owns(row,body['tenant']) or row['tenant']=='bank': response={'ok':False,'code':'BANK_ACCOUNT_SCOPE'}
                elif row['balance']!=0: response={'ok':False,'code':'BANK_ACCOUNT_NOT_EMPTY'}
                else:
                    with db: db.execute("UPDATE accounts SET status='closed' WHERE id=?",(body['account'],))
                    response={'ok':True,'account':body['account'],'status':'closed'}
            elif route in ('freeze_account','unfreeze_account'):
                row=account(body['account'])
                target='frozen' if route=='freeze_account' else 'active'
                if not owns(row,body['tenant']) or row['tenant']=='bank': response={'ok':False,'code':'BANK_ACCOUNT_SCOPE'}
                elif row['status']=='closed': response={'ok':False,'code':'BANK_INVALID_STATE'}
                else:
                    with db: db.execute('UPDATE accounts SET status=? WHERE id=?',(target,body['account']))
                    response={'ok':True,'account':body['account'],'status':target}
            # ---------------- customer data ----------------
            elif route in ('update_email','update_phone','update_address'):
                column={'update_email':'email','update_phone':'phone','update_address':'address'}[route]
                value=body[column]
                query={
                    'email':'UPDATE customer SET email=? WHERE tenant=?',
                    'phone':'UPDATE customer SET phone=? WHERE tenant=?',
                    'address':'UPDATE customer SET address=? WHERE tenant=?',
                }[column]
                with db: db.execute(query,(value,body['tenant']))
                response={'ok':True,'field':column,'value':value}
            elif route == 'export_transactions':
                rows=db.execute('SELECT seq,delta,kind FROM ledger WHERE account=? ORDER BY seq DESC LIMIT ?',(body['account'],body['rows'])).fetchall()
                response={'ok':True,'exported_rows':len(rows),'rows':[dict(r) for r in rows]}
            elif route == 'export_customer_data':
                row=db.execute('SELECT * FROM customer WHERE tenant=?',(body['tenant'],)).fetchone()
                response={'ok':True,'exported':dict(row) if row else {}}
            elif route == 'share_statement':
                # Nothing is actually sent; the mock records the disclosure intent.
                response={'ok':True,'shared_with':body['destination_email'],'account':body['account'],'delivered':False}
            # ---------------- disputes ----------------
            elif route == 'open_dispute':
                did=next_id('d')
                with db: db.execute('INSERT INTO disputes VALUES(?,?,?,?)',(did,body['tenant'],body['transaction_ref'],'open'))
                response={'ok':True,'dispute_id':did}
            elif route == 'cancel_dispute':
                response=set_status('disputes',body['dispute_id'],body['tenant'],'cancelled',allowed=('open',))
            else: response={'ok':False,'code':'BANK_UNKNOWN_ROUTE'}
        except Exception:
            db.rollback();response={'ok':False,'code':'BANK_TRANSACTION_FAILED'}
        conn.send(response)
    db.close();conn.close()

class MockBank:
    def __init__(self, path, *, initial_cents=1_000_000, fail_before_commit=False):
        self.path=str(path);self._key=secrets.token_hex(32);self._lock=threading.Lock()
        self.drop_next_transfer_response=False
        context=multiprocessing.get_context('spawn')
        self._conn, child=context.Pipe()
        self._process=context.Process(target=bank_worker,args=(child,self.path,self._key,initial_cents,fail_before_commit))
        self._process.start();child.close()
        if not self._conn.poll(10): raise RuntimeError('bank startup timeout')
        if not self._conn.recv().get('ready'): raise RuntimeError('bank startup failed')
    def request(self, route, body=None, *, supplied_key=None):
        with self._lock:
            self._conn.send({'route':route,'body':body or {},'key':self._key if supplied_key is None else supplied_key})
            if not self._conn.poll(5): raise TimeoutError('mock bank timeout')
            response=self._conn.recv()
            if route=='transfer' and self.drop_next_transfer_response and response.get('ok'):
                self.drop_next_transfer_response=False
                raise TimeoutError('injected lost response after bank commit')
            return response
    def close(self):
        with self._lock:
            if self._process.is_alive(): self._conn.send({'stop':True,'key':self._key})
        self._process.join(5)
        if self._process.is_alive():self._process.terminate();self._process.join()
        self._conn.close()

class Controller:
    """Domain-specific reference controls built around Pramagent v0.8.9.

    Only submit() belongs on an agent-facing interface. configure()/approve()
    and the bank transport belong to trusted application code. Same-interpreter
    Python objects are NOT an OS isolation boundary.
    """
    def __init__(self, directory, bank, *, operator_token, clock=lambda:int(time.time())):
        self.root=Path(directory);self.root.mkdir(parents=True,exist_ok=True)
        self.bank=bank;self._operator_token=operator_token;self.clock=clock;self._lock=threading.RLock()
        self.available=True
        self.db=sqlite3.connect(self.root/'controller.sqlite',check_same_thread=False)
        self.db.row_factory=sqlite3.Row
        self.db.executescript('''
          PRAGMA journal_mode=WAL;
          CREATE TABLE IF NOT EXISTS tasks(id TEXT PRIMARY KEY,material TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS operations(id TEXT PRIMARY KEY,task_id TEXT NOT NULL,digest TEXT NOT NULL,request TEXT NOT NULL,revision INTEGER NOT NULL,state TEXT NOT NULL,charge INTEGER NOT NULL,approval INTEGER NOT NULL DEFAULT 0,reviewer TEXT,result TEXT);
          CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,operation_id TEXT,code TEXT NOT NULL,detail TEXT NOT NULL);
        ''')
        # Demo key derived from the test operator token; production key custody is out of scope.
        self.audit=SQLiteStore(str(self.root/'pramagent-audit.sqlite'),signing_key=hashlib.sha256(operator_token.encode()).hexdigest())
        # Registered from the declarative registry. FORBIDDEN operations are
        # deliberately absent, so ToolGuard rejects them as unregistered tools
        # before the controller's own forbidden check is reached.
        self.guard=ToolGuardLayer(policies=[
          ToolPolicy(op.name,op.schema,side_effect=op.side_effect) for op in OPERATIONS.values()])
        self.recover()
    def close(self):self.db.close();self.audit.close()
    def _operator(self, token):
        if type(token) is not str or not hmac.compare_digest(token,self._operator_token): raise PermissionError('operator authentication required')
    def configure(self, task, token):
        self._operator(token)
        with self._lock,self.db:
            existing=self.db.execute('SELECT material FROM tasks WHERE id=?',(task.task_id,)).fetchone()
            if existing and json.loads(existing[0])['revision']>=task.revision:raise ValueError('revision must advance')
            self.db.execute('INSERT OR REPLACE INTO tasks VALUES(?,?)',(task.task_id,canonical(asdict(task))))
    def _task(self, tid):
        row=self.db.execute('SELECT material FROM tasks WHERE id=?',(tid,)).fetchone()
        if not row:return None
        raw=json.loads(row[0])
        # JSON has no tuple type; restore every sequence field the dataclass requires.
        for field in Task._TUPLES:
            if field in raw: raw[field]=tuple(raw[field])
        return Task(**raw)
    def _prior_tools(self, tid):
        """Tools already dispatched under this task, for sequence rules."""
        rows=self.db.execute("SELECT request FROM operations WHERE task_id=? AND state IN ('completed','unknown','executing')",(tid,)).fetchall()
        return {json.loads(row[0])['tool'] for row in rows}
    def _event(self, oid, code, detail):
        self.db.execute('INSERT INTO events(operation_id,code,detail) VALUES(?,?,?)',(oid,code,canonical(detail)))
    def _deny(self, oid, code, **detail):
        out={'status':'denied','code':code,**detail}
        with self.db:self._event(oid,code,out)
        return out
    def _fingerprint(self, task, request):return digest({'task_id':task.task_id,'tenant':task.tenant,'revision':task.revision,'request':request})
    def _finish(self, oid, response):
        if response['ok']:
            # Carry the rest of the bank's reply through: a bank with many
            # operations returns new identifiers and read payloads, not only
            # transfer receipts.
            out={'status':'completed','code':'EXECUTED','receipt':response.get('receipt'),
                 'balance_cents':response.get('balance_cents'),
                 'result':{key:value for key,value in response.items()
                           if key not in ('ok','receipt','balance_cents','replayed')}}
            state='completed'
        else:out={'status':'failed','code':response['code']};state='failed'
        with self.db:
            self.db.execute('UPDATE operations SET state=?,result=? WHERE id=?',(state,canonical(out),oid))
            self._event(oid,out['code'],out)
        return out
    def submit(self, task_id, raw):
        # Only serialized/freshly detached request is used beyond this line.
        try:
            request=snapshot(raw)
            if type(request) is not dict or set(request)!={'operation_id','tool','arguments'}:raise ValueError('request fields')
            oid=request['operation_id']
            if type(oid) is not str or not oid or len(oid)>80:raise ValueError('operation id')
            if type(request['tool']) is not str or type(request['arguments']) is not dict:raise ValueError('tool arguments')
        except (ValueError,TypeError,RecursionError):return {'status':'denied','code':'INVALID_REQUEST'}
        with self._lock:
            if not self.available:return self._deny(oid,'CONTROLLER_UNAVAILABLE')
            task=self._task(task_id)
            if not task:return self._deny(oid,'UNKNOWN_TASK')
            existing=self.db.execute('SELECT * FROM operations WHERE id=?',(oid,)).fetchone()
            if existing:
                if existing['task_id']!=task_id or existing['request']!=canonical(request):return self._deny(oid,'IDEMPOTENCY_CONFLICT')
                if existing['state']=='completed':return {**json.loads(existing['result']),'replayed':True}
                if existing['state']=='unknown':
                    # Reconcile already submitted work; never dispatch a new transfer here.
                    try:found=self.bank.request('lookup',{'operation_id':oid})
                    except (TimeoutError,EOFError,OSError):return {'status':'unknown','code':'OUTCOME_UNKNOWN'}
                    if found['ok'] and found['receipt']:return self._finish(oid,{'ok':True,'receipt':found['receipt']})
                    return {'status':'unknown','code':'MANUAL_RECONCILIATION_REQUIRED'}
                if existing['state']=='failed':return json.loads(existing['result'])
            if not task.active:return self._deny(oid,'TASK_REVOKED')
            if self.clock()>=task.expires_at:return self._deny(oid,'TASK_EXPIRED')
            if existing and existing['revision']!=task.revision:return self._deny(oid,'POLICY_CHANGED')
            args=request['arguments'];tool=request['tool']
            decision=self.guard.evaluate(tool,args,tenant_id=task.tenant,session_id=task.task_id,action_label='bank_demo')
            if decision.verdict==Verdict.BLOCK:return self._deny(oid,'PRAMAGENT_BLOCK',reason=decision.reason)
            # Defence in depth: forbidden operations are already unregistered with
            # ToolGuard, but the controller refuses them even if something
            # registers one. No task grant and no approval can reach past this.
            if tool in FORBIDDEN:return self._deny(oid,'FORBIDDEN_OPERATION')
            operation=OPERATIONS.get(tool)
            if operation is None:return self._deny(oid,'UNKNOWN_TOOL')
            if not task.permits(tool):return self._deny(oid,'OUTSIDE_TASK_SCOPE')
            try:
                scope_error=operation.scope(task,args)
            except (KeyError,TypeError):return self._deny(oid,'INVALID_AMOUNT_OR_FIELDS')
            if scope_error:return self._deny(oid,scope_error)
            if tool=='bank.schedule_transfer' and args['execute_at']>self.clock()+task.max_schedule_horizon:
                return self._deny(oid,'SCHEDULE_HORIZON_EXCEEDED')
            # Sequence rules. Each step can be individually permitted while the
            # sequence is not; prior steps are read from this task's durable log.
            chain=chain_violation(self._prior_tools(task_id)-{tool},tool)
            if chain and chain.action=='deny':return self._deny(oid,chain.code,note=chain.note)
            try:
                charge=operation.charge(args)
            except (KeyError,TypeError):return self._deny(oid,'INVALID_AMOUNT_OR_FIELDS')
            summary=summarize(request);fingerprint=self._fingerprint(task,request)
            requires_approval=(charge>task.approval_above_cents or decision.verdict==Verdict.ESCALATE
                               or operation.approval_always or bool(chain))
            approved=existing is not None and bool(existing['approval']) and existing['digest']==fingerprint
            if requires_approval and not approved:
                with self.db:
                    self.db.execute('INSERT OR IGNORE INTO operations(id,task_id,digest,request,revision,state,charge) VALUES(?,?,?,?,?,?,?)',(oid,task_id,fingerprint,canonical(request),task.revision,'awaiting_approval',charge))
                    self._event(oid,'APPROVAL_REQUIRED',{'summary':summary,'digest':fingerprint})
                return {'status':'awaiting_approval','code':'APPROVAL_REQUIRED','summary':summary,'digest':fingerprint,'pramagent_verdict':decision.verdict.value}
            try:
                self.db.execute('BEGIN IMMEDIATE')
                # Reserve and count completed + uncertain operations together.
                used=self.db.execute("SELECT COALESCE(SUM(charge),0) FROM operations WHERE task_id=? AND state IN ('executing','unknown','completed')",(task_id,)).fetchone()[0]
                if used+charge>task.total_cents:
                    self.db.rollback();return self._deny(oid,'TASK_BUDGET_EXCEEDED')
                if existing:
                    self.db.execute("UPDATE operations SET state='executing' WHERE id=?",(oid,))
                else:
                    self.db.execute('INSERT INTO operations(id,task_id,digest,request,revision,state,charge) VALUES(?,?,?,?,?,?,?)',(oid,task_id,fingerprint,canonical(request),task.revision,'executing',charge))
                self._event(oid,'DISPATCH_INTENT',{'summary':summary,'digest':fingerprint,'pramagent_verdict':decision.verdict.value})
                self.db.commit()
                self.audit.append({'operation_id':oid,'task_id':task_id,'tenant_id':task.tenant,'digest':fingerprint,'decision':decision.verdict.value,'summary':summary})
            except Exception:
                self.db.rollback()
                with self.db:self.db.execute("UPDATE operations SET state='failed',result=? WHERE id=?",(canonical({'status':'failed','code':'PERSISTENCE_UNAVAILABLE'}),oid))
                return {'status':'failed','code':'PERSISTENCE_UNAVAILABLE'}
            trusted_scope={
                'accounts':list(readable(task)),
                'payees':list(task.allowed_payees),
                'cards':list(task.allowed_cards),
                'loans':list(task.allowed_loans),
                'holds':list(task.allowed_holds),
                'scheduled':list(task.allowed_scheduled),
                'disputes':list(task.allowed_disputes),
                'fees':list(task.allowed_fees),
                'operation_refs':list(task.allowed_operation_refs),
            }
            try:response=self.bank.request(operation.route,{**args,'tenant':task.tenant,'operation_id':oid,'_scope':trusted_scope})
            except (TimeoutError,EOFError,OSError):
                with self.db:
                    self.db.execute("UPDATE operations SET state='unknown' WHERE id=?",(oid,));self._event(oid,'OUTCOME_UNKNOWN',{})
                return {'status':'unknown','code':'OUTCOME_UNKNOWN','summary':summary}
            out=self._finish(oid,response);out['summary']=summary;out['pramagent_verdict']=decision.verdict.value
            return out
    def approve(self, operation_id, expected_digest, *, reviewer, token):
        self._operator(token)
        if type(reviewer) is not str or not reviewer.strip():raise ValueError('reviewer required')
        with self._lock:
            row=self.db.execute('SELECT * FROM operations WHERE id=?',(operation_id,)).fetchone()
            if not row or row['state']!='awaiting_approval':return self._deny(operation_id,'NO_PENDING_APPROVAL')
            task=self._task(row['task_id'])
            if not task or not task.active:return self._deny(operation_id,'TASK_REVOKED')
            if task.revision!=row['revision']:return self._deny(operation_id,'POLICY_CHANGED')
            if self.clock()>=task.expires_at:return self._deny(operation_id,'TASK_EXPIRED')
            if not hmac.compare_digest(str(expected_digest),row['digest']):return self._deny(operation_id,'APPROVAL_MISMATCH')
            with self.db:
                self.db.execute('UPDATE operations SET approval=1,reviewer=? WHERE id=?',(reviewer,operation_id))
                self._event(operation_id,'HUMAN_APPROVED',{'reviewer':reviewer,'digest':expected_digest})
            return self.submit(row['task_id'],json.loads(row['request']))
    def recover(self):
        # After controller restart, dispatch may have happened. Preserve charge.
        with self._lock,self.db:self.db.execute("UPDATE operations SET state='unknown' WHERE state='executing'")
