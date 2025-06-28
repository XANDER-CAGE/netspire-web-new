# -*- coding: utf-8 -*-

from __future__ import division

import collections
import datetime
import functools
import hashlib
import json
import memcache
import psycopg2
import re
import time
import uuid
from decimal import Decimal
from tornado.options import options

from model import *
from utils import datetime_utc_to_local, datetime_local_to_utc

__all__ = []

mc = memcache.Client(['127.0.0.1:11211'], debug=0)

SESSION_LIFETIME = 600


def set_session_maker(s):
    global session_maker
    session_maker = s


def authenticate(email, password):
    global session_maker
    db = session_maker()
    admin_id = None
    try:
        accounts = db.query(Admin).filter_by(email=email, active=True).all()
        if len(accounts) != 1:
            return None, False
        admin = accounts[0]
        if check_passwords(password, admin.password):
            session_id = str(uuid.uuid4())
            mc.set(session_id, str(email))
            mc.set(session_id + '_lft', int(time.time() + SESSION_LIFETIME))
            admin_id = admin.id
        else:
            return None, None, False
    finally:
        db.commit()
        db.close()
    return session_id, admin_id, True


def fetch_update_session(session_id, update=False):
    email = mc.get(session_id)
    if email is None:
        return None, False
    valid_until = mc.get(session_id + '_lft')
    if valid_until is None:
        mc.delete(session_id)
        return None, False
    now = int(time.time())
    if now < valid_until:
        if update:
            mc.set(session_id + '_lft', now + SESSION_LIFETIME)
        return email, True
    mc.delete(session_id + '_lft')
    mc.delete(session_id)
    return None, False


def logout(session_id):
    mc.delete(session_id)


def balance_at(session_id, contract_id, balance_at):
    email, ok = fetch_update_session(session_id)
    global session_maker
    db = session_maker()
    balance_at = datetime_local_to_utc(balance_at)
    balance = 0
    try:
        f = db.query(FinTransaction).filter_by(contract_id=contract_id)
        f = f.filter(FinTransaction.created_at <= balance_at)
        f = f.order_by(FinTransaction.created_at.desc())
        f = f.first()
        if f is not None:
            balance = f.balance_after
    except:
        db.rollback()
        db.close()
        raise
    db.commit()
    db.close()
    return balance


def debt_by_days(session_id, currency_id, year, month):
    email, ok = fetch_update_session(session_id)
    if not ok:
        return None
    global session_maker
    db = session_maker()
    start = datetime.datetime(year, month, 1, 0, 0, 0)
    if month == 12:
        range_end = datetime.datetime(year + 1, 1, 1, 0, 0, 0)
    else:
        range_end = datetime.datetime(year, month + 1, 1, 0, 0, 0)
    range_start = datetime_local_to_utc(start)
    range_end = datetime_local_to_utc(range_end)
    try:
        f = db.query(FinTransaction)
        f = f.filter(FinTransaction.created_at >= range_start)
        f = f.filter(FinTransaction.created_at < range_end)
        f = f.order_by(FinTransaction.created_at)
        f = f.all()
        c = db.query(Contract)
        c = c.filter_by(state='open').filter_by(currency_id=currency_id)
        c = c.all()
        return _debt_by_days(db, f, c, start, range_start, range_end)
    except:
        db.rollback()
        db.close()
        raise
    db.commit()
    db.close()
    return balance


def monthly_fees_sum(contract_id):
    db = None
    s = 0
    try:
        m = mc.get('monthly_fees_' + str(contract_id))
        if m is None:
            if db is None:
                db = session_maker()
            c = db.query(Contract).filter_by(id=contract_id).one()
            for a in c.accounts:
                if a.state != 'closed':
                    settings = json.loads(a.plan.settings)
                    s += settings['MONTHLY_FEE']
            mc.set('monthly_fees_' + str(contract_id), float(s), 24 * 3600)
        else:
            s = m
    except:
        if db is not None:
            db.rollback()
            db.close()
        raise
    if db is not None:
        db.commit()
        db.close()
    return s

def db_connection():
    return psycopg2.connect(database=options.db_name, user=options.db_user,
                            password=options.db_password, host=options.db_host)


def list_invoices(contract_id):
    conn = db_connection()
    try:
        c = conn.cursor()
        c.execute("""
SELECT year, month, invoice_id, approved, created_at
FROM invoices
WHERE contract_id = %(contract_id)s
ORDER BY year, month""",
                  locals())
        invoices = []
        while True:
            row = c.fetchone()
            if row is None:
                break
            invoices.append(dict(contract_id=contract_id,
                                 year=row[0],
                                 month=row[1],
                                 invoice_id=row[2],
                                 approved=row[3],
                                 created_at=row[4]))
        return invoices
    finally:
        conn.rollback()
        conn.close()


def fetch_invoice(contract_id, year, month):
    conn = db_connection()
    try:
        c = conn.cursor()
        c.execute("""
SELECT id, contract_id, year, month, invoice_id, approved, data_yaml, created_at
FROM invoices
WHERE contract_id = %(contract_id)s AND year = %(year)s AND month = %(month)s""",
                  locals())
        row = c.fetchone()
        if row is None:
            return None
        return dict(id=row[0],
                    contract_id=row[1],
                    year=row[2],
                    month=row[3],
                    invoice_id=row[4],
                    approved=row[5],
                    data_yaml=row[6],
                    created_at=row[7])
    finally:
        conn.rollback()
        conn.close()


def log_logon(admin_id, when, where):
    conn = db_connection()
    ok = False
    try:
        c = conn.cursor()
        c.execute("""
INSERT INTO logons (admin_id, logged_in_at, ip)
VALUES (%(admin_id)s, %(when)s, %(where)s)""",
                  locals())
        ok = True
    finally:
        if ok:
            conn.commit()
        else:
            conn.rollback()
        conn.close()


def fetch_logons(start, end):
    conn = db_connection()
    ok = False
    try:
        c = conn.cursor()
        c.execute("""
SELECT admin_id, logged_in_at, ip
FROM logons
WHERE logged_in_at >= %(start)s AND logged_in_at < %(end)s
ORDER BY logged_in_at""",
                  locals())
        result = []
        while True:
            row = c.fetchone()
            if row is None:
                break
            result.append(
                dict(admin_id=row[0], logged_in_at=row[1], ip=row[2]))
        return result
    finally:
        conn.rollback()
        conn.close()


def fetch_ods_invoice(contract_id, year, month):
    conn = db_connection()
    try:
        c = conn.cursor()
        c.execute("""
SELECT ods
FROM invoices
WHERE contract_id = %(contract_id)s AND year = %(year)s AND month = %(month)s""",
                  locals())
        row = c.fetchone()
        if row is None:
            return None
        return row[0]
    finally:
        conn.rollback()
        conn.close()


ip_re = re.compile('^\d+\.\d+\.\d+\.\d+$')
date_local_re = re.compile('^\d+-\d+-\d+ \d+:\d+:\d+$')
date_utc_re = re.compile('^\d+-\d+-\d+T\d+:\d+:\d+Z$')


def find_session(ip, when):
    if ip_re.search(ip) is None:
        return None
    if ip_to_int(ip) is None:
        return None
    if date_local_re.search(when) is not None:
        t = datetime.datetime.strptime(when, "%Y-%m-%d %H:%M:%S")
        t = datetime_local_to_utc(t)
    elif date_utc_re.search(when) is not None:
        t = datetime.datetime.strptime(when, "%Y-%m-%dT%H:%M:%SZ")
    else:
        return None
    conn = db_connection()
    result = dict(ip=ip, time=datetime_utc_to_local(
        t), session=None, account=None, contract=None)
    try:
        c = conn.cursor()
        c.execute("""
SELECT account_id, started_at, finished_at
FROM iptraffic_sessions
WHERE ip=%(ip)s AND started_at<=%(when)s AND (%(when)s <= finished_at OR finished_at IS NULL)""",
                  dict(ip=ip, when=t))
        row = c.fetchone()
        if row is None:
            return result
        result['session'] = dict(started_at=datetime_utc_to_local(row[1]))
        if row[2] is not None:
            result['session']['finished_at'] = datetime_utc_to_local(row[2])
        else:
            result['session']['finished_at'] = None
        c.execute("SELECT contract_id, login FROM accounts WHERE id=%(account_id)s", dict(
            account_id=row[0]))
        row = c.fetchone()
        result['contract'] = []
        result['contract'].append(('Contract no', row[0]))
        result['account'] = row[1]
        c.execute("""
SELECT cii.field_name, ci.info_value
FROM contracts c, contract_info ci, contract_info_items cii
WHERE c.id=%(id)s AND c.id=ci.contract_id AND c.kind_id=ci.kind_id
    AND ci.info_id=cii.id AND ci.kind_id=cii.kind_id
ORDER by cii.sort_order""",
                  dict(id=row[0]))
        while True:
            row = c.fetchone()
            if row is None:
                break
            result['contract'].append((row[0], row[1]))
    finally:
        conn.rollback()
        conn.close()
    return result

# internal functions


def check_passwords(password, hashed):
    salt = hashed[0: 2]
    h = hashlib.sha1()
    h.update(salt)
    h.update(password)
    return h.hexdigest() == hashed[2:]


def _debt_by_days(db, transactions, contracts, start_local, utc_start, utc_end):
    txs = {}
    # group transactions per contract
    for t in transactions:
        try:
            txs[t.contract_id].append(t)
        except KeyError:
            txs[t.contract_id] = [t]

    # find starting balance for each contract having txs for period
    missing_txs = []
    id2contract = {}
    starting_balance = {}
    for c in contracts:
        id2contract[c.id] = c
        if c.id not in txs:
            missing_txs.append(c.id)
            txs[c.id] = []
        else:
            starting_balance[c.id] = txs[c.id][0].balance_after - \
                txs[c.id][0].amount_in_contract_currency

    # find starting (constant) balance for contracts missing any txs
    for contract_id in missing_txs:
        f = db.query(FinTransaction)
        f = f.filter_by(contract_id=contract_id)
        f = f.filter(FinTransaction.created_at >= utc_end)
        f = f.order_by(FinTransaction.created_at)
        f = f.first()
        if f is None:
            starting_balance[contract_id] = id2contract[contract_id].balance
        else:
            starting_balance[contract_id] = f.balance_after - \
                f.amount_in_contract_currency

    # initialize debts by day to be zero
    by_day = []
    current = start_local
    total_days = 0
    while datetime_local_to_utc(current) < utc_end:
        by_day.append([current, 0])
        current = current + datetime.timedelta(1)
        total_days += 1

    for c in contracts:
        current = start_local
        i = 0
        j = 0
        while i < total_days:
            if starting_balance[c.id] < 0:
                by_day[i][1] += starting_balance[c.id]
            next_day = current + datetime.timedelta(1)
            n = datetime_local_to_utc(next_day)
            i += 1
            while j < len(txs[c.id]) and txs[c.id][j].created_at < n:
                starting_balance[c.id] = txs[c.id][j].balance_after
                j += 1
            current = next_day
    by_day = map(lambda x: (x[0], -x[1]), by_day)
    return by_day


def ip_to_int(ip):
    parts = ip.split('.')
    n = 0
    for part in parts:
        p = int(part)
        if p > 255:
            return None
        n = n * 256 + p
    return n


def recalculateFinHistory(contract_id):
    conn = db_connection()
    ok = False
    try:
        c = conn.cursor()
        c.execute("""
UPDATE fin_transactions f1
SET balance_after = (SELECT SUM(amount) FROM fin_transactions f2
                     WHERE f2.contract_id=f1.contract_id AND f2.created_at<=f1.created_at)
WHERE contract_id=%(contract_id)s
""", locals())
        c.execute("""
UPDATE contracts
SET balance=COALESCE((SELECT SUM(amount_in_contract_currency) FROM fin_transactions WHERE contract_id=contracts.id), 0)
WHERE id=%(contract_id)s
""", locals())
        conn.commit()
        ok = True
    finally:
        if not ok:
            conn.rollback()
        conn.close()


def contract_managers(contract_id):
    ids = mc.get('contract_manager_c{}'.format(contract_id))
    if ids is not None:
        return ids
    ids = []
    conn = db_connection()
    try:
        c = conn.cursor()
        c.execute("""
SELECT manager_id
FROM contract_manager
WHERE contract_id=%(contract_id)s
""", locals())
        while True:
            row = c.fetchone()
            if row is None:
                break
            ids.append(row[0])
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    mc.set('contract_manager_c{}'.format(contract_id), ids, 60)
    return ids


def debits_for_period(starting_from, ending_at, currency_id, kind_id):
    conn = db_connection()
    totals = collections.defaultdict(functools.partial(collections.defaultdict,
                                                       Decimal))
    unknowns = collections.defaultdict(list)
    ABON = 'abon'
    OVERLIMIT = 'overlimit'
    CONNECT = 'connect'
    UNKNOWN = 'unknown'
    try:
        c = conn.cursor()
        if kind_id is not None:
            c.execute("""
            SELECT id, kind_id, contract_id, amount, comment
            FROM fin_transactions
            WHERE created_at >= %(starting_from)s AND created_at < %(ending_at)s
               AND kind_id = %(kind_id)s AND currency_id = %(currency_id)s AND amount < 0
    """, locals())
        else:
            c.execute("""
            SELECT id, contract_id, amount, comment
            FROM fin_transactions
            WHERE created_at >= %(starting_from)s AND created_at < %(ending_at)s
                AND currency_id = %(currency_id)s AND amount < 0
            """, locals())
        while True:
            row = c.fetchone()
            if row is None:
                break
            if kind_id is not None:
                fin_id, kind_id, cid, amount, comment = row
            else:
                fin_id, cid, amount, comment = row
            if comment.startswith('абонентская') or 'списание а/п' in comment:
                totals[cid][ABON] += amount
            elif comment.startswith('session '):
                totals[cid][OVERLIMIT] += amount
            elif 'за подключ' in comment or 'списание подключ' in comment:
                totals[cid][CONNECT] += amount
            else:
                totals[cid][UNKNOWN] += amount
                unknowns[cid].append(fin_id)
    except Exception:
        conn.rollback()
        raise
    else:
        conn.commit()
    return totals, unknowns
