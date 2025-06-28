from __future__ import division

import json
import memcache
import time
import uuid

from model import *
from utils import datetime_utc_to_local

__all__ = []

mc = memcache.Client(['127.0.0.1:11211'], debug=0)

SESSION_LIFETIME = 600


def set_session_maker(s):
    global session_maker
    session_maker = s


def authenticate(login, password):
    global session_maker
    db = session_maker()
    try:
        accounts = db.query(Account).filter_by(
            login=login).filter_by(password=password).all()
        if len(accounts) != 1:
            return None, False
        session_id = str(uuid.uuid4())
        mc.set(session_id, login)
        mc.set(session_id + '_lft', int(time.time() + SESSION_LIFETIME))
    finally:
        db.commit()
        db.close()
    return session_id, True


def fetch_update_session(session_id, update=False):
    login = mc.get(session_id)
    if login is None:
        return None, False
    valid_until = mc.get(session_id + '_lft')
    if valid_until is None:
        mc.delete(session_id)
        return None, False
    now = int(time.time())
    if now < valid_until:
        if update:
            mc.set(session_id + '_lft', now + SESSION_LIFETIME)
        return login, True
    mc.delete(session_id + '_lft')
    mc.delete(session_id)
    return None, False


def name(session_id):
    global session_maker
    login, ok = fetch_update_session(session_id)
    if not ok:
        return None, False
    db = session_maker()
    try:
        account = db.query(Account).filter_by(login=login).one()
        return account.contract.key_field.info_value, True
    finally:
        db.commit()
        db.close()
    return None, False


def overview(session_id):
    login, ok = fetch_update_session(session_id, update=True)
    if not ok:
        return None, False
    global session_maker
    db = session_maker()
    i = {'session': {}}
    try:
        account = db.query(Account).filter_by(login=login).one()
        i['balance'] = '{:.1f}'.format(account.contract.balance)
        i['contract_id'] = account.contract_id
        i['contract_type'] = account.contract.kind.kind_name
        online = (db.query(TrafficSession)
                  .filter_by(finished_at=None)
                  .filter_by(account_id=account.id)
                  .all())
        if len(online) == 0:
            i['session']['ip'] = None
        else:
            online = online[0]
            i['session']['traffic'] = online.octets_in, online.octets_out
            i['session']['ip'] = online.ip
        i['traffic_limits'] = traffic_limits(account)
        return i
    finally:
        db.commit()
        db.close()
    return None, False


def traffic_limits(account):
    settings = json.loads(account.plan.settings)
    data = json.loads(account.plan_data)
    if settings['PREPAID'] > 0:
        return {'remainder': data['PREPAID'], 'total': settings['PREPAID']}
    return None


def transactions(session_id, from_moment, till_moment, kind):
    login, ok = fetch_update_session(session_id, update=True)
    if not ok:
        return None, False
    global session_maker
    db = session_maker()
    r = []
    try:
        account = db.query(Account).filter_by(login=login).one()
        q = db.query(FinTransaction).filter_by(contract_id=account.contract_id)
        q = q.filter(FinTransaction.created_at >= from_moment)
        q = q.filter(FinTransaction.created_at <= till_moment)
        if kind == 'credit':
            q = q.filter(FinTransaction.amount < 0)
        elif kind == 'debit':
            q = q.filter(FinTransaction.amount > 0)
        q = q.order_by(FinTransaction.created_at)
        for item in q.all():
            r.append({'created_at': str(datetime_utc_to_local(item.created_at)),
                      'amount': item.amount,
                      'amount_in_contract_currency': item.amount_in_contract_currency,
                      'balance_after': item.balance_after,
                      'comment': item.comment})
        return r, True
    finally:
        db.commit()
        db.close()
    return None, False


def sessions(session_id, from_moment, till_moment):
    login, ok = fetch_update_session(session_id, update=True)
    if not ok:
        return None, False
    db = session_maker()
    r = []
    try:
        account = db.query(Account).filter_by(login=login).one()
        q = db.query(TrafficSession).filter_by(account_id=account.id)
        q = q.filter(TrafficSession.started_at >= from_moment)
        q = q.filter(TrafficSession.finished_at <= till_moment)
        q = q.order_by(TrafficSession.started_at)
        for s in q.all():
            item = dict(started_at=str(datetime_utc_to_local(s.started_at)),
                        finished_at=str(datetime_utc_to_local(s.finished_at)),
                        ip=s.ip,
                        octets_in=s.octets_in,
                        octets_out=s.octets_out,
                        amount='{:.6f}'.format(s.amount),
                        details={})
            for d in db.query(SessionDetail).filter_by(id=s.id):
                item['details'][d.traffic_class] = d.octets_in, d.octets_out
            r.append(item)
        return r, True
    finally:
        db.commit()
        db.close()
    return None, False


def change_password(session_id, old_pass, new_pass):
    login, ok = fetch_update_session(session_id, update=True)
    if not ok:
        return False
    db = session_maker()
    try:
        account = db.query(Account).filter_by(login=login).one()
        if account.password == old_pass:
            account.password = new_pass
            return True
        return False
    finally:
        db.commit()
        db.close()
    return False
