# -*- coding: utf-8 -*-

from __future__ import division

import datetime
import hashlib
import json
import re
import urllib
import time

import tornado.httpclient
from tornado.options import options

from model import *
from utils import datetime_utc_to_local, string_to_utc_datetime
import adminapi

__all__ = [
    'ContractSearcher',
    'create_new_account',
    'FinancialOperation',
    'get_online_sessions',
    'is_acceptable_account_password',
    'kick_session',
    'get_mac_address_by_ip',
    'get_online_sessions_with_mac',
    'connect_log_entries'
]

ACCOUNT_RE = re.compile('^[a-z0-9][a-z0-9-]*[a-z0-9]$')


class FinancialOperation(object):
    def __init__(self, session, contract, created_at=None):
        self.session = session
        self.contract = contract
        self.created_at = created_at

    def _make_operation(self, amount, comment, currency, admin):
        if currency.id != self.contract.currency.id:
            r = (self.session.query(CurrencyRate)
                 .filter_by(from_id=currency.id,
                            to_id=self.contract.currency.id)
                 .all())
            if len(r) != 1:
                r = (self.session.query(CurrencyRate)
                     .filter_by(from_id=self.contract.currency.id,
                                to_id=currency.id)
                     .all())
            if len(r) != 1:
                raise Exception('Cannot convert between currencies')
            r = r[0]
            if r.from_id == currency.id:
                true_amount = amount * r.rate
            else:
                true_amount = amount / r.rate
        else:
            true_amount = amount
        q = self.session.query(Contract).filter_by(id=self.contract.id)
        q.update({Contract.balance: Contract.balance + true_amount})
        new_balance = (self.session.query(Contract)
                       .filter_by(id=self.contract.id)
                       .one().balance)
        if self.created_at is None:
            operation = FinTransaction(kind_id=self.contract.kind_id,
                                       contract_id=self.contract.id,
                                       currency_id=currency.id,
                                       amount=amount,
                                       amount_in_contract_currency=true_amount,
                                       balance_after=new_balance,
                                       comment=comment,
                                       admin_id=admin.id)
        else:
            older = self.session.query(FinTransaction)
            older = older.filter_by(kind_id=self.contract.kind_id,
                                    contract_id=self.contract.id)
            older = older.filter(FinTransaction.created_at >= self.created_at)
            for each in older:
                each.balance_after += true_amount
            previous = self.session.query(FinTransaction)
            previous = previous.filter_by(kind_id=self.contract.kind_id,
                                          contract_id=self.contract.id)
            previous = previous.filter(
                FinTransaction.created_at < self.created_at)
            previous = previous.order_by(FinTransaction.created_at.desc())
            previous = previous.first()
            if previous == None:
                new_balance = true_amount
            else:
                new_balance = previous.balance_after + true_amount
            operation = FinTransaction(kind_id=self.contract.kind_id,
                                       contract_id=self.contract.id,
                                       currency_id=currency.id,
                                       amount=amount,
                                       amount_in_contract_currency=true_amount,
                                       balance_after=new_balance,
                                       created_at=self.created_at,
                                       comment=comment,
                                       admin_id=admin.id)
        self.session.add(operation)

    def credit(self, amount, comment, currency, admin):
        if amount == 0:
            return
        if amount < 0:
            raise Exception('Cannot perform negative credits')
        self._make_operation(amount, comment, currency, admin)

    def debit(self, amount, comment, currency, admin):
        if amount == 0:
            return
        if amount < 0:
            raise Exception('Cannot perform negative debits')
        if self.contract.currency.id != currency.id:
            raise Exception("Debits can be made only in contract's currency")
        self._make_operation(-amount, comment, currency, admin)


class ContractSearcher(object):
    def __init__(self, session, admin):
        self.session = session
        self.admin = admin

    def search(self, query, kind_id, state):
        if len(query) == 0:
            return {}
        r = dict(number=[], name=[], account=[])
        if self.looks_like_number(query):
            r['number'] = self.search_by_number(query, kind_id, state)
        if self.looks_like_account(query):
            r['account'] = self.search_by_account(query, kind_id, state)
        r['name'] = self.search_by_name(query, kind_id, state)
        return r

    def search_by_number(self, q, kind_id, state):
        r = self.session.query(Contract).filter_by(id=q)
        if state != 'any':
            r = r.filter_by(state=state)
        if kind_id != -1:
            r = r.filter_by(kind_id=kind_id)
        if self.admin.has_role('manager'):
            r = [c for c in r
                 if self.admin.id in adminapi.contract_managers(c.id)]
        return r

    def search_by_account(self, q, kind_id, state):
        accounts = self.session.query(Account).filter_by(login=q).all()
        if self.admin.has_role('manager'):
            r = [a.contract for a in accounts
                 if self.admin.id in adminapi.contract_managers(a.contract.id)]
        else:
            r = [a.contract for a in accounts]
        if state != 'any':
            r = [c for c in r if c.state == state]
        if kind_id != -1:
            r = [c for c in r if c.kind_id == kind_id]
        return r

    def search_by_name(self, q, kind_id, state):
        r = []
        for kind in self.session.query(ContractKind).all():
            if kind_id != -1 and kind.id != kind_id:
                continue
            key_id = kind.fields[0].id
            infos = (self.session.query(ContractInfo)
                     .filter_by(kind_id=kind.id,
                                info_id=key_id)
                     .filter(ContractInfo.info_value.ilike('%' + q + '%')).all())
            if self.admin.has_role('manager'):
                r.extend([i.contract
                          for i in infos
                          if self.admin.id in
                          adminapi.contract_managers(i.contract.id)])
            else:
                r.extend([i.contract for i in infos])
        if state != 'any':
            return [c for c in r if c.state == state]
        return r

    def looks_like_number(self, q):
        for c in q:
            if c not in '0123456789':
                return False
        return True

    def looks_like_account(self, q):
        m = ACCOUNT_RE.search(q)
        return m is not None

    def all(self, kind_id, state):
        r = dict(name=[], account=[])
        contracts = self.session.query(Contract)
        if kind_id != -1:
            contracts = contracts.filter_by(kind_id=kind_id)
        if state != 'any':
            contracts = contracts.filter_by(state=state)
        contracts = contracts.order_by(Contract.id)
        if self.admin.has_role('manager'):
            contracts = [c for c in contracts
                         if self.admin.id in adminapi.contract_managers(c.id)]
        r['number'] = contracts
        return r


def create_new_account(session, contract, login, password, plan):
    m = ACCOUNT_RE.search(login)
    if m is None:
        return 'Логин может содержать только буквы a-z, цифры 0-9, и знак дефиса'
    acceptable_password, error_message = is_acceptable_account_password(
        password)
    if not acceptable_password:
        return error_message
    account = Account(login=login, password=password, active=False,
                      plan_data='')
    account.plan = plan
    account.plan_data = plan.settings
    account.new_plan_id = plan.id
    contract.accounts.append(account)
    return None


def get_online_sessions(session):
    return (session.query(TrafficSession, Account, Contract)
            .filter(TrafficSession.finished_at == None)
            .filter(TrafficSession.account_id == Account.id)
            .filter(Account.contract_id == Contract.id)
            .order_by(TrafficSession.started_at).all())


def create_kick_request(nas_url, ip):
    args = urllib.urlencode({'ip_address': ip})
    return tornado.httpclient.HTTPRequest(nas_url + 'kick',
                                          method="POST",
                                          body=args)


def kick_session(ip):
    kicked = False
    for nas_url in options.nas.split('|'):
        http_client = tornado.httpclient.HTTPClient()
        kick_request = create_kick_request(nas_url, ip)
        response = http_client.fetch(kick_request)
        kicked = kicked or response.code == 200
    return kicked


def is_acceptable_account_password(password):
    if len(password) < 8:
        return False, 'Пароль должен содержать не менее 8 символов'
    return True, ''


denied_re = re.compile('^User (.*) is denied access for reason \((.*)\),')
denied_unk_re = re.compile('^User (.*) is denied access for unknown reason')
denied_session_re = re.compile(
    '^Can not initialize session for user (.*) due to (.*)$')
success_re = re.compile('^PAP authentication succeeded: "(.*)"$')
password_re = re.compile('^PAP authentication failed: "(.*)"$')


def connect_log_entries(log_path, s):
    def denied_for_a_reason(current_date, login, reason):
        return current_date, login, False, reason

    def denied_for_unknown_reason(current_date, login):
        return current_date, login, False, 'unknown'

    def denied_session(current_date, login, reason):
        return current_date, login, False, reason

    def authorized(current_date, login):
        return current_date, login, True, ''

    def password_failed(current_date, login):
        return current_date, login, False, 'password'
    log_file = open(log_path, 'rb')
    log_file.seek(0, 2)
    log_file.seek(-min(log_file.tell(), 1000000), 2)
    last_data = log_file.read()
    lines = last_data.split('\n')[1:]
    converted = []
    i = 0
    current_date = None
    log_converters = [(denied_re, denied_for_a_reason),
                      (denied_unk_re, denied_for_unknown_reason),
                      (denied_session_re, denied_session),
                      (success_re, authorized),
                      (password_re, password_failed)]
    while i < len(lines):
        if lines[i].startswith('=INFO REPORT='):
            current_date = lines[i][17:38].replace('::', ' ')
            i += 1
            continue
        for regexp, converter in log_converters:
            m = regexp.search(lines[i])
            if m:
                converted.append(converter(current_date, *m.groups()))
                break
        i += 1
    converted.reverse()
    relevant = [r for r in converted if r[1].find(s) != -1][0: 200]
    results = []
    for result in relevant:
        if result[2]:
            results.append(
                (result[0], result[1], result[2], 'доступ разрешен'))
        else:
            if result[3] == 'unknown':
                results.append((result[0], result[1], result[2],
                                'логин выключен или не существует'))
            elif result[3].startswith('{already_started,'):
                results.append((result[0], result[1], result[2],
                                'уже в сети или недавно отключился'
                                ' (сессия в состоянии закрытия)'))
            elif result[3] == 'time_of_day':
                results.append((result[0], result[1], result[2],
                                'доступ запрещён из-за времени суток'))
            elif result[3] == 'low_balance':
                results.append((result[0], result[1], result[2],
                                'недостаточно денег на счету'))
            elif result[3] == 'password':
                results.append((result[0], result[1], result[2],
                                'неверный пароль'))
            else:
                results.append(result)
    return results


def get_mac_address_by_ip(ip_address):
    """Получает MAC-адрес по IP-адресу через API браса"""
    try:
        for nas_url in options.nas.split('|'):
            http_client = tornado.httpclient.HTTPClient()
            # Используем эндпоинт /getmac для получения MAC-адреса
            request_url = nas_url + 'getmac?ip_address=' + urllib.quote_plus(ip_address)
            request = tornado.httpclient.HTTPRequest(request_url, request_timeout=5)
            response = http_client.fetch(request)
            if response.code == 200:
                # Парсим ответ от браса
                response_body = response.body
                if isinstance(response_body, bytes):
                    response_body = response_body.decode('utf-8')
                for line in response_body.split('\n'):
                    if line.startswith('MAC:'):
                        mac = line.split(': ')[1].strip()
                        if mac and mac != 'unknown':
                            return mac
                return 'unknown'
    except Exception as e:
        # В случае ошибки возвращаем unknown
        pass
    return 'unknown'


def get_all_mac_addresses():
    """Получает все MAC-адреса с браса одним запросом"""
    mac_addresses = {}
    try:
        for nas_url in options.nas.split('|'):
            http_client = tornado.httpclient.HTTPClient()
            # Используем эндпоинт /mac для получения всех MAC-адресов
            request_url = nas_url + 'mac'
            request = tornado.httpclient.HTTPRequest(request_url, request_timeout=10)
            response = http_client.fetch(request)
            if response.code == 200:
                response_body = response.body
                if isinstance(response_body, bytes):
                    response_body = response_body.decode('utf-8')
                import json
                data = json.loads(response_body)
                
                # API возвращает либо массив сессий напрямую, либо объект с полем sessions
                sessions_list = data
                if isinstance(data, dict) and 'sessions' in data:
                    sessions_list = data['sessions']
                
                # Обрабатываем список сессий
                if isinstance(sessions_list, list):
                    for session_info in sessions_list:
                        if 'client_ip' in session_info and 'mac' in session_info:
                            ip = session_info['client_ip']
                            mac = session_info['mac']
                            if mac and mac != 'unknown' and mac != 'error':
                                mac_addresses[ip] = mac
                break  # Используем только первый работающий NAS
    except Exception as e:
        # Для отладки можно раскомментировать:
        # print("Error getting MAC addresses: %s" % str(e))
        pass
    return mac_addresses


def get_online_sessions_with_mac(session):
    """Получает онлайн сессии с MAC-адресами из базы данных"""
    # Получаем базовые данные сессий
    online_sessions = get_online_sessions(session)
    
    # Добавляем MAC-адреса из поля cid в базе данных
    sessions_with_mac = []
    for s, a, c in online_sessions:
        # Используем MAC-адрес из базы данных (поле cid)
        mac_address = s.cid if s.cid else 'unknown'
        sessions_with_mac.append((s, a, c, mac_address))
    
    return sessions_with_mac


def get_online_sessions_statistics(session):
    """Получает детальную статистику по онлайн сессиям"""
    online_sessions = get_online_sessions_with_mac(session)
    
    stats = {
        'total_sessions': len(online_sessions),
        'total_traffic_in': 0,
        'total_traffic_out': 0,
        'total_amount': 0,
        'active_sessions': 0,  # сессии с трафиком
        'long_sessions': 0,    # сессии больше 8 часов
        'high_traffic_sessions': 0,  # сессии с трафиком > 100 МБ
        'mac_addresses_found': 0,
        'top_users_by_traffic': [],
        'duration_distribution': {
            'under_1h': 0,
            '1h_to_4h': 0,
            '4h_to_8h': 0,
            '8h_to_24h': 0,
            'over_24h': 0
        }
    }
    
    import datetime
    now = datetime.datetime.now()
    traffic_users = []
    
    for s, a, c, mac in online_sessions:
        # Базовая статистика
        stats['total_traffic_in'] += s.octets_in
        stats['total_traffic_out'] += s.octets_out
        stats['total_amount'] += s.amount
        
        # MAC адреса
        if mac and mac != 'unknown':
            stats['mac_addresses_found'] += 1
        
        # Активные сессии (с трафиком)
        total_traffic = s.octets_in + s.octets_out
        if total_traffic > 1048576:  # больше 1 МБ
            stats['active_sessions'] += 1
        
        # Высокий трафик
        if total_traffic > 104857600:  # больше 100 МБ
            stats['high_traffic_sessions'] += 1
        
        # Длительность сессий
        from utils import datetime_utc_to_local
        start_time = datetime_utc_to_local(s.started_at)
        duration = now - start_time
        duration_hours = duration.total_seconds() / 3600
        
        if duration_hours > 8:
            stats['long_sessions'] += 1
        
        # Распределение по времени
        if duration_hours < 1:
            stats['duration_distribution']['under_1h'] += 1
        elif duration_hours < 4:
            stats['duration_distribution']['1h_to_4h'] += 1
        elif duration_hours < 8:
            stats['duration_distribution']['4h_to_8h'] += 1
        elif duration_hours < 24:
            stats['duration_distribution']['8h_to_24h'] += 1
        else:
            stats['duration_distribution']['over_24h'] += 1
        
        # Топ пользователей по трафику
        traffic_users.append({
            'login': a.login,
            'name': c.key_field.info_value,
            'traffic': total_traffic,
            'traffic_mb': total_traffic / 1048576.0
        })
    
    # Сортируем и берем топ-10 по трафику
    traffic_users.sort(key=lambda x: x['traffic'], reverse=True)
    stats['top_users_by_traffic'] = traffic_users[:10]
    
    return stats
