#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import division

import base64
import collections
from ConfigParser import SafeConfigParser
from datetime import date, datetime, timedelta
from operator import attrgetter
from tornado.options import define, options, parse_command_line, parse_config_file
import decimal
import hashlib
import json
import math
import random
import os
import re
import requests
import sqlalchemy
import sqlalchemy.orm.exc
from sqlalchemy.pool import NullPool
import time
import tornado.httpclient
import tornado.ioloop
import tornado.web
import urlparse
import yaml
import uuid
import adminapi
import userapi
from model import *
import uimodules
from utils import storage, string_to_utc_datetime, datetime_local_to_utc, convert_bytes
from logic import *

random.seed()

MONTH_NAMES = u"январь февраль март апрель май июнь июль август сентябрь октябрь ноябрь декабрь".split()
SERIOUS_API = 'http://localhost:8081/'

def make_path(tail):
    import os
    # Получаем директорию файла server.py (/opt/netspire-web/src)
    current_dir = os.path.dirname(os.path.abspath(__file__))
    # Идем на уровень вверх до netspire-web
    project_dir = os.path.dirname(current_dir)
    # Добавляем нужную поддиректорию
    return os.path.join(project_dir, tail)


class FrontRedirectHandler(tornado.web.RequestHandler):
    def get(self):
        self.redirect('/user/')


class AdminAreaMixin(object):
    def get_current_user(self):
        session_id = self.get_secure_cookie('a_sid')
        if session_id is None:
            return None
        login, ok = adminapi.fetch_update_session(session_id, update=True)
        if ok:
            return login
        return None

    def get_login_url(self):
        self.require_setting("admin_login_url", "@tornado.web.authenticated")
        return self.application.settings["admin_login_url"]


class BaseHandler(tornado.web.RequestHandler):
    def prepare(self):
        self.session = session_maker()

    def on_finish(self):
        self.session.rollback()
        self.session.close()

    def get_flash_message(self):
        msg = self.get_secure_cookie('flash_msg')
        self.clear_cookie('flash_msg')
        if msg is not None:
            msg = base64.b64decode(msg)
        return msg

    def set_flash_message(self, message):
        if isinstance(message, unicode):
            message = message.encode('utf-8')
        self.set_secure_cookie('flash_msg', base64.b64encode(message))


class AdminLogin(tornado.web.RequestHandler):
    def get(self):
        if self.get_argument('new', '') != '':
            self.render('admin_login2.html')
        self.render('admin_login.html')

    def post(self):
        email = self.get_argument("email", default="").lower()
        password = self.get_argument("password", default="")
        next_url = self.get_argument(
            "next", default=self.reverse_url('AdminHome'))
        if email == '' or password == '':
            self.render('admin_login.html')
            return
        ip = self.request.headers.get('X-Forwarded-For', 'unknown')
        session_id, admin_id, ok = adminapi.authenticate(email, password)
        ok = ok and (email != 'bb@salom.uz' or ip == '195.69.189.173')
        if not ok:
            self.render('admin_login.html')
            return
        now = datetime.utcnow()
        adminapi.log_logon(admin_id, now, ip)
        self.set_secure_cookie('a_sid', session_id)
        self.redirect(next_url)

class APIError(Exception):
    pass


def sapiContract(contract_id):
    result = requests.get(SERIOUS_API + 'contract/',
                          params=(dict(id=contract_id)))
    if result.status_code != 200:
        raise APIError("status code: {}".format(result.status_code))
    return result.json()


class AdminContractOverviewPage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self, contract_id):
        session_id = self.get_secure_cookie('a_sid')
        try:
            contract = self.session.query(
                Contract).filter_by(id=contract_id).one()
            admin = self.session.query(Admin).filter_by(
                email=self.current_user, active=True).one()
        except sqlalchemy.orm.exc.NoResultFound:
            raise tornado.web.HTTPError(404)
        managers = adminapi.contract_managers(contract.id)
        if admin.has_role('manager') and admin.id not in managers:
            raise tornado.web.HTTPError(403)
        now = datetime.now()
        month1st = datetime(now.year, now.month, 1, 0, 0, 0)
        balance1 = adminapi.balance_at(session_id, contract_id, month1st)
        now = datetime.utcnow()
        planned_events = self.session.query(ActionLogEntry).\
            filter_by(target_type='contract', target_id=contract.id, status='new').\
            filter(ActionLogEntry.planned_at > now).\
            order_by(ActionLogEntry.planned_at).all()
        # fetch managers of a contract
        try:
            result = sapiContract(contract_id)
        except APIError:
            managers = []
        else:
            managers = result.get('Managers', [])
        self.render('admin_contract_overview.html',
                    contract=contract,
                    section='',
                    admin=admin,
                    planned_events=planned_events,
                    managers=managers,
                    balance1=balance1)


class AdminContractInfoPage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self, contract_id):
        try:
            contract = self.session.query(
                Contract).filter_by(id=contract_id).one()
            admin = self.session.query(Admin).filter_by(
                email=self.current_user, active=True).one()
        except sqlalchemy.orm.exc.NoResultFound:
            raise tornado.web.HTTPError(404)
        managers = adminapi.contract_managers(contract.id)
        if admin.has_role('manager') and admin.id not in managers:
            raise tornado.web.HTTPError(403)
        self.render('admin_contract_info.html',
                    contract=contract,
                    section='info',
                    managers=managers,
                    admin=admin)


class AdminContractInfoEditPage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self, contract_id):
        try:
            contract = self.session.query(
                Contract).filter_by(id=contract_id).one()
            admin = self.session.query(Admin).filter_by(
                email=self.current_user, active=True).one()
        except sqlalchemy.orm.exc.NoResultFound:
            raise tornado.web.HTTPError(404)
        managers = adminapi.contract_managers(contract.id)
        if admin.has_role('bb'):
            raise tornado.web.HTTPError(403)
        if admin.has_role('manager') and admin.id not in managers:
            raise tornado.web.HTTPError(403)
        if contract.state != 'open':
            self.redirect(self.reverse_url('AdminContractInfo', contract.id))
            return
        self.render('admin_contract_info_edit.html',
                    contract=contract,
                    section='info-edit',
                    managers=managers,
                    admin=admin)

    @tornado.web.authenticated
    def post(self, contract_id):
        try:
            contract = self.session.query(
                Contract).filter_by(id=contract_id).one()
            admin = self.session.query(Admin).filter_by(
                email=self.current_user, active=True).one()
        except sqlalchemy.orm.exc.NoResultFound:
            raise tornado.web.HTTPError(404)
        managers = adminapi.contract_managers(contract.id)
        if admin.has_role('bb'):
            raise tornado.web.HTTPError(403)
        if admin.has_role('manager') and admin.id not in managers:
            raise tornado.web.HTTPError(403)
        if contract.state != 'open':
            self.redirect(self.reverse_url('AdminContractInfo', contract.id))
            return
        for info in contract.infos:
            self.session.delete(info)
        prefix = 'ui_info_item_'
        for arg_name in self.request.arguments:
            if not arg_name.startswith(prefix):
                continue
            value = self.get_argument(arg_name, '').strip()
            info = ContractInfo(info_id=int(arg_name[len(prefix):]),
                                info_value=value)
            contract.infos.append(info)
        self.session.commit()
        self.redirect(self.reverse_url('AdminContractInfo', contract.id))


class AdminContractAccountsPage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self, contract_id):
        try:
            contract = self.session.query(
                Contract).filter_by(id=contract_id).one()
            admin = self.session.query(Admin).filter_by(
                email=self.current_user, active=True).one()
        except sqlalchemy.orm.exc.NoResultFound:
            raise tornado.web.HTTPError(404)
        managers = adminapi.contract_managers(contract.id)
        if admin.has_role('manager') and admin.id not in managers:
            raise tornado.web.HTTPError(403)
        plans = (self.session.query(Plan)
                 .filter_by(currency_id=contract.currency_id)
                 .order_by(Plan.name))
        self.render('admin_contract_accounts.html',
                    contract=contract,
                    section='accounts',
                    plans=plans,
                    managers=managers,
                    admin=admin)

    @tornado.web.authenticated
    def post(self, contract_id):
        try:
            contract = self.session.query(
                Contract).filter_by(id=contract_id).one()
            admin = self.session.query(Admin).filter_by(
                email=self.current_user, active=True).one()
        except sqlalchemy.orm.exc.NoResultFound:
            raise tornado.web.HTTPError(404)
        if admin.has_role('bb'):
            raise tornado.web.HTTPError(403)
        if not (admin.has_role('plan') or admin.has_role('super')) or contract.state != 'open':
            raise tornado.web.HTTPError(403)
        login = self.get_argument('login', '').strip()
        password = self.get_argument('password', '')
        password_confirm = self.get_argument('password_confirm', '')
        plan_id = self.get_argument('plan')
        plan = self.session.query(Plan).filter_by(id=int(plan_id)).one()
        if contract.currency_id != plan.currency_id:
            self.set_flash_message(u'Неверный тарифный план')
            self.redirect(self.reverse_url(
                'AdminContractAccounts', contract.id))
            return
        if password != password_confirm:
            self.set_flash_message('Пароль и его подтверждение не совпадают')
            self.redirect(self.reverse_url(
                'AdminContractAccounts', contract.id))
            return
        error = create_new_account(
            self.session, contract, login, password, plan)
        if error is not None:
            self.set_flash_message(error)
        else:
            self.session.commit()
        self.redirect(self.reverse_url('AdminContractAccounts', contract.id))


class AdminAccountChangeComment(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self, account_id):
        try:
            account = self.session.query(
                Account).filter_by(id=account_id).one()
            admin = self.session.query(Admin).filter_by(
                email=self.current_user, active=True).one()
        except sqlalchemy.orm.exc.NoResultFound:
            raise tornado.web.HTTPError(404)
        managers = adminapi.contract_managers(account.contract.id)
        if admin.has_role('bb'):
            raise tornado.web.HTTPError(403)
        if admin.has_role('manager') and admin.id not in managers:
            raise tornado.web.HTTPError(403)
        if account.state == 'closed':
            self.redirect(self.reverse_url(
                'AdminContractAccounts', account.contract.id))
            return
        self.render('admin_account_change_comment.html',
                    contract=account.contract,
                    section='accounts',
                    account=account,
                    managers=managers,
                    admin=admin)

    @tornado.web.authenticated
    def post(self, account_id):
        try:
            account = self.session.query(
                Account).filter_by(id=account_id).one()
            admin = self.session.query(Admin).filter_by(
                email=self.current_user, active=True).one()
        except sqlalchemy.orm.exc.NoResultFound:
            raise tornado.web.HTTPError(404)
        managers = adminapi.contract_managers(account.contract.id)
        if admin.has_role('bb'):
            raise tornado.web.HTTPError(403)
        if admin.has_role('manager') and admin.id not in managers:
            raise tornado.web.HTTPError(403)
        if account.state == 'closed':
            self.redirect(self.reverse_url(
                'AdminContractAccounts', account.contract.id))
            return
        account.comment = self.get_argument('comment', '').strip()
        self.session.commit()
        self.redirect(self.reverse_url(
            'AdminContractAccounts', account.contract.id))


class AdminContractFLogPage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self, contract_id):
        try:
            contract = self.session.query(
                Contract).filter_by(id=contract_id).one()
            admin = self.session.query(Admin).filter_by(
                email=self.current_user, active=True).one()
        except sqlalchemy.orm.exc.NoResultFound:
            raise tornado.web.HTTPError(404)
        managers = adminapi.contract_managers(contract.id)
        if admin.has_role('bb'):
            raise tornado.web.HTTPError(403)
        if admin.has_role('manager') and admin.id not in managers:
            raise tornado.web.HTTPError(403)
        from_date = self.get_argument('from', '')
        till_date = self.get_argument('till', '')
        kind = self.get_argument('kind', 'all')
        if from_date != '':
            from_date = string_to_utc_datetime(from_date)
            till_date = string_to_utc_datetime(till_date)
            transactions = (self.session.query(FinTransaction)
                            .filter(FinTransaction.contract_id == contract.id)
                            .filter(FinTransaction.created_at >= from_date)
                            .filter(FinTransaction.created_at <= till_date))
            if kind != 'all':
                if kind == 'debit':
                    transactions = transactions.filter(
                        FinTransaction.amount < 0)
                else:
                    transactions = transactions.filter(
                        FinTransaction.amount > 0)
            transactions = transactions.order_by(FinTransaction.created_at)
        else:
            transactions = None
        self.render('admin_contract_flog.html',
                    contract=contract,
                    section='flog',
                    transactions=transactions,
                    managers=managers,
                    admin=admin)


class AdminContractFOperPage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self, contract_id):
        try:
            contract = self.session.query(
                Contract).filter_by(id=contract_id).one()
            admin = self.session.query(Admin).filter_by(
                email=self.current_user, active=True).one()
        except sqlalchemy.orm.exc.NoResultFound:
            raise tornado.web.HTTPError(404)
        managers = adminapi.contract_managers(contract.id)
        if admin.has_role('bb'):
            raise tornado.web.HTTPError(403)
        if admin.has_role('manager') and admin.id not in managers:
            raise tornado.web.HTTPError(403)
        if not admin.has_role('foper'):
            raise tornado.web.HTTPError(403)
        currencies = self.session.query(Currency).filter_by(active=True).all()
        created_at = self.get_argument('created_at', '')
        if created_at == '':
            created_at = datetime.now().date()
        self.render('admin_contract_foper.html',
                    contract=contract,
                    section='foper',
                    currencies=currencies,
                    created_at=created_at,
                    managers=managers,
                    admin=admin)

    @tornado.web.authenticated
    def post(self, contract_id):
        created_at = self.created_at()
        try:
            contract = self.session.query(
                Contract).filter_by(id=contract_id).one()
            admin = self.session.query(Admin).filter_by(
                email=self.current_user, active=True).one()
        except sqlalchemy.orm.exc.NoResultFound:
            raise tornado.web.HTTPError(404)
        managers = adminapi.contract_managers(contract.id)
        if admin.has_role('bb'):
            raise tornado.web.HTTPError(403)
        if admin.has_role('manager') and admin.id not in managers:
            raise tornado.web.HTTPError(403)
        if not admin.has_role('foper'):
            raise tornado.web.HTTPError(403)
        oper_type = self.get_argument('type')
        oper_currency_id = self.get_argument('currency')
        oper_currency = (self.session.query(Currency).
                         filter_by(id=oper_currency_id).one())
        amount = decimal.Decimal(self.get_argument('amount', '').strip())
        comment = self.get_argument('comment', '').strip()
        if amount == '' or comment == '':
            self.redirect(self.reverse_url('AdminContractFOper', contract_id))
            return
        f = FinancialOperation(self.session, contract, created_at)
        if oper_type == 'up':
            f.credit(amount, comment, oper_currency, admin)
        else:
            f.debit(amount, comment, oper_currency, admin)
        self.session.commit()
        self.redirect(self.reverse_url('AdminContractOverview', contract_id))

    def created_at(self):
        created_at = self.get_argument('created_at', '')
        if created_at == '':
            return None
        t = time.strptime(created_at, '%Y-%m-%d')
        created_at = date(t.tm_year, t.tm_mon, t.tm_mday)
        today = date.today()
        if created_at >= today:
            return None
        created_at = datetime.utcfromtimestamp(time.mktime(t))
        return created_at + timedelta(0, 12 * 3600 + random.randint(0, 59), random.randint(0, 999999))


class AdminEditFinTransaction(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self, contract_id, op_id):
        try:
            contract = self.session.query(
                Contract).filter_by(id=contract_id).one()
            admin = self.session.query(Admin).filter_by(
                email=self.current_user, active=True).one()
            op = self.session.query(FinTransaction).filter_by(id=op_id).one()
        except sqlalchemy.orm.exc.NoResultFound:
            raise tornado.web.HTTPError(404)
        managers = adminapi.contract_managers(contract.id)
        if admin.has_role('bb'):
            raise tornado.web.HTTPError(403)
        if admin.has_role('manager') and admin.id not in managers:
            raise tornado.web.HTTPError(403)
        if not admin.has_role('foper'):
            raise tornado.web.HTTPError(403)
        referer = self.request.headers.get('Referer', '')
        back = ''
        if referer != '':
            u = urlparse.urlparse(referer)
            if u.path == self.reverse_url('AdminContractFlog', contract_id):
                back = u.query
        self.render('admin_edit_fin_transaction.html',
                    contract=contract,
                    section='foper',
                    op=op,
                    back=back,
                    managers=managers,
                    admin=admin)

    @tornado.web.authenticated
    def post(self, contract_id, op_id):
        try:
            contract = self.session.query(
                Contract).filter_by(id=contract_id).one()
            admin = self.session.query(Admin).filter_by(
                email=self.current_user, active=True).one()
            op = self.session.query(FinTransaction).filter_by(id=op_id).one()
        except sqlalchemy.orm.exc.NoResultFound:
            raise tornado.web.HTTPError(404)
        managers = adminapi.contract_managers(contract.id)
        if admin.has_role('bb'):
            raise tornado.web.HTTPError(403)
        if admin.has_role('manager') and admin.id not in managers:
            raise tornado.web.HTTPError(403)
        if not admin.has_role('foper'):
            raise tornado.web.HTTPError(403)
        back = self.get_argument('back', '')
        amount = self.get_argument('amount', '').strip().replace(',', '.')
        comment = self.get_argument('comment', '').strip()
        if amount == '' or comment == '':
            self.render('admin_edit_fin_transaction.html',
                        contract=contract,
                        section='foper',
                        op=op,
                        back=back,
                        managers=managers,
                        admin=admin)
            return
        amount = decimal.Decimal(amount)
        op.amount = amount
        op.amount_in_contract_currency = amount
        op.comment = comment
        op.admin_id = admin.id
        self.session.commit()
        adminapi.recalculateFinHistory(contract_id)
        if len(back) > 0:
            self.redirect(self.reverse_url(
                'AdminContractFlog', contract_id) + '?' + back)
        else:
            self.redirect(self.reverse_url(
                'AdminContractOverview', contract_id))


class AdminContractSessionsPage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self, contract_id):
        try:
            contract = self.session.query(
                Contract).filter_by(id=contract_id).one()
            admin = self.session.query(Admin).filter_by(
                email=self.current_user, active=True).one()
        except sqlalchemy.orm.exc.NoResultFound:
            raise tornado.web.HTTPError(404)
        managers = adminapi.contract_managers(contract.id)
        if admin.has_role('manager') and admin.id not in managers:
            raise tornado.web.HTTPError(403)
        from_date = self.get_argument('from', '')
        till_date = self.get_argument('till', '')
        account_id = int(self.get_argument('account', -1))
        session_id = self.get_argument('session_id', None)
        if from_date != '' and till_date != '' and account_id != -1:
            from_date = string_to_utc_datetime(from_date)
            till_date = string_to_utc_datetime(till_date)
            sessions = (self.session.query(TrafficSession)
                        .filter(TrafficSession.account_id == account_id)
                        .filter(TrafficSession.started_at >= from_date)
                        .filter(TrafficSession.finished_at <= till_date)
                        .order_by(TrafficSession.started_at))
            traffic = (self.session.query(SessionDetail.traffic_class,
                                          sqlalchemy.func.sum(
                                              SessionDetail.octets_in),
                                          sqlalchemy.func.sum(SessionDetail.octets_out))
                       .join(TrafficSession)
                       .filter(TrafficSession.account_id == account_id)
                       .filter(TrafficSession.started_at >= from_date)
                       .filter(TrafficSession.finished_at <= till_date)
                       .group_by(SessionDetail.traffic_class))
            self.render('admin_contract_sessions.html', contract=contract,
                        section='sessions', sessions=sessions, traffic=traffic, admin=admin)
        elif session_id is not None:
            session = self.session.query(
                TrafficSession).filter_by(id=session_id).one()
            self.render('admin_contract_session_details.html',
                        contract=contract,
                        section='sessions',
                        session=session,
                        managers=managers,
                        admin=admin)
        else:
            self.render('admin_contract_sessions.html',
                        contract=contract,
                        section='sessions',
                        sessions=None,
                        managers=managers,
                        admin=admin)

class AdminContractMonitoringPage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self, contract_id):
            from_date = self.get_argument('from', '')
            till_date = self.get_argument('till', '')
            account_id = int(self.get_argument('account', -1))
            session_id = self.get_argument('session_id', None)
            contract = self.session.query(
                Contract).filter_by(id=contract_id).one()
            admin = self.session.query(Admin).filter_by(
                email=self.current_user, active=True).one()
            managers = adminapi.contract_managers(contract.id)
            sessions = (self.session.query(TrafficSession)
                        .filter(TrafficSession.account_id == account_id)
                        .filter(TrafficSession.started_at >= from_date)
                        .filter(TrafficSession.finished_at <= till_date)
                        .order_by(TrafficSession.started_at))

            self.render('admin_contract_monitoring.html',
                        contract=contract,
                        section='sessions',
                        sessions=None,
                        managers=managers,
                        admin=admin)

class AdminCloseContractPage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self, contract_id):
        try:
            contract = self.session.query(
                Contract).filter_by(id=contract_id).one()
            admin = self.session.query(Admin).filter_by(
                email=self.current_user, active=True).one()
        except sqlalchemy.orm.exc.NoResultFound:
            raise tornado.web.HTTPError(404)
        managers = adminapi.contract_managers(contract.id)
        if admin.has_role('manager') and admin.id not in managers or \
                not admin.has_role('close'):
            raise tornado.web.HTTPError(403)
        self.render('admin_close_contract.html',
                    section='',
                    contract=contract,
                    managers=managers,
                    admin=admin)

    @tornado.web.authenticated
    def post(self, contract_id):
        try:
            contract = self.session.query(
                Contract).filter_by(id=contract_id).one()
            admin = self.session.query(Admin).filter_by(
                email=self.current_user, active=True).one()
        except sqlalchemy.orm.exc.NoResultFound:
            raise tornado.web.HTTPError(404)
        managers = adminapi.contract_managers(contract.id)
        if admin.has_role('manager') and admin.id not in managers or \
                not admin.has_role('close'):
            raise tornado.web.HTTPError(403)
        when = self.get_argument('when', 'now')
        if when == 'now':
            for a in contract.accounts:
                if a.state != 'closed':
                    self.redirect(self.reverse_url(
                        'AdminCloseContract', contract.id))
                    return
            contract.closed_at = datetime.utcnow()
            contract.state = 'closed'
            self.session.commit()
        else:
            planned_at = self.get_argument('planned_at', '')
            if planned_at == '':
                self.redirect(self.reverse_url(
                    'AdminContractOverview', contract.id))
                return
            planned_at = string_to_utc_datetime(planned_at)
            a = ActionLogEntry()
            a.admin_id = admin.id
            a.target_type = 'contract'
            a.target_id = contract.id
            a.action = 'close'
            a.planned_at = planned_at
            a.status = 'new'
            self.session.add(a)
            self.session.commit()
        self.redirect(self.reverse_url('AdminContractOverview', contract.id))


class AdminResumeContractPage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self, contract_id):
        try:
            contract = self.session.query(
                Contract).filter_by(id=contract_id).one()
            admin = self.session.query(Admin).filter_by(
                email=self.current_user, active=True).one()
        except sqlalchemy.orm.exc.NoResultFound:
            raise tornado.web.HTTPError(404)
        managers = adminapi.contract_managers(contract.id)
        if admin.has_role('manager') and admin.id not in managers or \
                not admin.has_role('close'):
            raise tornado.web.HTTPError(403)
        
        messages = []
        action = self.session.query(ActionLogEntry).filter_by(target_id=contract_id, target_type='contract').one()
        action.status = 'canceled'
        messages.append('Контракт был успешно возобновлен');
        self.set_flash_message(' '.join(messages))
        self.session.commit()
        self.redirect(self.reverse_url(
                'AdminContractOverview', contract.id))

class AdminViewInvoicePage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self, contract_id, year, month):
        year = int(year)
        month = int(month)
        try:
            contract = self.session.query(
                Contract).filter_by(id=contract_id).one()
            admin = self.session.query(Admin).filter_by(
                email=self.current_user, active=True).one()
        except sqlalchemy.orm.exc.NoResultFound:
            raise tornado.web.HTTPError(404)
        managers = adminapi.contract_managers(contract.id)
        if admin.has_role('bb'):
            raise tornado.web.HTTPError(403)
        if admin.has_role('manager') and admin.id not in managers or \
                not admin.has_role('foper'):
            raise tornado.web.HTTPError(403)
        invoice = adminapi.fetch_invoice(contract.id, year, month)
        invoice = prepare_invoice_for_display(invoice, contract.currency_id)
        if invoice["month"] == 12:
            next1st = "{0}-01-01".format(invoice["year"] + 1, invoice["month"])
        else:
            next1st = "{0}-{1:02}-01".format(
                invoice["year"], invoice["month"] + 1)
        self.render('admin_view_invoice.html',
                    section='invoices',
                    contract=contract,
                    invoice=invoice,
                    next1st=next1st,
                    month_names=MONTH_NAMES,
                    ods_name=ods_name(
                        contract.key_field.info_value, year, month, invoice["invoice_id"]),
                    managers=managers,
                    admin=admin)


def ods_name(name, year, month, invoice_id):
    name = re.sub('\s+', '_', name)
    name = name.replace('"', '').replace("'", '')
    name = name.replace('/', '_').replace("\\", "_")
    return u'{0}{1:02}_{2}_{3}.ods'.format(year, month, invoice_id, name).encode('utf-8')


def round_to_01(x):
    invert = x < 0
    if invert:
        x = abs(x)
    y = x * 100 + 0.5
    y = math.floor(y) / 100
    if invert:
        return -y
    return y


def prepare_invoice_for_display(invoice, currency_id):
    data = yaml.load(invoice["data_yaml"])
    del invoice["data_yaml"]
    invoice["expenses"] = {}
    total_expenses = 0
    total_expenses_sum = 0
    for k in data["expenses"]:
        if data["expenses"][k] > 0:
            invoice["expenses"][k] = "{0:.2f}".format(data["expenses"][k])
            total_expenses += data["expenses"][k]
            if currency_id == 1:
                e = round_to_01(data["expenses"][k] * data["rate1to2"])
                invoice["expenses"][k + "_sum"] = e
                total_expenses_sum += e
    invoice["total_expenses"] = total_expenses
    if currency_id == 1:
        invoice["total_expenses_sum"] = total_expenses_sum
    invoice["balance1st"] = "{0:.2f}".format(data["balance1st"])
    invoice["monthly_fees"] = "{0:.2f}".format(data["monthly_fees"])
    invoice["due_payment"] = "{0:.2f}".format(data["due_payment"])
    invoice["rate1to2"] = data["rate1to2"]
    return invoice


class AdminODSInvoicePage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self, contract_id, year, month, name):
        year = int(year)
        month = int(month)
        try:
            contract = self.session.query(
                Contract).filter_by(id=contract_id).one()
            admin = self.session.query(Admin).filter_by(
                email=self.current_user, active=True).one()
        except sqlalchemy.orm.exc.NoResultFound:
            raise tornado.web.HTTPError(404)
        managers = adminapi.contract_managers(contract.id)
        if admin.has_role('bb'):
            raise tornado.web.HTTPError(403)
        if admin.has_role('manager') and admin.id not in managers or \
                not admin.has_role('foper'):
            raise tornado.web.HTTPError(403)
        ods = adminapi.fetch_ods_invoice(contract_id, year, month)
        if ods is None:
            raise tornado.web.HTTPError(404)
        self.set_header(
            "Content-Type", "application/vnd.oasis.opendocument.spreadsheet")
        self.set_header("Content-Length", str(int(len(ods))))
        self.finish(bytes(ods))


class AdminListInvoicesPage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self, contract_id):
        try:
            contract = self.session.query(
                Contract).filter_by(id=contract_id).one()
            admin = self.session.query(Admin).filter_by(
                email=self.current_user, active=True).one()
        except sqlalchemy.orm.exc.NoResultFound:
            raise tornado.web.HTTPError(404)
        managers = adminapi.contract_managers(contract.id)
        if admin.has_role('bb'):
            raise tornado.web.HTTPError(403)
        if admin.has_role('manager') and admin.id not in managers or \
                not admin.has_role('foper'):
            raise tornado.web.HTTPError(403)
        invoices = adminapi.list_invoices(contract.id)
        self.render('admin_list_invoices.html',
                    section='invoices',
                    contract=contract,
                    month_names=MONTH_NAMES,
                    invoices=invoices,
                    managers=managers,
                    admin=admin)


class SettingsKinds(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if admin.has_role('bb'):
            raise tornado.web.HTTPError(403)
        remove_id = self.get_argument('remove', None)
        if remove_id is None:
            kinds = self.session.query(ContractKind).all()
            self.render('admin_kinds.html',
                        delete_failed=False,
                        kinds=kinds,
                        admin=admin)
        else:
            kind = self.session.query(
                ContractKind).filter_by(id=remove_id).one()
            self.render('admin_kinds_remove.html',
                        kind=kind,
                        admin=admin)

    @tornado.web.authenticated
    def post(self):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if admin.has_role('bb'):
            raise tornado.web.HTTPError(403)
        remove_id = self.get_argument('remove', None)
        if remove_id is not None:
            kind = self.session.query(
                ContractKind).filter_by(id=remove_id).one()
            if len(kind.fields) == 0:
                self.session.delete(kind)
                self.session.commit()
            else:
                kinds = self.session.query(ContractKind).all()
                self.render('admin_kinds.html',
                            delete_failed=True, kinds=kinds)
                return
        else:
            name = self.get_argument('name', '').strip()
            description = self.get_argument('description', '').strip()
            kind = ContractKind(kind_name=name, description=description)
            self.session.add(kind)
            self.session.commit()
        self.redirect(self.reverse_url('SettingsKinds'))


class SettingsInfos(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self, kind_id):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if not admin.has_role('super'):
            raise tornado.web.HTTPError(403)
        kind = None
        kinds = None
        if kind_id != '':
            kind = self.session.query(ContractKind).filter(
                ContractKind.id == kind_id).one()
        else:
            kinds = self.session.query(ContractKind).all()
        self.render('settings_info.html',
                    kind=kind,
                    kinds=kinds,
                    admin=admin)

    @tornado.web.authenticated
    def post(self, kind_id):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if not admin.has_role('super'):
            raise tornado.web.HTTPError(403)
        action = self.get_argument('action', '')
        if action == '':
            kind = self.session.query(ContractKind).filter(
                ContractKind.id == kind_id).one()
            name = self.get_argument('name', '').strip()
            description = self.get_argument('description', '').strip()
            item = ContractInfoItem(field_name=name,
                                    field_description=description)
            if len(kind.fields) == 0:
                item.sort_order = 0
            else:
                item.sort_order = 1 + \
                    max(map(attrgetter('sort_order'), kind.fields))
            kind.fields.append(item)
            self.session.commit()
            self.redirect(self.reverse_url('SettingsInfos', kind_id))
        elif action == 'remove':
            item_id = self.get_argument('id')
            item = (self.session.query(ContractInfoItem)
                    .filter_by(id=item_id, kind_id=kind_id)
                    .one())
            self.session.delete(item)
            self.session.commit()
            self.redirect(self.reverse_url('SettingsInfos', kind_id))
        elif action == 'edit':
            item_id = self.get_argument('id')
            item = (self.session.query(ContractInfoItem)
                    .filter_by(id=item_id, kind_id=kind_id)
                    .one())
            item.field_name = self.get_argument('name', '').strip()
            item.field_description = self.get_argument(
                'description', '').strip()
            self.session.commit()
            self.redirect(self.reverse_url('SettingsInfos', kind_id))


class AdminsPage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self):
        form = storage()
        action = self.get_argument('action', '')
        if action == 'create':
            form.email = ''
            form.real_name = ''
            self.render('admins.html', message=None, form=form)
        elif action == 'edit':
            admin_id = self.get_argument('id')
            admin = self.session.query(Admin).filter_by(id=admin_id).first()
            self.render('admins.html', message=None, form=form, admin=admin)
        else:
            admins = self.session.query(Admin).all()
            self.render('admins.html', message=None, form=form, admins=admins)

    @tornado.web.authenticated
    def post(self):
        action = self.get_argument('action')
        password = self.get_argument('password', '').strip()
        confirmation = self.get_argument('password_confirm', '').strip()
        form = storage()
        form.email = self.get_argument('email', '').strip()
        form.real_name = self.get_argument('real_name', '').strip()
        message = None
        if form.email == '':
            message = 3
        elif form.real_name == '':
            message = 4
        elif action == 'edit' and len(password) != 0 and len(password) < 8:
            message = 1
        elif action == 'create' and len(password) < 8:
            message = 1
        elif password != confirmation:
            message = 2
        if message is not None:
            self.render('admins.html', message=message, form=form)
            return
        if action == 'create':
            admin = Admin(email=form.email,
                          password=create_password(password.encode('utf-8')),
                          real_name=form.real_name,
                          roles='')
            self.session.add(admin)
        else:
            admin_id = self.get_argument('id')
            admin = self.session.query(Admin).filter_by(id=admin_id).first()
            if len(password) > 0:
                admin.password = create_password(password.encode('utf-8'))
            admin.email = form.email
            admin.real_name = form.real_name
            admin.active = self.get_argument('active') == '1'
        self.session.commit()
        self.redirect(self.reverse_url('Admins'))


class ContractCreate(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self, kind_id):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if admin.has_role('bb'):
            raise tornado.web.HTTPError(403)
        if kind_id != '':
            kind = self.session.query(ContractKind).filter_by(id=kind_id).one()
            currencies = self.session.query(
                Currency).filter_by(active=True).all()
            self.render('admin_contract_create.html',
                        kind=kind,
                        currencies=currencies,
                        admin=admin)
        else:
            kinds = self.session.query(ContractKind).all()
            self.render('admin_contract_create.html',
                        kind=None,
                        kinds=kinds,
                        admin=admin)

    @tornado.web.authenticated
    def post(self, kind_id):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if admin.has_role('bb'):
            raise tornado.web.HTTPError(403)
        if kind_id == '':
            raise tornado.web.HTTPError(404)
        kind = self.session.query(ContractKind).filter_by(id=kind_id).one()
        currency_id = self.get_argument('currency')
        currency = self.session.query(Currency).filter_by(
            id=currency_id, active=True).one()
        contract = Contract(kind=kind,
                            balance=0,
                            currency=currency)
        for arg_name in self.request.arguments:
            if not arg_name.startswith('item'):
                continue
            value = self.get_argument(arg_name, '').strip()
            info = ContractInfo(info_value=value)
            contract.infos.append(info)
            info.info_id = int(arg_name[4:])
        if self.is_required_info_present(contract):
            self.session.add(contract)
            self.session.commit()
            self.redirect(self.reverse_url(
                'AdminContractOverview', contract.id))
        else:
            self.redirect(self.reverse_url('ContractCreate', kind_id))

    def is_required_info_present(self, contract):
        required = contract.kind.fields[0]
        for f in contract.infos:
            if f.info_id == required.id:
                return len(f.info_value) > 0
        return False


class AdminSettingsCurrencyPage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if not admin.has_role('super'):
            raise tornado.web.HTTPError(403)
        currencies = self.session.query(Currency).all()
        self.render('admin_settings_currency.html',
                    currencies=currencies,
                    admin=admin)


class AdminSearch(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self):
        action = self.get_argument('action', 'search')
        searched_for = self.get_argument('search', '').strip()
        search_results = None
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        kind_id = int(self.get_argument('k', -1))
        state = self.get_argument('state', 'open')
        if action == 'search':
            if searched_for != '':
                search_results = ContractSearcher(
                    self.session, admin).search(searched_for, kind_id, state)
        elif action == 'display':
            search_results = ContractSearcher(
                self.session, admin).all(kind_id, state)
        kinds = self.session.query(
            ContractKind).order_by(ContractKind.kind_name)
        self.render('admin_search.html',
                    kinds=kinds,
                    results=search_results,
                    admin=admin)


class AdminSettingsPlansPage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if not admin.has_role('plan') and not admin.has_role('super'):
            raise tornado.web.HTTPError(403)
        plans = self.session.query(Plan).order_by(Plan.name)
        self.render('admin_settings_plans.html',
                    admin=admin,
                    plans=plans)


class AdminSettingsPlansEditPage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self, plan_id):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if not admin.has_role('plan') and not admin.has_role('super'):
            raise tornado.web.HTTPError(403)
        currencies = self.session.query(Currency).filter_by(
            active=True).order_by(Currency.id).all()
        plan = self.session.query(Plan).filter_by(id=plan_id).one()
        settings = json.loads(plan.settings)
        self.render('admin_settings_plans_edit.html',
                    admin=admin,
                    currencies=currencies,
                    plan=plan,
                    settings=settings)

    @tornado.web.authenticated
    def post(self, plan_id):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if not admin.has_role('plan') and not admin.has_role('super'):
            raise tornado.web.HTTPError(403)
        currencies = self.session.query(Currency).filter_by(
            active=True).order_by(Currency.id).all()
        plan = self.session.query(Plan).filter_by(id=plan_id).one()
        settings, continue_edit = plan_settings_from_post(self)
        plan = plan_from_post(self, plan)
        if continue_edit:
            self.render('admin_settings_plans_edit.html',
                        currencies=currencies,
                        plan=plan,
                        settings=settings,
                        admin=admin)
        else:
            plan.settings = json.dumps(settings)
            # FIXME TODO: validate plan before adding to DB
            self.session.commit()
            self.redirect(self.reverse_url('AdminSettingsPlans'))


class AdminSettingsPlansViewPage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self, plan_id):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if admin.has_role('bb'):
            raise tornado.web.HTTPError(403)
        currencies = self.session.query(Currency).filter_by(
            active=True).order_by(Currency.id).all()
        plan = self.session.query(Plan).filter_by(id=plan_id).one()
        settings = json.loads(plan.settings)
        self.render('admin_settings_plans_view.html',
                    admin=admin,
                    currencies=currencies,
                    plan=plan,
                    settings=settings)


class AdminSettingsPlansCreatePage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if not admin.has_role('plan') and not admin.has_role('super'):
            raise tornado.web.HTTPError(403)
        currencies = self.session.query(Currency).filter_by(
            active=True).order_by(Currency.id).all()
        settings = dict(MONTHLY_FEE=0,
                        PREPAID=0,
                        SHAPER='131072 131072 131072',
                        ACCESS_INTERVALS=[],
                        INTERVALS=[])
        self.render('admin_settings_plans_create.html',
                    currencies=currencies,
                    plan=plan_from_post(self, Plan()),
                    settings=settings,
                    admin=admin)

    @tornado.web.authenticated
    def post(self):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if not admin.has_role('plan') and not admin.has_role('super'):
            raise tornado.web.HTTPError(403)
        currencies = self.session.query(Currency).filter_by(
            active=True).order_by(Currency.id).all()
        settings, continue_edit = plan_settings_from_post(self)
        plan = Plan()
        plan = plan_from_post(self, plan)
        if continue_edit:
            self.render('admin_settings_plans_create.html',
                        currencies=currencies,
                        plan=plan,
                        settings=settings,
                        admin=admin)
        else:
            plan.settings = json.dumps(settings)
            plan.created_at = datetime.utcnow()
            plan.updated_at = plan.created_at
            # FIXME TODO: validate plan before adding to DB
            self.session.add(plan)
            self.session.commit()
            update_field = self.session.query(RadiusReply).filter_by(
                name='Acct-Interim-Interval').one()
            assigned_reply = AssignedRadiusReply()
            assigned_reply.target_id = plan.id
            assigned_reply.target_type = 'Plan'
            assigned_reply.radius_reply_id = update_field.id
            assigned_reply.value = options.interim_update_interval
            self.session.add(assigned_reply)
            self.session.commit()
            self.redirect(self.reverse_url('AdminSettingsPlans'))


def plan_from_post(handler, plan):
    plan.name = handler.get_argument('name', '')
    plan.code = handler.get_argument('code', '')
    plan.currency_id = handler.get_argument('currency', None)
    plan.auth_algo = handler.get_argument(
        'auth_algo', 'algo_builtin:prepaid_auth')
    plan.acct_algo = handler.get_argument(
        'acct_algo', 'algo_builtin:prepaid_acct')
    return plan


def plan_settings_from_post(handler):
    continue_edit = False
    s = {'CREDIT': 0,
         'MONTHLY_FEE': float(handler.get_argument('monthly_fee', '0')),
         'PREPAID_internet_in': 'PREPAID',
         'PREPAID_internet_out': 'PREPAID_',
         'PREPAID_tasix_in': 'PREPAID_',
         'PREPAID_tasix_out': 'PREPAID_'}
    default_speeds = map(lambda x: int(handler.get_argument(x, '64')) * 1024,
                         ['speed_local', 'speed_tasix', 'speed_internet'])
    s['SHAPER'] = ' '.join(map(str, default_speeds))
    s['PREPAID'] = int(handler.get_argument('prepaid', '')) * 1024 * 1024
    accesses = []
    prices = []
    for name in handler.request.arguments.keys():
        if name.startswith('access_'):
            access = handler.get_argument(name, '')
            if access != 'accept' and access != 'reject':
                access = 'reject'
                continue_edit = True
            end = int(name[len('access_'):])
            int_speeds = []
            for i in [0, 1, 2]:
                speed = handler.get_argument('int_speed%d_%d' % (i, end), None)
                if speed is None:
                    continue_edit = True
                    speed = default_speeds[i]
                else:
                    speed = int(speed) * 1024
                int_speeds.append(speed)
            accesses.append([end, access, ' '.join(map(str, int_speeds))])
        elif name.startswith('price_'):
            price = float(handler.get_argument(name, '0'))
            end = int(name[len('price_'):])
            prices.append([end, {'tasix': [0, 0],
                                 'internet': [price, 0]}])
    add_action = handler.get_argument('add_i', '')
    if add_action == 'access':
        continue_edit = True
        hours, minutes = handler.get_argument(
            'new_ai_time', '24:00').split(':')
        end = int(hours, 10) * 3600 + int(minutes, 10) * 60
        access = handler.get_argument('new_ai_access', 'reject')
        if access != 'accept':
            access = 'reject'
        int_speeds = []
        for i in [0, 1, 2]:
            speed = handler.get_argument('new_ai_speed%d' % i, None)
            if speed is None:
                speed = default_speeds[i]
            else:
                speed = int(speed) * 1024
            int_speeds.append(speed)
        accesses.append([end, access, ' '.join(map(str, int_speeds))])
    elif add_action == 'price':
        continue_edit = True
        hours, minutes = handler.get_argument(
            'new_pi_time', '24:00').split(':')
        end = int(hours, 10) * 3600 + int(minutes, 10) * 60
        price = float(handler.get_argument('new_pi_price', '0'))
        prices.append([end, {'tasix': [0, 0],
                             'internet': [price, 0]}])
    accesses.sort()
    if len(accesses) == 1:
        if accesses[0][0] != 86400:
            accesses[0][0] = 86400
            continue_edit = True
    prices.sort()
    if len(prices) == 1:
        if prices[0][0] != 86400:
            prices[0][0] = 86400
            continue_edit = True
    elif len(prices) == 0:
        continue_edit = True

    remove_ai = handler.get_argument('remove_ai', '')
    if remove_ai != '':
        remove_ai = int(remove_ai)
        continue_edit = True
        accesses = filter(lambda x: x[0] != remove_ai, accesses)
    remove_pi = handler.get_argument('remove_pi', '')
    if remove_pi != '':
        remove_pi = int(remove_pi)
        continue_edit = True
        prices = filter(lambda x: x[0] != remove_pi, prices)

    s['ACCESS_INTERVALS'] = accesses
    s['INTERVALS'] = prices
    return s, continue_edit


class AdminEditAccountPage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self, account_id):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if admin.has_role('manager') or admin.has_role('bb'):
            raise tornado.web.HTTPError(403)
        account = self.session.query(Account).filter_by(id=account_id).one()
        if account.state != 'open':
            self.redirect(self.reverse_url(
                'AdminContractAccounts', account.contract.id))
            return
        plan_data = json.loads(account.plan_data)
        online_sessions = get_online_sessions(self.session)
        is_online = any(
            [s.account_id == account.id for s, a, c in online_sessions])
        plans = (self.session.query(Plan)
                 .filter_by(currency_id=account.contract.currency_id)
                 .order_by(Plan.name))
        new_plan = self.session.query(Plan).filter_by(
            id=account.new_plan_id).one()
        
        self.render('admin_edit_account.html',
                    section='accounts',
                    contract=account.contract,
                    account=account,
                    is_online=is_online,
                    plan_data=plan_data,
                    new_plan=new_plan,
                    plans=plans,
                    admin=admin)

    @tornado.web.authenticated
    def post(self, account_id):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if admin.has_role('manager') or admin.has_role('bb'):
            raise tornado.web.HTTPError(403)
        messages = []
        account = self.session.query(Account).filter_by(id=account_id).one()
        if account.state != 'open':
            self.redirect(self.reverse_url(
                'AdminContractAccounts', account.contract.id))
            return
        action = self.get_argument('action')
        if action == 'toggle_active':
            if not (admin.has_role('super') or admin.has_role('account_toggle')):
                raise tornado.web.HTTPError(403)
            account.active = not account.active
            kicked = False
            for session, a, c in get_online_sessions(self.session):
                if session.account_id == account.id:
                    kick_session(session.ip)
                    kicked = True
            if kicked:
                messages.append('Отправлен запрос на закрытие сессии логина.')
            if account.active:
                messages.append('Акканут включен.')
            else:
                messages.append('Аккаунт выключен.')
            self.set_flash_message(' '.join(messages))
            self.session.commit()
            self.redirect(self.reverse_url('AdminEditAccount', account.id))
            return

        if action == 'change_plan':
            new_plan_id = self.get_argument('new_plan')
            account.new_plan_id = int(new_plan_id)
            self.session.commit()
            self.set_flash_message('Переход тарифного плана запланирован.')
            self.redirect(self.reverse_url('AdminEditAccount', account.id))
            return
        online_sessions = get_online_sessions(self.session)
        is_online = any(
            [s.account_id == account.id for s, c, a in online_sessions])
        if not is_online and action == 'change_plan_immediate':
            account.plan_id = account.new_plan_id
            account.plan_data = account.plan.settings
            self.session.commit()
            self.set_flash_message('Перевод на новый тарифный план выполнен.')
            self.redirect(self.reverse_url('AdminEditAccount', account.id))
        password = self.get_argument('password', '')
        password2 = self.get_argument('password2', '')
        if password != '':
            if password != password2:
                self.set_flash_message(
                    'Пароль и его подтверждение не совпадают')
                self.redirect(self.reverse_url('AdminEditAccount', account.id))
                return
            password_good, error_message = is_acceptable_account_password(
                password)
            if password_good:
                account.password = password
                messages.append('Пароль изменён.')
            else:
                self.set_flash_message(error_message)
                self.redirect(self.reverse_url('AdminEditAccount', account.id))
                return
        contract_id = self.get_argument('contract_id')
        account.contract_id = int(contract_id)

        login = self.get_argument('login')
        account.login = login

        ip_address = self.get_argument('ip', '')
        current_ip_address = account.static_ip_address()
        if ip_address == '' and current_ip_address != '':
            account.clear_static_ip_address()
            messages.append('Статический ip-адрес удалён.')
        elif ip_address != '':
            if ip_address != current_ip_address:
                account.set_static_ip_address(ip_address)
                messages.append('Выставлен статический ip-адрес.')
        
        self.session.commit()
        if messages:
            self.set_flash_message(' '.join(messages))
        self.redirect(self.reverse_url('AdminEditAccount', account.id))


class AdminCloseAccountPage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self, account_id):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if not admin.has_role('close') or admin.has_role('manager'):
            raise tornado.web.HTTPError(403)
        account = self.session.query(Account).filter_by(id=account_id).one()
        self.render('admin_close_account.html',
                    section='accounts',
                    admin=admin,
                    account=account,
                    contract=account.contract)

    @tornado.web.authenticated
    def post(self, account_id):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if not admin.has_role('close') or admin.has_role('manager'):
            raise tornado.web.HTTPError(403)
        account = self.session.query(Account).filter_by(id=account_id).one()
        if account.state == 'closed':
            self.redirect(self.reverse_url(
                'AdminContractAccounts', account.contract.id))
            return
        if account.active:
            account.active = False
            for session, a, c in get_online_sessions(self.session):
                if session.account_id == account.id:
                    kick_session(session.ip)
        account.state = 'closed'
        account.closed_at = datetime.utcnow()
        account.clear_static_ip_address()
        self.session.commit()
        if self.get_argument('close_contract', '0') == '1':
            self.redirect(self.reverse_url(
                'AdminCloseContract', account.contract.id))
        else:
            self.redirect(self.reverse_url(
                'AdminContractAccounts', account.contract.id))


class AdminSuspendAccount(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self, account_id):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if not admin.has_role('close') or admin.has_role('manager'):
            raise tornado.web.HTTPError(403)
        account = self.session.query(Account).filter_by(id=account_id).one()
        if account.state != 'open':
            self.redirect(self.reverse_url('AdminContractAccounts',
                                           account.contract.id))
        else:
            self.render('admin_suspend_account.html',
                        section='accounts',
                        admin=admin,
                        account=account,
                        contract=account.contract)

    @tornado.web.authenticated
    def post(self, account_id):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if not admin.has_role('close') or admin.has_role('manager'):
            raise tornado.web.HTTPError(403)
        account = self.session.query(Account).filter_by(id=account_id).one()
        if account.state != 'open':
            self.redirect(self.reverse_url(
                'AdminContractAccounts', account.contract.id))
            return

        resume_date = self.get_argument('resume_date', '')
        suspend = ActionLogEntry()
        suspend.admin_id = admin.id
        suspend.target_type = 'account'
        suspend.target_id = account.id
        suspend.action = 'suspend'
        suspend.planned_at = datetime.utcnow()
        suspend.status = 'new'
        self.session.add(suspend)
        if resume_date != '':
            resume = ActionLogEntry()
            resume.admin_id = admin.id
            resume.target_type = 'account'
            resume.target_id = account.id
            resume.action = 'resume'
            resume.planned_at = string_to_utc_datetime(resume_date)
            resume.status = 'new'
            self.session.add(resume)
        self.session.commit()

        self.set_flash_message('Аккаунт будет приостановлен.')
        self.redirect(self.reverse_url(
            'AdminContractAccounts', account.contract.id))


class AdminResumeAccount(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self, account_id):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if not admin.has_role('close') or admin.has_role('manager'):
            raise tornado.web.HTTPError(403)
        account = self.session.query(Account).filter_by(id=account_id).one()
        if account.state != 'suspended':
            self.redirect(self.reverse_url('AdminContractAccounts',
                                           account.contract.id))
        else:
            self.render('admin_resume_account.html',
                        section='accounts',
                        admin=admin,
                        account=account,
                        contract=account.contract)

    @tornado.web.authenticated
    def post(self, account_id):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if not admin.has_role('close') or admin.has_role('manager'):
            raise tornado.web.HTTPError(403)
        account = self.session.query(Account).filter_by(id=account_id).one()
        if account.state != 'suspended':
            self.redirect(self.reverse_url(
                'AdminContractAccounts', account.contract.id))
            return

        resume = ActionLogEntry()
        resume.admin_id = admin.id
        resume.target_type = 'account'
        resume.target_id = account.id
        resume.action = 'resume'
        resume.planned_at = datetime.utcnow()
        resume.status = 'new'
        self.session.add(resume)
        self.session.commit()

        self.set_flash_message('Аккаунт будет возобновлён.')
        self.redirect(self.reverse_url(
            'AdminContractAccounts', account.contract.id))


class AdminChangeDiscountPage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self, account_id):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if not admin.has_role('plan') or admin.has_role('manager'):
            raise tornado.web.HTTPError(403)
        account = self.session.query(Account).filter_by(id=account_id).one()
        if account.state != 'open':
            raise tornado.web.HTTPError(403)
        self.render('admin_change_discount.html',
                    section='accounts',
                    admin=admin,
                    account=account,
                    contract=account.contract)

    @tornado.web.authenticated
    def post(self, account_id):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if not admin.has_role('plan') or admin.has_role('manager'):
            raise tornado.web.HTTPError(403)
        account = self.session.query(Account).filter_by(id=account_id).one()
        if account.state != 'open':
            self.redirect(self.reverse_url(
                'AdminContractAccounts', account.contract.id))
            return
        try:
            discount = int(self.get_argument('discount'))
            if discount < 0 or discount > 100:
                raise Exception()
        except:
            self.set_flash_message('Неверное значение скидки')
            self.redirect(self.reverse_url('AdminChangeDiscount', account_id))
            return
        special_till = string_to_utc_datetime(
            self.get_argument('special_till'))
        special = self.get_argument('special', '0') == '1' and discount > 0
        if special and special_till < datetime.utcnow():
            self.set_flash_message('Дата срока скидки уже прошла')
            self.redirect(self.reverse_url('AdminChangeDiscount', account_id))
            return
        a = ActionLogEntry()
        a.admin_id = admin.id
        a.target_type = 'account'
        a.target_id = account.id
        a.action = 'setDiscount'
        a.planned_at = datetime.utcnow()
        a.status = 'new'
        params = dict(discount=discount)
        if special:
            params['SpecialTill'] = str(special_till)
        a.params = json.dumps(params)
        self.session.add(a)
        self.session.commit()
        self.redirect(self.reverse_url(
            'AdminContractAccounts', account.contract.id))


class AdminChangeCreditPage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self, account_id):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if not (admin.has_role('credit') or admin.has_role('credit2')) or admin.has_role('manager'):
            raise tornado.web.HTTPError(403)
        account = self.session.query(Account).filter_by(id=account_id).one()
        if account.state != 'open':
            raise tornado.web.HTTPError(403)
        self.render('admin_change_credit.html',
                    section='accounts',
                    admin=admin,
                    account=account,
                    contract=account.contract)

    @tornado.web.authenticated
    def post(self, account_id):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if not (admin.has_role('credit') or admin.has_role('credit2')) or admin.has_role('manager'):
            raise tornado.web.HTTPError(403)
        account = self.session.query(Account).filter_by(id=account_id).one()
        if account.state != 'open':
            self.redirect(self.reverse_url(
                'AdminContractAccounts', account.contract.id))
            return
        try:
            credit = float(self.get_argument('credit'))
        except:
            self.set_flash_message('Неверное значение кредита')
            self.redirect(self.reverse_url('AdminChangeDiscount', account_id))
            return
        if credit < 0:
            self.set_flash_message('Неверное значение кредита')
            self.redirect(self.reverse_url('AdminChangeCredit', account_id))
            return
        web_action = self.get_argument('action', 'clear')
        if web_action == 'set':
            if admin.has_role('credit2'):
                deadline = self.get_argument('deadline', '')
                if deadline == '':
                    self.set_flash_message(
                        'Не задана дата окончания действия кредита')
                    self.redirect(self.reverse_url(
                        'AdminChangeCredit', account_id))
                    return
                deadline = string_to_utc_datetime(deadline)
                if deadline < datetime.utcnow():
                    self.set_flash_message(
                        'Неверное значение срока действия кредита')
                    self.redirect(self.reverse_url(
                        'AdminChangeCredit', account_id))
                    return
                deadline = str(deadline)
            else:
                deadline = self.get_argument('deadline', '1')
                deadline = int(deadline)
                if deadline < 1 or deadline > 7:
                    self.set_flash_message(
                        'Неверное значение срока действия кредита')
                    self.redirect(self.reverse_url(
                        'AdminChangeCredit', account_id))
                    return
                d = datetime.now() + timedelta(deadline)
                deadline = str(datetime_local_to_utc(
                    datetime(d.year, d.month, d.day, 0, 0, 0)))
        a = ActionLogEntry()
        a.admin_id = admin.id
        a.target_type = 'account'
        a.target_id = account.id
        if web_action == 'set':
            a.action = 'setCredit'
            params = dict(Amount=credit, Deadline=deadline)
            a.params = json.dumps(params)
        else:
            a.action = 'clearCredit'
            a.params = ''
        a.planned_at = datetime.utcnow()
        a.status = 'new'
        self.session.add(a)
        self.session.commit()
        self.redirect(self.reverse_url(
            'AdminContractAccounts', account.contract.id))


class AdminHomePage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self):
        start = time.time()
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        contracts = self.session.query(Contract)
        if admin.has_role('manager'):
            contracts = [c for c in contracts
                         if admin.id in adminapi.contract_managers(c.id)]
        s = {'state-open': 0, 'state-other': 0, 'debtors': 0}
        currencies = self.session.query(Currency).all()
        accounts = self.session.query(Account).all()

        s['debtor-per-currency'] = {}
        s['balance'] = 0
        s['balance_discount'] = 0

        for a in accounts:
            srv_params = self.session.query(ServiceParameters).filter_by(account_id=a.id).all()
            month_fee = json.loads(a.plan_data)
            if a.state == 'open':
                s['balance'] += int(month_fee['MONTHLY_FEE'])
                for param in srv_params:
                    s['balance_discount'] += int(month_fee['MONTHLY_FEE'])-int(param.discount)
        for c in currencies:
            s['debtor-per-currency'][c.id] = 0
        for c in contracts:
            if c.state == 'open':
                s['state-open'] += 1
                if c.balance < 0:
                    s['debtors'] += 1
                    s['debtor-per-currency'][c.currency_id] += c.balance
            else:
                s['state-other'] += 1
        if admin.has_role('manager'):
            s['online'] = 0
            for session, a, c in get_online_sessions(self.session):
                if admin.id in adminapi.contract_managers(c.id):
                    s['online'] += 1
        else:
            s['online'] = len(get_online_sessions(self.session))
        end = time.time()
        s['duration'] = end - start
        self.render('admin_home.html',
                    s=s,
                    currencies=currencies,
                    admin=admin)


class AdminDebtorsPage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if admin.has_role('bb'):
            raise tornado.web.HTTPError(403)
        debtors = self.session.query(Contract)
        kind = self.get_argument("k", "-1")
        if kind != "-1":
            debtors = debtors.filter(Contract.kind_id == int(kind))
        state = self.get_argument("state", "any")
        if state != "any":
            debtors = debtors.filter(Contract.state == state)
        debtors = debtors.filter(Contract.balance < 0)
        debtors = debtors.order_by(Contract.kind_id, Contract.balance).all()
        if admin.has_role('manager'):
            debtors = [c for c in debtors
                       if admin.id in adminapi.contract_managers(c.id)]
        monthly_fees = {}
        for c in debtors:
            monthly_fees[c.id] = adminapi.monthly_fees_sum(c.id)
        kinds = self.session.query(
            ContractKind).order_by(ContractKind.kind_name)
        self.render('admin_debtors.html',
                    debtors=debtors,
                    monthly_fees=monthly_fees,
                    kinds=kinds,
                    admin=admin)


class AdminSuspended(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if admin.has_role('bb'):
            raise tornado.web.HTTPError(403)
        contracts = self.session.query(Contract).filter(Contract.state == 'open')
        if admin.has_role('manager'):
            contracts = [c for c in contracts if admin.id in adminapi.contract_managers(c.id)]
        contracts = [c for c in contracts if any([a.state == 'suspended' for a in c.accounts])]
        managers = {}
        for c in contracts:
            try:
                managers[c.id] = sapiContract(c.id).get('Managers', [])
            except APIError:
                managers[c.id] = []
        self.render('admin_suspended.html',
                    contracts=contracts,
                    managers=managers,
                    admin=admin)

class AdminContractFilesPage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self, contract_id):
        contract = self.session.query(Contract).filter_by(id=contract_id).one()
        admin = self.session.query(Admin).filter_by(email=self.current_user, active=True).one()
        managers = adminapi.contract_managers(contract.id)
        if admin.has_role('manager') and admin.id not in managers:
            raise tornado.web.HTTPError(403)

        messages = []

        action = self.get_argument('action', 'delete')
        if action == 'delete':
            file_id = self.get_argument('id')
            file = self.session.query(ContractUploads).filter_by(id=file_id).one()
            file.status = "remove"
            self.session.commit()
            messages.append('Файл успешно удален.')
            self.set_flash_message(' '.join(messages))
            self.session.commit()
            self.redirect(self.reverse_url('AdminContractFiles', contract_id) + '?' + 'action=display')
            return
        elif action == 'display':
            files = self.session.query(ContractUploads).filter_by(contract_id=contract_id, status='active').all()
            self.render('admin_contract_files.html',
                            action=action,
                            contract=contract,
                            section='files',
                            sessions=None,
                            managers=managers,
                            admin=admin,
                            files=files)

    @tornado.web.authenticated
    def post(self, contract_id):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if not admin.has_role('plan') and not admin.has_role('super'):
            raise tornado.web.HTTPError(403)
        
        messages = []

        file = self.request.files['file'][0]
        new_name = str(uuid.uuid4()) + os.path.splitext(file['filename'])[1]
        
        output_file = open("uploads/" + new_name, 'w')
        output_file.write(file['body'])

        contract_file = ContractUploads()
        contract_file.contract_id = contract_id
        contract_file.admin_id = admin.real_name
        contract_file.file_name = new_name
        contract_file.type = self.get_argument('type')
        contract_file.size = os.path.getsize("uploads/" + new_name)
        contract_file.status = "active"
        contract_file.created_at = datetime.utcnow()
        self.session.add(contract_file)
        messages.append('Файл успешно загружен.')
        self.set_flash_message(' '.join(messages))
        self.session.commit()
        
        self.redirect(self.reverse_url(
                'AdminContractFiles', contract_id) + '?' + 'action=display')

class AdminOnlineSessionsPage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if admin.has_role('bb'):
            raise tornado.web.HTTPError(403)
        action = self.get_argument('action', 'view')
        if action == 'view':
            online = get_online_sessions_with_mac(self.session)
            if admin.has_role('manager'):
                filtered = []
                for s, a, c, mac in online:
                    if admin.id in adminapi.contract_managers(c.id):
                        filtered.append((s, a, c, mac))
                online = filtered
            self.render('admin_online_sessions.html',
                        action=action,
                        online=online,
                        admin=admin)
        else:
            session_id = int(self.get_argument('id'))
            session = self.session.query(
                TrafficSession).filter_by(id=session_id).one()
            self.render('admin_online_sessions.html',
                        action=action,
                        session=session,
                        admin=admin)

    @tornado.web.authenticated
    def post(self):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if admin.has_role('bb'):
            raise tornado.web.HTTPError(403)
        session_id = int(self.get_argument('id'))
        session = self.session.query(
            TrafficSession).filter_by(id=session_id).one()
        if session.finished_at is not None:
            self.redirect(self.reverse_url('AdminOnlineList'))
            return
        if kick_session(session.ip):
            self.set_flash_message(
                u'Запрос на закрытие сессии успешно отправлен')
        else:
            self.set_flash_message(u'Произошла ошибка')
        self.redirect(self.reverse_url('AdminOnlineList'))

# class AdminLogoutPage(BaseHandler):
#     def get(self):
#         self.clear_cookie('admin_user')
#         self.redirect(self.reverse_url('AdminLogin'))


class AdminLogoutPage(tornado.web.RequestHandler):
    def get(self):
        session_id = self.get_secure_cookie('a_sid')
        if session_id is not None:
            adminapi.logout(session_id)
        self.clear_cookie('a_sid')
        self.redirect(self.reverse_url('AdminLogin'))


class AdminConnectLogPage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        searched_for = self.get_argument('q', '').strip()
        results = connect_log_entries(options.netspire_log, searched_for)
        self.render('admin_connect_log.html',
                    searched_for=searched_for,
                    results=results,
                    admin=admin)


class AdminSettingsSpeedsPage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if not admin.has_role('port'):
            raise tornado.web.HTTPError(403)
        speeds = self.session.query(PortSpeed).order_by(
            PortSpeed.input, PortSpeed.output).all()
        self.render('admin_settings_speeds.html',
                    admin=admin,
                    speeds=speeds)


class AdminSettingsCOAreasPage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if not admin.has_role('port'):
            raise tornado.web.HTTPError(403)
        areas = self.session.query(COArea).order_by(COArea.name).all()
        self.render('admin_settings_co_areas.html',
                    admin=admin,
                    areas=areas)


class AdminPortsPage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if not admin.has_role('port'):
            raise tornado.web.HTTPError(403)
        providers = self.session.query(
            PortProvider).order_by(PortProvider.name)
        ports = self.session.query(Port).filter(Port.deleted_at != None)
        self.render('admin_ports.html',
                    admin=admin,
                    providers=providers,
                    ports=ports)


class AdminPortsStatsPage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if not admin.has_role('port'):
            raise tornado.web.HTTPError(403)
        ports = self.session.query(Port).filter(Port.deleted_at != None).all()
        providers = self.session.query(
            PortProvider).order_by(PortProvider.name)
        per_provider = {}
        for p in providers:
            per_provider[p.id] = {'name': p.name, 'count': 0}
        speeds = self.session.query(PortSpeed).order_by(PortSpeed.input)
        per_speed = {}
        for s in speeds:
            per_speed[s.id] = {'count': 0, 'speed': s}
        for p in ports:
            per_provider[p.port_provider_id]['count'] += 1
            per_speed[p.speed_id]['count'] += 1
        total = len(ports)
        self.render('admin_ports_stats.html',
                    admin=admin,
                    per_provider=per_provider,
                    per_speed=per_speed,
                    total=total)


class AdminNewPortPage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if not admin.has_role('port'):
            raise tornado.web.HTTPError(403)
        self.render_form(admin)

    def render_form(self, admin):
        areas = self.session.query(COArea).order_by(COArea.name)
        port_types = self.session.query(PortType).order_by(PortType.name)
        providers = self.session.query(
            PortProvider).order_by(PortProvider.name)
        speeds = self.session.query(PortSpeed).order_by(
            PortSpeed.input, PortSpeed.output)
        self.render('admin_new_port.html',
                    admin=admin,
                    port_types=port_types,
                    providers=providers,
                    speeds=speeds,
                    areas=areas)

    def post(self):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if not admin.has_role('port'):
            raise tornado.web.HTTPError(403)
        action = self.get_argument('action', '')
        if action == 'edit':
            self.render_form(admin)
        elif action == 'confirm':
            self.confirm(admin)
        else:
            # action == 'create'
            port_type = self.session.query(PortType).filter_by(
                id=self.get_argument('port_type')).one()
            provider = self.session.query(PortProvider).filter_by(
                id=self.get_argument('port_provider')).one()
            account = self.session.query(Account).filter_by(
                login=self.get_argument('login')).one()
            info = self.get_argument('info', '')
            co = self.session.query(CO).filter_by(
                id=self.get_argument('co')).one()
            speed = self.session.query(PortSpeed).filter_by(
                id=self.get_argument('speed')).one()
            new_port = Port()
            new_port.account = account
            new_port.port_type = port_type
            new_port.port_provider = provider
            new_port.info = info
            new_port.co = co
            new_port.speed = speed
            self.session.add(new_port)
            self.session.commit()
            self.redirect(self.reverse_url('AdminPorts'))

    def confirm(self, admin):
        port_type = self.session.query(PortType).filter_by(
            id=self.get_argument('port_type')).one()
        provider = self.session.query(PortProvider).filter_by(
            id=self.get_argument('port_provider')).one()
        login = self.get_argument('login', '')
        account = self.session.query(Account).filter_by(
            login=self.get_argument('login')).all()
        if len(account) > 0:
            account = account[0]
        else:
            account = None
        info = self.get_argument('info', '')
        co = self.session.query(CO).filter_by(id=self.get_argument('co')).one()
        speed = self.session.query(PortSpeed).filter_by(
            id=self.get_argument('speed')).one()
        self.render('admin_new_port_confirm.html',
                    admin=admin,
                    port_type=port_type,
                    provider=provider,
                    login=login,
                    account=account,
                    info=info,
                    co=co,
                    speed=speed)


class AdminEditPortPage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self, port_id):
        port_id = int(port_id)
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if not admin.has_role('port'):
            raise tornado.web.HTTPError(403)
        port = self.session.query(Port).filter_by(id=port_id).one()
        self.render_form(admin, port_id, port=port)

    def render_form(self, admin, port_id, port=None):
        areas = self.session.query(COArea).order_by(COArea.name)
        port_types = self.session.query(PortType).order_by(PortType.name)
        providers = self.session.query(
            PortProvider).order_by(PortProvider.name)
        speeds = self.session.query(PortSpeed).order_by(
            PortSpeed.input, PortSpeed.output)
        p = {}
        if port is not None:
            p['port_type'] = port.port_type.id
            p['port_provider'] = port.port_provider.id
            p['login'] = port.account.login
            p['info'] = port.info
            p['co'] = port.co.id
            p['speed'] = port.speed.id
        else:
            p['port_type'] = int(self.get_argument('port_type'))
            p['port_provider'] = int(self.get_argument('port_provider'))
            p['login'] = self.get_argument('login', '')
            p['info'] = self.get_argument('info', '')
            p['co'] = int(self.get_argument('co'))
            p['speed'] = int(self.get_argument('speed'))
        self.render('admin_edit_port.html',
                    admin=admin,
                    port_types=port_types,
                    providers=providers,
                    speeds=speeds,
                    areas=areas,
                    port_id=port_id,
                    p=p)

    def post(self, port_id):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        port_id = int(port_id)
        if not admin.has_role('port'):
            raise tornado.web.HTTPError(403)
        action = self.get_argument('action', '')
        if action == 'edit':
            self.render_form(admin, port_id)
        elif action == 'confirm':
            self.confirm(admin, port_id)
        else:
            # action == 'update'
            port = self.session.query(Port).filter_by(id=port_id).one()
            port_type = self.session.query(PortType).filter_by(
                id=self.get_argument('port_type')).one()
            provider = self.session.query(PortProvider).filter_by(
                id=self.get_argument('port_provider')).one()
            account = self.session.query(Account).filter_by(
                login=self.get_argument('login')).one()
            info = self.get_argument('info', '')
            co = self.session.query(CO).filter_by(
                id=self.get_argument('co')).one()
            speed = self.session.query(PortSpeed).filter_by(
                id=self.get_argument('speed')).one()
            port.account = account
            port.port_type = port_type
            port.port_provider = provider
            port.info = info
            port.co = co
            port.speed = speed
            self.session.commit()
            self.redirect(self.reverse_url('AdminPorts'))

    def confirm(self, admin, port_id):
        port_type = self.session.query(PortType).filter_by(
            id=self.get_argument('port_type')).one()
        provider = self.session.query(PortProvider).filter_by(
            id=self.get_argument('port_provider')).one()
        login = self.get_argument('login', '')
        account = self.session.query(Account).filter_by(
            login=self.get_argument('login')).all()
        if len(account) > 0:
            account = account[0]
        else:
            account = None
        info = self.get_argument('info', '')
        co = self.session.query(CO).filter_by(id=self.get_argument('co')).one()
        speed = self.session.query(PortSpeed).filter_by(
            id=self.get_argument('speed')).one()
        self.render('admin_edit_port_confirm.html',
                    admin=admin,
                    port_type=port_type,
                    provider=provider,
                    login=login,
                    account=account,
                    info=info,
                    co=co,
                    speed=speed,
                    port_id=port_id)


class AdminReportsDebtPage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if admin.has_role('bb'):
            raise tornado.web.HTTPError(403)
        session_id = self.get_secure_cookie('a_sid')
        today = datetime.now()
        currencies = self.session.query(Currency).all()
        year = int(self.get_argument('year', str(today.year)))
        if year < 2013 or year > today.year:
            year = today.year
        month = int(self.get_argument('month', str(today.month)))
        if month < 1 or month > 12 or year == today.year and month > today.month:
            month = today.month
        currency = int(self.get_argument('currency', str(currencies[0].id)))
        for c in currencies:
            if currency == c.id:
                break
        else:
            currency = currencies[0].id
        by_day = adminapi.debt_by_days(session_id, currency, year, month)
        bd = []
        for row in by_day:
            bd.append([row[0].day, float(row[1])])
        self.render('admin_reports_debt.html',
                    admin=admin,
                    by_day=by_day,
                    by_day_graph=bd,
                    currencies=currencies,
                    year=year, month=month,
                    today=today)


class AdminViewAdminsPage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if not admin.has_role('super') and not admin.has_role('supermanager'):
            raise tornado.web.HTTPError(403)
        admins = self.session.query(Admin).filter(
            Admin.id != 0).order_by(Admin.real_name).all()
        active_admins = [a for a in admins if a.active]
        disabled_admins = [a for a in admins if not a.active]
        self.render('admin_view_admins.html',
                    admin=admin,
                    active=active_admins,
                    disabled=disabled_admins)


class AdminViewAdminPage(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self, admin_id):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if not admin.has_role('super') and not admin.has_role('supermanager'):
            raise tornado.web.HTTPError(403)
        user = self.session.query(Admin).filter_by(id=int(admin_id)).one()
        # FIXME: here is a manager_id use that should be eliminated
        # contracts = self.session.query(Contract).filter_by(
        #     state='open', manager_id=user.id).all()
        raise Exception('not implemented')
        self.render('admin_view_admin.html',
                    admin=admin,
                    user=user,
                    contracts=contracts)


class AdminFindSession(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if not admin.has_role('find_session') and not admin.has_role('super'):
            raise tornado.web.HTTPError(403)
        ip = self.get_argument('ip', '')
        time = self.get_argument('time', '')
        if ip != '' and time != '':
            result = adminapi.find_session(ip, time)
        else:
            result = None
        self.render('admin_find_session.html',
                    result=result,
                    admin=admin)

class AdminBalance(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self):
        start = time.time()
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        contracts = self.session.query(Contract)
        if admin.has_role('manager'):
            contracts = [c for c in contracts
                         if admin.id in adminapi.contract_managers(c.id)]
        currencies = self.session.query(Currency).all()
        accounts = self.session.query(Account).all()
        s = {'state-open': 0, 'state-other': 0, 'debtors': 0, 'balance': 0}

        
        s['balance_open'] = 0
        s['balance_closed'] = 0
        s['balance_suspended'] = 0
        s['balance_discount_open'] = 0
        s['balance_discount_closed'] = 0
        s['balance_discount_suspended'] = 0

        for a in accounts:
            srv_params = self.session.query(ServiceParameters).filter_by(account_id=a.id).all()
            month_fee = json.loads(a.plan_data)

            if a.state == 'open':
                for param in srv_params:
                    s['balance_discount_open'] += int(month_fee['MONTHLY_FEE'])-int(param.discount)
                s['balance_open'] += int(month_fee['MONTHLY_FEE'])
            if a.state == 'closed':
                for param in srv_params:
                    s['balance_discount_closed'] += int(month_fee['MONTHLY_FEE'])-int(param.discount)
                s['balance_closed'] += int(month_fee['MONTHLY_FEE'])
            if a.state == 'suspended':
                for param in srv_params:
                    s['balance_discount_suspended'] += int(month_fee['MONTHLY_FEE'])-int(param.discount)
                s['balance_suspended'] += int(month_fee['MONTHLY_FEE'])
            
        
        self.render('admin_balance.html',
                    s=s,
                    currencies=currencies,
                    accounts=accounts,
                    admin=admin,
                    contracts=contracts
                    )


class AdminDebitsReport(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if not admin.has_role('reports') and not admin.has_role('super'):
            raise tornado.web.HTTPError(403)
        from_date = self.get_argument('from_date', '')
        kind = self.get_argument("k", "-1")
        names = None
        result = None
        details = None
        unknowns = None
        totals = None

        if from_date != '':
            from_date = string_to_utc_datetime(from_date)
            to_date = string_to_utc_datetime(self.get_argument('to_date'))
            # currency_id = int(self.get_argument('to_date'))
            if kind == '-1':
                result, unknowns = adminapi.debits_for_period(from_date, to_date, 2, None)
            else:
                result, unknowns = adminapi.debits_for_period(from_date, to_date, 2, kind)
            names = {}
            details = {}
            totals = collections.defaultdict(decimal.Decimal)
            for cid in result:
                contract = (self.session.query(Contract)
                            .filter_by(id=cid).one())
                names[cid] = contract.key_field.info_value
                details[cid] = {'link': '', 'ids': []}
                if result[cid]['unknown'] != 0:
                    details[cid]['link'] = (
                        self.reverse_url('AdminContractFlog', cid)
                        + '?' + '&'.join([
                            'from=' + self.get_argument('from_date'),
                            'till=' + self.get_argument('to_date'),
                            'kind=debit',
                        ]))
                for kind, amount in result[cid].items():
                    totals[kind] += amount
        kinds = self.session.query(ContractKind).order_by(ContractKind.kind_name)
        self.render('admin_debits_report.html',
                    kinds=kinds,
                    result=result,
                    names=names,
                    details=details,
                    unknowns=unknowns,
                    totals=totals,
                    admin=admin)


class AdminViewLogons(AdminAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self):
        admin = self.session.query(Admin).filter_by(
            email=self.current_user, active=True).one()
        if not (admin.has_role('super') or admin.has_role('view_logons')):
            raise tornado.web.HTTPError(403)
        when = self.get_argument('when', '')
        if when != '':
            start = string_to_utc_datetime(when)
            end = start + timedelta(1)
            result = adminapi.fetch_logons(start, end)
        else:
            result = None
        admins = {}
        for a in self.session.query(Admin).all():
            admins[a.id] = a
        self.render('admin_view_logons.html',
                    admin=admin,
                    admins=admins,
                    result=result)


class UserAreaMixin(object):
    def get_current_user(self):
        user_session_id = self.get_secure_cookie('u_sid')
        if user_session_id is None:
            return None
        login, ok = userapi.fetch_update_session(user_session_id)
        if ok:
            return login
        return None

    def name(self):
        name = self.get_cookie('u_name')
        if name is None:
            return None
        else:
            return base64.b64decode(name).decode('utf-8')


class UserDashboardPage(UserAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self):
        session_id = self.get_secure_cookie('u_sid')
        info = userapi.overview(session_id)
        try:
            result = sapiContract(info['contract_id'])
        except APIError:
            managers = []
        else:
            managers = result.get('Managers', [])
        self.render('user_dashboard.html', tab='overview', info=info,
                    managers=managers)


class UserLoginPage(BaseHandler):
    def get(self):
        next_url = self.get_argument(
            "next", default=self.reverse_url('UserDashboard'))
        self.render('user_login.html')

    def post(self):
        next_url = self.get_argument(
            "next", default=self.reverse_url('UserDashboard'))
        login = self.get_argument('login', default='')
        password = self.get_argument('password', default='')
        if login == '' or password == '':
            self.render('user_login.html')
            return
        session_id, ok = userapi.authenticate(login, password)
        if not ok:
            self.render('user_login.html')
            return
        name, ok = userapi.name(session_id)
        if not ok:
            self.render('user_login.html')
            return
        self.set_secure_cookie('u_sid', session_id)
        self.set_cookie('u_name', base64.b64encode(name.encode('utf-8')))
        self.redirect(next_url)


class UserLogoutPage(BaseHandler):
    def get(self):
        self.clear_cookie('u_sid')
        self.redirect(self.reverse_url('UserLogin'))


class UserFinanceLogPage(UserAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self):
        session_id = self.get_secure_cookie('u_sid')
        from_date = self.get_argument('from', None)
        till_date = self.get_argument('till', None)
        if from_date is None:
            now = datetime.now()
            from_date = str(datetime(now.year, now.month, 1, 0, 0, 0).date())
            till_date = str(now.date())
            userapi.fetch_update_session(session_id, update=True)
            transactions = None
        else:
            from_moment = string_to_utc_datetime(from_date)
            till_moment = string_to_utc_datetime(till_date)
            till_moment = till_moment + timedelta(1)
            kind = self.get_argument('kind')
            transactions, ok = userapi.transactions(
                session_id, from_moment, till_moment, kind)
        self.render('user_finance_log.html', tab='finance_log',
                    from_date=from_date,
                    till_date=till_date,
                    transactions=transactions)


class UserSessionLogPage(UserAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self):
        session_id = self.get_secure_cookie('u_sid')
        from_date = self.get_argument('from', None)
        till_date = self.get_argument('till', None)
        if from_date is None:
            now = datetime.now()
            from_date = str(datetime(now.year, now.month, 1, 0, 0, 0).date())
            till_date = str(now.date())
            userapi.fetch_update_session(session_id, update=True)
            sessions = None
        else:
            from_moment = string_to_utc_datetime(from_date)
            till_moment = string_to_utc_datetime(till_date)
            till_moment = till_moment + timedelta(1)
            sessions, ok = userapi.sessions(
                session_id, from_moment, till_moment)
        self.render('user_session_log.html', tab='sessions',
                    from_date=from_date,
                    till_date=till_date,
                    sessions=sessions)

class UserPasswordChangePage(UserAreaMixin, BaseHandler):
    @tornado.web.authenticated
    def get(self):
        userapi.fetch_update_session(
            self.get_secure_cookie('u_sid'), update=True)
        self.render('user_password_change.html', tab='change_password')

    @tornado.web.authenticated
    def post(self):
        self.redirect(self.reverse_url('UserPasswordChange'))
        return  # password changing disabled
        password = self.get_argument('password', '')
        new_password = self.get_argument('new_password', '')
        confirmation = self.get_argument('confirmation', '')
        if password == '':
            self.redirect(self.reverse_url('UserPasswordChange'))
            return
        if new_password != confirmation:
            self.set_flash_message(u'Пароль и его подтверждение не совпадают.')
            self.redirect(self.reverse_url('UserPasswordChange'))
            return
        if len(new_password) < 6:
            self.set_flash_message(u'Минимальная длина пароля - 6 символов.')
            self.redirect(self.reverse_url('UserPasswordChange'))
            return
        ok = userapi.change_password(
            self.get_secure_cookie('u_sid'), password, new_password)
        if not ok:
            self.set_flash_message(u'Неверный текущий пароль.')
            self.redirect(self.reverse_url('UserPasswordChange'))
            return
        self.set_flash_message(u'Пароль успешно изменён.')
        self.redirect(self.reverse_url('UserDashboard'))


def check_passwords(password, hashed):
    salt = hashed[0: 2]
    h = hashlib.sha1()
    h.update(salt)
    h.update(password)
    return h.hexdigest() == hashed[2:]


def create_password(password):
    salt_chars = map(chr, range(ord('a'), ord('z') + 1))
    salt_chars.extend(map(chr, range(ord('A'), ord('Z') + 1)))
    salt = random.choice(salt_chars) + random.choice(salt_chars)
    return salt + hashlib.sha1(salt + password).hexdigest()


def application():
    settings = dict(upload_path=make_path('uploads'),
                    static_path=make_path('static'),
                    template_path=make_path('templates'),
                    ui_modules=uimodules,
                    cookie_secret=options.cookie_secret,
                    admin_login_url='/admin/login',
                    login_url='/user/login')
    url = tornado.web.URLSpec
    return tornado.web.Application([
        (r'/', FrontRedirectHandler),
        url(r'/admin/login', AdminLogin, name='AdminLogin'), 
        url(r'/admin/', AdminHomePage, name='AdminHome'), 
        url(r'/admin/balance', AdminBalance, name='AdminBalance'),
        url(r'/admin/users', AdminsPage, name='Admins'),
        url(r'/admin/accounts/(\d+)/', AdminEditAccountPage, name='AdminEditAccount'), 
        url(r'/admin/accounts/(\d+)/close', AdminCloseAccountPage, name='AdminCloseAccount'),
        url(r'/admin/accounts/(\d+)/credit', AdminChangeCreditPage, name='AdminChangeCredit'),
        url(r'/admin/accounts/(\d+)/discount', AdminChangeDiscountPage, name='AdminChangeDiscount'),
        url(r'/admin/accounts/(\d+)/comment', AdminAccountChangeComment, name='AdminAccountChangeComment'),
        url(r'/admin/accounts/(\d+)/suspend', AdminSuspendAccount, name='AdminSuspendAccount'),
        url(r'/admin/accounts/(\d+)/resume', AdminResumeAccount, name='AdminResumeAccount'),
        url(r'/admin/contracts/(\d+)/files', AdminContractFilesPage, name='AdminContractFiles'),
        url(r'/admin/contracts/(\d+)/resume', AdminResumeContractPage, name='AdminResumeContract'),
        url(r'/admin/contracts/(\d+)/', AdminContractOverviewPage, name='AdminContractOverview'),
        url(r'/admin/contracts/(\d+)/info', AdminContractInfoPage, name='AdminContractInfo'),
        url(r'/admin/contracts/(\d+)/info-edit', AdminContractInfoEditPage, name='AdminContractInfoEdit'),
        url(r'/admin/contracts/(\d+)/accounts', AdminContractAccountsPage, name='AdminContractAccounts'),
        url(r'/admin/contracts/(\d+)/flog', AdminContractFLogPage, name='AdminContractFlog'),
        url(r'/admin/contracts/(\d+)/foper', AdminContractFOperPage, name='AdminContractFOper'),
        url(r'/admin/contracts/(\d+)/fedit/(\d+)/', AdminEditFinTransaction, name='AdminEditFinTransaction'),
        url(r'/admin/contracts/(\d+)/sessions', AdminContractSessionsPage, name='AdminContractSessions'),
        url(r'/admin/contracts/(\d+)/monitoring', AdminContractMonitoringPage, name='AdminContractMonitoring'),
        url(r'/admin/contracts/(\d+)/close', AdminCloseContractPage, name='AdminCloseContract'),
        url(r'/admin/contracts/(\d+)/invoices/', AdminListInvoicesPage, name='AdminListInvoices'),
        url(r'/admin/contracts/(\d+)/invoice/(\d+)/(\d+)/', AdminViewInvoicePage, name='AdminViewInvoice'),
        url(r'/admin/contracts/(\d+)/invoice/(\d+)/(\d+)/ods/(.*)', AdminODSInvoicePage, name='AdminODSInvoice'),
        url(r'/admin/contracts/search', AdminSearch, name='ContractSearch'),
        url(r'/admin/contracts/create/(\d*)', ContractCreate, name='ContractCreate'),
        url(r'/admin/contracts/debtors/', AdminDebtorsPage, name='AdminDebtors'),
        url(r'/admin/contracts/suspended/', AdminSuspended, name='AdminSuspended'),
        url(r'/admin/settings/info/(\d*)', SettingsInfos, name='SettingsInfos'),
        url(r'/admin/settings/kinds', SettingsKinds, name='SettingsKinds'),
        url(r'/admin/settings/plans', AdminSettingsPlansPage, name='AdminSettingsPlans'),
        url(r'/admin/settings/plans/(\d+)', AdminSettingsPlansEditPage, name='AdminSettingsPlansEdit'),
        url(r'/admin/settings/plans/view/(\d+)', AdminSettingsPlansViewPage, name='AdminSettingsPlansView'),
        url(r'/admin/settings/plans/create', AdminSettingsPlansCreatePage, name='AdminSettingsPlansCreate'),
        url(r'/admin/admins/', AdminViewAdminsPage, name='AdminViewAdmins'),
        url(r'/admin/admins/(\d+)/', AdminViewAdminPage, name='AdminViewAdmin'),
        url(r'/admin/connect_log', AdminConnectLogPage, name='AdminConnectLog'),
        url(r'/admin/online', AdminOnlineSessionsPage, name='AdminOnlineList'),
        url(r'/admin/currency', AdminSettingsCurrencyPage, name='AdminSettingsCurrency'),
        url(r'/admin/logout', AdminLogoutPage, name='AdminLogout'),
        url(r'/admin/ports', AdminPortsPage, name='AdminPorts'),
        url(r'/admin/ports/stats', AdminPortsStatsPage, name='AdminPortsStats'),
        url(r'/admin/ports/new', AdminNewPortPage, name='AdminNewPort'),
        url(r'/admin/ports/edit/(\d+)', AdminEditPortPage, name='AdminEditPort'),
        url(r'/admin/settings/speeds', AdminSettingsSpeedsPage, name='AdminSettingsSpeeds'),
        url(r'/admin/settings/co_areas', AdminSettingsCOAreasPage, name='AdminSettingsCOAreas'),
        url(r'/admin/settings/logons', AdminViewLogons, name='AdminViewLogons'),
        url(r'/admin/reports/debt', AdminReportsDebtPage, name='AdminReportsDebt'),
        url(r'/admin/reports/ip', AdminFindSession, name='AdminFindSession'),
        url(r'/admin/reports/debits', AdminDebitsReport, name='AdminDebitsReport'),
        url(r'/user/', UserDashboardPage, name='UserDashboard'),
        url(r'/user/login', UserLoginPage, name='UserLogin'),
        url(r'/user/logout', UserLogoutPage, name='UserLogout'),
        url(r'/user/finance', UserFinanceLogPage, name='UserFinanceLog'),
        url(r'/user/sessions', UserSessionLogPage, name='UserSessionLog'),
        url(r'/user/password', UserPasswordChangePage, name='UserPasswordChange')
    ], **settings)


def prepare_database():
    global db_engine, session_maker
    url = 'postgres://{0}:{1}@{2}/{3}'.format(options.db_user,
                                              options.db_password,
                                              options.db_host,
                                              options.db_name)
    db_engine = sqlalchemy.create_engine(url, poolclass=NullPool)
    session_maker = sqlalchemy.orm.sessionmaker(bind=db_engine)
    userapi.set_session_maker(session_maker)
    adminapi.set_session_maker(session_maker)


if __name__ == "__main__":
    define('config', help='configuration file')
    define('cookie_secret', help='cookie secret')
    define('db_host', default='127.0.0.1', help='database host')
    define('db_name', help='database name')
    define('db_user', help='database user name')
    define('db_password', help='database password')
    define('interim_update_interval', type=int,
           default=65, help='Acct-Interim-Interval value')
    define('nas', help='NAS url')
    define('netspire_log', help='Netspire log file location')
    parse_command_line()
    if options.config:
        parse_config_file(options.config)
    prepare_database()
    application().listen(8888)
    tornado.ioloop.IOLoop.instance().start()
