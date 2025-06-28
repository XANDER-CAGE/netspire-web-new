# -*- coding: utf-8 -*-

import datetime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import (
    Boolean,
    Column,
    Date,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Integer,
    Numeric,
    String
)
from sqlalchemy.orm import Session, relationship

__all__ = [
    'Account',
    'ActionLogEntry',
    'Admin',
    'AssignedRadiusReply',
    'CO',
    'COArea',
    'Contract',
    'ContractInfo',
    'ContractInfoItem',
    'ContractKind',
    'Currency',
    'CurrencyRate',
    'FinTransaction',
    'Plan',
    'Port',
    'PortProvider',
    'PortSpeed',
    'PortType',
    'RadiusReply',
    'SessionDetail',
    'TrafficSession',
    'ContractUploads',
    'ServiceParameters'
]

Base = declarative_base()


class ContractKind(Base):
    __tablename__ = 'contract_kinds'

    id = Column(Integer, primary_key=True)
    kind_name = Column(String, unique=True)
    description = Column(String, nullable=False)
    fields = relationship('ContractInfoItem',
                          order_by='ContractInfoItem.sort_order',
                          backref='kind')


class Admin(Base):
    __tablename__ = 'admins'

    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True)
    active = Column(Boolean, nullable=False, default=True)
    password = Column(String, nullable=False)
    real_name = Column(String, nullable=False)
    created_at = Column(Date, nullable=False, default=datetime.date.today)
    roles = Column(String, nullable=False)
    phone = Column(String, nullable=False, default='')

    def has_role(self, role):
        return role in self.roles.split(',')


class ContractInfoItem(Base):
    __tablename__ = 'contract_info_items'

    kind_id = Column(Integer, ForeignKey('contract_kinds.id'),
                     primary_key=True)
    id = Column(Integer, primary_key=True)
    sort_order = Column(Integer, nullable=False)
    field_name = Column(String, nullable=False, unique=True)
    field_description = Column(String, nullable=False)


class Currency(Base):
    __tablename__ = 'currencies'
    id = Column(Integer, primary_key=True)
    short_name = Column(String, nullable=False, unique=True)
    name = Column(String, nullable=False, unique=True)
    description = Column(String, nullable=False)
    active = Column(Boolean, nullable=False, default=True)


class Contract(Base):
    __tablename__ = 'contracts'
    id = Column(Integer, nullable=False, unique=True, primary_key=True)
    kind_id = Column(Integer, ForeignKey('contract_kinds.id'),
                     nullable=False, primary_key=True)
    balance = Column(Numeric(20, 10, asdecimal=True), nullable=False,
                     default=0)
    created_at = Column(Date, nullable=False, default=datetime.datetime.utcnow)
    updated_at = Column(Date, nullable=False, default=datetime.datetime.utcnow)
    currency_id = Column(Integer, ForeignKey('currencies.id'), nullable=False)
    state = Column(String, nullable=False, default='open')
    closed_at = Column(DateTime, nullable=True)

    currency = relationship('Currency')
    kind = relationship('ContractKind')
    accounts = relationship(
        'Account', order_by='Account.login', backref='contract')
    infos = relationship('ContractInfo', backref='contract')

    @property
    def key_field(self):
        if len(self.kind.fields) == 0:
            return None
        key_id = self.kind.fields[0].id
        for f in self.infos:
            if key_id == f.info_id:
                return f
        return None


class ContractInfo(Base):
    __tablename__ = 'contract_info'
    id = Column(Integer, primary_key=True)
    kind_id = Column(Integer, nullable=False, autoincrement=False)
    contract_id = Column(Integer, nullable=False, autoincrement=False)
    info_id = Column(Integer, nullable=False, autoincrement=False)
    info_value = Column(String, nullable=False, default='')
    __table_args__ = (
        ForeignKeyConstraint([kind_id, info_id],
                             [ContractInfoItem.kind_id, ContractInfoItem.id]),
        ForeignKeyConstraint([kind_id, contract_id],
                             [Contract.kind_id, Contract.id])
    )
    field = relationship('ContractInfoItem')


class FinTransaction(Base):
    __tablename__ = 'fin_transactions'
    id = Column(Integer, primary_key=True)
    kind_id = Column(Integer, nullable=False)
    contract_id = Column(Integer, nullable=False)
    currency_id = Column(Integer, ForeignKey('currencies.id'), nullable=False)
    amount = Column(Numeric(20, 10, asdecimal=True), nullable=False)
    amount_in_contract_currency = Column(
        Numeric(20, 10, asdecimal=True), nullable=False)
    created_at = Column(DateTime, nullable=False,
                        default=datetime.datetime.utcnow)
    balance_after = Column(Numeric(20, 10, asdecimal=True), nullable=False)
    comment = Column(String, nullable=False)
    admin_id = Column(Integer, ForeignKey('admins.id'), nullable=False)
    __table_args__ = (ForeignKeyConstraint([kind_id, contract_id],
                                           [Contract.kind_id, Contract.id]),)
    admin = relationship('Admin')
    currency = relationship('Currency')


class CurrencyRate(Base):
    __tablename__ = 'currencies_rate'
    from_id = Column(Integer, ForeignKey('currency.id'),
                     nullable=False, primary_key=True)
    to_id = Column(Integer, ForeignKey('currency.id'),
                   nullable=False, primary_key=True)
    rate = Column(Numeric(20, 10, asdecimal=True), nullable=False)


class Plan(Base):
    __tablename__ = 'plans'
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False, unique=True)
    code = Column(String, nullable=False, unique=True)
    currency_id = Column(Integer, ForeignKey('currencies.id'), nullable=False)
    created_at = Column(DateTime, nullable=False,
                        default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, nullable=False,
                        default=datetime.datetime.utcnow)
    auth_algo = Column(String, nullable=False)
    acct_algo = Column(String, nullable=False)
    settings = Column(String, nullable=False)

    currency = relationship('Currency')


class Account(Base):
    __tablename__ = 'accounts'
    id = Column(Integer, primary_key=True)
    contract_id = Column(Integer, ForeignKey('contracts.id'), nullable=False)
    plan_id = Column(Integer, ForeignKey('plans.id'), nullable=False)
    login = Column(String, nullable=False, unique=True)
    password = Column(String, nullable=False)
    active = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False,
                        default=datetime.datetime.utcnow)
    plan_data = Column(String, nullable=False, default='')
    new_plan_id = Column(Integer)
    state = Column(String, nullable=False, default='open')
    closed_at = Column(DateTime, nullable=True)
    plan = relationship('Plan')
    comment = Column(String, nullable=False, default='')

    def clear_static_ip_address(self):
        session = Session.object_session(self)
        f_ip_a = session.query(RadiusReply).filter_by(
            name='Framed-IP-Address').one()
        assigned_replies = (session.query(AssignedRadiusReply)
                            .filter_by(target_id=self.id)
                            .filter_by(target_type='Account')
                            .filter_by(radius_reply_id=f_ip_a.id)
                            .all())
        for ip in assigned_replies:
            session.delete(ip)

    def static_ip_address(self):
        session = Session.object_session(self)
        f_ip_a = session.query(RadiusReply).filter_by(
            name='Framed-IP-Address').one()
        assigned_replies = (session.query(AssignedRadiusReply)
                            .filter_by(target_id=self.id)
                            .filter_by(target_type='Account')
                            .filter_by(radius_reply_id=f_ip_a.id)
                            .all())
        if len(assigned_replies) == 0:
            return ''
        else:
            return assigned_replies[0].value

    def set_static_ip_address(self, ip_address):
        session = Session.object_session(self)
        f_ip_a = session.query(RadiusReply).filter_by(
            name='Framed-IP-Address').one()
        assigned_replies = (session.query(AssignedRadiusReply)
                            .filter_by(target_id=self.id)
                            .filter_by(target_type='Account')
                            .filter_by(radius_reply_id=f_ip_a.id)
                            .all())
        if len(assigned_replies) > 0:
            if assigned_replies[0].value != ip_address:
                assigned_replies[0].value = ip_address
                assigned_replies[0].updated_at = datetime.datetime.utcnow()
        else:
            new_address = AssignedRadiusReply()
            new_address.target_id = self.id
            new_address.target_type = 'Account'
            new_address.radius_reply_id = f_ip_a.id
            new_address.value = ip_address
            new_address.created_at = datetime.datetime.utcnow()
            new_address.updated_at = new_address.created_at
            session.add(new_address)


class ServiceParameters(Base):
    __tablename__ = 'service_params'
    account_id = Column(Integer, ForeignKey('accounts.id'), primary_key=True)
    discount = Column(Integer, nullable=False)
    special_till = Column(DateTime, nullable=True)
    credit = Column(Numeric(20, 10, asdecimal=True), nullable=False)
    credit_deadline = Column(DateTime, nullable=True)
    account = relationship('Account', backref='service_parameters')
    ip_price = Column(Numeric(20, 10, asdecimal=True), nullable=False)


class TrafficSession(Base):
    __tablename__ = 'iptraffic_sessions'
    id = Column(Integer, primary_key=True)
    account_id = Column(Integer, ForeignKey('accounts.id'), nullable=False)
    sid = Column(String, nullable=False)
    ip = Column(String, nullable=False)
    octets_in = Column(Integer, nullable=False, default=0)
    octets_out = Column(Integer, nullable=False, default=0)
    amount = Column(Numeric(20, 10, asdecimal=True), nullable=False)
    started_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    expired = Column(Boolean, nullable=True)
    account = relationship('Account')
    details = relationship(
        'SessionDetail', order_by='SessionDetail.traffic_class')


class SessionDetail(Base):
    __tablename__ = 'session_details'
    id = Column(Integer, ForeignKey('iptraffic_sessions.id'), primary_key=True)
    traffic_class = Column(String, primary_key=True)
    octets_in = Column(Integer, nullable=False)
    octets_out = Column(Integer, nullable=False)


class RadiusReply(Base):
    __tablename__ = 'radius_replies'
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    description = Column(String)
    active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, nullable=True)


class AssignedRadiusReply(Base):
    __tablename__ = 'assigned_radius_replies'
    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, nullable=False)
    target_type = Column(String, nullable=False)
    radius_reply_id = Column(Integer, ForeignKey(
        'radius_replies.id'), nullable=False)
    value = Column(String, nullable=False)
    created_at = Column(DateTime, nullable=True,
                        default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, nullable=True,
                        default=datetime.datetime.utcnow)


class PortSpeed(Base):
    __tablename__ = 'speeds'
    id = Column(Integer, primary_key=True)
    input = Column(Integer, nullable=False)
    output = Column(Integer, nullable=False)


class COArea(Base):
    __tablename__ = 'co_area'
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)
    COs = relationship('CO', order_by='CO.name', backref='area')


class CO(Base):
    __tablename__ = 'co'
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)
    area_id = Column(Integer, ForeignKey('co_area.id'), nullable=False)


class PortType(Base):
    __tablename__ = 'port_types'
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)


class PortProvider(Base):
    __tablename__ = 'port_providers'
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)


class Port(Base):
    __tablename__ = 'ports'
    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, nullable=False,
                        default=datetime.datetime.utcnow)
    deleted_at = Column(DateTime, nullable=True,
                        default=datetime.datetime.utcnow)
    account_id = Column(Integer, ForeignKey('accounts.id'), nullable=True)
    port_type_id = Column(Integer, ForeignKey('port_types.id'), nullable=False)
    port_provider_id = Column(Integer, ForeignKey(
        'port_providers.id'), nullable=False)
    info = Column(String, nullable=False)
    co_id = Column(Integer, ForeignKey('co.id'), nullable=False)
    speed_id = Column(Integer, ForeignKey('speeds.id'), nullable=False)

    account = relationship('Account')
    port_type = relationship('PortType')
    port_provider = relationship('PortProvider')
    co = relationship('CO')
    speed = relationship('PortSpeed')


class ActionLogEntry(Base):
    __tablename__ = 'action_log'
    id = Column(Integer, primary_key=True)
    admin_id = Column(Integer, ForeignKey('admins.id'), nullable=False)
    target_type = Column(String, nullable=False)
    target_id = Column(Integer, nullable=True)
    action = Column(String, nullable=False)
    params = Column(String, nullable=False, default='')
    parent_action_id = Column(
        Integer, ForeignKey('action_log.id'), nullable=True)
    planned_at = Column(DateTime, nullable=False,
                        default=datetime.datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    status = Column(String, nullable=False)

    admin = relationship('Admin')

class ContractUploads(Base):
    __tablename__ = 'contract_uploads'
    id = Column(Integer, primary_key=True)
    contract_id = Column(Integer, nullable=False, unique=True)
    admin_name = Column(Integer, nullable=False, unique=True)
    file_name = Column(String, nullable=False, unique=True)
    type = Column(String, nullable=False)
    size = Column(Integer, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)
    status = Column(String, nullable=False)