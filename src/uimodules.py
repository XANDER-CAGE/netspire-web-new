# -*- coding: utf-8 -*-

import json
import tornado.web

class FlashMessage(tornado.web.UIModule):
    def render(self, message):
        if message is not None:
            return self.render_string('flash-message.html', message=message)
        else:
            return ''

class PlanEditor(tornado.web.UIModule):
    def render(self, currencies, plan, settings):
        return self.render_string('ui_create_plan.html',
                                  currencies=currencies,
                                  plan=plan,
                                  settings=settings)

class ContractInfoEditor(tornado.web.UIModule):
    def render(self, contract):
        infos = {}
        for info in contract.infos:
            infos[info.info_id] = info.info_value
        return self.render_string('ui_contract_info_edit.html',
                                  contract = contract,
                                  infos = infos)

class RenderAccountInfo(tornado.web.UIModule):
    def render(self, admin, account, managers):
        plan_data = json.loads(account.plan_data)
        return self.render_string('ui_account_info.html',
                                  admin = admin,
                                  account = account,
                                  managers = managers,
                                  plan_data = plan_data)
