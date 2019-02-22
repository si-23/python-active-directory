#
# This file is part of Python-AD. Python-AD is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# Python-AD is copyright (c) 2007 by the Python-AD authors. See the file
# "AUTHORS" for a complete overview.

from __future__ import absolute_import
import pytest

from activedirectory.core.object import activate
from activedirectory.core.client import Client
from activedirectory.core.locate import Locator
from activedirectory.core.constant import AD_USERCTRL_NORMAL_ACCOUNT
from activedirectory.core.creds import Creds
from activedirectory.core.exception import Error as ADError
from six.moves import range

from ..base import assert_raises
from . import utils


class TestADClient(object):
    """Test suite for ADClient"""

    def test_search(self, conf):
        pytest.skip('test disabled: hanging')
        conf.require(ad_user=True)
        domain = conf.domain()
        creds = Creds(domain)
        creds.acquire(conf.ad_user_account(), conf.ad_user_password())
        activate(creds)
        client = Client(domain)
        result = client.search('(objectClass=user)')
        assert len(result) > 1

    def test_add(self, conf):
        conf.require(ad_admin=True)
        domain = conf.domain()
        creds = Creds(domain)
        creds.acquire(conf.ad_admin_account(), conf.ad_admin_password())
        activate(creds)
        client = Client(domain)
        user = utils.create_user(client, 'test-usr')
        delete_obj(client, user)

    def test_delete(self, conf):
        conf.require(ad_admin=True)
        domain = conf.domain()
        creds = Creds(domain)
        creds.acquire(conf.ad_admin_account(), conf.ad_admin_password())
        activate(creds)
        client = Client(domain)
        dn = utils.create_user(client, 'test-usr')
        client.delete(dn)

    def test_modify(self, conf):
        conf.require(ad_admin=True)
        domain = conf.domain()
        creds = Creds(domain)
        creds.acquire(conf.ad_admin_account(), conf.ad_admin_password())
        activate(creds)
        client = Client(domain)
        user = utils.create_user(client, 'test-usr')
        mods = []
        mods.append(('replace', 'sAMAccountName', ['test-usr-2']))
        client.modify(user, mods)
        delete_obj(client, user)

    def test_modrdn(self, conf):
        conf.require(ad_admin=True)
        domain = conf.domain()
        creds = Creds(domain)
        creds.acquire(conf.ad_admin_account(), conf.ad_admin_password())
        activate(creds)
        client = Client(domain)
        result = client.search('(&(objectClass=user)(sAMAccountName=test-usr))')
        if result:
            client.delete(result[0][0])
        user = utils.create_user(client, 'test-usr')
        client.modrdn(user, 'cn=test-usr2')
        result = client.search('(&(objectClass=user)(cn=test-usr2))')
        assert len(result) == 1

    def test_rename(self, conf):
        conf.require(ad_admin=True)
        domain = conf.domain()
        creds = Creds(domain)
        creds.acquire(conf.ad_admin_account(), conf.ad_admin_password())
        activate(creds)
        client = Client(domain)
        result = client.search('(&(objectClass=user)(sAMAccountName=test-usr))')
        if result:
            client.delete(result[0][0])
        user = utils.create_user(client, 'test-usr')
        client.rename(user, 'cn=test-usr2')
        result = client.search('(&(objectClass=user)(cn=test-usr2))')
        assert len(result) == 1
        user = result[0][0]
        ou = utils.create_ou(client, 'test-ou')
        client.rename(user, 'cn=test-usr', ou)
        newdn = 'cn=test-usr,%s' % ou
        result = client.search('(&(objectClass=user)(cn=test-usr))')
        assert len(result) == 1
        assert result[0][0].lower() == newdn.lower()

    def test_forest(self, conf):
        conf.require(ad_user=True)
        domain = conf.domain()
        creds = Creds(domain)
        creds.acquire(conf.ad_user_account(), conf.ad_user_password())
        activate(creds)
        client = Client(domain)
        forest = client.forest()
        assert forest
        assert forest.isupper()

    def test_domains(self, conf):
        conf.require(ad_user=True)
        domain = conf.domain()
        creds = Creds(domain)
        creds.acquire(conf.ad_user_account(), conf.ad_user_password())
        activate(creds)
        client = Client(domain)
        domains = client.domains()
        for domain in domains:
            assert domain
            assert domain.isupper()

    def test_naming_contexts(self, conf):
        conf.require(ad_user=True)
        domain = conf.domain()
        creds = Creds(domain)
        creds.acquire(conf.ad_user_account(), conf.ad_user_password())
        activate(creds)
        client = Client(domain)
        naming_contexts = client.naming_contexts()
        assert len(naming_contexts) >= 3

    def test_search_all_domains(self, conf):
        conf.require(ad_user=True)
        domain = conf.domain()
        creds = Creds(domain)
        creds.acquire(conf.ad_user_account(), conf.ad_user_password())
        activate(creds)
        client = Client(domain)
        domains = client.domains()
        for domain in domains:
            base = client.dn_from_domain_name(domain)
            result = client.search('(objectClass=*)', base=base, scope='base')
            assert len(result) == 1

    def test_search_schema(self, conf):
        conf.require(ad_user=True)
        domain = conf.domain()
        creds = Creds(domain)
        creds.acquire(conf.ad_user_account(), conf.ad_user_password())
        activate(creds)
        client = Client(domain)
        base = client.schema_base()
        result = client.search('(objectClass=*)', base=base, scope='base')
        assert len(result) == 1

    def test_search_configuration(self, conf):
        conf.require(ad_user=True)
        domain = conf.domain()
        creds = Creds(domain)
        creds.acquire(conf.ad_user_account(), conf.ad_user_password())
        activate(creds)
        client = Client(domain)
        base = client.configuration_base()
        result = client.search('(objectClass=*)', base=base, scope='base')
        assert len(result) == 1

    def test_incremental_retrieval_of_multivalued_attributes(self, conf):
        conf.require(ad_admin=True, expensive=True)
        domain = conf.domain()
        creds = Creds(domain)
        creds.acquire(conf.ad_admin_account(), conf.ad_admin_password())
        activate(creds)
        client = Client(domain)
        user = utils.create_user(client, 'test-usr')
        groups = []
        for i in range(2000):
            group = utils.create_group(client, 'test-grp-%04d' % i)
            utils.add_user_to_group(client, user, group)
            groups.append(group)
        result = client.search('(sAMAccountName=test-usr)')
        assert len(result) == 1
        dn, attrs = result[0]
        assert 'memberOf' in attrs
        assert len(attrs['memberOf']) == 2000
        delete_obj(client, user)
        for group in groups:
            utils.delete_group(client, group)

    def test_paged_results(self, conf):
        conf.require(ad_admin=True, expensive=True)
        domain = conf.domain()
        creds = Creds(domain)
        creds.acquire(conf.ad_admin_account(), conf.ad_admin_password())
        activate(creds)
        client = Client(domain)
        users = []
        for i in range(2000):
            user = utils.create_user(client, 'test-usr-%04d' % i)
            users.append(user)
        result = client.search('(cn=test-usr-*)')
        assert len(result) == 2000
        for user in users:
            delete_obj(client, user)

    def test_search_rootdse(self, conf):
        conf.require(ad_user=True)
        domain = conf.domain()
        creds = Creds(domain)
        creds.acquire(conf.ad_user_account(), conf.ad_user_password())
        activate(creds)
        locator = Locator()
        server = locator.locate(domain)
        client = Client(domain)
        result = client.search(base='', scope='base', server=server)
        assert len(result) == 1
        dns, attrs = result[0]
        assert 'supportedControl' in attrs
        assert 'supportedSASLMechanisms' in attrs

    def test_search_server(self, conf):
        conf.require(ad_user=True)
        domain = conf.domain()
        creds = Creds(domain)
        creds.acquire(conf.ad_user_account(), conf.ad_user_password())
        activate(creds)
        locator = Locator()
        server = locator.locate(domain)
        client = Client(domain)
        result = client.search('(objectClass=user)', server=server)
        assert len(result) > 1

    def test_search_gc(self, conf):
        conf.require(ad_user=True)
        domain = conf.domain()
        creds = Creds(domain)
        creds.acquire(conf.ad_user_account(), conf.ad_user_password())
        activate(creds)
        client = Client(domain)
        result = client.search('(objectClass=user)', scheme='gc')
        assert len(result) > 1
        for res in result:
            dn, attrs = res
            # accountExpires is always set, but is not a GC attribute
            assert 'accountExpires' not in attrs

    def test_set_password(self, conf):
        conf.require(ad_admin=True)
        domain = conf.domain()
        creds = Creds(domain)
        creds.acquire(conf.ad_admin_account(), conf.ad_admin_password())
        activate(creds)
        client = Client(domain)
        user = utils.create_user(client, 'test-usr-1')
        principal = 'test-usr-1@%s' % domain
        client.set_password(principal, 'Pass123')
        mods = []
        ctrl = AD_USERCTRL_NORMAL_ACCOUNT
        mods.append(('replace', 'userAccountControl', [str(ctrl)]))
        client.modify(user, mods)
        creds = Creds(domain)
        creds.acquire('test-usr-1', 'Pass123')
        assert_raises(ADError, creds.acquire, 'test-usr-1', 'Pass321')
        delete_obj(client, user)

    def test_set_password_target_pdc(self, conf):
        conf.require(ad_admin=True)
        domain = conf.domain()
        creds = Creds(domain)
        creds.acquire(conf.ad_admin_account(), conf.ad_admin_password())
        activate(creds)
        client = Client(domain)
        locator = Locator()
        pdc = locator.locate(domain, role='pdc')
        user = utils.create_user(client, 'test-usr-2', server=pdc)
        principal = 'test-usr-2@%s' % domain
        client.set_password(principal, 'Pass123', server=pdc)
        mods = []
        ctrl = AD_USERCTRL_NORMAL_ACCOUNT
        mods.append(('replace', 'userAccountControl', [str(ctrl)]))
        client.modify(user, mods, server=pdc)
        creds = Creds(domain)
        creds.acquire('test-usr-2', 'Pass123', server=pdc)
        assert_raises(ADError, creds.acquire, 'test-usr-2','Pass321', server=pdc)
        delete_obj(client, user, server=pdc)

    def test_change_password(self, conf):
        conf.require(ad_admin=True)
        domain = conf.domain()
        creds = Creds(domain)
        creds.acquire(conf.ad_admin_account(), conf.ad_admin_password())
        activate(creds)
        client = Client(domain)
        user = utils.create_user(client, 'test-usr-3')
        principal = 'test-usr-3@%s' % domain
        client.set_password(principal, 'Pass123')
        mods = []
        ctrl = AD_USERCTRL_NORMAL_ACCOUNT
        mods.append(('replace', 'userAccountControl', [str(ctrl)]))
        mods.append(('replace', 'pwdLastSet', ['0']))
        client.modify(user, mods)
        client.change_password(principal, 'Pass123', 'Pass456')
        creds = Creds(domain)
        creds.acquire('test-usr-3', 'Pass456')
        assert_raises(ADError, creds.acquire, 'test-usr-3', 'Pass321')
        delete_obj(client, user)

    def test_change_password_target_pdc(self, conf):
        conf.require(ad_admin=True)
        domain = conf.domain()
        creds = Creds(domain)
        creds.acquire(conf.ad_admin_account(), conf.ad_admin_password())
        activate(creds)
        client = Client(domain)
        locator = Locator()
        pdc = locator.locate(domain, role='pdc')
        user = utils.create_user(client, 'test-usr-4', server=pdc)
        principal = 'test-usr-4@%s' % domain
        client.set_password(principal, 'Pass123', server=pdc)
        mods = []
        ctrl = AD_USERCTRL_NORMAL_ACCOUNT
        mods.append(('replace', 'userAccountControl', [str(ctrl)]))
        mods.append(('replace', 'pwdLastSet', ['0']))
        client.modify(user, mods, server=pdc)
        client.change_password(principal, 'Pass123', 'Pass456', server=pdc)
        creds = Creds(domain)
        creds.acquire('test-usr-4', 'Pass456', server=pdc)
        assert_raises(ADError, creds.acquire, 'test-usr-4', 'Pass321', server=pdc)
        delete_obj(client, user, server=pdc)
