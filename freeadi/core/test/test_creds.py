#
# This file is part of FreeADI. FreeADI is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
# "AUTHORS" for a complete overview.

import os
import pexpect
import py.test

from freeadi.test.base import BaseTest
from freeadi.core.creds import Creds as ADCreds
from freeadi.core.object import instance, activate


class TestCreds(BaseTest):
    """Test suite for freeadi.core.creds."""

    def test_acquire_password(self):
        if not self.online_tests_allowed() or not \
                self.administrator_tests_allowed():
            return
        domain = self.domain()
        creds = ADCreds(domain)
        principal = self.admin_account()
        password = self.admin_password()
        creds.acquire(principal, password)
        principal = '%s@%s' % (principal, domain)
        assert creds.principal().lower() == principal.lower()
        child = pexpect.spawn('klist')
        pattern = '.*krbtgt/%s@%s' % (domain.upper(), domain.upper())
        assert child.expect([pattern]) == 0

    def test_acquire_keytab(self):
        if not self.online_tests_allowed() or not \
                self.administrator_tests_allowed():
            return
        domain = self.domain()
        creds = ADCreds(domain)
        principal = self.admin_account()
        password = self.admin_password()
        creds.acquire(principal, password)
        os.environ['PATH'] = '/usr/kerberos/sbin:/usr/kerberos/bin:%s' % \
                             os.environ['PATH']
        fullprinc = creds.principal()
        child = pexpect.spawn('kvno %s' % fullprinc)
        child.expect('kvno =')
        kvno = int(child.readline())
        child.expect(pexpect.EOF)
        child = pexpect.spawn('ktutil')
        child.expect('ktutil:')
        child.sendline('addent -password -p %s -k %d -e rc4-hmac' %
                      (fullprinc, kvno))
        child.expect('Password for.*:')
        child.sendline(password)
        child.expect('ktutil:')
        keytab = self.tempfile(remove=True)
        child.sendline('wkt %s' % keytab)
        child.expect('ktutil:')
        child.sendline('quit')
        child.expect(pexpect.EOF)
        creds.release()
        os.system('klist -k -t %s' % keytab)
        os.system('ls -l %s' % keytab)
        creds.acquire(principal, keytab=keytab)
        child = pexpect.spawn('klist')
        pattern = '.*krbtgt/%s@%s' % (domain.upper(), domain.upper())
        assert child.expect([pattern]) == 0

    def test_acquire_multi(self):
        if not self.online_tests_allowed() or not \
                self.administrator_tests_allowed():
            return
        domain = self.domain()
        principal = self.admin_account()
        password = self.admin_password()
        creds1 = ADCreds(domain)
        creds1.acquire(principal, password)
        ccache1 = creds1._ccache_name()
        config1 = creds1._config_name()
        assert ccache1 == os.environ['KRB5CCNAME']
        assert config1 == os.environ['KRB5_CONFIG']
        creds2 = ADCreds(domain)
        creds2.acquire(principal, password)
        ccache2 = creds2._ccache_name()
        config2 = creds2._config_name()
        assert ccache2 == os.environ['KRB5CCNAME']
        assert config2 == os.environ['KRB5_CONFIG']
        assert ccache1 != ccache2
        assert config1 != config2
        activate(creds1)
        assert os.environ['KRB5CCNAME'] == ccache1
        assert os.environ['KRB5_CONFIG'] == config1
        activate(creds2)
        assert os.environ['KRB5CCNAME'] == ccache2
        assert os.environ['KRB5_CONFIG'] == config2

    def test_release_multi(self):
        if not self.online_tests_allowed() or not \
                self.administrator_tests_allowed():
            return
        domain = self.domain()
        principal = self.admin_account()
        password = self.admin_password()
        ccorig = os.environ.get('KRB5CCNAME')
        cforig = os.environ.get('KRB5_CONFIG')
        creds1 = ADCreds(domain)
        creds1.acquire(principal, password)
        ccache1 = creds1._ccache_name()
        config1 = creds1._config_name()
        creds2 = ADCreds(domain)
        creds2.acquire(principal, password)
        ccache2 = creds2._ccache_name()
        config2 = creds2._config_name()
        creds1.release()
        assert os.environ['KRB5CCNAME'] == ccache2
        assert os.environ['KRB5_CONFIG'] == config2
        creds2.release()
        assert os.environ.get('KRB5CCNAME') == ccorig
        assert os.environ.get('KRB5_CONFIG') == cforig

    def test_cleanup_files(self):
        if not self.online_tests_allowed() or not \
                self.administrator_tests_allowed():
            return
        domain = self.domain()
        principal = self.admin_account()
        password = self.admin_password()
        creds = ADCreds(domain)
        creds.acquire(principal, password)
        ccache = creds._ccache_name()
        config = creds._config_name()
        assert os.access(ccache, os.R_OK)
        assert os.access(config, os.R_OK)
        creds.release()
        assert not os.access(ccache, os.R_OK)
        assert not os.access(config, os.R_OK)

    def test_cleanup_environment(self):
        if not self.online_tests_allowed() or not \
                self.administrator_tests_allowed():
            return
        domain = self.domain()
        principal = self.admin_account()
        password = self.admin_password()
        ccorig = os.environ.get('KRB5CCNAME')
        cforig = os.environ.get('KRB5_CONFIG')
        creds = ADCreds(domain)
        creds.acquire(principal, password)
        ccache = creds._ccache_name()
        config = creds._config_name()
        assert ccache != ccorig
        assert config != cforig
        creds.release()
        assert os.environ.get('KRB5CCNAME') == ccorig
        assert os.environ.get('KRB5_CONFIG') == cforig