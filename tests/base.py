#
# This file is part of Python-AD. Python-AD is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# Python-AD is copyright (c) 2007 by the Python-AD authors. See the file
# "AUTHORS" for a complete overview.

from __future__ import absolute_import
import os
import sys
import os.path
from io import open
import tempfile

import six
from six.moves import range
from six.moves.configparser import ConfigParser
import pexpect
import pytest

from activedirectory.util.log import enable_logging


def assert_raises(error_class, function, *args, **kwargs):
    with pytest.raises(error_class):
        function(*args, **kwargs)


class Error(Exception):
    """Test error."""

def dedent(self, s):
    lines = s.splitlines()
    for i in range(len(lines)):
        lines[i] = lines[i].lstrip()
    if lines and not lines[0]:
        lines = lines[1:]
    if lines and not lines[-1]:
        lines = lines[:-1]
    return '\n'.join(lines) + '\n'


class Conf(object):
    """Base class for Python-AD tests."""

    def __init__(self):
        fname = os.environ.get(
            'PYAD_TEST_CONFIG',
            os.path.join(os.path.dirname(__file__), 'test.conf.example')
        )
        if fname is None:
            raise Error('Python-AD test configuration file not specified.')
        if not os.path.exists(fname):
            raise Error('Python-AD test configuration file {} does not exist.'.format(fname))
        self.config = ConfigParser()
        self.config.read(fname)
        self.basedir = os.path.dirname(__file__)
        self._iptables = None
        self._domain = self.config.get('test', 'domain')
        self._tempfiles = []
        enable_logging()

        self.readonly_ad_creds = None
        readonly_env = os.environ.get('PYAD_READONLY_CONFIG', None)
        if readonly_env:
            bits = readonly_env.rsplit('@', 1)
            if len(bits) == 2:
                creds, domain = bits
                bits = creds.split(':', 1)
                if len(bits) == 2:
                    self._domain = domain
                    self.readonly_ad_creds = bits
        elif self.config.getboolean('test', 'readonly_ad_tests'):
            self.readonly_ad_creds = [
                config.get('test', 'ad_user_account'),
                config.get('test', 'ad_user_password'),
            ]

    def teardown(self):
        for fname in self._tempfiles:
            try:
                os.unlink(fname)
            except OSError:
                pass
        self._tempfiles = []

    def tempfile(self, contents=None, remove=False):
        fd, name = tempfile.mkstemp()
        if contents:
            os.write(fd, dedent(contents))
        elif remove:
            os.remove(name)
        os.close(fd)
        self._tempfiles.append(name)
        return name

    def read_file(self, fname):
        fname = os.path.join(self.basedir, fname)
        with open(fname, 'rb') as fin:
            buf = fin.read()

        return buf

    def require(self, ad_user=False, local_admin=False, ad_admin=False,
                firewall=False, expensive=False):
        if firewall:
            local_admin = True
        config = self.config
        if ad_user and not (
            self.readonly_ad_creds and all(self.readonly_ad_creds)
        ):
            raise pytest.skip('test disabled by configuration')
        if local_admin:
            if not config.getboolean('test', 'intrusive_local_tests'):
                raise pytest.skip('test disabled by configuration')
            if not config.get('test', 'local_admin_account') or \
                    not config.get('test', 'local_admin_password'):
                raise pytest.skip('intrusive local tests enabled but no user/pw given')
        if ad_admin:
            if not config.getboolean('test', 'intrusive_ad_tests'):
                raise pytest.skip('test disabled by configuration')
            if not config.get('test', 'ad_admin_account') or \
                    not config.get('test', 'ad_admin_password'):
                raise pytest.skip('intrusive ad tests enabled but no user/pw given')
        if firewall and not self.iptables_supported:
            raise pytest.skip('iptables/conntrack not available')
        if expensive and not config.getboolean('test', 'expensive_tests'):
            raise pytest.skip('test disabled by configuration')

    def domain(self):
        return self._domain

    def ad_user_account(self):
        self.require(ad_user=True)
        return self.readonly_ad_creds[0]

    def ad_user_password(self):
        self.require(ad_user=True)
        return self.readonly_ad_creds[1]

    def local_admin_account(self):
        self.require(local_admin=True)
        return self.config.get('test', 'local_admin_account')

    def local_admin_password(self):
        self.require(local_admin=True)
        return self.config.get('test', 'local_admin_password')

    def ad_admin_account(self):
        self.require(ad_admin=True)
        return self.config.get('test', 'ad_admin_account')

    def ad_admin_password(self):
        self.require(ad_admin=True)
        return self.config.get('test', 'ad_admin_password')

    def execute_as_root(self, command):
        self.require(local_admin=True)
        child = pexpect.spawn('su -c "%s" %s' % (command, self.local_admin_account()))
        child.expect('.*:')
        child.sendline(self.local_admin_password())
        child.expect(pexpect.EOF)
        assert not child.isalive()
        if child.exitstatus != 0:
            m = 'Root command exited with status %s' % child.exitstatus
            raise Error(m)
        return child.before

    def acquire_credentials(self, principal, password, ccache=None):
        if ccache is None:
            ccache = ''
        else:
            ccache = '-c %s' % ccache
        child = pexpect.spawn('kinit %s %s' % (principal, ccache))
        child.expect(':')
        child.sendline(password)
        child.expect(pexpect.EOF)
        assert not child.isalive()
        if child.exitstatus != 0:
            m = 'Command kinit exited with status %s' % child.exitstatus
            raise Error(m)

    def list_credentials(self, ccache=None):
        if ccache is None:
            ccache = ''
        child = pexpect.spawn('klist %s' % ccache)
        try:
            child.expect('Ticket cache: ([a-zA-Z0-9_/.:-]+)\r\n')
        except pexpect.EOF:
            m = 'Command klist exited with status %s' % child.exitstatus
            raise Error(m)
        ccache = child.match.group(1)
        child.expect('Default principal: ([a-zA-Z0-9_/.:@-]+)\r\n')
        principal = child.match.group(1)
        creds = []
        while True:
            i = child.expect(['\r\n', pexpect.EOF,
                              '\d\d/\d\d/\d\d \d\d:\d\d:\d\d\s+' \
                              '\d\d/\d\d/\d\d \d\d:\d\d:\d\d\s+' \
                              '([a-zA-Z0-9_/.:@-]+)\r\n'])
            if i == 0:
                continue
            elif i == 1:
                break
            creds.append(child.match.group(1))
        return ccache, principal, creds

    @property
    def iptables_supported(self):
        if self._iptables is None:
            try:
                self.execute_as_root('iptables -L -n')
                self.execute_as_root('conntrack -L')
            except Error:
                self._iptables = False
            else:
                self._iptables = True
        return self._iptables

    def remove_network_blocks(self):
        self.require(local_admin=True, firewall=True)
        self.execute_as_root('iptables -t nat -F')
        self.execute_as_root('conntrack -F')

    def block_outgoing_traffic(self, protocol, port):
        """Block outgoing traffic of type `protocol' with destination `port'."""
        self.require(local_admin=True, firewall=True)
        # Unfortunately we cannot simply insert a rule like this: -A OUTPUT -m
        # udp -p udp--dport 389 -j DROP.  If we do this the kernel code will
        # be smart and return an error when sending trying to connect or send
        # a datagram. In order realistically emulate a network failure we
        # instead redirect packets the discard port on localhost. This
        # complicates stopping the emulated failure though: merely flushling
        # the nat table is not enough. We also need to flush the conntrack
        # table that keeps state for NAT'ed connections even after the rule
        # that caused the NAT in the first place has been removed.
        self.execute_as_root(
            'iptables -t nat -A OUTPUT -m %s -p %s --dport %d '
            '-j DNAT --to-destination 127.0.0.1:9' % (protocol, protocol, port)
        )
