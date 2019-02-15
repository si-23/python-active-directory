#
# This file is part of Python-AD. Python-AD is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# Python-AD is copyright (c) 2007 by the Python-AD authors. See the file
# "AUTHORS" for a complete overview.

from __future__ import absolute_import
import os.path
from activedirectory.test.base import BaseTest
from activedirectory.protocol import ldap


class TestLDAP(BaseTest):
    """Test suite for activedirectory.util.ldap."""

    def test_encode_real_search_request(self):
        client = ldap.Client()
        filter = '(&(DnsDomain=FREEADI.ORG)(Host=magellan)(NtVer=\\06\\00\\00\\00))'
        req = client.create_search_request('', filter, ('NetLogon',),
                                          scope=ldap.SCOPE_BASE, msgid=4)

        buf = self.read_file('lib/activedirectory/protocol/test/searchrequest.bin')
        assert req == buf

    def test_decode_real_search_reply(self):
        client = ldap.Client()
        buf = self.read_file('lib/activedirectory/protocol/test/searchresult.bin')
        reply = client.parse_message_header(buf)
        assert reply == (4, 4)
        reply = client.parse_search_result(buf)
        assert len(reply) == 1
        msgid, dn, attrs = reply[0]
        assert msgid == 4
        assert dn == ''

        netlogon = self.read_file('lib/activedirectory/protocol/test/netlogon.bin')
        print(repr(attrs))
        print(repr({ 'netlogon': [netlogon] }))
        assert attrs == { 'netlogon': [netlogon] }
