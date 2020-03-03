#
# This file is part of Python-AD. Python-AD is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# Python-AD is copyright (c) 2007 by the Python-AD authors. See the file
# "AUTHORS" for a complete overview.
"""Test suite for activedirectory.util.ldap."""

from __future__ import absolute_import
import os.path
from activedirectory.protocol import ldap



def test_encode_real_search_request(conf):
    client = ldap.Client()
    filter = '(&(DnsDomain=FREEADI.ORG)(Host=magellan)(NtVer=\\06\\00\\00\\00))'
    req = client.create_search_request('', filter, ('NetLogon',),
                                      scope=ldap.SCOPE_BASE, msgid=4)

    buf = conf.read_file('protocol/searchrequest.bin')
    assert req == buf

def test_decode_real_search_reply(conf):
    client = ldap.Client()
    buf = conf.read_file('protocol/searchresult.bin')
    reply = client.parse_message_header(buf)
    assert reply == (4, 4)
    reply = client.parse_search_result(buf)
    assert len(reply) == 1
    msgid, dn, attrs = reply[0]
    assert msgid == 4
    assert dn == b''

    netlogon = conf.read_file('protocol/netlogon.bin')
    print(repr(attrs))
    print(repr({ 'netlogon': [netlogon] }))
    assert attrs == { b'netlogon': [netlogon] }
