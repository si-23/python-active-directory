#
# This file is part of Python-AD. Python-AD is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# Python-AD is copyright (c) 2007 by the Python-AD authors. See the file
# "AUTHORS" for a complete overview.

from __future__ import absolute_import
import os.path
import signal
import dns.resolver
from threading import Timer

import six
from six.moves import range

import pytest
from activedirectory.protocol import netlogon

from ..base import assert_raises


def decode_uint32(buffer, offset):
    d = netlogon.Decoder()
    d.start(buffer)
    d._set_offset(offset)
    return d._decode_uint32(), d._offset()


def decode_rfc1035(buffer, offset):
    d = netlogon.Decoder()
    d.start(buffer)
    d._set_offset(offset)
    return d._decode_rfc1035(), d._offset()


class TestDecoder(object):
    """Test suite for netlogon.Decoder."""

    def test_uint32_simple(self):
        s = b'\x01\x00\x00\x00'
        assert decode_uint32(s, 0) == (1, 4)

    def test_uint32_byte_order(self):
        s = b'\x00\x01\x00\x00'
        assert decode_uint32(s, 0) == (0x100, 4)
        s = b'\x00\x00\x01\x00'
        assert decode_uint32(s, 0) == (0x10000, 4)
        s = b'\x00\x00\x00\x01'
        assert decode_uint32(s, 0) == (0x1000000, 4)

    def test_uint32_long(self):
        s = b'\x00\x00\x00\xff'
        assert decode_uint32(s, 0) == (0xff000000, 4)
        s = b'\xff\xff\xff\xff'
        assert decode_uint32(s, 0) == (0xffffffff, 4)

    def test_error_uint32_null_input(self):
        s = b''
        assert_raises(netlogon.Error, decode_uint32, s, 0)

    def test_error_uint32_short_input(self):
        s = b'\x00'
        assert_raises(netlogon.Error, decode_uint32, s, 0)
        s = b'\x00\x00'
        assert_raises(netlogon.Error, decode_uint32, s, 0)
        s = b'\x00\x00\x00'
        assert_raises(netlogon.Error, decode_uint32, s, 0)

    def test_rfc1035_simple(self):
        s = b'\x03foo\x00'
        assert decode_rfc1035(s, 0) == (b'foo', 5)

    def test_rfc1035_multi_component(self):
        s = b'\x03foo\x03bar\x00'
        assert decode_rfc1035(s, 0) == (b'foo.bar', 9)

    def test_rfc1035_pointer(self):
        s = b'\x03foo\x00\xc0\x00'
        assert decode_rfc1035(s, 5) == (b'foo', 7)

    def test_rfc1035_forward_pointer(self):
        s = b'\xc0\x02\x03foo\x00'
        assert decode_rfc1035(s, 0) == (b'foo', 2)

    def test_rfc1035_pointer_component(self):
        s = b'\x03foo\x00\x03bar\xc0\x00'
        assert decode_rfc1035(s, 5) == (b'bar.foo', 11)

    def test_rfc1035_pointer_multi_component(self):
        s = b'\x03foo\x03bar\x00\x03baz\xc0\x00'
        assert decode_rfc1035(s, 9) == (b'baz.foo.bar', 15)

    def test_rfc1035_pointer_recursive(self):
        s = b'\x03foo\x00\x03bar\xc0\x00\x03baz\xc0\x05'
        assert decode_rfc1035(s, 11) == (b'baz.bar.foo', 17)

    def test_rfc1035_multi_string(self):
        s = b'\x03foo\x00\x03bar\x00'
        assert decode_rfc1035(s, 0) == (b'foo', 5)
        assert decode_rfc1035(s, 5) == (b'bar', 10)

    def test_rfc1035_null(self):
        s = b'\x00'
        assert decode_rfc1035(s, 0) == (b'', 1)

    def test_error_rfc1035_null_input(self):
        s = b''
        assert_raises(netlogon.Error, decode_rfc1035, s, 0)

    def test_error_rfc1035_missing_tag(self):
        s = b'\x03foo'
        assert_raises(netlogon.Error, decode_rfc1035, s, 0)

    def test_error_rfc1035_truncated_input(self):
        s = b'\x04foo'
        assert_raises(netlogon.Error, decode_rfc1035, s, 0)

    def test_error_rfc1035_pointer_overflow(self):
        s = b'\xc0\x03'
        assert_raises(netlogon.Error, decode_rfc1035, s, 0)

    def test_error_rfc1035_cyclic_pointer(self):
        s = b'\xc0\x00'
        assert_raises(netlogon.Error, decode_rfc1035, s, 0)
        s = b'\x03foo\xc0\x06\x03bar\xc0\x0c\x03baz\xc0\x00'
        assert_raises(netlogon.Error, decode_rfc1035, s, 0)

    def test_error_rfc1035_illegal_tags(self):
        s = b'\x80' + 0x80 * b'a' + b'\x00'
        assert_raises(netlogon.Error, decode_rfc1035, s, 0)
        s = b'\x40' + 0x40 * b'a' + b'\x00'
        assert_raises(netlogon.Error, decode_rfc1035, s, 0)

    def test_error_rfc1035_half_pointer(self):
        s = b'\xc0'
        assert_raises(netlogon.Error, decode_rfc1035, s, 0)

    def test_io_byte(self):
        d = netlogon.Decoder()
        s = b'foo'
        d.start(s)
        assert d._read_byte() == ord('f')
        assert d._read_byte() == ord('o')
        assert d._read_byte() == ord('o')

    def test_io_bytes(self):
        d = netlogon.Decoder()
        s = b'foo'
        d.start(s)
        assert d._read_bytes(3) == b'foo'

    def test_error_io_byte(self):
        d = netlogon.Decoder()
        s = b'foo'
        d.start(s)
        for i in range(3):
            d._read_byte()
        assert_raises(netlogon.Error, d._read_byte)

    def test_error_io_bytes(self):
        d = netlogon.Decoder()
        s = b'foo'
        d.start(s)
        assert_raises(netlogon.Error, d._read_bytes, 4)

    def test_error_io_bounds(self):
        d = netlogon.Decoder()
        s = b'foo'
        d.start(s)
        d._set_offset(4)
        assert_raises(netlogon.Error, d._read_byte)
        assert_raises(netlogon.Error, d._read_bytes, 4)

    def test_error_negative_offset(self):
        d = netlogon.Decoder()
        s = b'foo'
        d.start(s)
        assert_raises(netlogon.Error, d._set_offset, -1)

    def test_error_io_type(self):
        d = netlogon.Decoder()
        assert_raises(netlogon.Error, d.start, 1)
        assert_raises(netlogon.Error, d.start, 1)
        assert_raises(netlogon.Error, d.start, ())
        assert_raises(netlogon.Error, d.start, [])
        assert_raises(netlogon.Error, d.start, {})
        assert_raises(netlogon.Error, d.start, u'test')

    def test_real_packet(self, conf):
        buf = conf.read_file('protocol/netlogon.bin')
        dec = netlogon.Decoder()
        dec.start(buf)
        res = dec.parse()
        assert res.forest == b'freeadi.org'
        assert res.domain == b'freeadi.org'
        assert res.client_site == b'Default-First-Site'
        assert res.server_site == b'Test-Site'

    def test_error_short_input(self):
        buf = b'x' * 24
        dec = netlogon.Decoder()
        dec.start(buf)
        assert_raises(netlogon.Error, dec.parse)


class TestClient(object):
    """Test suite for netlogon.Client."""

    def test_simple(self, conf):
        conf.require(ad_user=True)
        domain = conf.domain()
        client = netlogon.Client()
        answer = dns.resolver.query('_ldap._tcp.%s' % domain, 'SRV')
        addrs = [ (ans.target.to_text(), ans.port) for ans in answer ]
        names = [ ans.target.to_text().rstrip('.') for ans in answer ]
        for addr in addrs:
            client.query(addr, domain)
        result = client.call()
        assert len(result) == len(addrs)  # assume retries are succesful
        for res in result:
            assert res.type in (23,)
            assert res.flags & netlogon.SERVER_LDAP
            assert res.flags & netlogon.SERVER_KDC
            assert res.flags & netlogon.SERVER_WRITABLE
            assert len(res.domain_guid) == 16
            assert len(res.forest) > 0
            assert res.domain == domain
            assert res.hostname in names
            assert len(res.netbios_domain) > 0
            assert len(res.netbios_hostname) > 0
            assert len(res.client_site) > 0
            assert len(res.server_site) > 0
            assert (res.q_hostname, res.q_port) in addrs
            assert res.q_domain.lower() == domain.lower()
            assert res.q_timing >= 0.0

    def test_network_failure(self, conf):
        conf.require(ad_user=True, local_admin=True, firewall=True)
        domain = conf.domain()
        client = netlogon.Client()
        answer = dns.resolver.query('_ldap._tcp.%s' % domain, 'SRV')
        addrs = [ (ans.target.to_text(), ans.port) for ans in answer ]
        for addr in addrs:
            client.query(addr, domain)
        # Block CLDAP traffic and enable it after 3 seconds. Because
        # NetlogonClient is retrying, it should be succesfull.
        conf.remove_network_blocks()
        conf.block_outgoing_traffic('udp', 389)
        t = Timer(3, conf.remove_network_blocks); t.start()
        result = client.call()
        assert len(result) == len(addrs)
