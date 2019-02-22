#
# This file is part of Python-AD. Python-AD is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# Python-AD is copyright (c) 2007 by the Python-AD authors. See the file
# "AUTHORS" for a complete overview.
"""Test suite for protocol.krb5."""

from __future__ import absolute_import
import os
import stat
import pexpect

from activedirectory.protocol import krb5
from ..base import assert_raises, Error


def test_cc_default(conf):
    conf.require(ad_user=True)
    domain = conf.domain().upper()
    principal = '%s@%s' % (conf.ad_user_account(), domain)
    password = conf.ad_user_password()
    conf.acquire_credentials(principal, password)
    ccache = krb5.cc_default()
    ccname, princ, creds = conf.list_credentials(ccache)
    assert princ.lower() == principal.lower()
    assert len(creds) > 0
    assert creds[0] == 'krbtgt/%s@%s' % (domain, domain)

def test_cc_copy_creds(conf):
    conf.require(ad_user=True)
    domain = conf.domain().upper()
    principal = '%s@%s' % (conf.ad_user_account(), domain)
    password = conf.ad_user_password()
    conf.acquire_credentials(principal, password)
    ccache = krb5.cc_default()
    cctmp = conf.tempfile()
    assert_raises(Error, conf.list_credentials, cctmp)
    krb5.cc_copy_creds(ccache, cctmp)
    ccname, princ, creds = conf.list_credentials(cctmp)
    assert princ.lower() == principal.lower()
    assert len(creds) > 0
    assert creds[0] == 'krbtgt/%s@%s' % (domain, domain)

def test_cc_get_principal(conf):
    conf.require(ad_user=True)
    domain = conf.domain().upper()
    principal = '%s@%s' % (conf.ad_user_account(), domain)
    password = conf.ad_user_password()
    conf.acquire_credentials(principal, password)
    ccache = krb5.cc_default()
    princ = krb5.cc_get_principal(ccache)
    assert princ.lower() == principal.lower()
