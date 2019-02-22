from activedirectory.core.exception import Error as ADError, LDAPError
from activedirectory.core.constant import (
    AD_USERCTRL_ACCOUNT_DISABLED,
    AD_USERCTRL_NORMAL_ACCOUNT
)


def delete_obj(client, dn, server=None):
    try:
        client.delete(dn, server=server)
    except (ADError, LDAPError):
        pass

def delete_user(client, name, server=None):
    # Delete any user that may conflict with a newly to be created user
    filter = '(|(cn=%s)(sAMAccountName=%s)(userPrincipalName=%s))' % \
             (name, name, '%s@%s' % (name, client.domain().upper()))
    result = client.search('(&(objectClass=user)(sAMAccountName=%s))' % name,
                           server=server)
    for res in result:
        client.delete(res[0], server=server)


def create_user(client, name, server=None):
    attrs = []
    attrs.append(('cn', [name]))
    attrs.append(('sAMAccountName', [name]))
    attrs.append(('userPrincipalName', ['%s@%s' % (name, client.domain().upper())]))
    ctrl = AD_USERCTRL_ACCOUNT_DISABLED | AD_USERCTRL_NORMAL_ACCOUNT
    attrs.append(('userAccountControl', [str(ctrl)]))
    attrs.append(('objectClass', ['user']))
    dn = 'cn=%s,cn=users,%s' % (name, client.dn_from_domain_name(client.domain()))
    delete_user(client, name, server=server)
    client.add(dn, attrs, server=server)
    return dn


def create_ou(client, name, server=None):
    attrs = []
    attrs.append(('objectClass', ['organizationalUnit']))
    attrs.append(('ou', [name]))
    dn = 'ou=%s,%s' % (name, client.dn_from_domain_name(client.domain()))
    delete_obj(client, dn, server=server)
    client.add(dn, attrs, server=server)
    return dn

def delete_group(client, dn, server=None):
    try:
        client.delete(dn, server=server)
    except (ADError, LDAPError):
        pass

def create_group(client, name, server=None):
    attrs = []
    attrs.append(('cn', [name]))
    attrs.append(('sAMAccountName', [name]))
    attrs.append(('objectClass', ['group']))
    dn = 'cn=%s,cn=Users,%s' % (name, client.dn_from_domain_name(client.domain()))
    delete_group(client, dn, server=server)
    client.add(dn, attrs, server=server)
    return dn

def add_user_to_group(client, user, group):
    mods = []
    mods.append(('delete', 'member', [user]))
    try:
        client.modify(group, mods)
    except (ADError, LDAPError):
        pass
    mods = []
    mods.append(('add', 'member', [user]))
    client.modify(group, mods)
