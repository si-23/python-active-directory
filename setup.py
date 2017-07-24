#
# This file is part of Python-AD. Python-AD is free software that is made
# available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# Python-AD is copyright (c) 2007 by the Python-AD authors. See the file
# "AUTHORS" for a complete overview.

from setuptools import setup, Extension
import pkg_resources

# Prefer pyldap over python-ldap
ldap_req = "pyldap"
try:
    pkg_resources.get_distribution("python-ldap")
except pkg_resources.DistributionNotFound:
    pass
else:
    try:
        pkg_resources.get_distribution("pyldap")
    except pkg_resources.DistributionNotFound:
        ldap_req = "python-ldap"


setup(
    name='python-active-directory',
    version='0.9',
    description='An Active Directory client library for Python',
    author='Geert Jansen',
    author_email='programmers@theatlantic.com',
    url='https://github.com/theatlantic/python-active-directory',
    license='MIT',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python'],
    package_dir={'': 'lib'},
    packages=[
        'activedirectory', 'activedirectory.core', 'activedirectory.protocol',
        'activedirectory.util'],
    install_requires=[ldap_req, 'dnspython', 'ply'],
    ext_modules=[
        Extension('activedirectory.protocol.krb5',
            ['lib/activedirectory/protocol/krb5.c'],
            libraries=['krb5'])],
    test_suite='nose.collector'
)
