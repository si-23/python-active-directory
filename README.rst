Python-Active-Directory
=======================

This is Python-AD, an Active Directory client library for Python on UNIX/Linux systems.

**Note** - version 1.0 added support for Python >= 3.6 and version 2.0 will drop support for Python 2

Install
-------

.. code:: bash

    $ pip install -e git+git@github.com:theatlantic/python-active-directory.git@v1.0.0+atl.2.0#egg=python-active-directory


Development
-----------

Get the code
~~~~~~~~~~~~

.. code:: bash

    $ git clone git@github.com:theatlantic/python-active-directory.git
    $ cd python-active-directory


Create virtual environment
~~~~~~~~~~~~~~~~~~~~~~~~~~

* Python 2: ``virtualenv venv``
* Python 3: ``python -mvenv venv``

.. code:: bash

    $ . venv/bin/activate
    $ pip install -e .


Testing
~~~~~~~

Version 1.0 switched to using pytest instead of nose, and added tox configuration
for supporting testing across various supported Python versions.

.. code:: bash

    $ pip install tox
    $ tox

Special environment variables:

* ``PYAD_TEST_CONFIG`` - Override the default test configuration file (formerly ``FREEADI_TEST_CONFIG``)
* ``PYAD_READONLY_CONFIG`` - Enable readonly tests, must be in the form of ``username:password@domain.tld``


