Signet - Protect your users and customers from hackers
======================================================

:mod:`signet` provides support for building and delivering tamper resistant python to
your users and customers.

Signet creates a custom python loader (aka: an executable binary) which you
deliver with your script. On each invocation, the loader it will verify no
tampering has ocurred before it runs the python script.

Users have the confidence of knowing their scripts are safe and yet retain
full access to the python source for code review and enhancement. And you know
your users are running the right version of code.

Signet is fully integrated with `distutils <https://docs.python.org/2.7/library/distutils.html>`_ to make the process of
building and installing new python projects as simple and painless as possible.

-----------------
How does it work?
-----------------

Signet relies on the strength of cryptographic hash to reliably detect file
modifications.  Signet builds hashes of your script and all your script's
dependencies. These hashes are incorporated into a custom python loader which
will handle re-verifying the hashes before it will agree to run your script.

If your script or any of it's dependencies are tampered with, the loader will
emit an error and exit. If everything matches, the loader will run your script.

-------------
Example usage
-------------

For example, if you had a simple script ``hello.py``:

.. code-block:: py

    import os
    print('hello from %s' % os.name)

And you deployed it with this simple ``setup.py``

.. code-block:: py

    from distutils.core import setup, Extension
    from signet.command.build_signet import build_signet

    setup(name = 'hello',
        cmdclass = {'build_signet': build_signet},
        ext_modules = [Extension('hello', sources=['hello.py'])],
        )

Build your loader::

    python setup.py build_signet

On Windows you'll have ``hello.exe`` and on POSIX you'll have ``hello``.

--------
Features
--------

* Multiplatform: works under

  * Windows (32/64-bit)
  * Linux
  * FreeBSD

* Integrated with Distutils
* Protection from tampering (SHA1 hashed content)
* On Windows

  * Provides code signing executables
  * Loader performs PE executable verification
  * Resource file support (for icons, company name & version reporting)

* Customizable python loader (c++)
* Unique process name 

  * show ``hello`` rather than ``python hello.py``


Contents
========

.. toctree::
   :maxdepth: 2

   signet


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

