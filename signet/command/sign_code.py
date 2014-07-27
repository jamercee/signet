#!/usr/bin/env python2.7
# pylint: disable=C0301
r""":mod:`sign_code` - Digially sign code
=========================================

.. module:: signet.command.sign_code
   :synopsis: Digitially sign executable code files
.. moduleauthor:: Jim Carroll <jim@carroll.com>

The :mod:`signet.command.sign_code` module is responsible for digitally
signing code. The module acts as a wrapper for the Windows SDK tool 
`signtool <http://msdn.microsoft.com/en-us/library/8s9b9yaz%28v=vs.110%29.aspx>`_.
It is intended to be a companion to :mod:`signet.command.build_signet`, but can
be used standalone to sign any executable code file.

The signed code will be timestamped if your computer is connected to the
internet. **sign_code** will randomly select a public timestamp server. If
the first attempt to timestamp fails, it will cycle through it's list of
servers, trying each up to 5 times before giving up.

.. py:class:: sign_code

   .. py:method:: sign_code.run()

   This is the main function responsible for digitally signing your code. It
   is not expected to be invoked directly, but installs itself into the 
   distutils.command heirarcy by nature of it's inheritance from
   `disutils.command.config <https://docs.python.org/2/distutils/apiref.html#module-distutils.core>`_ .

   **sign_code** makes available additional arguments you can specify
   when calling `distutils.core.setup() <https://docs.python.org/2/distutils/apiref.html#distutils.core.setup>`_ 

   .. tabularcolumns:: |l|L|l

   +-----------------+---------------------------------------+-------------------------------+
   |  argument name  | value                                 | type                          |
   +=================+=======================================+===============================+
   | *pfx-file*      | Path to PKCS#12 file with your signing| a string                      |
   |                 | signing certificate. This setting is  |                               |
   |                 | required.                             |                               |
   +-----------------+---------------------------------------+-------------------------------+
   | *password*      | Password associated with PKCS#12 file | a string                      |
   |                 | Either this or *savedpassword* is     |                               |
   |                 | required.                             |                               |
   +-----------------+---------------------------------------+-------------------------------+
   | *savepassword*  | Request **sign_tool** save password   | a boolean                     |
   |                 | in your private registry. The saved   |                               |
   |                 | password is stored encrypted (using   |                               |
   |                 | windows DPAPI).                       |                               |
   +-----------------+---------------------------------------+-------------------------------+
   | *resetpassword* | Delete stored password.               | a boolean                     |
   +-----------------+---------------------------------------+-------------------------------+
   | *digest*        | Digest to use when signing (default   | a string                      |
   |                 | is SHA1).                             |                               |
   +-----------------+---------------------------------------+-------------------------------+
   | *winsdk-path*   | The path to find Windows SDK (if it   | a string                      |
   |                 | is not installed in default path)     |                               |
   +-----------------+---------------------------------------+-------------------------------+

Examples
--------

With options specified on command line, ``setup.py``::

    from distutils.core import setup, Extension
    from signet.command.sign_code import sign_code

    setup(name = 'hello',
        cmdclass = {'sign_code': sign_code},
        ext_modules = [Extension('hello', sources=['hello.py'])],
        )

Invoked as ``python setup.py sign_code --savedpassword --pfx-file CERT-1-Expired-2014-11.pfx``

With options embedded in ``setup.py``::

    from distutils.core import setup, Extension
    from signet.command.sign_code import sign_code

    setup(name = 'hello',
        cmdclass = {'sign_code': sign_code},
        ext_modules = [Extension('hello', sources=['hello.py'])],
        options = { 'sign_code': {
                        'savedpassword': True,
                        'pfx_file': 'CERT-1-Expired-2014-11.pfx',
                        }
                  },
        )

Invoked as ``python setup.py sign_code``


Utility Functions
-----------------

.. autofunction:: get_winsdk_path

.. autofunction:: get_saved_password

.. autofunction:: save_password

"""
# pylint: enable=C0301


# ----------------------------------------------------------------------------
# Standard library imports
# ----------------------------------------------------------------------------
import base64
from distutils import log
from distutils.errors import (DistutilsModuleError, DistutilsPlatformError, 
        DistutilsSetupError)
from distutils.command.config import config
import getpass
import os
import random
import subprocess
import _winreg

WINSDK_ERROR = ("Windows SDK may not be installed on this machine. "
                "You can read more and (re-)download from "
                "https://en.wikipedia.org/wiki/Microsoft_Windows_SDK")

def get_winsdk_path():
    r"""Retrieve installed path for windows sdk."""

    key = None

    try:
        with _winreg.OpenKeyEx(_winreg.HKEY_LOCAL_MACHINE, 
                "SOFTWARE\\Microsoft\\Microsoft SDKs\\Windows") as key:
            pth = _winreg.QueryValueEx(key, 'CurrentInstallFolder')[0]
            pp = []
            for part in pth.split('\\'):
                if len(part):
                    pp.append(part)
            return '\\'.join(pp)
    except (WindowsError, IndexError):
        raise DistutilsPlatformError('missing windows sdk registry entry: %s' 
                % WINSDK_ERROR)

def get_saved_password(name):
    r"""Retrieve previously saved password. The password is returned 
        unencrypted.  *name* is used to lookup a password on this machine,
        which must be the same *name* used in :py:func:`.save_password`."""

    try:
        # Only import pywin32 dependency if user creates a project
        # that requires encrypted password.
        import win32crypt
    except ImportError:
        raise DistutilsModuleError("system missing required win32api "
                "module. You can download from "
                "http://sourceforge.net/projects.pywin32")

    try:
        # retrieve value from user's private registry

        with _winreg.OpenKeyEx(_winreg.HKEY_CURRENT_USER,
                "SOFTWARE\\signet") as key:

            enc = _winreg.QueryValue(key, name)
            enc =  base64.b64decode(enc)

            # decrypt password using DPAPI (CRYPTPROECT_LOCAL_MACHINE)

            return win32crypt.CryptUnprotectData(enc, 
                            None, None, None, 4)[1]

    except (WindowsError, IndexError):
        return None


def save_password(name, password):
    r"""Save password to user's private registry (encrypted). *name* is used
        to save a password on this machine and can be any string that complies
        with Windows's registry naming rules. *password* is the plain text
        password associated with *name*. Set *password* to None, to delete
        value from the registry.
    
        **TIP** I recommend you use the certificate expiration date as the name.
        Remebering when a cert will expire is a maintenance headache, and using
        this as the name will help with this chore.

        Example use::

            >>> from signet.command.sign_code import *
            >>> save_password('Cert-1-Expires-2014-11', 'abc123')
            >>> get_saved_password('Cert-1-Expires-2014-11')
            'abc123'
        """

    if password is None:
        _winreg.DeleteKey(_winreg.HKEY_CURRENT_USER,
                "SOFTWARE\\signet\\%s" % name)
        return

    try:
        # Only import pywin32 dependency if user creates a project
        # that requires encrypted password.

        import win32crypt
    except ImportError:
        raise DistutilsModuleError("system missing required win32api "
                "module. You can download from "
                "http://sourceforge.net/projects/pywin32")

    # encrypt password using DPAPI (CRYPTPROECT_LOCAL_MACHINE)

    enc = win32crypt.CryptProtectData(password, name,
                None, None, None, 4)
    enc = base64.b64encode(enc)

    # create any missing subkeys

    key = _winreg.CreateKey(_winreg.HKEY_CURRENT_USER, 
                "SOFTWARE\\signet")

    # save password

    _winreg.SetValue(key, name, _winreg.REG_SZ, enc)

class sign_code(config):
    r"""Digitally sign code"""

    description = "digitally sign code"
    user_options = config.user_options

    timestamp_urls = (
        'http://timestamp.comodoca.com/authenticode', 
        'http://timestamp.verisign.com/scripts/timstamp.dll',
        'http://timestamp.globalsign.com/scripts/timestamp.dll',
        'http://tsa.starfieldtech.com')

    user_options.extend([
        ('winsdk-path=', None,
         "path to windows sdk (if non-standard)"),
        ('digest=', None,
         "signature digest to use (default SHA1)"),
        ('pfx-file=', None,
         "pathname of PFX file"),
        ('password=', None,
         "plaintext password of PFX file"),
        ('savedpassword', None,
         "prompt & store password using DPAPI"),
        ('resetpassword', None,
         "change the stored password"),
        ]) 

    boolean_options = ['savedpassword', 'resetpassword']


    def initialize_options(self):
        r"""set default option values"""

        config.initialize_options(self)

        self.winsdk_path = None
        self.signtool = None
        self.digest = None
        self.pfx_file = None
        self.password = None
        self.savedpassword = None
        self.resetpassword = None

    def finalize_options(self):
        r"""finished initializing option values"""

        # R0912 (too-many-branches)
        # pylint: disable=R0912

        config.finalize_options(self)

        opts = self.distribution.get_option_dict('sign_code')

        # validate pfx_file (REQUIRED)

        if self.pfx_file is None and opts:
            self.pfx_file = opts.get('pfx-file', (None, None))[1]

        certname = os.path.basename(self.pfx_file)
        certname = os.path.splitext(certname)[0]

        # did user ask to delete password?

        if self.resetpassword:
            save_password(certname, None)

        if self.pfx_file is None:
            raise DistutilsSetupError("sign_code requires 'pfx-file=' setting")

        if not os.path.isfile(self.pfx_file):
            raise DistutilsSetupError("missing the the pfx file '%s'" 
                    % self.pfx_file)

        # validate winsdk_path

        if self.winsdk_path is None and opts:
            self.winsdk_path = opts.get('winsdk-path', (None, None))[1]

        if self.winsdk_path is None:
            self.winsdk_path = get_winsdk_path()

        # find signtool.exe

        self.signtool = os.path.join(self.winsdk_path, 'Bin', 'signtool.exe')
        if not os.path.isfile(self.signtool):
            raise DistutilsPlatformError('missing signtool.exe: %s' 
                    % WINSDK_ERROR)

        # validate digest (leave it none if not specified)

        if self.digest is None and opts:
            self.digest = opts.get('digest', (None, None))[1]
      
        # validate password & savedpassword (must specify one)

        if self.password is None and opts:
            self.password = opts.get('password', (None, None))[1]

        if self.savedpassword is None and opts:
            self.savedpassword = opts.get('savedpassword', (None, None))[1]

        if self.password is None and not self.savedpassword:
            raise DistutilsSetupError("sign_code requires either "
                                      "'password=' or 'savedpassword'")

        if self.savedpassword:
            self.password = get_saved_password(certname)
            if not self.password:
                self.password = getpass.getpass("Enter password: ")
                save_password(certname, self.password)


    def next_timeserver(self):
        r"""Return next timeserver url, generator pattern. Each timeserver
            url will be returned 5 times."""

        # pick a random starting timestamp_url, to spread the load
        # evenly against these public services.

        count = len(self.timestamp_urls)
        seed = random.randint(0, count - 1)

        # try each url at most 5 times

        for curr in xrange(count * 5):
            ndx = (curr + seed) % count
            return self.timestamp_urls[ndx]

    def run(self):
        r"""Perform signing action"""

        if os.name != 'nt':
            log.error('sign_code only available on windows')
            return

        for ext in self.distribution.ext_modules:
            py_source = ext.sources[0]
            exename = os.path.splitext(py_source)[0] + ".exe"

            if not os.path.isfile(exename):
                raise DistutilsSetupError("missing '%s' to sign" % exename)

            log.info('sign %s', exename)

            while 1:

                timestamp_url = self.next_timeserver()
                if timestamp_url is None:
                    raise DistutilsSetupError("exhausted timestamp servers")

                cmd = [self.signtool, 'sign', 
                            '/f', self.pfx_file,
                            '/p', self.password,
                            '/t', timestamp_url,
                      ]
                if self.verbose:
                    cmd.extend(['/v'])

                cmd.extend([exename])

                task = subprocess.Popen(cmd,
                            stdout = subprocess.PIPE, stderr = subprocess.PIPE)
                (stdout, stderr) = task.communicate()
                if task.returncode == 2:
                    log.debug('failed to sign w/ timestamp url %s', 
                            timestamp_url)
                    continue

                if task.returncode:
                    log.info(stdout)
                    log.error(stderr)

                # If we get here, code is signed

                log.debug(stdout)
                break

