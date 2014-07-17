#!/usr/bin/env python2.7
## \file tests/winutils.py
# \brief windows utils for testing signet project
# \date July 16th, 2014
# \copyright Copyright(c), 2014, Carroll-Net, Inc.
# \copyright All Rights Reserved.
# pylint: disable=C0301
r"""used by unittesting for signet on windows

Functions to invoke windows code signing tools. The tools used are:

   .. tabularcolumns:: |l|L|l

    +-----------+-----------------------------------+----------------------------+
    | *tool*    | *description*                     | *url*                      |
    +===========+===================================+============================+
    | makecert  | Certificate creation tool.        | http://tinyurl.com/njh7cry |
    +-----------+-----------------------------------+----------------------------+
    | cert2spc  | Convert private key to Software   | http://tinyurl.com/pab4n7q |
    |           | Publish Certificate               |                            |
    +-----------+-----------------------------------+----------------------------+
    | certutil  | Interact with certificate services| http://tinyurl.com/punbfdl |
    |           | on your local machine.            |                            |
    +-----------+-----------------------------------+----------------------------+
    | pvk2pfx   | Combine private key .spc, .cer    | http://tinyurl.com/mu5c6n8 |
    |           | and .pvk to personal information  |                            |
    |           | exchange (.pfx) file.             |                            |
    +-----------+-----------------------------------+----------------------------+

The makecert and certutil have popup windows that need to be acknowledge. For the 
purpose of automation, these utility functions will handle the details of responding.
You should not hit any keys while these tests are running.

Also, the certutil will sound your system bell when the windows popup. It's annoying
but you can safely ignore it.

Copyright(c), 2014, Carroll-Net, Inc.
All Rights Reserved"""
# pylint: enable=C0301

# ----------------------------------------------------------------------------
# Standard library imports
# ----------------------------------------------------------------------------
import datetime
import os
import re
import shutil
import subprocess
import tempfile
import time
import win32com.client

# ----------------------------------------------------------------------------
# Project library imports
# ----------------------------------------------------------------------------
from signet.command.sign_code import get_winsdk_path

# ----------------------------------------------------------------------------
# Module level initializations
# ----------------------------------------------------------------------------
__pychecker__  = 'unusednames=__maintainer__,__status__'
__version__    = '2.4.1'
__author__     = 'Jim Carroll'
__maintainer__ = 'Jim Carroll'
__email__      = 'jim@carroll.com'
__status__     = 'Testing'
__copyright__  = 'Copyright(c) 2014, Carroll-Net, Inc., All Rights Reserved'


def run_makecert(cmd, password, issuer_prompt):
    r"""run makecert.exe, respond to windows popups. *cmd* is the command to
        pass to WScript.Shell.Run() (assumed to be makecert.exe). *password*
        the password submitted to the popup window. *issuer_prompt* if False,
        assume there are two popup window, if True assume a third window needs
        responses (the prompt for Issuer's password)."""

    # Run cmd using WshShell Object (run in background)

    shell = win32com.client.Dispatch('WScript.Shell')
    shell.Run(cmd, 1, False)

    # Wait 10-seconds for popup (polling every 1/2 second)

    for _ in xrange(20):
        if shell.AppActivate('Create Private Key Password'):
            break
        time.sleep(0.5)
    if not shell.AppActivate('Create Private Key Password'):
        raise RuntimeError("timeout waiting for makecert popup(1)")

    # First screen - 'Create Private Key Password'

    shell.SendKeys(password)
    time.sleep(0.2)
    shell.SendKeys('{TAB}')
    time.sleep(0.2)
    shell.SendKeys(password)
    time.sleep(0.2)
    shell.SendKeys('{TAB}')
    time.sleep(0.2)
    shell.SendKeys('{ENTER}')
    time.sleep(0.2)

    # Second screen - 'Private Key Password'

    shell.SendKeys(password)
    time.sleep(0.2)
    shell.SendKeys('{TAB}')
    time.sleep(0.2)
    shell.SendKeys('{ENTER}')
    time.sleep(0.2)

    if not issuer_prompt:
        return

    # Third screen - 'Issuer Password'

    shell.SendKeys(password)
    time.sleep(0.2)
    shell.SendKeys('{TAB}')
    time.sleep(0.2)
    shell.SendKeys('{ENTER}')
    time.sleep(0.2)

def run_certutil(cmd, title):
    r"""run certutil.exe command, respond to windows popups.  When adding or
        removing from Root store, windows requires the user to acknowledge the
        action."""

    # Run cmd using WshShell Object (run in background)

    shell = win32com.client.Dispatch('WScript.Shell')
    shell.Run(cmd, 1, False)

    # Note -- the certutil security popup does not respond 'True'
    # when AppActivate() hits it (which is likely a security measure).
    # So, we just add a reasonable sleep period.

    time.sleep(1.0)
    shell.AppActivate(title)

    time.sleep(0.5)

    time.sleep(0.2)
    shell.SendKeys('{TAB}')
    time.sleep(0.2)
    shell.SendKeys('{ENTER}')
    time.sleep(0.2)

def make_ca(password, pvk_filename, cer_filename):
    r"""create self signed certificate authority -- add to windows cert store.
        *password* is the secret to protect CA's private key. *pvk_filename*
        is where to create the CA's private key file. *cer_filename* is where
        to create the CA's public certificate.

        For security, the certificate authority is only valid for 24-hours,
        but it's still recommended when you are done using this CA, you delete
        it from your windows cert store by calling :func:``remove_ca()``"""

    mkcert = os.path.join(get_winsdk_path(), 'Bin', 'makecert.exe')

    end_date = datetime.datetime.now().date() + datetime.timedelta(days=1)
    end_date = end_date.strftime('%m/%d/%Y')

    run_makecert("\"%s\" "
                "-r "                   # create self-signed cert
                "-pe "                  # make private key exportable
                "-e %s "                # end of validity date
                "-n \"CN=TESTCA\" "     # subject of our CA
                "-ss CA "               # certificate store name
                "-sr CurrentUser "      # store user's private store
                "-cy authority "        # create an authority cert type
                "-sky signature "       # key will be used for signing
                "-sv \"%s\" "           # pvk filename to create
                "\"%s\""                # output cert filename
                % (mkcert, end_date, pvk_filename, cer_filename), 
            password, False)

    run_certutil("certutil.exe "
                "-user "                # user's private store
                "-addstore Root "       # store name
                "%s"                    # filename of certificate to import
                % cer_filename,
                "Security Warning")

def remove_ca():
    r"""remove cert's with a subject of 'CN=TESTCA' from user's
        CA windows store"""

    snum_pat = re.compile(r'^Serial Number: ([a-f\d]+)$')
    subj_pat = re.compile(r'^Issuer: (CN=TESTCA)$')

    snum, subj = None, None

    output = subprocess.check_output(["certutil.exe",
                "-user",                # user's private store
                "-store", "Root",       # certificate store name
                "TESTCA"],              # cert subject common name
                shell=True, universal_newlines=True)

    for line in output.split("\n"):
        ma = snum_pat.match(line)
        if ma:
            snum = ma.group(1)
            continue
        ma = subj_pat.match(line)
        if ma:
            subj = ma.group(1)
            continue

        if snum and subj:
            run_certutil("certutil.exe "
                "-user "                # user's private store
                "-delstore Root "       # store name
                "%s"                    # filename of certificate to import
                % snum, 
                "Root Certificate Store")

            snum, subj = None, None

def make_pfx(password, ca_cer_filename, ca_pvk_filename, pfx_filename):
    r"""create 'personal info exchange' file (\*.pfx). *password* is the secret
        used to protect the new pfx file. *pfx_filename* is where to store the
        new pfx file. -1 indicates an error, 0 is sucess."""

    sdkpath = os.path.join(get_winsdk_path(), 'Bin')

    mkcert   = os.path.join(sdkpath, 'makecert.exe')
    cert2spc = os.path.join(sdkpath, "cert2spc.exe")
    pvk2pfx  = os.path.join(sdkpath, "pvk2pfx")

    tmpd = tempfile.mkdtemp()

    pvk = os.path.join(tmpd, 'mykey.pvk')
    cer = os.path.join(tmpd, 'mycert.cer')
    spc = os.path.join(tmpd, 'mycert.spc')

    try:
        # create private key (*.pvk) & certificate (*.cer)
        run_makecert("\"%s\""
                "-pe "                  # make private key exportable
                "-n \"CN=TESTSPC\" "    # subject's common name
                "-cy end "              # create an end-entity cert type
                "-sky signature "       # key will be used for signing
                "-ic %s "               # issuer's certificate file
                "-iv %s "               # issuer's private key file
                "-sv \"%s\" "           # pvk filename to create
                "\"%s\""                # output cert filename
                    % (mkcert, ca_cer_filename, ca_pvk_filename, pvk, cer), 
                password, True)

        # convert cert (*.cer) -> software publish certificate (*.spc)
        subprocess.check_call([cert2spc, cer, spc], stdout=subprocess.PIPE)

        # combine private key + cert -> personal info exchange (*.pfx)
        subprocess.check_call([pvk2pfx, 
                    "-pvk", pvk,            # .pvk filename
                    "-pi", password,        # password to read .pvk file
                    "-spc", spc,            # .spc filename
                    '-f',                   # overwrite .pfx (if it exsits)
                    "-pfx", pfx_filename,   # .pfx filename to create
                    "-po", password],       # password written to .pfx file
                    stdout=subprocess.PIPE)
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)

    return 0

